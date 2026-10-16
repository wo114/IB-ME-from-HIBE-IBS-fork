"""Independent paper object/algebra checks, without a slow lifecycle.

The zero-witness fixture is deliberately a public algebra fixture, not a
cryptographic setup. Gadget tests do use the real finite scalar Gaussian.
Full production-random lifecycles are recorded separately by paper_audit.
"""
from dataclasses import replace
from fractions import Fraction
import json
from math import isqrt

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.candidates.srgg import paper_backend as api
from experiments.research.candidates.srgg.paper_algebra import (
    PaperRing, identity_target, message_challenge, public_matrix,
)
from experiments.research.candidates.srgg.paper_objects import (
    MasterSecret, PublicKey, Signature, SigningKey, _encode,
)
from experiments.research.candidates.srgg.paper_parameters import PaperParams, pi_enclosure


class NoRead:
    def read(self, _size):
        raise AssertionError("object or public operation unexpectedly consumed entropy")


@pytest.fixture(scope="module", params=("PARAM-I", "PARAM-II", "PARAM-III"))
def algebra_fixture(request):
    p = PaperParams(request.param)
    ring = PaperRing(p)
    seed = bytes(range(32))
    a_hat = public_matrix(p, seed)
    witness = tuple(tuple(ring.constant(0) for _ in range(p.rank*p.digits))
                    for _ in range(2*p.rank))
    public = PublicKey(p, seed, a_hat, ring.build_public(a_hat, witness))
    key = SigningKey(public, b"algebra-fixture", (ring.constant(0),)*((1+p.digits)*p.rank))
    master = MasterSecret(public, witness, {key.identity: ("issued", key),
                          b"failed": ("failed", None), b"pending": ("pending", None)})
    signature = Signature(public.context, (ring.constant(0),)*(p.columns+1), ring.constant(0))
    return ring, public, master, key, signature


@pytest.mark.parametrize("position", (1, 2, 3, 4))
def test_four_objects_roundtrip_and_reject_structural_mutations(algebra_fixture, position):
    obj = algebra_fixture[position]
    data = obj.to_bytes()
    assert type(obj).from_bytes(data) == obj
    record = json.loads(data)
    for malformed in (data[:-1], data+b" ", data+b"x", b"[1]",
                      b'{"kind":"duplicate",'+data[1:],
                      _encode({**record, "unexpected": 0}),
                      _encode({**record, "kind": "wrong"}),
                      _encode({**record, "schema": "IBME/SRGG-STRUCTURED-OBJECT/1"})):
        with pytest.raises(SerializationError):
            type(obj).from_bytes(malformed)


@pytest.mark.parametrize("field,value", (
    ("perturbation_noise_factor", True), ("perturbation_noise_factor", 1.0),
    ("pi_precision_bits", 512.0), ("pi_precision_bits", True),
    ("source_sha256", "0"*64), ("interpretation", "default"),
    ("gadget_remainder_representative", "unsigned-mod-p"),
    ("hnf_representative", "unsigned-mod-Q"),
))
def test_parameter_restore_rejects_numeric_aliases_and_convention_changes(field, value):
    p = PaperParams()
    record = {**p.record(), field: value}
    with pytest.raises((ValueError, TypeError)):
        PaperParams.from_record(record)


def test_explicit_notations_preserve_table_values_and_bind_public_context(algebra_fixture):
    _, public, _, _, _ = algebra_fixture
    p = public.params
    literal = PaperParams(p.profile_name, "literal-density-width")
    lo, hi = pi_enclosure()
    for field in ("r_squared", "master_first_squared", "master_second_squared",
                  "signature_first_squared", "signature_second_squared"):
        assert 2*lo*getattr(literal, field) <= getattr(p, field) <= 2*hi*getattr(literal, field)
    assert literal.r_squared == Fraction(29, 25)**2
    assert p.modulus == literal.modulus == 15744063
    assert p.digits == literal.digits == 2
    gamma = Fraction(p.source.gamma)
    assert p.signature_norm_cap <= gamma**2 < p.signature_norm_cap+1
    alternate = PublicKey(literal, public.seed, public_matrix(literal, public.seed), public.b)
    assert alternate.context != public.context
    assert p.record()["perturbation_noise_factor"] == 1


def test_seed_matrix_dimensions_and_exact_public_residues_are_checked(algebra_fixture):
    _, public, _, _, _ = algebra_fixture
    record = json.loads(public.to_bytes())
    variants = []
    for value in (True, 0.0, -1, public.params.modulus):
        bad = json.loads(public.to_bytes())
        bad["b"][0][0][0] = value
        variants.append(bad)
    wrong_dimension = json.loads(public.to_bytes())
    wrong_dimension["b"][0].pop()
    variants.append(wrong_dimension)
    for bad in variants:
        with pytest.raises(SerializationError):
            PublicKey.from_bytes(_encode(bad))
    changed = [[list(poly) for poly in row] for row in public.a_hat]
    changed[0][0][0] = (changed[0][0][0]+1) % public.params.modulus
    with pytest.raises(ValueError, match="seed/public"):
        replace(public, a_hat=changed)
    assert set(record) == {"schema", "kind", "params", "seed", "b"}


def test_hnf_key_identity_binding_and_cached_restore_need_no_entropy(algebra_fixture):
    ring, public, master, key, _ = algebra_fixture
    assert key.identity_digest == hash_identity(key.identity, 32)
    assert ring.matvec(ring.public_a(public), key.full, public.params.modulus) == identity_target(public, key.identity)
    normalized = SigningKey(public, bytearray(key.identity), key.tail)
    assert type(normalized.identity) is bytes and normalized == key
    recovered = MasterSecret.from_bytes(master.to_bytes())
    backend = api.Backend(rng=NoRead())
    assert backend.key_extract(recovered, key.identity) == key
    for identity in (b"failed", b"pending"):
        with pytest.raises(SamplingAbort, match="blocked"):
            backend.key_extract(recovered, identity)
    for invalid in (b"", "id", b"i"*4097):
        with pytest.raises(EncodingError):
            SigningKey(public, invalid, key.tail)


def test_master_restore_checks_cbd1_relation_and_state_key_binding(algebra_fixture):
    _, public, master, key, _ = algebra_fixture
    for value in (True, 1.0, 2, 1):
        record = json.loads(master.to_bytes())
        record["witness"][0][0][0] = value
        with pytest.raises(SerializationError):
            MasterSecret.from_bytes(_encode(record))
    for state in ("unknown", True):
        with pytest.raises(SerializationError):
            MasterSecret(public, master.witness, {key.identity: (state, None)})
    with pytest.raises(SerializationError, match="cached key mismatch"):
        MasterSecret(public, master.witness, {b"another-identity": ("issued", key)})
    with pytest.raises(SerializationError, match="must be absent"):
        MasterSecret(public, master.witness, {key.identity: ("failed", key)})


def test_signature_load_checks_context_shape_and_original_gamma(algebra_fixture):
    ring, public, _, _, signature = algebra_fixture
    backend = api.Backend(rng=NoRead())
    assert backend.load_signature(public, signature.to_bytes()) == signature
    cap = isqrt(public.params.signature_norm_cap)+1
    huge = (ring.constant(cap),)+(ring.constant(0),)*public.params.columns
    for malformed in (replace(signature, context=bytes(32)),
                      replace(signature, response=signature.response[:-1]),
                      replace(signature, challenge=signature.challenge[:256],
                              response=tuple(poly[:256] for poly in signature.response)),
                      replace(signature, response=huge)):
        with pytest.raises(SerializationError):
            backend.load_signature(public, malformed.to_bytes())
    rows = [[list(poly) for poly in row] for row in public.b]
    rows[0][0][0] = (rows[0][0][0]+1) % public.params.modulus
    with pytest.raises(SerializationError):
        backend.load_signature(replace(public, b=rows), signature.to_bytes())
    for field, value in (("challenge", [True]*512), ("challenge", [2]*512),
                         ("response", [[True]*512]), ("response", [[2**256]*512])):
        record = json.loads(signature.to_bytes())
        with pytest.raises(SerializationError):
            Signature.from_bytes(_encode({**record, field: value}))


def test_public_verification_rejects_invalid_inputs_without_sampling(algebra_fixture, monkeypatch):
    _, public, _, key, signature = algebra_fixture
    backend = api.Backend(rng=NoRead())
    def forbidden(*_args, **_kwargs):
        raise AssertionError("public verification prepared a private sampler")
    monkeypatch.setattr(backend, "_components", forbidden)
    assert backend.verify(public, key.identity, b"m"*32, signature) is False
    for identity, message, sig in ((None, b"m", signature), (b"", b"m", signature),
                                   (key.identity, None, signature),
                                   (key.identity, b"m"*65537, signature),
                                   (key.identity, b"m", object())):
        assert backend.verify(public, identity, message, sig) is False


@pytest.mark.parametrize("interpretation", ("table-standard-deviation", "literal-density-width"))
def test_real_scalar_gadget_uses_centered_error_and_exact_original_modulus(interpretation):
    p = PaperParams("PARAM-I", interpretation)
    _series, scalar = api.sampler_profile("query-bounded")
    gadget = api.PaperGadget(p, scalar_options=scalar, aggregate_abort_bits=192)
    rng = DeterministicRandom(("paper-centered-scalar-"+interpretation).encode())
    targets = (0, 1, p.p//2, p.p//2+1, p.p-1, p.p, p.p+1,
               p.modulus//2, p.modulus-p.p, p.modulus-2, p.modulus-1)
    for target in targets:
        digits, error = gadget.sample_scalar(target, rng)
        assert -p.p//2 <= error <= p.p//2
        assert abs(error) <= p.p//2
        assert (target-error) % p.p == 0
        assert (p.p*sum(p.base**i*x for i, x in enumerate(digits))-target+error) % p.modulus == 0
        assert len(digits) == p.digits and all(type(x) is int for x in digits)
    _, error = gadget.sample_scalar(p.p-1, rng)
    assert error == -1  # The former unsigned error was p-1, not a small lift.
    for invalid in (True, 1.0, -1, p.modulus):
        with pytest.raises(ValueError, match="canonical"):
            gadget.sample_scalar(invalid, NoRead())


def test_real_scalar_error_is_exactly_the_reconstructed_hnf_head(algebra_fixture):
    # Sparse scalar embedding is an algebra fixture, not a full SampleF draw.
    ring, public, master, _, _ = algebra_fixture
    p = public.params
    _series, scalar = api.sampler_profile("query-bounded")
    gadget = api.PaperGadget(p, scalar_options=scalar, aggregate_abort_bits=192)
    source = DeterministicRandom(("paper-hnf-error-"+p.profile_name).encode())
    targets, digits, errors = [], [], []
    choices = (p.p-1, p.p//2+1, p.modulus-1, p.p+1)
    for target in choices[:p.rank]:
        sampled, error = gadget.sample_scalar(target, source)
        targets.append(ring.constant(target))
        digits.extend(ring.constant(value) for value in sampled)
        errors.append(ring.constant(error))
    target, errors = tuple(targets), tuple(errors)
    raw = ring.raw_from_values(public, master.witness, target,
                              (ring.constant(0),)*p.columns, tuple(digits), errors)
    repaired = ring.reconstruct(public, target, raw[p.rank:])
    assert repaired[:p.rank] == errors
    assert repaired[p.rank:] == raw[p.rank:]
    assert ring.matvec(ring.public_a(public), repaired, p.modulus) == target


def test_exact_response_recovers_commitment_at_paper_twoQ(algebra_fixture):
    ring, public, _, key, _ = algebra_fixture
    p = public.params
    perturbation = tuple(ring.constant(i-3) for i in range(p.columns+1))
    challenge = tuple(i % 2 for i in range(p.degree))
    u = ring.constant(-7)
    target = identity_target(public, key.identity)
    commitment = ring.matvec(ring.signing_matrix(public, target), perturbation, 2*p.modulus)
    response = ring.response(key.full, perturbation, u, challenge)
    assert ring.recover(public, target, response, challenge) == commitment
    assert ring.multiply(ring.zeta(), ring.zeta(True)) == ring.constant(2)
    assert len(message_challenge(public, commitment, b"m"*32)) == 512


def test_32_public_random_signature_attempts_are_rejected_without_sampling(algebra_fixture):
    # A finite parser/verification negative control, not an unforgeability proof.
    ring, public, _, key, _ = algebra_fixture
    p = public.params
    source = DeterministicRandom(("paper-random-forgery-"+p.profile_name).encode())
    backend = api.Backend(rng=NoRead())
    for _ in range(32):
        coefficients = source.read((p.columns+1)*p.degree)
        response = tuple(tuple((x % 9)-4 for x in coefficients[i*p.degree:(i+1)*p.degree])
                         for i in range(p.columns+1))
        challenge = tuple(x & 1 for x in source.read(p.degree))
        attempt = Signature(public.context, response, challenge)
        assert backend.verify(public, key.identity, b"m"*32, attempt) is False


def test_public_Q_shift_keeps_a_valid_fixture_signature_and_original_gamma(algebra_fixture):
    # This zero-trapdoor fixture has public short preimages. Constructing its
    # transcript is NOT a Gaussian signature or a real cryptographic lifecycle.
    # The test independently checks the Q-shift mechanism; actual-key attack
    # observations belong to the separately recorded production-random audits.
    ring, public, _, old_key, _ = algebra_fixture
    p = public.params
    target = identity_target(public, old_key.identity)
    tail = [ring.constant(0) for _ in range(p.rank)]
    for poly in target:
        digit_columns = [[] for _ in range(p.digits)]
        for coefficient in poly:
            error = (coefficient+p.p//2) % p.p-p.p//2
            state = (coefficient-error)//p.p
            for column in digit_columns:
                digit = (state+p.base//2) % p.base-p.base//2
                column.append(digit)
                state = (state-digit)//p.base
        tail.extend(tuple(column) for column in digit_columns)
    key = SigningKey(public, old_key.identity, tuple(tail))
    commitment = (ring.constant(0),)*p.rank
    message = b"Q-shift-mathematical-fixture"
    challenge = message_challenge(public, commitment, message)
    response = ring.response(key.full, (ring.constant(0),)*(p.columns+1),
                             ring.constant(0), challenge)
    original = Signature(public.context, response, challenge)
    backend = api.Backend(rng=NoRead())
    assert backend.verify(public, key.identity, message, original) is True
    changed = [list(poly) for poly in response]
    changed[0][0] += -p.modulus if changed[0][0] >= 0 else p.modulus
    forged = replace(original, response=changed)
    assert original.to_bytes() != forged.to_bytes()
    assert sum(x*x for poly in forged.response for x in poly) <= p.signature_norm_cap
    assert ring.recover(public, target, original.response, challenge) == commitment
    assert ring.recover(public, target, forged.response, challenge) == commitment
    assert backend.verify(public, key.identity, message, forged) is True
