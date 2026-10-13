"""Independent Yu Figure 5 integration/encoding checks; research evidence only.

Success fixtures execute real AP09, BPR NAND evaluation, RandBasis/LLL and
GPV sampling. A public AP09 A1 prefix fixes rank; the remaining bytes come
from SecureRandom. This is not an unconditioned Setup distribution experiment.
The separate evidence runner owns a fully SecureRandom chain. No generated
keys, entropy seeds or sampler geometry are written by these tests.

The tiny q=3 profile is forgeable: q*e_1 passes every context. Context mutations
are compared with independently evaluated public modular equations, never
assumed to fail. Failure-injection tests below are explicitly named and must
not be counted as successful cryptographic executions.
"""

from dataclasses import replace
from math import isqrt
from pathlib import Path
from types import SimpleNamespace
import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("sage.all", reason="Use WSL ~/miniconda3/envs/sage/bin/python")
from sage.all import ZZ, matrix as sage_matrix

from ibme.core.randomness import SecureRandom
from experiments.research.candidates.yu import bpr, evaluation, standalone as yu
from experiments.research.candidates.yu.profiles import tiny_profile
from experiments.research.gaussian_reference import SamplingAbort


IDENTITY, MESSAGE = (1, 0), (0, 1)


class CountingRandom:
    def __init__(self, *, rank_prefix=False):
        self.prefix = iter((1, 2, 0) if rank_prefix else ())
        self.source = SecureRandom()
        self.calls = 0

    def read(self, count):
        self.calls += 1
        value = next(self.prefix, None)
        if value is not None:
            assert count == 1
            return bytes((value,))
        return self.source.read(count)


class NoEntropy:
    def read(self, count):
        pytest.fail("unexpected entropy consumption")


@pytest.fixture(scope="module")
def params():
    return tiny_profile()


@pytest.fixture(scope="module")
def family(params):
    public, master = yu.setup(params, rng=CountingRandom(rank_prefix=True))
    rng = CountingRandom()
    authority = yu.Authority(master, rng=rng)
    user = authority.extract(IDENTITY)
    return SimpleNamespace(public=public, master=master, user=user,
                           authority=authority, rng=rng)


@pytest.fixture(scope="module")
def signatures(family):
    # Mandatory success: no catches, retries, substituted vectors or mocks.
    return tuple(family.authority.sign(IDENTITY, MESSAGE) for _ in range(3))


def reference_public_evaluation(n, q, circuit, blocks):
    """Direct NAND/gadget arithmetic, independent of evaluation.eval_public.

    Reuse the declared circuit (homomorphic output depends on its syntax),
    not the production evaluator, multiplication, inverse, or gate helpers.
    Keep all wires, so no production dead-wire release logic is shared.
    """
    ell = (q - 1).bit_length()
    w = n * ell
    zero = tuple((0,) * w for _ in range(n))
    gadget = tuple(tuple((2 ** (j % ell)) % q if j // ell == i else 0
                         for j in range(w)) for i in range(n))
    wires = list(blocks)

    def read(wire):
        return zero if wire == -1 else gadget if wire == -2 else wires[wire]

    for left, right in circuit.gates:
        a, b = read(left), read(right)
        wires.append(tuple(tuple(
            (gadget[i][j] - sum(a[i][k] * ((b[k // ell][j] >> (k % ell)) & 1)
                                for k in range(w))) % q
            for j in range(w)) for i in range(n)))
    return tuple(read(wire) for wire in circuit.outputs)


def reference_match(public, values, pattern, *, identity):
    p = public.params
    spec, blocks = ((p.identity_prf, public.hat) if identity
                    else (p.signing_prf, public.tilde))
    circuit = bpr.compile_key_circuit(spec, values)
    outputs = reference_public_evaluation(p.root.n, p.root.q, circuit, blocks)
    return reference_public_evaluation(p.root.n, p.root.q,
                                      evaluation.equality_circuit(pattern), outputs)[0]


def reference_matrix(public, identity, message, signature):
    hat = reference_match(public, identity, signature.r_hat, identity=True)
    tilde = reference_match(public, identity + message + signature.salt,
                            signature.r_tilde, identity=False)
    return tuple(public.a[i] + hat[i] + tilde[i] for i in range(public.params.root.n))


def reference_accepts(public, identity, message, signature):
    p = public.params
    rows = reference_matrix(public, identity, message, signature)
    norm = sum(value * value for value in signature.s)
    return (0 < norm <= p.delta_squared * p.signature_dimension
            and all(sum(a * value for a, value in zip(row, signature.s)) % p.root.q == 0
                    for row in rows))


def template_signature(params):
    # Synthetic public wire fixture, NOT a generated cryptographic signature.
    return yu.Signature((-3,) + (0,) * (params.signature_dimension - 1),
                        (0,) * params.identity_prf.params.output_bits,
                        (0,) * params.signing_prf.params.output_bits,
                        (0,) * params.salt_bits)


def test_real_setup_keygen_repeated_sign_verify(family, signatures, params):
    public, master, user = family.public, family.master, family.user
    assert (len(public.a), len(public.a[0]), len(user.basis.basis_rows)) == (1, 15, 17)
    assert user.basis.public.rows == tuple(a + c for a, c in zip(public.a, user.c_hat))
    for basis in (master.basis, user.basis):
        a, t = sage_matrix(ZZ, basis.public.rows), sage_matrix(ZZ, basis.basis_rows)
        assert all(x % params.root.q == 0 for x in (a * t).list())
        assert abs(t.det()) == params.root.q ** params.root.n
    for signature in signatures:
        assert len(signature.s) == 19 and all(type(x) is int for x in signature.s)
        assert signature.r_hat == user.r_hat
        assert yu.verify(public, IDENTITY, MESSAGE, signature) is True
        assert reference_accepts(public, IDENTITY, MESSAGE, signature)
        assert yu.verification_matrix(public, IDENTITY, MESSAGE, signature) == reference_matrix(
            public, IDENTITY, MESSAGE, signature)
    assert len({signature.s for signature in signatures}) == 3
    assert not params.backend_admitted and params.security_claim == "none"


def test_authority_reuses_same_identity_object_without_entropy(family):
    before = family.rng.calls
    assert family.authority.extract(IDENTITY) is family.user
    assert family.authority.extract(list(IDENTITY)) is family.user
    assert family.rng.calls == before


def test_verify_in_fresh_process_has_only_public_material(family, signatures):
    payload = dict(a=family.public.a, hat=family.public.hat, tilde=family.public.tilde,
                   identity=IDENTITY, message=MESSAGE,
                   signature=signatures[0].to_bytes(family.public.params).hex())
    script = """
import json, sys
from experiments.research.candidates.yu.profiles import tiny_profile
from experiments.research.candidates.yu.standalone import PublicKey, verify
p = json.load(sys.stdin)
public = PublicKey(tiny_profile(), p['a'], p['hat'], p['tilde'])
assert verify(public, p['identity'], p['message'], bytes.fromhex(p['signature'])) is True
print('PUBLIC_ONLY_VERIFY_OK')
"""
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps(payload),
                            text=True, capture_output=True, timeout=90, env=environment,
                            cwd=Path(__file__).resolve().parents[1])
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PUBLIC_ONLY_VERIFY_OK"


@pytest.mark.parametrize("field,index", [
    ("identity", 0), ("identity", 1), ("message", 0), ("message", 1),
    *((name, index) for name in ("salt", "r_hat", "r_tilde") for index in range(4)),
])
def test_context_mutations_follow_independent_equation(family, signatures, field, index,
                                                       record_property):
    signature, identity, message = signatures[0], IDENTITY, MESSAGE
    value = identity if field == "identity" else message if field == "message" else getattr(signature, field)
    changed = value[:index] + (1 - value[index],) + value[index + 1:]
    if field == "identity":
        identity = changed
    elif field == "message":
        message = changed
    else:
        signature = replace(signature, **{field: changed})
    expected = reference_accepts(family.public, identity, message, signature)
    assert yu.verify(family.public, identity, message, signature) is expected
    record_property("toy_mutation_accepted", expected)
    print(f"YU_TOY_MUTATION {field}[{index}] accepted={expected}")


def test_zero_overnorm_and_single_coefficient_equation_failure_rejected(family, signatures):
    p, signature = family.public.params, signatures[0]
    dimension, q = p.signature_dimension, p.root.q
    zero = replace(signature, s=(0,) * dimension)
    assert yu.verify(family.public, IDENTITY, MESSAGE, zero) is False
    large = q * (isqrt(p.delta_squared * dimension) // q + 1)
    outlier = replace(signature, s=(large,) + (0,) * (dimension - 1))
    assert yu.verify(family.public, IDENTITY, MESSAGE, outlier) is False
    rows = reference_matrix(family.public, IDENTITY, MESSAGE, signature)
    coordinate = next(j for j in range(dimension) if any(row[j] % q for row in rows))
    # Move towards zero so the valid signature's norm cannot increase.
    step = -1 if signature.s[coordinate] > 0 else 1
    values = list(signature.s)
    values[coordinate] += step
    changed = replace(signature, s=tuple(values))
    assert any(sum(a * x for a, x in zip(row, changed.s)) % q for row in rows)
    assert sum(x*x for x in changed.s) <= p.delta_squared * dimension
    assert yu.verify(family.public, IDENTITY, MESSAGE, changed) is False


def test_public_q_multiple_forgery_is_explicit_toy_insecurity(family, params):
    signature = replace(template_signature(params),
                        s=(params.root.q,) + (0,) * (params.signature_dimension - 1))
    # Every tail is zero: independent of either evaluated context block.
    assert sum(x*x for x in signature.s) <= params.delta_squared * params.signature_dimension
    assert all(sum(a*x for a, x in zip(row, signature.s[:len(row)])) % params.root.q == 0
               for row in family.public.a)
    assert yu.verify(family.public, (0, 0), (0, 0), signature) is True
    assert yu.verify(family.public, (1, 1), (1, 1), signature) is True


def test_generated_signature_roundtrip_and_public_bytes_verification(family, signatures):
    for signature in signatures:
        encoded = signature.to_bytes(family.public.params)
        restored = yu.Signature.from_bytes(encoded, family.public.params)
        assert restored == signature
        assert restored.to_bytes(family.public.params) == encoded
        assert yu.verify(family.public, IDENTITY, MESSAGE, encoded) is True


def test_signed_integer_wire_roundtrip(params):
    signature = template_signature(params)
    assert yu.Signature.from_bytes(signature.to_bytes(params), params) == signature
    assert yu.Signature.from_bytes(signature.to_bytes(params), params).s[0] == -3


def test_every_truncation_and_appended_duplicate_rejected(params):
    encoded = template_signature(params).to_bytes(params)
    for end in range(len(encoded)):
        with pytest.raises(ValueError):
            yu.Signature.from_bytes(encoded[:end], params)
    for suffix in (b"\x00", b"\x00\x04\x00\x00\x00\x00", encoded):
        with pytest.raises(ValueError):
            yu.Signature.from_bytes(encoded + suffix, params)


@pytest.mark.parametrize("kind", ["magic", "dimension", "r_hat_len", "r_tilde_len", "salt_len",
                                  "r_hat_bit", "r_tilde_bit", "salt_bit"])
def test_malformed_lengths_domain_and_noncanonical_bit_bytes(params, kind):
    encoded = bytearray(template_signature(params).to_bytes(params))
    vector = len(yu.SIGNATURE_MAGIC)
    offsets, offset = {}, vector + 2 + 16 * params.signature_dimension
    for name, count in (("r_hat", params.identity_prf.params.output_bits),
                        ("r_tilde", params.signing_prf.params.output_bits),
                        ("salt", params.salt_bits)):
        offsets[name + "_len"], offsets[name + "_bit"] = offset, offset + 2
        offset += 2 + count
    if kind == "magic":
        encoded[0] ^= 1
    elif kind == "dimension":
        encoded[vector:vector+2] = (params.signature_dimension + 1).to_bytes(2, "big")
    elif kind.endswith("_len"):
        encoded[offsets[kind]:offsets[kind]+2] = (65535).to_bytes(2, "big")
    else:
        encoded[offsets[kind]] = 2
    with pytest.raises(ValueError):
        yu.Signature.from_bytes(bytes(encoded), params)


@pytest.mark.parametrize("data", [None, "bytes", bytearray(b"x"), memoryview(b"x"), b"x" * 8193])
def test_parser_requires_bounded_bytes(params, data):
    with pytest.raises(ValueError):
        yu.Signature.from_bytes(data, params)


@pytest.mark.parametrize("field", ["s", "r_hat", "r_tilde", "salt"])
@pytest.mark.parametrize("bad", [True, 0.0, "0", None])
def test_signature_constructor_rejects_noncanonical_types(params, field, bad):
    signature = template_signature(params)
    value = getattr(signature, field)
    with pytest.raises(ValueError):
        replace(signature, **{field: (bad,) + value[1:]})


@pytest.mark.parametrize("bad", [True, 1.0])
def test_verify_revalidates_untrusted_signature_coefficients(params, bad):
    e = params.evaluation
    public = yu.PublicKey(params, ((1, 2, 0) + (0,) * (e.m - 3),),
                          (((0,) * e.w,),) * params.identity_prf.params.key_bits,
                          (((0,) * e.w,),) * params.signing_prf.params.key_bits)
    signature = template_signature(params)
    # Deliberate malformed object simulating a bypassed constructor; this
    # tests public input rejection, not a mocked cryptographic success path.
    object.__setattr__(signature, "s", (0, 0, bad) + (0,) * (params.signature_dimension - 3))
    assert yu.verify(public, (0, 0), (0, 0), signature) is False


@pytest.mark.parametrize("field", ["identity", "message"])
@pytest.mark.parametrize("bad", [(), (0,), (0, 0, 0), (True, 0), (0.0, 1), (2, 0), b"00"])
def test_invalid_context_rejected_without_entropy(family, signatures, field, bad):
    identity, message = (bad, MESSAGE) if field == "identity" else (IDENTITY, bad)
    assert yu.verify(family.public, identity, message, signatures[0]) is False
    with pytest.raises(ValueError):
        if field == "identity":
            yu.keygen(family.master, bad, rng=NoEntropy())
        else:
            yu.sign(family.user, bad, rng=NoEntropy())


@pytest.mark.parametrize("stage", ["setup", "keygen", "sign"])
@pytest.mark.parametrize("mode", ["raise", "short", "wrong_type", "multibyte"])
def test_failure_injection_entropy_response_and_error_propagate_once(family, params, stage, mode):
    class Broken:
        calls = 0

        def read(self, count):
            self.calls += 1
            if mode == "raise":
                raise OSError("injected entropy failure")
            if mode == "multibyte":
                return memoryview(bytearray(count * 4)).cast("I")
            return b"" if mode == "short" else "x" * count

    rng = Broken()
    with pytest.raises(OSError if mode == "raise" else ValueError):
        if stage == "setup":
            yu.setup(params, rng=rng)
        elif stage == "keygen":
            yu.keygen(family.master, IDENTITY, rng=rng)
        else:
            yu.sign(family.user, MESSAGE, rng=rng)
    assert rng.calls == 1


@pytest.mark.parametrize("stage", ["generate_root", "issue_basis", "sample_zero"])
def test_failure_injection_sampling_abort_propagates_once(family, params, monkeypatch, stage):
    error, calls = SamplingAbort("injected sampler abort"), []

    def abort(*args, **kwargs):
        calls.append(1)
        raise error

    monkeypatch.setattr(yu, stage, abort)
    with pytest.raises(SamplingAbort) as caught:
        if stage == "generate_root":
            yu.setup(params, rng=SecureRandom())
        elif stage == "issue_basis":
            yu.keygen(family.master, IDENTITY, rng=SecureRandom())
        else:
            yu.sign(family.user, MESSAGE, rng=SecureRandom())
    assert caught.value is error and len(calls) == 1


def test_failure_injection_authority_does_not_cache_failed_issue(family, monkeypatch):
    authority = yu.Authority(family.master, rng=SecureRandom())
    calls = []

    def abort(*args, **kwargs):
        calls.append(1)
        raise SamplingAbort("injected key issue abort")

    monkeypatch.setattr(yu, "issue_basis", abort)
    with pytest.raises(SamplingAbort):
        authority.extract(IDENTITY)
    assert len(calls) == 1 and authority._keys == {}


def test_failure_injection_random_bits_checks_memoryview_byte_count():
    class MultibyteResponse:
        calls = 0

        def read(self, count):
            self.calls += 1
            # len(view) matches the request, but the actual byte count does not.
            return memoryview(bytearray(count * 4)).cast("I")

    rng = MultibyteResponse()
    with pytest.raises(ValueError, match="random source"):
        yu._random_bits(rng, 4)
    assert rng.calls == 1


@pytest.mark.parametrize("container", ["bytes", "bytearray", "byte_view", "word_view"])
def test_checked_random_normalizes_valid_byte_counts(container):
    expected = b"\x01\x02\x03\x04"
    values = {"bytes": expected, "bytearray": bytearray(expected),
              "byte_view": memoryview(expected),
              "word_view": memoryview(expected).cast("I")}

    class Source:
        calls = 0

        def read(self, count):
            self.calls += 1
            assert count == 4
            return values[container]

    source = Source()
    checked = yu._source(source)
    assert yu._source(checked) is checked
    received = checked.read(4)
    assert type(received) is bytes and received == expected
    assert source.calls == 1
