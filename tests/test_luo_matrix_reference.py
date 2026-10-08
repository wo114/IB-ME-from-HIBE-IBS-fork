"""Real equations, mutation rejection, canonical state and independent replay."""

from collections import Counter
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.core.errors import IBMEError
from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.modmat import ModMatrix, ModVector

from experiments.research.luo_matrix_audit import forge_tiny_challenge, wide_challenge_params
from experiments.research.luo_matrix_reference import (
    MatrixParams, MasterState, PublicKey, SamplingAbort, Signature, SigningKey,
    hash_h1, hash_h2, key_extract, setup, sign, sign_for_identity, uniform_below, verify,
)


class NoRead:
    def read(self, count):
        raise RuntimeError("cached operation unexpectedly requested fresh randomness")


class ByteStream:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def read(self, count):
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result


class Ones:
    def read(self, count):
        return b"\xff" * count


@pytest.fixture(scope="module")
def scenario():
    random = DeterministicRandom(b"luo-m1:functional-fixture")
    public, master = setup(wide_challenge_params(), rng=random)
    key = key_extract(master, b"Alice", rng=random)
    return public, master, key


def test_master_and_user_equations_independent_integer_loops(scenario):
    public, master, key = scenario
    p = public.params
    for i in range(p.n):
        for j in range(p.k):
            assert sum(public.A[i][h] * master.S[h][j] for h in range(p.m)) % p.q == public.T[i][j]
    C = hash_h1(public, key.identity, key.W)
    for i in range(p.n):
        for j in range(p.k):
            left = sum(public.A[i][h] * key.Z[h][j] for h in range(p.m))
            right = key.W[i][j] + sum(public.T[i][h] * C[h][j] for h in range(p.k))
            assert (left - right) % p.q == 0


def test_signature_equation_independent_integer_reconstruction(scenario):
    public, _, key = scenario
    p = public.params
    message = b"equation-check"
    sig = sign(key, message, rng=DeterministicRandom(b"luo-m1:equation-sign"))
    C = hash_h1(public, key.identity, sig.W)
    reconstructed = []
    for i in range(p.n):
        az = sum(public.A[i][h] * sig.z[h] for h in range(p.m))
        hidden = sum((sig.W[i][j] + sum(public.T[i][h] * C[h][j] for h in range(p.k)))
                     * sig.c[j] for j in range(p.k))
        reconstructed.append((az - hidden) % p.q)
    assert hash_h2(public, key.identity, ModVector(reconstructed, p.q), message) == sig.c
    assert max(map(abs, sig.z)) < p.gamma2 - p.beta2
    assert verify(public, key.identity, message, sig)


def test_h1_and_h2_use_fixed_weight_signed_challenges(scenario):
    public, _, key = scenario
    p = public.params
    C = hash_h1(public, key.identity, key.W)
    assert all(sum(abs(C[i][j]) for i in range(p.k)) == p.kappa for j in range(p.k))
    c = hash_h2(public, key.identity, ModVector([0] * p.n, p.q), b"challenge")
    assert sum(map(abs, c)) == p.kappa
    assert all(x in (-1, 0, 1) for row in C for x in row)


@pytest.mark.parametrize("message", [b"", b"\x00", bytes(range(32)), "消息".encode(), b"x" * 32])
def test_real_signatures_binary_empty_and_capacity_boundary(scenario, message):
    public, _, key = scenario
    sig = sign(key, message, rng=DeterministicRandom(b"luo-m1:message" + message))
    assert verify(PublicKey.from_bytes(public.to_bytes()), key.identity, message,
                  Signature.from_bytes(public, sig.to_bytes()))


def test_multiple_messages_keep_one_key_but_use_fresh_masks(scenario):
    public, master, key = scenario
    before = key.to_bytes()
    random = DeterministicRandom(b"luo-m1:repeat-sign")
    signatures = [sign_for_identity(master, b"Alice", b"repeat", rng=random) for _ in range(12)]
    assert all(verify(public, b"Alice", b"repeat", sig) for sig in signatures)
    assert all(sig.W == key.W for sig in signatures)
    assert len({sig.to_bytes() for sig in signatures}) > 1
    assert key_extract(master, b"Alice", rng=NoRead()).to_bytes() == before


def test_sign_before_extract_shares_the_same_cached_key():
    public, master = setup(rng=DeterministicRandom(b"luo-m1:sign-first"))
    sig = sign_for_identity(master, b"Before", b"message", rng=DeterministicRandom(b"luo-m1:first"))
    key = key_extract(master, b"Before", rng=NoRead())
    assert sig.W == key.W
    assert verify(public, b"Before", b"message", sig)


def test_changed_identity_message_W_and_context_rejected(scenario):
    public, _, key = scenario
    sig = sign(key, b"bound-message", rng=DeterministicRandom(b"luo-m1:mutations"))
    assert not verify(public, b"Mallory", b"bound-message", sig)
    assert not verify(public, b"Alice", b"bound-message!", sig)
    rows = sig.W.to_lists()
    rows[0][0] = (rows[0][0] + 1) % public.params.q
    assert not verify(public, b"Alice", b"bound-message", replace(sig, W=ModMatrix(rows, public.params.q)))
    other, _ = setup(public.params, rng=DeterministicRandom(b"luo-m1:other-context"))
    assert not verify(other, b"Alice", b"bound-message", sig)


@pytest.mark.parametrize("change", [
    {"z": (1,)}, {"c": (0,)}, {"context": b"wrong"}, {"z": (False,) * 8},
    {"c": (0,) * 32}, {"c": (2,) * 32},
])
def test_malformed_signatures_return_false(scenario, change):
    public, _, key = scenario
    sig = sign(key, b"message", rng=DeterministicRandom(b"luo-m1:bad-signature"))
    assert not verify(public, b"Alice", b"message", replace(sig, **change))


def test_strict_signature_boundary_rejected_before_hash(scenario):
    public, _, key = scenario
    sig = sign(key, b"boundary", rng=DeterministicRandom(b"luo-m1:boundary"))
    z = list(sig.z)
    z[0] = public.params.gamma2 - public.params.beta2
    assert not verify(public, b"Alice", b"boundary", replace(sig, z=tuple(z)))


def test_key_boundary_is_inclusive_as_in_algorithm2():
    p = MatrixParams()
    public = PublicKey(p, ModMatrix.zeros(p.n, p.m, p.q), ModMatrix.zeros(p.n, p.k, p.q))
    Z = ((p.gamma1 - p.beta1,) * p.k,) * p.m
    key = SigningKey(public, b"Boundary", Z, ModMatrix.zeros(p.n, p.k, p.q))
    assert SigningKey.from_bytes(key.to_bytes()).Z == Z
    with pytest.raises(ValueError):
        SigningKey(public, b"Boundary", ((p.gamma1 - p.beta1 + 1,) * p.k,) * p.m, key.W)


@pytest.mark.parametrize("identity,message", [(b"", b"ok"), (b"x" * 17, b"ok"),
                                             ("Alice", b"ok"), (b"Alice", "text"),
                                             (b"Alice", b"x" * 33)])
def test_bad_verifier_inputs_do_not_throw(scenario, identity, message):
    public, _, key = scenario
    sig = sign(key, b"ok", rng=DeterministicRandom(b"luo-m1:input-validation"))
    assert not verify(public, identity, message, sig)


def test_modulus_dimension_and_sparse_weight_validation(scenario):
    public, _, key = scenario
    p = public.params
    sig = sign(key, b"dims", rng=DeterministicRandom(b"luo-m1:dimensions"))
    assert not verify(public, key.identity, b"dims", replace(sig, W=ModMatrix.zeros(p.n, p.k, 257)))
    with pytest.raises(ValueError):
        PublicKey(p, ModMatrix.zeros(p.n, p.m + 1, p.q), public.T)


@pytest.mark.parametrize("change", [{"q": 65535}, {"n": True}, {"m": 4},
                                   {"kappa": 5}, {"gamma1": 2}, {"gamma2": 256}])
def test_invalid_parameter_conditions(change):
    with pytest.raises(ValueError):
        MatrixParams(**change)


def test_unbiased_uniform_draw_complete_byte_cycle():
    stream = ByteStream(bytes(range(256)))
    draws = [uniform_below(stream, 3) for _ in range(192)]
    assert Counter(draws) == {0: 64, 1: 64, 2: 64}
    assert uniform_below(NoRead(), 1) == 0


def test_sampling_abort_and_bad_entropy_length_are_explicit():
    with pytest.raises(SamplingAbort):
        uniform_below(Ones(), 3, attempts=4)
    with pytest.raises(TypeError):
        uniform_below(ByteStream(b""), 65537)
    with pytest.raises(SamplingAbort):
        setup(rng=Ones())


def test_verification_hash_budget_exhaustion_returns_false():
    p = MatrixParams(max_uniform_attempts=1)
    public = PublicKey(p, ModMatrix.zeros(p.n, p.m, p.q), ModMatrix.zeros(p.n, p.k, p.q))
    W = ModMatrix.zeros(p.n, p.k, p.q)
    sig = Signature(public.context, (0,) * p.m, (1, 1, 0, 0), W)
    identity = None
    for i in range(16):
        candidate = f"Budget{i}".encode()
        try:
            hash_h1(public, candidate, W)
        except SamplingAbort:
            identity = candidate
            break
    assert identity is not None
    assert verify(public, identity, b"budget", sig) is False


def test_cache_limit_is_atomic_and_repeated_key_still_available():
    p = MatrixParams(max_cached_identities=1)
    _, master = setup(p, rng=DeterministicRandom(b"luo-m1:cache-limit"))
    first = key_extract(master, b"First", rng=DeterministicRandom(b"luo-m1:key-limit"))
    snapshot = master.to_bytes()
    with pytest.raises(SamplingAbort):
        key_extract(master, b"Second", rng=NoRead())
    assert master.to_bytes() == snapshot
    assert key_extract(master, b"First", rng=NoRead()).to_bytes() == first.to_bytes()


def test_invalid_or_aborted_extraction_does_not_cache_a_key():
    _, master = setup(rng=DeterministicRandom(b"luo-m1:abort"))
    with pytest.raises(ValueError):
        key_extract(master, b"", rng=NoRead())
    with pytest.raises(SamplingAbort):
        key_extract(master, b"Never", rng=Ones())
    assert master.cached_identities == ()


def test_public_user_and_master_roundtrips_preserve_cache(scenario):
    public, master, key = scenario
    assert PublicKey.from_bytes(public.to_bytes()).to_bytes() == public.to_bytes()
    assert SigningKey.from_bytes(key.to_bytes()).to_bytes() == key.to_bytes()
    raw = master.to_bytes()
    restored = MasterState.from_bytes(raw)
    assert restored.to_bytes() == raw
    assert key_extract(restored, b"Alice", rng=NoRead()).to_bytes() == key.to_bytes()
    assert "S=" not in repr(master) and "Z=" not in repr(key)


@pytest.mark.parametrize("kind", ["public", "user", "master", "signature"])
@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "version"])
def test_wire_rejects_truncation_append_duplicates_and_unknown_version(scenario, kind, mutation):
    public, master, key = scenario
    sig = sign(key, b"wire", rng=DeterministicRandom(b"luo-m1:wire"))
    objects = {"public": (public, PublicKey.from_bytes),
               "user": (key, SigningKey.from_bytes),
               "master": (master, MasterState.from_bytes),
               "signature": (sig, lambda raw: Signature.from_bytes(public, raw))}
    value, loader = objects[kind]
    raw = value.to_bytes()
    if mutation == "truncate": raw = raw[:-1]
    elif mutation == "append": raw += b"\x00"
    elif mutation == "duplicate": raw += raw
    else: raw = b"L24R2" + raw[5:]
    with pytest.raises((ValueError, TypeError, IBMEError)):
        loader(raw)


def test_private_wrong_equation_and_cross_context_cache_are_rejected(scenario):
    public, master, key = scenario
    changed = [list(row) for row in master.S]
    changed[0][0] = 0 if changed[0][0] else 1
    with pytest.raises(ValueError, match="master public equation"):
        MasterState(public, tuple(map(tuple, changed)))
    other, other_master = setup(public.params, rng=DeterministicRandom(b"luo-m1:wrong-cache"))
    other_master._cache[b"Alice"] = key
    with pytest.raises(ValueError, match="context"):
        other_master.to_bytes()


def _replace_master_cache(raw, cache):
    offset = 5
    for _ in range(4):  # version, kind, public key, integer secret matrix
        _, offset = decode_bytes(raw, offset)
    return raw[:offset] + encode_bytes(cache)


@pytest.mark.parametrize("mutation", ["duplicate-id", "unordered-id", "over-limit", "appended-entry"])
def test_private_cache_is_unique_canonical_and_bounded(scenario, mutation):
    _, master, _ = scenario
    restored = MasterState.from_bytes(master.to_bytes())
    alice = key_extract(restored, b"Alice", rng=NoRead()).to_bytes()
    bob = key_extract(restored, b"Bob", rng=DeterministicRandom(b"luo-m1:second-cache-entry")).to_bytes()
    if mutation == "duplicate-id":
        cache = (2).to_bytes(4, "big") + encode_bytes(alice) + encode_bytes(alice)
    elif mutation == "unordered-id":
        cache = (2).to_bytes(4, "big") + encode_bytes(bob) + encode_bytes(alice)
    elif mutation == "over-limit":
        cache = (129).to_bytes(4, "big")
    else:
        cache = (1).to_bytes(4, "big") + encode_bytes(alice) + encode_bytes(bob)
    with pytest.raises(ValueError):
        MasterState.from_bytes(_replace_master_cache(restored.to_bytes(), cache))


def test_noncanonical_modular_coefficient_is_not_reduced_during_load(scenario):
    public, _, _ = scenario
    raw = public.to_bytes()
    invalid = raw[:-4] + public.params.q.to_bytes(4, "big")
    with pytest.raises(IBMEError):
        PublicKey.from_bytes(invalid)


def test_toy_profile_public_forgery_is_a_real_negative_control():
    public, master = setup(rng=DeterministicRandom(b"luo-m1:public-attack-control"))
    message, sig, queries = forge_tiny_challenge(public, b"Unissued")
    assert master.cached_identities == ()
    assert queries <= 16 * 24
    assert verify(public, b"Unissued", message, Signature.from_bytes(public, sig.to_bytes()))
    assert public.params.security_claim == "none"


def test_public_forgery_enumerator_cannot_run_on_large_challenge_space(scenario):
    public, _, _ = scenario
    with pytest.raises(ValueError, match="tiny"):
        forge_tiny_challenge(public, b"Unissued")


def test_random_forgery_samples_on_wide_functional_profile(scenario):
    public, _, key = scenario
    p = public.params
    random = DeterministicRandom(b"luo-m1:random-forgeries")
    c = (1,) * p.kappa + (0,) * (p.k - p.kappa)
    for _ in range(64):
        z = tuple(uniform_below(random, 2 * (p.gamma2 - p.beta2) - 1)
                  - (p.gamma2 - p.beta2 - 1) for _ in range(p.m))
        fake = Signature(public.context, z, c, key.W)
        assert not verify(public, b"Alice", b"unsigned", fake)


def test_master_state_and_public_signature_replay_in_fresh_process(scenario, tmp_path):
    public, master, key = scenario
    path = tmp_path / "private-research-state.bin"
    path.write_bytes(master.to_bytes())
    seed = b"luo-m1:cross-process-sign"
    expected = sign(key, b"fresh-process", rng=DeterministicRandom(seed))
    child = """
import json, sys
from hashlib import sha256
from pathlib import Path
from experiments.research.luo_matrix_reference import MasterState, key_extract, sign, verify
from ibme.core.randomness import DeterministicRandom
state=MasterState.from_bytes(Path(sys.argv[1]).read_bytes())
key=key_extract(state,b'Alice')
sig=sign(key,b'fresh-process',rng=DeterministicRandom(b'luo-m1:cross-process-sign'))
print(json.dumps({'key_sha256':sha256(key.to_bytes()).hexdigest(),'signature_hex':sig.to_bytes().hex(),'verified':verify(state.public,b'Alice',b'fresh-process',sig)}))
"""
    result = subprocess.run([sys.executable, "-B", "-c", child, str(path)],
                            cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, timeout=30, check=True)
    output = json.loads(result.stdout)
    assert output["key_sha256"] == sha256(key.to_bytes()).hexdigest()
    assert output["signature_hex"] == expected.to_bytes().hex()
    assert output["verified"]


def test_fresh_process_verifies_with_public_artifacts_only(scenario, tmp_path):
    public, _, key = scenario
    sig = sign(key, b"public-only", rng=DeterministicRandom(b"luo-m1:public-only"))
    public_path, signature_path = tmp_path / "public.bin", tmp_path / "signature.bin"
    public_path.write_bytes(public.to_bytes())
    signature_path.write_bytes(sig.to_bytes())
    child = """
import sys
from pathlib import Path
from experiments.research.luo_matrix_reference import PublicKey, Signature, verify
public=PublicKey.from_bytes(Path(sys.argv[1]).read_bytes())
sig=Signature.from_bytes(public,Path(sys.argv[2]).read_bytes())
assert verify(public,b'Alice',b'public-only',sig)
print('public-only verification passed')
"""
    result = subprocess.run([sys.executable, "-B", "-c", child, str(public_path), str(signature_path)],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True,
                            text=True, timeout=30, check=True)
    assert result.stdout.strip() == "public-only verification passed"


def test_system_entropy_default_smoke():
    public, master = setup(wide_challenge_params())
    key = key_extract(master, b"SystemRng")
    sig = sign(key, b"smoke")
    assert verify(public, b"SystemRng", b"smoke", sig)
