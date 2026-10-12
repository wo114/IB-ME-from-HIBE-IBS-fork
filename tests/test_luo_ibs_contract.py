"""Luo package contract, independent persistence and negative controls.

Functional research parameters only. Rejection observations do not prove
unforgeability, and the deliberately tiny challenge control stays forgeable.
"""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.core.errors import EncodingError, InvalidParameterError, RandomnessError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.api import IBSBackend, IBSMasterSecret, IBSPublicKey, IBSSigningKey, IBSSignature
from ibme.ibs.luo import (
    CONFIG_VERSION, LuoIBSBackend, LuoMatrixParams, LuoMasterSecret, LuoPublicKey,
    LuoSamplingAbort, LuoSignature, LuoSigningKey,
)
from ibme.ibs import luo_reference as reference
from ibme.ibs.mock import MockIBSBackend
from ibme.lattice.params import EDUCATION_PARAMS


def functional_params(**changes):
    # Bigger input limits exercise the contract, not a second algorithm or a
    # safe preset. n=4, m=8, k=32 are still hand-selected research parameters.
    return LuoMatrixParams(k=32, kappa=8, q=2**31 - 1, gamma1=4096,
                           gamma2=131072, identity_max_bytes=64,
                           message_max_bytes=4096, **changes)


class NoRead:
    def read(self, count):
        raise AssertionError("public/cached operation requested entropy")


@pytest.fixture(scope="module")
def fixture_bytes():
    backend = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:fixture"))
    pk, msk = backend.setup(functional_params())
    key = backend.key_extract(msk, b"Alice")
    sig = backend.sign(key, b"message")
    return pk.to_bytes(), msk.to_bytes(), key.to_bytes(), sig.to_bytes()


def scenario(data):
    p, m, k, s = data
    pk = LuoPublicKey.from_bytes(p)
    return pk, LuoMasterSecret.from_bytes(m), LuoSigningKey.from_bytes(k), LuoSignature.from_bytes(s, pk)


def test_frozen_methods_objects_and_safety(fixture_bytes):
    backend = LuoIBSBackend(rng=NoRead())
    assert isinstance(backend, IBSBackend)
    pk, msk, sk, sig = scenario(fixture_bytes)
    for obj, base in zip((pk, msk, sk, sig), (IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature)):
        assert isinstance(obj, base)
    assert sk.identity == b"Alice"
    assert sk.identity_digest == hash_identity(b"Alice", 32)
    assert sk.public_key == msk.public_key == pk
    assert backend.verify(pk, b"Alice", b"message", sig) is True
    assert backend.security_claim == pk.params.security_claim == "none"
    assert backend.backend_admitted is False and backend.research_only is True
    with pytest.raises(TypeError):
        hash(msk)  # cache-bearing state cannot safely be a hash-table key


@pytest.mark.parametrize("identity", [b"A", b"Alice@example.com", "发送者@example.com".encode(),
                                      b"\x00\xff", b"a" * 64])
@pytest.mark.parametrize("message", [b"", bytes(range(64)), "签名消息".encode()])
def test_identity_binding_and_messages(fixture_bytes, identity, message):
    pk, msk, _, _ = scenario(fixture_bytes)
    backend = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:inputs" + identity + message))
    key = backend.key_extract(msk, identity)
    before = key.to_bytes()
    sig = backend.sign(key, message)
    assert backend.verify(pk, identity, message, sig) is True
    assert backend.verify(pk, identity, message + b"!", sig) is False
    wrong = b"B" if identity == b"A" else b"A"
    assert backend.verify(pk, wrong, message, sig) is False
    assert key.to_bytes() == before
    assert backend.key_extract(msk, identity) == key
    assert key.identity_digest == hash_identity(identity, 32)


def test_maximum_message_and_input_snapshot(fixture_bytes):
    pk, _, sk, _ = scenario(fixture_bytes)
    backend = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:max-message"))
    source = bytearray(b"x" * 4096)
    sig = backend.sign(sk, memoryview(source))
    source[0] = 0
    assert backend.verify(pk, bytearray(b"Alice"), b"x" * 4096, sig)
    assert not backend.verify(pk, b"Alice", source, sig)
    with pytest.raises(EncodingError):
        backend.sign(sk, b"x" * 4097)


@pytest.mark.parametrize("bad", [None, "Alice", b"", 42, b"x" * 65])
def test_key_extract_invalid_id_is_encoding_error(fixture_bytes, bad):
    _, master, _, _ = scenario(fixture_bytes)
    with pytest.raises(EncodingError):
        LuoIBSBackend(rng=NoRead()).key_extract(master, bad)


@pytest.mark.parametrize("bad", [None, "message", 42])
def test_sign_invalid_message_is_encoding_error(fixture_bytes, bad):
    _, _, key, _ = scenario(fixture_bytes)
    with pytest.raises(EncodingError):
        LuoIBSBackend(rng=NoRead()).sign(key, bad)


@pytest.mark.parametrize("position,bad", [(0, None), (1, "Alice"), (1, b""), (1, b"a" * 65),
                                         (2, None), (2, b"m" * 4097), (3, None), (3, b"sig")])
def test_verify_returns_bool_for_invalid_inputs(fixture_bytes, position, bad):
    pk, _, _, sig = scenario(fixture_bytes)
    inputs = [pk, b"Alice", b"message", sig]
    inputs[position] = bad
    assert LuoIBSBackend(rng=NoRead()).verify(*inputs) is False


def test_foreign_backend_objects_rejected(fixture_bytes):
    pk, _, sk, sig = scenario(fixture_bytes)
    other = MockIBSBackend(rng=DeterministicRandom(b"luo-m2:other"))
    mpk, msk = other.setup(EDUCATION_PARAMS)
    mkey = other.key_extract(msk, b"Alice")
    msig = other.sign(mkey, b"message")
    backend = LuoIBSBackend(rng=NoRead())
    assert not backend.verify(mpk, b"Alice", b"message", sig)
    assert not backend.verify(pk, b"Alice", b"message", msig)
    for operation, args in ((backend.setup, (EDUCATION_PARAMS,)), (backend.setup, (None,)),
                            (backend.key_extract, (msk, b"Alice")), (backend.sign, (mkey, b"msg")),
                            (backend.load_signature, (mpk, sig.to_bytes()))):
        with pytest.raises(TypeError):
            operation(*args)
    with pytest.raises(SerializationError):
        backend.load_signature(pk, msig.to_bytes())


@pytest.mark.parametrize("field", ["z", "c", "W", "context"])
def test_signature_mutations_and_norm_bound(fixture_bytes, field):
    pk, _, _, signature = scenario(fixture_bytes)
    sig = signature._reference
    if field == "z":
        value = (pk.params.gamma2 - pk.params.beta2,) + sig.z[1:]
    elif field == "c":
        value = (0,) * pk.params.k
    elif field == "W":
        value = sig.W + reference.ModMatrix.identity(pk.params.n, pk.params.q) @ reference.ModMatrix(
            [[int(i == j) for j in range(pk.params.k)] for i in range(pk.params.n)], pk.params.q)
    else:
        value = b"x" * 32
    mutated = LuoSignature(replace(sig, **{field: value}))
    backend = LuoIBSBackend(rng=NoRead())
    assert not backend.verify(pk, b"Alice", b"message", mutated)
    # W has legal dimensions/range and is parseable, though cryptographically
    # invalid. The other mutations violate the signature parser's contract.
    if field != "W":
        with pytest.raises(SerializationError):
            backend.load_signature(pk, mutated.to_bytes())


@pytest.mark.parametrize("which", range(4))
@pytest.mark.parametrize("mutation", ["truncate", "append", "duplicate", "wrong-version", "wrong-type"])
def test_all_object_parsers_reject_malformed(fixture_bytes, which, mutation):
    pk = LuoPublicKey.from_bytes(fixture_bytes[0])
    raw = fixture_bytes[which]
    if mutation == "truncate":
        raw = raw[:-1]
    elif mutation == "append":
        raw += b"\x00"
    elif mutation == "duplicate":
        raw += raw
    elif mutation == "wrong-version":
        raw = raw.replace(reference.VERSION, reference.VERSION[:-1] + b"9", 1)
    else:
        raw = "bytes required"
    parser = (LuoPublicKey.from_bytes, LuoMasterSecret.from_bytes, LuoSigningKey.from_bytes,
              lambda data: LuoIBSBackend().load_signature(pk, data))[which]
    with pytest.raises(SerializationError):
        parser(raw)


def test_other_public_context_rejected(fixture_bytes):
    pk, _, _, sig = scenario(fixture_bytes)
    other, _ = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:other-context")).setup(pk.params)
    assert not LuoIBSBackend(rng=NoRead()).verify(other, b"Alice", b"message", sig)
    with pytest.raises(SerializationError):
        LuoIBSBackend().load_signature(other, sig.to_bytes())


def test_cache_survives_restore_without_rng(fixture_bytes):
    pk, master, key, _ = scenario(fixture_bytes)
    assert master.cached_identities == (b"Alice",)
    assert LuoIBSBackend(rng=NoRead()).key_extract(master, memoryview(b"Alice")) == key
    backend = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:after-restart"))
    first, second = (backend.sign(key, b"same message") for _ in range(2))
    assert first != second
    for sig in (first, second):
        assert backend.verify(pk, b"Alice", b"same message", sig)
    assert master.to_bytes() == fixture_bytes[1]
    assert key.to_bytes() == fixture_bytes[2]
    assert "redacted" in repr(master) and "redacted" in repr(key)


def test_random_source_validation_and_system_entropy():
    with pytest.raises(RandomnessError):
        LuoIBSBackend(rng=object())

    class Short:
        def read(self, count):
            return b""

    with pytest.raises(RandomnessError):
        LuoIBSBackend(rng=Short()).setup(LuoMatrixParams())
    backend = LuoIBSBackend()  # no test seed: real system entropy smoke
    pk, master = backend.setup(functional_params())
    key = backend.key_extract(master, b"system")
    assert backend.verify(pk, b"system", b"", backend.sign(key, b""))


def test_cache_budget_does_not_issue_partial_key():
    backend = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:cache-limit"))
    _, master = backend.setup(functional_params(max_cached_identities=1))
    first = backend.key_extract(master, b"A")
    before = master.to_bytes()
    with pytest.raises(LuoSamplingAbort):
        backend.key_extract(master, b"B")
    assert master.to_bytes() == before
    assert backend.key_extract(master, b"A") == first


def test_configuration_and_parameter_encoding():
    p = functional_params()
    config = json.loads(json.dumps(p.to_config()))
    assert config["config_version"] == CONFIG_VERSION
    assert LuoMatrixParams.from_config(config) == p
    assert LuoMatrixParams.from_json(p.to_json()) == p
    assert LuoMatrixParams.from_json(p.to_json().encode()) == p
    assert LuoMatrixParams.from_bytes(p.to_bytes()) == p
    with pytest.raises(SerializationError):
        LuoMatrixParams.from_bytes(p.to_bytes() + b"\x00")


@pytest.mark.parametrize("data", ['{"parameters":{"n":4,"n":8}}',
                                  '{"security_claim":"none","security_claim":"none"}',
                                  '{} {}', b"\xff", None, " " * 4097])
def test_json_configuration_rejects_duplicates_and_malformed_data(data):
    with pytest.raises(InvalidParameterError):
        LuoMatrixParams.from_json(data)


@pytest.mark.parametrize("change", [{"q": 2**34 + 1}, {"k": 128}, {"n": 256},
                                   {"kappa": True}, {"gamma2": 256}])
def test_parameter_resource_caps_are_not_silent(change):
    with pytest.raises(InvalidParameterError):
        LuoMatrixParams(**change)


@pytest.mark.parametrize("change", [{"security_claim": "128-bit"}, {"backend_admitted": True},
                                   {"backend_admitted": 0}, {"config_version": "2"},
                                   {"extra": "ignored"}, {"parameters": {"n": 4}}])
def test_configuration_cannot_override_safety_or_ignore_fields(change):
    config = functional_params().to_config()
    config.update(change)
    with pytest.raises(InvalidParameterError):
        LuoMatrixParams.from_config(config)


def test_reference_and_adapter_identical_transcript():
    seed = b"luo-m2:compatibility"
    backend = LuoIBSBackend(rng=DeterministicRandom(seed))
    pk, master = backend.setup(functional_params())
    key = backend.key_extract(master, b"Alice")
    sig = backend.sign(key, b"compatibility")
    rng = DeterministicRandom(seed)
    rp, rm = reference.setup(functional_params(), rng=rng)
    rk = reference.key_extract(rm, b"Alice", rng=rng)
    rs = reference.sign(rk, b"compatibility", rng=rng)
    assert (pk.to_bytes(), master.to_bytes(), key.to_bytes(), sig.to_bytes()) == (
        rp.to_bytes(), rm.to_bytes(), rk.to_bytes(), rs.to_bytes())


def test_toy_public_forgery_remains_a_negative_control():
    from experiments.research.luo_matrix_audit import forge_tiny_challenge
    rp, _ = reference.setup(reference.MatrixParams(), rng=DeterministicRandom(b"luo-m1:attack"))
    message, signature, _ = forge_tiny_challenge(rp, b"target")
    pk = LuoPublicKey.from_bytes(rp.to_bytes())
    sig = LuoIBSBackend().load_signature(pk, signature.to_bytes())
    assert LuoIBSBackend(rng=NoRead()).verify(pk, b"target", message, sig)


def test_source_only_fresh_process_without_experiments(fixture_bytes, tmp_path):
    """Foreign cwd: Luo must work even when all research imports are forbidden.

    An installed optional HIBE may expose the experiments support namespace.
    Availability is unrelated to whether the independent Luo backend uses it.
    """
    p, m, k, s = fixture_bytes
    for name, raw in (("pk", p), ("master", m), ("key", k), ("signature", s)):
        (tmp_path / name).write_bytes(raw)  # private data only in temporary dir
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
               PYTHONDONTWRITEBYTECODE="1")
    code = '''
import importlib.abc
import sys
from pathlib import Path

blocked_imports = []
class ForbidResearchImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "experiments" or fullname.startswith("experiments."):
            blocked_imports.append(fullname)
            raise ImportError("research imports forbidden for independent Luo")

assert not any(n == "experiments" or n.startswith("experiments.") for n in sys.modules)
sys.meta_path.insert(0, ForbidResearchImports())
# Prove this guard wins even over an installed optional support package.
try:
    __import__("experiments")
except ImportError as exc:
    assert "research imports forbidden" in str(exc)
else:
    raise AssertionError("research import guard was bypassed")
assert blocked_imports == ["experiments"]
blocked_imports.clear()

from ibme.ibs.luo import *
from ibme.core.randomness import DeterministicRandom
b = LuoIBSBackend(rng=DeterministicRandom(b"luo-m2:child"))
p = LuoPublicKey.from_bytes(Path("pk").read_bytes())
m = LuoMasterSecret.from_bytes(Path("master").read_bytes())
k = b.key_extract(m, b"Alice")
assert k.to_bytes() == Path("key").read_bytes()
s = b.load_signature(p, Path("signature").read_bytes())
assert b.verify(p, b"Alice", b"message", s)
assert b.verify(p, b"Alice", b"fresh", b.sign(k, b"fresh"))
assert blocked_imports == []
assert not any(n == "experiments" or n.startswith("experiments.") for n in sys.modules)
print("package-only restore/sign/verify passed")
'''
    result = subprocess.run([sys.executable, "-B", "-c", code], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "package-only restore/sign/verify passed"
