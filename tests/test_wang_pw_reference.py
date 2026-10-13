"""Real Wang Figure 4 + PW Figure 5 research lifecycle; no secure-profile claim."""
from dataclasses import replace
import importlib
import json
import os
import subprocess
import sys

import pytest

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import DeterministicRandom


def test_backend_exposes_complete_five_method_chain():
    try:
        module = importlib.import_module("experiments.research.candidates.wang_pw")
    except ModuleNotFoundError:
        pytest.fail("Wang/PW real signing chain has not been implemented")
    assert all(callable(getattr(module.Backend, name, None)) for name in
               ("setup", "key_extract", "sign", "verify", "load_signature"))


@pytest.fixture(scope="module")
def wp():
    try:
        return importlib.import_module("experiments.research.candidates.wang_pw")
    except ModuleNotFoundError:
        pytest.fail("Wang + Pan–Wagner complete signing implementation is missing")


@pytest.fixture(scope="module")
def lifecycle(wp):
    pytest.importorskip("sage.all", reason="Actual sampling requires prescribed WSL Sage")
    backend = wp.Backend(rng=DeterministicRandom(b"B:WangPW:master"))
    pk, master = backend.setup(wp.Params())
    key = backend.key_extract(master, b"Alice")
    signature = backend.sign(key, b"hello")
    return backend, pk, master, key, signature


def test_params_bind_paper_dimensions_and_public_widths(wp):
    p = wp.Params()
    assert (p.w, p.m, p.dimension) == (5, 10, 15)
    assert p.delegation_width_squared == 8127
    assert p.signature_width_squared == 25600113
    assert p.signature_bound_squared == 384001695
    assert p.security_claim == "none" and p.backend_admitted is False
    assert p.signature_bound_squared > p.q**2
    for values in ({"q": 15}, {"n": True}, {"m_bar": 1}, {"salt_bytes": 0},
                   {"master_quality": -1}, {"message_max_bytes": 0}):
        with pytest.raises(ValueError):
            wp.Params(**values)


def test_domain_separation_and_injective_framing(wp):
    h = importlib.import_module("experiments.research.candidates.wang_pw.hashing")
    p = wp.Params()
    assert len(set(h.DOMAINS)) == 4
    salt = b"r" * p.salt_bytes
    assert h.inner_identity(p, b"A", salt) != h.inner_identity(p, b"B", salt)
    assert h.inner_identity(p, b"A", salt) != h.inner_message(p, b"A", salt)
    assert h.frame(b"a", b"bc") != h.frame(b"ab", b"c")
    # Feed rejecting candidates followed by accepted ones. Mod reduction would
    # return 0 for 255; rejection must skip it for q=17 (cutoff=255).
    class Stream:
        def __init__(self): self.values = iter([b"\xff", b"\x01", b"\x02"])
        def read(self, n): assert n == 1; return next(self.values)
    assert h.uniform_values(Stream(), 17, 2) == (1, 2)


def test_actual_four_algorithms_and_secret_delegation(lifecycle, wp):
    b, pk, master, key, sig = lifecycle
    assert b.verify(pk, b"Alice", b"hello", sig) is True
    assert b.verify(pk, b"Bob", b"hello", sig) is False
    assert b.verify(pk, b"Alice", b"changed", sig) is False
    assert key.identity == b"Alice"
    # Algebra is recomputed independently of the engine's own assertions.
    h = importlib.import_module("experiments.research.candidates.wang_pw.hashing")
    x = h.inner_identity(pk.params, key.identity, key.identity_salt)
    y = h.inner_message(pk.params, b"hello", sig.message_salt)
    B, target = h.identity_matrix(pk, x), h.message_vector(pk, x, y)
    F = tuple(a + bb for a, bb in zip(pk.a, B))
    for i, row in enumerate(F):
        assert sum(a * z for a, z in zip(row, sig.z)) % pk.params.q == target[i]
        for j in range(pk.params.w):
            actual = sum(pk.a[i][t] * key.trapdoor[t][j] for t in range(pk.params.m)) + B[i][j]
            assert actual % pk.params.q == (2**j if i == 0 else 0) % pk.params.q
    assert sum(z*z for z in sig.z) <= pk.params.signature_bound_squared
    other_pk, _ = wp.Backend(rng=DeterministicRandom(b"B:other-master")).setup(pk.params)
    assert b.verify(other_pk, b"Alice", b"hello", sig) is False
    for pos, bad in ((0, None), (1, b""), (1, "Alice"), (2, None), (3, None)):
        args = [pk, b"Alice", b"hello", sig]
        args[pos] = bad
        assert b.verify(*args) is False


def test_fixed_identity_multiple_messages_and_empty_message(lifecycle):
    b, pk, _, key, first = lifecycle
    samples = [b.sign(key, m) for m in (b"hello", b"second", b"")]
    assert all(s.identity_salt == key.identity_salt for s in samples)
    assert len({first.message_salt, *(s.message_salt for s in samples)}) == 4
    assert all(b.verify(pk, key.identity, m, s)
               for m, s in zip((b"hello", b"second", b""), samples))


def test_objects_canonical_and_resume_preserves_user_secret(lifecycle, wp):
    b, pk, master, key, sig = lifecycle
    for obj, kind in ((pk, wp.PublicKey), (master, wp.MasterSecret),
                      (key, wp.SigningKey), (sig, wp.Signature)):
        raw = obj.to_bytes()
        restored = kind.from_bytes(raw)
        assert restored.to_bytes() == raw
        for corrupt in (raw[:-1], raw+b"x", raw+raw):
            with pytest.raises(SerializationError): kind.from_bytes(corrupt)
        header, payload = raw.split(b"\x00", 1)
        record = json.loads(payload)
        first = next(iter(record))
        duplicate = payload[:-1] + b",\"" + first.encode() + b"\":" + json.dumps(record[first]).encode() + b"}"
        with pytest.raises(SerializationError): kind.from_bytes(header+b"\x00"+duplicate)
        with pytest.raises(SerializationError): kind.from_bytes(header+b"\x00"+b" "+payload)
    restored_key = wp.SigningKey.from_bytes(key.to_bytes())
    resumed = wp.Backend(rng=DeterministicRandom(b"B:resumed")).sign(restored_key, b"after restart")
    assert resumed.identity_salt == sig.identity_salt
    assert b.verify(pk, b"Alice", b"after restart", resumed)
    # Fresh interpreter, no cached engine/master, no secret written to disk.
    code = "from experiments.research.candidates.wang_pw import *; import sys; k=SigningKey.from_bytes(bytes.fromhex(sys.stdin.read())); b=Backend(); s=b.sign(k,b'new-process'); assert b.verify(k.public_key,k.identity,b'new-process',s); print('ok')"
    run = subprocess.run([sys.executable, "-c", code], input=key.to_bytes().hex(),
                         text=True, capture_output=True, env=os.environ.copy(), timeout=60)
    assert run.returncode == 0, run.stderr
    assert run.stdout.strip() == "ok"


def test_full_parameter_and_trapdoor_binding(lifecycle, wp):
    b, pk, master, key, sig = lifecycle
    with pytest.raises(ValueError):
        replace(master, trapdoor=tuple(tuple(v+1 for v in row) for row in master.trapdoor))
    with pytest.raises(ValueError): replace(key, identity_salt=b"s" * pk.params.salt_bytes)
    with pytest.raises(ValueError): replace(key, _identity=b"Bob")
    with pytest.raises(ValueError): replace(key, trapdoor=tuple(tuple(v+1 for v in row) for row in key.trapdoor))
    altered = replace(pk, params=replace(pk.params, message_max_bytes=pk.params.message_max_bytes+1))
    assert b.verify(altered, b"Alice", b"hello", sig) is False
    with pytest.raises(SerializationError): b.load_signature(altered, sig.to_bytes())
    assert b.load_signature(pk, sig.to_bytes()) == sig


def test_entropy_failures_no_fallback_and_no_signature_retry(lifecycle, wp, monkeypatch):
    b, pk, master, key, sig = lifecycle
    class NoRead:
        def read(self, n): raise AssertionError("entropy was consumed")
    checked = wp.Backend(rng=NoRead())
    with pytest.raises(EncodingError): checked.sign(key, "bad")
    with pytest.raises(EncodingError): checked.key_extract(master, b"")
    class ShortRead:
        def read(self, n): return b""
    with pytest.raises(ValueError): wp.Backend(rng=ShortRead()).setup(pk.params)
    # A failed real sampling boundary propagates; no reroll of salt/signature.
    engine = importlib.import_module("experiments.research.candidates.wang_pw.engine")
    calls = []
    def failed(*args, **kwargs):
        calls.append(1)
        raise wp.SamplingAbort("deliberate sampler exhaustion")
    monkeypatch.setattr(engine, "sample_signature", failed)
    with pytest.raises(wp.SamplingAbort): b.sign(key, b"abort")
    assert len(calls) == 1


def test_random_signature_rejection_and_debug_public_forgery(lifecycle, wp):
    b, pk, _, key, sig = lifecycle
    random_sig = replace(sig, z=(pk.params.q*1000000,) * pk.params.dimension)
    assert b.verify(pk, b"Alice", b"hello", random_sig) is False
    # This profile deliberately lacks a nontrivial SIS norm regime. Keep the
    # successful PUBLIC-only forgery as a negative control, never hide it.
    from sage.all import GF, matrix, vector
    h = importlib.import_module("experiments.research.candidates.wang_pw.hashing")
    x = h.inner_identity(pk.params, b"Impersonated", sig.identity_salt)
    y = h.inner_message(pk.params, b"public forgery", sig.message_salt)
    F = tuple(a+bb for a, bb in zip(pk.a, h.identity_matrix(pk, x)))
    z = tuple(int(v) for v in matrix(GF(pk.params.q), F).solve_right(vector(GF(pk.params.q), h.message_vector(pk, x, y))))
    if not any(z):
        z = tuple(int(v) for v in matrix(GF(pk.params.q), F).right_kernel().basis()[0])
    forged = replace(sig, z=z)
    assert b.verify(pk, b"Impersonated", b"public forgery", forged) is True


def test_shared_protocol_uses_five_methods(lifecycle, wp):
    from ibme.hibe.mock import MockHIBE
    from ibme.lattice.params import EDUCATION_PARAMS
    from ibme.protocol.baseline import BaselineIBME, BOTTOM
    b, _, _, _, _ = lifecycle
    protocol = BaselineIBME(MockHIBE(), b)
    pk, master = protocol.setup(replace(EDUCATION_PARAMS, max_message_bytes=1024), ibs_params=wp.Params())
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob")
    ciphertext = protocol.encrypt(pk, sender, b"Bob", b"payload")
    assert protocol.decrypt(pk, receiver, b"Alice", ciphertext) == b"payload"
    assert protocol.decrypt(pk, receiver, b"Eve", ciphertext) is BOTTOM
    wrong = protocol.rkgen(master, b"Carol")
    assert protocol.decrypt(pk, wrong, b"Alice", ciphertext) is BOTTOM
    assert protocol.decrypt(pk, wrong, b"Eve", ciphertext) is BOTTOM


def test_public_audit_has_real_checks_and_no_secret_records(wp):
    pytest.importorskip("sage.all")
    try:
        audit = importlib.import_module("experiments.research.candidates.wang_pw.audit")
    except ModuleNotFoundError:
        pytest.fail("replayable real Wang+PW audit is missing")
    report = audit.audit_report(repetitions=3, rng=DeterministicRandom(b"B:public-audit"))
    assert report["honest_verified"] == 3
    assert report["restored_key_verified"] is True
    assert report["debug_public_forgery_accepted"] is True
    assert report["backend_admitted"] is False and report["security_claim"] == "none"
    assert len(report["samples"]) == 3
    assert all(s["signature_bytes"] > 2*wp.Params().salt_bytes for s in report["samples"])
    assert set(report) == {"schema_version", "algorithm", "parameters", "environment", "input",
                           "timings_seconds", "wire_bytes", "samples", "honest_verified",
                           "restored_key_verified", "debug_public_forgery_accepted", "sampler_classes",
                           "security_claim", "backend_admitted", "limitations"}
    serialized = json.dumps(report)
    assert "trapdoor" not in serialized and "squared_parameter_matrix" not in serialized


def test_memoryview_byte_budget_checked_before_copy_and_json(wp, monkeypatch):
    codec = importlib.import_module("experiments.research.candidates.wang_pw.codec")
    raw = codec.PREFIX+b"SIG\x00"+b" "*(codec.MAX_WIRE_BYTES+128)
    raw += b" "*((-len(raw)) % 4)
    view = memoryview(raw).cast("I")
    assert len(view) < codec.MAX_WIRE_BYTES < view.nbytes
    def forbidden(*args, **kwargs):
        pytest.fail("oversized byte view reached JSON parser")
    monkeypatch.setattr(codec.json, "loads", forbidden)
    with pytest.raises(SerializationError): wp.Signature.from_bytes(view)


def test_released_memoryview_is_serialization_error(wp):
    view = memoryview(b"invalid")
    view.release()
    with pytest.raises(SerializationError): wp.Signature.from_bytes(view)


def test_random_source_counts_bytes_in_typed_memoryviews(wp):
    backend = importlib.import_module("experiments.research.candidates.wang_pw.backend")
    class WrongView:
        def read(self, n): return memoryview(bytearray(4*n)).cast("I")
    with pytest.raises(ValueError): backend.CheckedRandom(WrongView()).read(3)
    class ValidView:
        def read(self, n): return memoryview(bytearray(n)).cast("I")
    assert backend.CheckedRandom(ValidView()).read(4) == b"\x00"*4
