"""Independent five-method/object checks using real bounded SRGG sampling.

The n=8 point is deliberately a research test point, not a security preset.
Fault injection is confined to explicit failure tests; the lifecycle fixture
uses the actual structured sampler, randomized gadget, and signing algorithm.
"""
from dataclasses import replace
from math import isqrt
import json

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.api import (
    IBSBackend, IBSMasterSecret, IBSPublicKey, IBSSignature, IBSSigningKey,
)
from ibme.ibs.srgg import structured as public_api
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.candidates.srgg import structured_backend as api
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.structured_execution import ExecutionParams


class NoRead:
    def read(self, _size):
        raise AssertionError("operation unexpectedly consumed entropy")


def _params():
    return ExecutionParams.from_candidate(conditional_candidate(degree=8, rank=1, digits=3))


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.fixture(scope="module")
def lifecycle():
    backend = api.Backend(rng=DeterministicRandom(b"srgg-structured-contract-real"))
    public, master = backend.setup(_params())
    key = backend.key_extract(master, b"Alice")
    signature = backend.sign(key, b"structured message")
    assert backend.verify(public, b"Alice", b"structured message", signature) is True
    return public, master, key, signature


def test_public_opt_in_namespace_preserves_five_method_and_object_contract(lifecycle):
    public, master, key, signature = lifecycle
    assert public_api.Parameters is ExecutionParams
    assert public_api.Backend is api.Backend
    assert public_api.PublicKey is api.PublicKey
    assert public_api.MasterSecret is api.MasterSecret
    assert public_api.SigningKey is api.SigningKey
    assert public_api.Signature is api.Signature
    assert isinstance(api.Backend(rng=NoRead()), IBSBackend)
    assert isinstance(public, IBSPublicKey)
    assert isinstance(master, IBSMasterSecret)
    assert isinstance(key, IBSSigningKey)
    assert isinstance(signature, IBSSignature)
    assert key.identity == b"Alice"
    assert key.identity_digest == hash_identity(b"Alice", 32)
    assert api.Backend.security_claim == "none"
    assert api.Backend.backend_admitted is False
    assert api.Backend.parameters_are_formal is False
    assert api.Backend.nist_security_category is None


@pytest.mark.parametrize("position", range(4))
def test_all_objects_have_canonical_strict_roundtrip(lifecycle, position):
    value = lifecycle[position]
    encoded = value.to_bytes()
    restored = type(value).from_bytes(encoded)
    assert restored == value
    assert restored.to_bytes() == encoded
    record = json.loads(encoded)
    malformed = [encoded[:-1], encoded+b" ", encoded+b"x", b"[1]", b"{}",
                 b'{"schema":"x","schema":"x"}',
                 _canonical(dict(record, unexpected=1))]
    missing = dict(record)
    missing.pop(next(iter(missing)))
    malformed.append(_canonical(missing))
    for payload in malformed:
        with pytest.raises(SerializationError):
            type(value).from_bytes(payload)


@pytest.mark.parametrize("field,value", [
    ("degree", True), ("rank", 1.0), ("sign_max_attempts", 0),
    ("sign_max_attempts", 17), ("base", 4), ("unexpected", 1),
])
def test_public_wire_binds_complete_exact_parameters(lifecycle, field, value):
    record = json.loads(lifecycle[0].to_bytes())
    record["params"][field] = value
    with pytest.raises(SerializationError):
        api.PublicKey.from_bytes(_canonical(record))


def test_public_wire_rejects_implicit_default_and_bad_public_shape(lifecycle):
    original = json.loads(lifecycle[0].to_bytes())
    missing = json.loads(_canonical(original))
    del missing["params"]["sign_max_attempts"]
    bad_coefficient = json.loads(_canonical(original))
    bad_coefficient["b"][0][0][0] = lifecycle[0].params.modulus
    wrong_shape = json.loads(_canonical(original))
    wrong_shape["b"][0].pop()
    uppercase = json.loads(_canonical(original))
    uppercase["seed"] = uppercase["seed"].upper()
    for record in (missing, bad_coefficient, wrong_shape, uppercase):
        with pytest.raises(SerializationError):
            api.PublicKey.from_bytes(_canonical(record))


@pytest.mark.parametrize("field,value", [
    ("context", "00"), ("context", "gg"*32),
    ("challenge", [True]*8), ("challenge", [2]*8),
    ("challenge", [0]*3), ("response", []),
    ("response", [[True]*8]), ("response", [[2**256]*8]),
])
def test_signature_wire_rejects_nonexact_values(lifecycle, field, value):
    record = json.loads(lifecycle[3].to_bytes())
    record[field] = value
    with pytest.raises(SerializationError):
        api.Signature.from_bytes(_canonical(record))


def test_load_signature_checks_public_context_dimensions_and_norm(lifecycle):
    public, _, _, signature = lifecycle
    backend = api.Backend(rng=NoRead())
    assert backend.load_signature(public, signature.to_bytes()) == signature
    changed_public, _ = api.Backend(rng=DeterministicRandom(b"srgg-structured-changed-params")).setup(
        replace(public.params, sign_max_attempts=1))
    malformed = [replace(signature, context=bytes(32)),
                 replace(signature, response=signature.response[:-1]),
                 replace(signature, challenge=signature.challenge[:4],
                         response=tuple(poly[:4] for poly in signature.response))]
    cap = isqrt(public.params.signature_norm_cap)+1
    large = ((cap,)+(0,)*7,)+((0,)*8,)*(public.params.columns)
    malformed.append(replace(signature, response=large))
    for value in malformed:
        with pytest.raises(SerializationError):
            backend.load_signature(public, value.to_bytes())
    with pytest.raises(SerializationError):
        backend.load_signature(changed_public, signature.to_bytes())


def test_verification_is_entropy_free_and_does_not_construct_a_sampler(lifecycle, monkeypatch):
    public, _, _, signature = lifecycle
    backend = api.Backend(rng=NoRead())
    def forbidden(*_args, **_kwargs):
        raise AssertionError("verify constructed a sampling execution")
    monkeypatch.setattr(backend, "_execution", forbidden)
    assert backend.verify(public, b"Alice", b"structured message", signature) is True
    assert backend.verify(public, b"Bob", b"structured message", signature) is False
    assert backend.verify(public, b"Alice", b"altered", signature) is False
    response = list(signature.response)
    response[0] = (response[0][0]+1,)+response[0][1:]
    assert backend.verify(public, b"Alice", b"structured message", replace(signature, response=response)) is False
    forged_attempt = api.Signature(public.context, ((0,)*8,)*(public.params.columns+1), (0,)*8)
    assert backend.verify(public, b"Alice", b"structured message", forged_attempt) is False


def test_tiny_research_point_retains_public_zero_response_forgery(lifecycle):
    # The effective challenge has only n/2=4 bits at this test point. In this
    # fixed public fixture H2(W=0, message) happens to equal (1,)*8, whose eta
    # is zero. No key is used to create this signature. Keeping the successful
    # counterexample prevents functional smoke tests being read as security.
    public = lifecycle[0]
    forged = api.Signature(public.context, ((0,)*8,)*(public.params.columns+1), (1,)*8)
    backend = api.Backend(rng=NoRead())
    assert backend.verify(public, b"Alice", b"structured message", forged) is True
    assert backend.verify(public, b"Bob", b"structured message", forged) is True


@pytest.mark.parametrize("slot,value", [
    ("public", None), ("identity", b""), ("identity", "Alice"),
    ("identity", b"x"*4097), ("message", None), ("message", b"x"*65537),
    ("signature", object()),
])
def test_verify_bad_inputs_return_literal_false(lifecycle, slot, value):
    public, _, _, signature = lifecycle
    args = dict(public=public, identity=b"Alice", message=b"structured message", signature=signature)
    args[slot] = value
    assert api.Backend(rng=NoRead()).verify(**args) is False


def test_restored_master_and_key_reuse_fixed_key_without_entropy(lifecycle):
    _, master, key, _ = lifecycle
    recovered = api.MasterSecret.from_bytes(master.to_bytes())
    cached = api.Backend(rng=NoRead()).key_extract(recovered, bytearray(b"Alice"))
    assert cached.to_bytes() == key.to_bytes()
    signer = api.Backend(rng=DeterministicRandom(b"srgg-structured-restored-sign"))
    restored_key = api.SigningKey.from_bytes(key.to_bytes())
    signature = signer.sign(restored_key, b"")
    assert signer.verify(restored_key.public_key, b"Alice", b"", signature) is True
    assert "redacted" in repr(restored_key) and "redacted" in repr(recovered)


def test_maximum_identity_and_message_are_real_accepted_inputs():
    backend = api.Backend(rng=DeterministicRandom(b"srgg-structured-max-input"))
    public, master = backend.setup(_params())
    identity, message = b"i"*4096, b"m"*65536
    key = backend.key_extract(master, identity)
    signature = backend.sign(key, message)
    assert backend.verify(public, identity, message, signature) is True


def test_sampling_failure_tombstones_identity_and_never_reselects(lifecycle, monkeypatch):
    _, master, _, _ = lifecycle
    master = api.MasterSecret.from_bytes(master.to_bytes())
    backend = api.Backend(rng=NoRead())
    calls = []
    class FailedExecution:
        def key_extract(self, *_args):
            calls.append(1)
            raise SamplingAbort("injected sampler abort")
    monkeypatch.setattr(backend, "_execution", lambda _params: FailedExecution())
    with pytest.raises(SamplingAbort, match="injected"):
        backend.key_extract(master, b"failed-id")
    assert master.states[b"failed-id"] == ("failed", None)
    recovered = api.MasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(SamplingAbort, match="no reselection"):
        backend.key_extract(recovered, b"failed-id")
    assert calls == [1]


@pytest.mark.parametrize("status", ["pending", "failed"])
def test_pending_failed_and_full_cache_stop_before_entropy(lifecycle, status):
    public, master, _, _ = lifecycle
    blocked = api.MasterSecret(public, master.witness, {b"blocked": (status, None)})
    backend = api.Backend(rng=NoRead())
    with pytest.raises(SamplingAbort, match="no reselection"):
        backend.key_extract(blocked, b"blocked")
    full = api.MasterSecret(public, master.witness,
        {bytes([i])+b"id": ("failed", None) for i in range(api.MAX_USERS)})
    with pytest.raises(SamplingAbort, match="capacity"):
        backend.key_extract(full, b"new")


def test_master_wire_rejects_changed_witness_and_cache_schema(lifecycle):
    original = json.loads(lifecycle[1].to_bytes())
    records = []
    changed = json.loads(_canonical(original))
    x = changed["witness"][0][0][0]
    changed["witness"][0][0][0] = -1 if x != -1 else 1
    records.append(changed)
    for status, tail in (("unknown", None), ("pending", original["entries"][0][2]), ("issued", None)):
        changed = json.loads(_canonical(original))
        changed["entries"][0][1:] = [status, tail]
        records.append(changed)
    duplicate = json.loads(_canonical(original))
    duplicate["entries"].append(duplicate["entries"][0])
    records.append(duplicate)
    for record in records:
        with pytest.raises(SerializationError):
            api.MasterSecret.from_bytes(_canonical(record))


@pytest.mark.parametrize("method,args", [
    ("setup", (None,)), ("key_extract", (None, b"Alice")),
    ("sign", (None, b"message")), ("load_signature", (None, b"{}")),
])
def test_programming_type_errors_are_explicit(method, args):
    with pytest.raises(TypeError):
        getattr(api.Backend(rng=NoRead()), method)(*args)


def test_invalid_identity_and_message_stop_before_entropy(lifecycle):
    _, master, key, _ = lifecycle
    backend = api.Backend(rng=NoRead())
    for identity in (b"", "Alice", b"x"*4097):
        with pytest.raises(EncodingError):
            backend.key_extract(master, identity)
    for message in (None, b"x"*65537):
        with pytest.raises(EncodingError):
            backend.sign(key, message)


def test_bad_entropy_is_propagated_without_fallback():
    class Short:
        calls = 0
        def read(self, size):
            self.calls += 1
            return bytes(size-1)
    source = Short()
    with pytest.raises(ValueError, match="byte count"):
        api.Backend(rng=source).setup(_params())
    assert source.calls == 1


def test_signature_size_bounds_actual_canonical_signature(lifecycle):
    assert len(lifecycle[3].to_bytes()) <= api.signature_size(lifecycle[0].params) <= api.MAX_WIRE
