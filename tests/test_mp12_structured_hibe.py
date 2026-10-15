"""Actual deterministic Gaussian H/G backend contracts and failed-slot rules.

The fixture performs genuine root generation, full-H DelTrap, 256 SampleD
calls and actual rounded-noise encryption. Fixed entropy is TEST-ONLY.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import threading
import pytest
pytest.importorskip("sage.all", reason="requires prescribed WSL Sage environment")

from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.api import HIBEBackend, HIBEKeyBindingValidator
from ibme.hibe.mp12_structured.backend import StructuredMP12HIBE
from ibme.hibe.mp12_structured.params import StructuredHIBEParams
from ibme.hibe.mp12_structured.objects import (StructuredPublicKey, StructuredMasterSecret,
    StructuredLevel1Key, StructuredLevel2Key, StructuredCiphertext)
from ibme.hibe.mp12_structured.registration import ciphertext_size
from ibme.lattice.matrix_sampling import mp12_extension
from ibme.lattice.chkp.leaf_state import SeedAddressBlocked


class NoEntropy:
    def __init__(self): self.calls = 0
    def read(self, count):
        self.calls += 1
        raise AssertionError("unexpected new issuance or restore entropy")


def root(label=b"root", **changes):
    return StructuredMP12HIBE().setup(replace(StructuredHIBEParams(), **changes),
        rng=DeterministicRandom(b"structured-HIBE-TEST-ONLY-"+label))


@pytest.fixture(scope="module")
def witness():
    backend = StructuredMP12HIBE()
    public, master = root()
    parent = backend.extract(master, b"B"*86, rng=DeterministicRandom(b"structured-HIBE-TEST-ONLY-parent"))
    child = backend.derive(parent, b"A"*86, rng=DeterministicRandom(b"structured-HIBE-TEST-ONLY-leaf256"))
    ct = backend.encrypt(public, parent.identity, child.child_identity, bytes(range(32)),
        rng=DeterministicRandom(b"structured-HIBE-TEST-ONLY-encrypt"))
    return backend, public, master, parent, child, ct


def test_real_six_method_path_keeps_complete_H_and_256_equations(witness):
    backend, public, master, parent, leaf, ct = witness
    assert isinstance(backend, HIBEBackend) and isinstance(backend, HIBEKeyBindingValidator)
    assert len(public.oracle.root_rows[0]) == 84
    assert len(parent.trapdoor.public.rows[0]) == 168
    assert len(leaf.key.preimages) == 256 and len(leaf.key.preimages[0]) == 252
    assert backend.decrypt(leaf, ct) == bytes(range(32))
    assert ciphertext_size(public.params, 32, 86) == len(ct.to_bytes())
    assert b"A"*86 not in ct.to_bytes() and b"B"*86 not in ct.to_bytes()


def test_all_five_objects_restore_and_reuse_byte_identically_without_entropy(witness, monkeypatch):
    backend, public, master, parent, leaf, ct = witness
    guard = NoEntropy()
    monkeypatch.setattr(SecureRandom, "read", guard.read)
    monkeypatch.setattr(mp12_extension, "StructuredLeftSampler", lambda *a, **k: pytest.fail("restore invoked sampler"))
    monkeypatch.setattr(mp12_extension, "delegate_extension", lambda *a, **k: pytest.fail("restore invoked DelTrap"))
    values = [type(value).from_bytes(value.to_bytes()) for value in (public, master, parent, leaf, ct)]
    assert [v.to_bytes() for v in values] == [v.to_bytes() for v in (public, master, parent, leaf, ct)]
    restored_parent = backend.extract(values[1], parent.identity, rng=guard)
    assert restored_parent.to_bytes() == parent.to_bytes()
    restored_leaf = backend.derive(restored_parent, leaf.child_identity, rng=guard)
    assert restored_leaf.to_bytes() == leaf.to_bytes()
    assert backend.decrypt(restored_leaf, values[4], rng=guard) == bytes(range(32)) and guard.calls == 0


@pytest.mark.parametrize("index", range(5))
@pytest.mark.parametrize("mutation", ["truncated", "append", "duplicate", "version"])
def test_strict_five_object_framing(witness, index, mutation):
    value = witness[index+1]; raw = value.to_bytes()
    altered = {"truncated": raw[:-1], "append": raw+b"x", "duplicate": raw+raw,
               "version": bytes([raw[0]^1])+raw[1:]}[mutation]
    with pytest.raises(SerializationError): type(value).from_bytes(altered)


def test_context_binding_and_fixed_seed_raw_capacity(witness):
    backend, public, master, parent, leaf, ct = witness
    other, _ = root(b"unrelated-root")
    assert all(backend.validate_key_binding(public, v) for v in (master, parent, leaf))
    assert all(not backend.validate_key_binding(other, v) for v in (master, parent, leaf))
    guard = NoEntropy()
    for value in (b"", bytes(31), bytes(33)):
        with pytest.raises(InvalidParameterError): backend.encrypt(public, b"Bob", b"Alice", value, rng=guard)
    assert guard.calls == 0


def test_receiver_failure_is_reserved_persisted_and_blocks_every_retry(monkeypatch):
    public, master = root(b"failed-receiver", max_receivers=1)
    snapshots, calls = [], []
    backend = StructuredMP12HIBE(persist_pending=lambda state: snapshots.append(state.to_bytes()))
    def failed(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("injected sampler failure")
    monkeypatch.setattr(mp12_extension, "delegate_extension", failed)
    with pytest.raises(RuntimeError): backend.extract(master, b"Bob", rng=NoEntropy())
    assert len(calls) == len(snapshots) == 1
    for restored in (master, StructuredMasterSecret.from_bytes(master.to_bytes()), StructuredMasterSecret.from_bytes(snapshots[0])):
        with pytest.raises(InvalidParameterError, match="no reissue"): backend.extract(restored, b"Bob", rng=NoEntropy())
        with pytest.raises(InvalidParameterError, match="capacity"): backend.extract(restored, b"Carol", rng=NoEntropy())
    assert len(calls) == 1


def test_pending_publication_failure_prevents_sampling_and_remains_blocked(monkeypatch):
    public, master = root(b"pending-publication-failure")
    monkeypatch.setattr(mp12_extension, "delegate_extension", lambda *a, **k: pytest.fail("failed persister reached sampler"))
    def failed(state): raise OSError("injected publication failure")
    backend = StructuredMP12HIBE(persist_pending=failed)
    with pytest.raises(OSError): backend.extract(master, b"Bob", rng=NoEntropy())
    restored = StructuredMasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(InvalidParameterError, match="no reissue"): backend.extract(restored, b"Bob", rng=NoEntropy())


def test_leaf_failure_survives_codec_consumes_capacity_and_is_never_resampled(witness, monkeypatch):
    parent = StructuredLevel1Key.from_bytes(witness[3].to_bytes())
    snapshots, calls = [], []
    backend = StructuredMP12HIBE(persist_pending=lambda state: snapshots.append(state.to_bytes()))
    def failed(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("injected leaf preflight failure")
    monkeypatch.setattr(mp12_extension, "StructuredLeftSampler", failed)
    with pytest.raises(RuntimeError): backend.derive(parent, b"Mallory", rng=NoEntropy())
    for restored in (parent, StructuredLevel1Key.from_bytes(parent.to_bytes()), StructuredLevel1Key.from_bytes(snapshots[0])):
        with pytest.raises(SeedAddressBlocked): backend.derive(restored, b"Mallory", rng=NoEntropy())
        with pytest.raises(InvalidParameterError, match="capacity"): backend.derive(restored, b"Eve", rng=NoEntropy())
    assert len(calls) == len(snapshots) == 1


def test_concurrent_failed_address_gets_exactly_one_attempt(monkeypatch):
    _, master = root(b"concurrent-failure")
    attempts, lock = [], threading.Lock()
    def failed(*args, **kwargs):
        with lock: attempts.append(True)
        raise RuntimeError("injected one-attempt failure")
    monkeypatch.setattr(mp12_extension, "delegate_extension", failed)
    def attempt(_):
        try: StructuredMP12HIBE().extract(master, b"Bob", rng=NoEntropy())
        except (RuntimeError, InvalidParameterError): return "failed"
        raise AssertionError("failed slot was issued")
    with ThreadPoolExecutor(max_workers=2) as pool: assert list(pool.map(attempt, range(2))) == ["failed", "failed"]
    assert len(attempts) == 1
