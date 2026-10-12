"""Independent lifecycle controls; small parameters are NOT security evidence.

Private snapshots live only in memory. These tests do not claim crash safety,
rollback protection, authenticated storage, or cross-process locking.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from ibme.core.errors import RandomnessError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import (
    LuoModuleIBSBackend, LuoModuleMasterSecret, LuoModuleParams,
    LuoModulePublicKey, LuoModuleSamplingAbort, LuoModuleSigningKey,
)
from ibme.ibs.luo_module_codec import (
    LuoModuleCompactIBSBackend, LuoModuleCompactSignature,
)


def parameters(**changes):
    return replace(LuoModuleParams(degree=8, k=2, l=1, q=769, root=27,
                                  kappa=1, gamma1=16, gamma2=256,
                                  gamma3=128, dropped_bits=3), **changes)


class ForbiddenEntropy:
    def __init__(self):
        self.calls = 0

    def read(self, count):
        self.calls += 1
        raise RuntimeError("entropy forbidden in cached-key control")


def setup(label, **changes):
    backend = LuoModuleIBSBackend(rng=DeterministicRandom(label))
    public, master = backend.setup(parameters(**changes))
    return backend, public, master


@pytest.mark.parametrize("identity_length", [1, 5, 64])
def test_restored_cached_key_never_consumes_entropy(identity_length):
    backend, public, master = setup(b"lifecycle-cache:" + bytes([identity_length]))
    identity = b"i" * identity_length
    original = backend.key_extract(master, identity)
    snapshot = master.to_bytes()
    restored = LuoModuleMasterSecret.from_bytes(snapshot)
    forbidden = ForbiddenEntropy()
    reader = LuoModuleIBSBackend(rng=forbidden)
    key = reader.key_extract(restored, identity)
    assert key.to_bytes() == original.to_bytes()
    assert restored.to_bytes() == snapshot
    assert reader.last_extract_attempts == 0 and forbidden.calls == 0
    # The control is live: requesting a genuinely new identity reaches entropy.
    with pytest.raises(RandomnessError):
        reader.key_extract(restored, b"new")
    assert forbidden.calls == 1
    assert restored.to_bytes() == snapshot


@pytest.mark.parametrize("message_length", [0, 256, 4096])
def test_restored_identity_continues_signing_without_changing_cache(message_length):
    backend, public, master = setup(b"lifecycle-sign:" + message_length.to_bytes(4, "big"))
    original = backend.key_extract(master, b"Alice")
    snapshot = master.to_bytes()
    restored = LuoModuleMasterSecret.from_bytes(snapshot)
    copied = LuoModuleSigningKey.from_bytes(original.to_bytes())
    signer = LuoModuleIBSBackend(rng=DeterministicRandom(b"lifecycle-restored-sign:" + message_length.to_bytes(4, "big")))
    cached = signer.key_extract(restored, b"Alice")
    assert cached.to_bytes() == copied.to_bytes()
    message = b"m" * message_length
    signature = signer.sign(cached, message)
    verifier = LuoModuleIBSBackend(rng=ForbiddenEntropy())
    compact_verifier = LuoModuleCompactIBSBackend(rng=ForbiddenEntropy())
    public_copy = LuoModulePublicKey.from_bytes(public.to_bytes())
    reference = verifier.load_signature(public_copy, signature.to_bytes())
    compact = compact_verifier.load_signature(public_copy, LuoModuleCompactSignature(signature).to_bytes())
    assert verifier.verify(public_copy, b"Alice", message, reference) is True
    assert compact_verifier.verify(public_copy, b"Alice", message, compact) is True
    for field in ("params", "context", "z", "c", "w1", "h"):
        assert getattr(reference, field) == getattr(compact.signature, field)
    assert restored.to_bytes() == snapshot == master.to_bytes()
    assert cached.to_bytes() == original.to_bytes()


def test_three_identity_snapshot_restores_every_fixed_key():
    backend, public, master = setup(b"lifecycle-three", max_cached_identities=3)
    snapshots = {0: master.to_bytes()}
    originals = {}
    for index, length in enumerate((1, 5, 64), 1):
        identity = b"i" * length
        originals[identity] = backend.key_extract(master, identity).to_bytes()
        if index in (1, 3):
            snapshots[index] = master.to_bytes()
    assert len(snapshots[0]) < len(snapshots[1]) < len(snapshots[3])
    forbidden = ForbiddenEntropy()
    reader = LuoModuleIBSBackend(rng=forbidden)
    for count, raw in snapshots.items():
        restored = LuoModuleMasterSecret.from_bytes(raw)
        assert len(restored.cached_identities) == count
        for identity in restored.cached_identities:
            assert reader.key_extract(restored, identity).to_bytes() == originals[identity]
            assert reader.last_extract_attempts == 0
        assert restored.to_bytes() == raw
    full = LuoModuleMasterSecret.from_bytes(snapshots[3])
    with pytest.raises(LuoModuleSamplingAbort):
        reader.key_extract(full, b"overflow")
    assert forbidden.calls == 0 and full.to_bytes() == snapshots[3]


def test_same_identity_threads_share_one_fixed_entry():
    backend, _, master = setup(b"lifecycle-threads", max_cached_identities=1)
    with ThreadPoolExecutor(max_workers=4) as pool:
        keys = list(pool.map(lambda _: backend.key_extract(master, b"Alice"), range(8)))
    assert all(key is keys[0] for key in keys)
    assert master.cached_identities == (b"Alice",)
    # Same-object locking only; this says nothing about independent snapshots.


def test_failed_restore_does_not_silently_reissue_key():
    backend, _, master = setup(b"lifecycle-bad-restore")
    backend.key_extract(master, b"Alice")
    snapshot = master.to_bytes()
    with pytest.raises(SerializationError):
        LuoModuleMasterSecret.from_bytes(snapshot[:-1])
    assert master.to_bytes() == snapshot
