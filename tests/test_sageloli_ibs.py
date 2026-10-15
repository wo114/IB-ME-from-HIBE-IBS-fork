"""Contract and failure tests for the Sageloli SIS/RSIS research IBS.

These tests exercise the implemented five-method lifecycle and the local
fixed-issuer state machine.  The profiles are deliberately teaching values;
the tests provide implementation evidence only and do not assert a security
level or a formal proof.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile

import pytest

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.sageloli import (
    FixedIssuer,
    IssuerPendingError,
    IssuerStateError,
    RSISParams,
    RSISBackend,
    SISParams,
    SISBackend,
)
from experiments.research.candidates.sageloli import hashing
from experiments.research.candidates.sageloli import backend as backend_module
from experiments.research.candidates.sageloli import codec
from experiments.research.candidates.sageloli import objects as objects_module
from experiments.research.candidates.sageloli.objects import MasterSecret
from experiments.research.candidates.sageloli.objects import (
    RsisMasterSecret,
    RsisPublicKey,
    RsisSigningKey,
    SisMasterSecret,
    SisPublicKey,
    SisSigningKey,
)
from experiments.research.candidates.sageloli.service import PENDING_FILE


ROUTES = [
    pytest.param("sis", SISParams, SISBackend, id="sis"),
    pytest.param("rsis", RSISParams, RSISBackend, id="rsis"),
]


class NoEntropy:
    """A test-only source proving a cached recovery consumes no randomness."""

    def __init__(self):
        self.calls = 0

    def read(self, size):
        self.calls += 1
        raise AssertionError("cached issuer unexpectedly consumed entropy")


def backend_of(factory, seed):
    return factory(rng=DeterministicRandom(seed))


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_complete_lifecycle_and_strict_recovery(route, params_type, backend_type):
    params = params_type()
    backend = backend_of(backend_type, f"{route}-lifecycle".encode())
    public, master = backend.setup(params)
    identity, message = b"alice", b"sageloli-message"

    signing_key = backend.key_extract(master, identity)
    signature = backend.sign(signing_key, message)
    assert backend.verify(public, identity, message, signature) is True

    loaded_signature = backend.load_signature(public, signature.to_bytes())
    assert backend.verify(public, identity, message, loaded_signature) is True

    restored_master = MasterSecret.from_bytes(master.to_bytes())
    restored_key = backend.key_extract(restored_master, identity)
    assert restored_key.to_bytes() == signing_key.to_bytes()
    assert type(restored_master).__name__.lower().startswith(route)

    restored_key_type = type(signing_key)
    assert restored_key_type.from_bytes(signing_key.to_bytes()).to_bytes() == signing_key.to_bytes()


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_identity_message_salt_and_context_binding(route, params_type, backend_type):
    params = params_type()
    backend = backend_of(backend_type, f"{route}-binding".encode())
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"alice")
    signature = backend.sign(key, b"message-a")

    assert backend.verify(public, b"bob", b"message-a", signature) is False
    assert backend.verify(public, b"alice", b"message-b", signature) is False

    other_public, _ = backend_of(backend_type, f"{route}-other".encode()).setup(params)
    assert backend.verify(other_public, b"alice", b"message-a", signature) is False

    changed_response = tuple(int(value) + 1 for value in signature.z)
    assert backend.verify(public, b"alice", b"message-a",
                          replace(signature, z=changed_response)) is False
    shifted_response = tuple(int(value) + params.q for value in signature.z)
    assert backend.verify(public, b"alice", b"message-a",
                          replace(signature, z=shifted_response)) is False
    assert backend.verify(public, b"alice", b"message-a",
                          replace(signature, identity_salt=b"r" * params.salt_bytes)) is False
    assert backend.verify(public, b"alice", b"message-a",
                          replace(signature, message_salt=b"s" * params.salt_bytes)) is False

    zeros = (0,) * len(signature.z)
    forged = type(signature)(public.context, b"r" * params.salt_bytes,
                             b"s" * params.salt_bytes, zeros)
    assert backend.verify(public, b"alice", b"message-a", forged) is False


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_h1_h2_domain_and_salt_separation(route, params_type, backend_type):
    params = params_type()
    backend = backend_of(backend_type, f"{route}-hash".encode())
    public, _ = backend.setup(params)
    context, identity, message = public.context, b"alice", b"m"
    r1, r2 = b"r" * params.salt_bytes, b"R" * params.salt_bytes
    s1, s2 = b"s" * params.salt_bytes, b"S" * params.salt_bytes

    if route == "sis":
        h1 = lambda r: hashing.sis_h1(context, r, identity, params.n, params.k, params.q)
        h2 = lambda r, s, m: hashing.sis_h2(context, r, s, identity, m, params.n, params.q)
    else:
        h1 = lambda r: hashing.rsis_h1(context, r, identity, params.k, params.d, params.q)
        h2 = lambda r, s, m: hashing.rsis_h2(context, r, s, identity, m, params.d, params.q)

    assert h1(r1) != h1(r2)
    assert h2(r1, s1, message) != h2(r1, s2, message)
    assert h2(r1, s1, message) != h2(r1, s1, b"different")
    assert h2(r1, s1, message) != h2(r2, s1, message)


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_wire_rejects_truncation_append_and_cross_context(route, params_type, backend_type):
    params = params_type()
    backend = backend_of(backend_type, f"{route}-wire".encode())
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"alice")
    signature = backend.sign(key, b"message")

    for parser, raw in (
        (type(public).from_bytes, public.to_bytes()),
        (type(master).from_bytes, master.to_bytes()),
        (type(key).from_bytes, key.to_bytes()),
    ):
        with pytest.raises(SerializationError):
            parser(raw[:-1])
        with pytest.raises(SerializationError):
            parser(raw + b"\x00")

    with pytest.raises(SerializationError):
        backend.load_signature(public, signature.to_bytes()[:-1])
    with pytest.raises(SerializationError):
        backend.load_signature(public, signature.to_bytes() + b"\x00")


def test_concrete_route_parsers_reject_cross_route_public_keys():
    sis_public, sis_master = SISBackend(rng=DeterministicRandom(b"sis-route")).setup(SISParams())
    sis_key = SISBackend(rng=DeterministicRandom(b"sis-route-key")).key_extract(sis_master, b"a")
    rsis_backend = RSISBackend(rng=DeterministicRandom(b"rsis-route"))
    rsis_public, rsis_master = rsis_backend.setup(RSISParams())
    rsis_key = rsis_backend.key_extract(rsis_master, b"a")
    with pytest.raises(SerializationError):
        RsisPublicKey.from_bytes(sis_public.to_bytes())
    with pytest.raises(SerializationError):
        SisPublicKey.from_bytes(rsis_public.to_bytes())
    with pytest.raises(SerializationError):
        RsisMasterSecret.from_bytes(sis_master.to_bytes())
    with pytest.raises(SerializationError):
        SisMasterSecret.from_bytes(rsis_master.to_bytes())
    with pytest.raises(SerializationError):
        RsisSigningKey.from_bytes(sis_key.to_bytes())
    with pytest.raises(SerializationError):
        SisSigningKey.from_bytes(rsis_key.to_bytes())


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_fixed_issuer_reuses_key_after_restart_and_concurrency(route, params_type, backend_type):
    params = params_type()
    with tempfile.TemporaryDirectory(prefix=f"sageloli-{route}-") as directory:
        path = Path(directory)
        issuer = FixedIssuer(path, backend_of(backend_type, f"{route}-issuer".encode()))
        public = issuer.initialize(params)
        first = issuer.key_extract(b"alice")
        signature = issuer.sign(first, b"message")
        assert issuer.verify(public, b"alice", b"message", signature) is True

        no_entropy = NoEntropy()
        restarted = FixedIssuer(path, backend_type(rng=no_entropy))
        assert restarted.public_key().to_bytes() == public.to_bytes()
        cached = restarted.key_extract(b"alice")
        assert cached.to_bytes() == first.to_bytes()
        assert no_entropy.calls == 0

        other_backend_type = RSISBackend if route == "sis" else SISBackend
        with pytest.raises(IssuerStateError, match="route"):
            FixedIssuer(path, other_backend_type(rng=NoEntropy())).public_key()

        def read_cached(_):
            return FixedIssuer(path, backend_type(rng=NoEntropy())).key_extract(b"alice").to_bytes()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(read_cached, range(2)))
        assert results == [first.to_bytes(), first.to_bytes()]


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_failed_extraction_leaves_durable_block(route, params_type, backend_type):
    class FailingBackend(backend_type):
        def key_extract(self, master, identity):
            raise RuntimeError("injected sampler failure")

    params = params_type()
    with tempfile.TemporaryDirectory(prefix=f"sageloli-fail-{route}-") as directory:
        path = Path(directory)
        issuer = FixedIssuer(path, backend_of(FailingBackend, f"{route}-failure".encode()))
        issuer.initialize(params)
        with pytest.raises(RuntimeError, match="injected sampler failure"):
            issuer.key_extract(b"alice")
        assert (path / PENDING_FILE).exists()

        no_entropy = NoEntropy()
        recovered = FixedIssuer(path, backend_type(rng=no_entropy))
        with pytest.raises(IssuerPendingError):
            recovered.key_extract(b"alice")
        with pytest.raises(IssuerPendingError):
            recovered.public_key()
        assert no_entropy.calls == 0


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_fixed_issuer_rejects_setup_parameter_mismatch(route, params_type, backend_type):
    requested = params_type()
    alternate = params_type(identity_max_bytes=requested.identity_max_bytes + 1)

    class WrongParamsBackend(backend_type):
        def setup(self, _):
            return super().setup(alternate)

    with tempfile.TemporaryDirectory(prefix=f"sageloli-mismatch-{route}-") as directory:
        issuer = FixedIssuer(Path(directory), backend_of(WrongParamsBackend,
                                                         f"{route}-mismatch".encode()))
        with pytest.raises(IssuerStateError, match="parameter"):
            issuer.initialize(requested)
        assert (Path(directory) / PENDING_FILE).exists()


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_fixed_issuer_rejects_wrong_route_before_pending(route, params_type, backend_type):
    other_backend_type = RSISBackend if route == "sis" else SISBackend
    with tempfile.TemporaryDirectory(prefix=f"sageloli-route-{route}-") as directory:
        path = Path(directory) / "issuer"
        issuer = FixedIssuer(path, other_backend_type(rng=NoEntropy()))
        with pytest.raises(TypeError, match="route"):
            issuer.initialize(params_type())
        assert not path.exists()


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_fixed_issuer_capacity_rejection_preserves_state(route, params_type, backend_type):
    params = params_type(max_users=1)
    with tempfile.TemporaryDirectory(prefix=f"sageloli-capacity-{route}-") as directory:
        path = Path(directory)
        issuer = FixedIssuer(path, backend_of(backend_type, f"{route}-capacity".encode()))
        public = issuer.initialize(params)
        first = issuer.key_extract(b"alice")

        with pytest.raises(IssuerStateError, match="capacity"):
            issuer.key_extract(b"bob")
        assert not (path / PENDING_FILE).exists()

        restarted = FixedIssuer(path, backend_type(rng=NoEntropy()))
        assert restarted.public_key().to_bytes() == public.to_bytes()
        assert restarted.key_extract(b"alice").to_bytes() == first.to_bytes()


def test_input_limits_are_checked_before_sampling():
    backend = backend_of(SISBackend, b"sageloli-inputs")
    params = SISParams(message_max_bytes=3)
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"a")
    with pytest.raises(EncodingError):
        backend.sign(key, b"toolong")
    assert backend.verify(public, b"a", b"toolong", backend.sign(key, b"ok")) is False


def test_matrix_route_supports_n_one_and_profile_sigmas():
    params = SISParams(n=1, k=2, m=4, q=9, trapdoor_sigma=1.25,
                       signing_sigma=1.5)
    backend = SISBackend(rng=DeterministicRandom(b"sageloli-n-one"))
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"n-one")
    signature = backend.sign(key, b"message")
    assert backend.verify(public, b"n-one", b"message", signature) is True


def test_matrix_route_accepts_zero_delegated_trapdoor(monkeypatch):
    """A zero H1-G target has a valid zero identity trapdoor."""
    params = SISParams(n=1, k=1, m=2, q=3)
    zero_target_h1 = lambda *args: ((1,),)
    monkeypatch.setattr(backend_module, "sis_h1", zero_target_h1)
    monkeypatch.setattr(hashing, "sis_h1", zero_target_h1)
    backend = SISBackend(rng=DeterministicRandom(b"sageloli-zero-trapdoor"))
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"zero-target")
    assert key.trapdoor == ((0,), (0,))
    signature = backend.sign(key, b"message")
    assert backend.verify(public, b"zero-target", b"message", signature) is True


@pytest.mark.parametrize("route,params_type,backend_type", ROUTES)
def test_recovery_rejects_corrupted_issued_key(route, params_type, backend_type):
    """A valid wire envelope cannot bypass the issued-key equation check."""
    params = params_type()
    backend = backend_of(backend_type, f"{route}-corrupt-key".encode())
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"alice")

    key_kind = b"SIS-SK" if route == "sis" else b"RSIS-SK"
    key_fields = codec.decode(key.to_bytes(), key_kind, 4)
    trap = objects_module._tensor_from_bytes(
        key_fields[3], objects_module._shape(params, "identity"))
    if route == "sis":
        rows = [list(row) for row in trap]
        rows[0][0] += 1
        bad_trap = tuple(tuple(row) for row in rows)
    else:
        ring = backend_module._collapse_ring_matrix(
            trap, params.d, params.l, params.k)
        ring_rows = [list(row) for row in ring]
        first_poly = list(ring_rows[0][0])
        first_poly[0] += 1
        ring_rows[0][0] = tuple(first_poly)
        bad_trap = backend_module._expand_ring_matrix(
            tuple(tuple(row) for row in ring_rows), params.d)
    bad_key = codec.encode(
        key_kind, key_fields[0], key_fields[1], key_fields[2],
        objects_module._tensor_bytes(
            bad_trap, objects_module._shape(params, "identity")))

    master_kind = b"SIS-MSK" if route == "sis" else b"RSIS-MSK"
    master_fields = codec.decode(master.to_bytes(), master_kind, 3)
    state_raw = master_fields[2]
    count, pos = codec.read_u32(state_raw)
    assert count == 1
    identity, pos = codec.read_blob(state_raw, pos, what="identity")
    status, pos = codec.read_blob(state_raw, pos, what="status")
    _, pos = codec.read_blob(state_raw, pos, what="key")
    assert pos == len(state_raw)
    bad_state = (codec.u32(count) + codec.blob(identity) + codec.blob(status)
                 + codec.blob(bad_key))
    bad_master = codec.encode(master_kind, master_fields[0], master_fields[1], bad_state)

    with pytest.raises(SerializationError, match="invalid Sageloli object"):
        MasterSecret.from_bytes(bad_master)
