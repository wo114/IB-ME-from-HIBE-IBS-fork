"""Regression tests for the reviewed sampler flaws; teaching profiles only."""
from dataclasses import replace

import pytest

pytest.importorskip("sage.all")
from sage.all import GF, Zmod, ZZ, matrix, vector

from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.sageloli import (
    SISBackend, RSISBackend, SISParams, RSISParams, SamplingAbort)
from experiments.research.candidates.sageloli import algebra, sampling, hashing, codec
from experiments.research.candidates.sageloli.objects import MasterSecret
from experiments.research.candidates.sageloli.probe import ternary_preimage

ROUTES = [(SISBackend, SISParams), (RSISBackend, RSISParams)]


@pytest.fixture(scope="module", params=ROUTES, ids=["sis", "rsis"])
def issued(request):
    backend_type, params_type = request.param
    backend = backend_type(rng=DeterministicRandom(b"sampler-v2-"+backend_type.route.encode()))
    public, master = backend.setup(params_type())
    key = backend.key_extract(master, b"test-user")
    return backend, public, master, key


def test_delegation_has_full_dimensional_noise_and_rejects_old_exact_relation(issued):
    _, public, master, key = issued
    p = public.params
    width = p.nk if isinstance(p, SISParams) else p.d*p.k
    root = matrix(ZZ, master.trapdoor)
    delegated = matrix(ZZ, key.trapdoor)
    top, bottom = delegated[:-width, :], delegated[-width:, :]
    # PR34's exact integer relation was top == R*bottom. A modular equation
    # alone would still pass that broken implementation.
    assert top != root*bottom
    assert any(int(x) % p.q for x in (top-root*bottom).list())
    restored = type(key).from_bytes(key.to_bytes())
    assert restored.trapdoor == key.trapdoor
    if isinstance(p, RSISParams):
        assert len(p.gadget) == p.k and all(len(poly) == p.d for poly in p.gadget)
        ring = tuple(tuple(tuple(master.trapdoor[i*p.d+h][j*p.d] for h in range(p.d))
                           for j in range(p.k)) for i in range(p.l-p.k))
        for row in ring:
            for poly in row:
                assert poly[0] in (-4, 0, 4) and poly[-1] in (-4, 0, 4)
                assert all(x in (-1, 0, 1) for x in poly[p.d//4:3*p.d//4])


def test_all_ternary_digits_are_gaussian_including_final_carry():
    rng = DeterministicRandom(b"last-ternary-digit")
    draws = [tuple(ternary_preimage((5,), 3, rng)) for _ in range(32)]
    assert all(sum(3**j*x for j, x in enumerate(draw)) % 27 == 5 for draw in draws)
    assert len({draw[-1] for draw in draws}) > 1
    assert any((5-sum(3**j*x for j, x in enumerate(draw)))//27 != 0 for draw in draws)


def test_private_tail_gate_uses_raw_integers_not_centered_values():
    from experiments.research.candidates.sageloli.backend import _matrix_trapdoor_ok
    assert not _matrix_trapdoor_ok(((81,), (0,)), 1, 1, 1, 81)
    assert _matrix_trapdoor_ok(((1,), (0,)), 1, 1, 1, 81)


def test_signing_recovery_uses_full_plan_and_exact_raw_admission(issued):
    backend, public, _, key = issued
    signature = backend.sign(key, b"x"*32)
    assert backend.verify(public, b"test-user", b"x"*32, signature)
    plan = key._signing_sampling_plan[1]
    report = sampling.public_certificate(plan)
    assert report["dimension"] == public.params.signature_dimension
    assert report["full_target_tv_upper_including_abort"] is None
    assert report["continuous_stage_tv_certified"] is False
    recovered = type(key).from_bytes(key.to_bytes())
    assert not hasattr(recovered, "_signing_sampling_plan")
    assert backend.verify(public, b"test-user", b"", backend.sign(recovered, b""))


def test_insufficient_width_aborts_before_entropy_and_does_not_reissue():
    p = SISParams(identity_width_squared=1)
    backend = SISBackend(rng=DeterministicRandom(b"narrow-root"))
    _, master = backend.setup(p)
    class NoEntropy:
        def read(self, size):
            raise AssertionError("admission must precede randomness")
    backend.rng = NoEntropy()
    with pytest.raises(SamplingAbort):
        backend.key_extract(master, b"bad-width")
    assert master.states[b"bad-width"] == ("failed", None)
    with pytest.raises(SamplingAbort, match="pending/failed"):
        backend.key_extract(master, b"bad-width")


def test_corrupt_root_equation_rejected_on_recovery(issued):
    _, public, master, _ = issued
    from experiments.research.candidates.sageloli import objects
    kind = b"SIS-MSK" if isinstance(public.params, SISParams) else b"RSIS-MSK"
    fields = codec.decode(master.to_bytes(), kind, 3)
    shape = objects._shape(public.params, "root")
    trapdoor = [list(row) for row in master.trapdoor]
    trapdoor[0][0] += 7
    raw = codec.encode(kind, fields[0], objects._tensor_bytes(trapdoor, shape), fields[2])
    with pytest.raises(SerializationError):
        MasterSecret.from_bytes(raw)


def test_v1_objects_are_rejected_without_migration(issued):
    backend, public, master, key = issued
    signature = backend.sign(key, b"migration")
    for obj, parse in ((public, type(public).from_bytes),
                       (master, MasterSecret.from_bytes), (key, type(key).from_bytes),
                       (signature, lambda raw: backend.load_signature(public, raw))):
        raw = obj.to_bytes().replace(codec.MAGIC, b"IBME:SAGELOLI-IBS:v1", 1)
        with pytest.raises(SerializationError):
            parse(raw)


def test_teaching_profiles_retain_public_linear_forgery_counterexample(issued):
    backend, public, _, key = issued
    p = public.params
    identity, message = b"unissued", b"f"*32
    r, s = b"r"*p.salt_bytes, b"s"*p.salt_bytes
    if isinstance(p, SISParams):
        h = hashing.sis_h1(public.context, r, identity, p.n, p.k, p.q)
        u = hashing.sis_h2(public.context, r, s, identity, message, p.n, p.q)
    else:
        from experiments.research.candidates.sageloli.backend import _expand_ring_matrix
        h = _expand_ring_matrix((hashing.rsis_h1(public.context, r, identity, p.k, p.d, p.q),), p.d, p.q)
        u = hashing.rsis_h2(public.context, r, s, identity, message, p.d, p.q)
    f = matrix(ZZ, algebra.hstack(public.a, h))
    # Every selected minor is invertible mod3, hence also mod3^k.
    pivots = f.change_ring(GF(3)).pivots()
    assert len(pivots) == f.nrows()
    coefficients = (f.matrix_from_columns(pivots).change_ring(Zmod(p.q)).inverse()
                    * vector(Zmod(p.q), u))
    z = [0]*f.ncols()
    for index, value in zip(pivots, coefficients):
        z[index] = algebra.centered(value, p.q)
    # Only local teaching test material; no forged object is written/emitted.
    forged = type(backend.sign(key, b"type"))(public.context, r, s, tuple(z))
    assert backend.verify(public, identity, message, forged) is True


@pytest.mark.parametrize("params", [
    lambda: SISParams(r_squared=1),
    lambda: SISParams(n=8, k=16, m=256, q=3**16),
    lambda: RSISParams(d=2), lambda: RSISParams(d=6),
    lambda: RSISParams(d=8),
])
def test_unsupported_sampling_domains_rejected(params):
    with pytest.raises(ValueError):
        params()


def test_salt_entropy_checks_actual_byte_length():
    from array import array
    from experiments.research.candidates.sageloli.backend import _read
    class Invalid:
        def read(self, size):
            return memoryview(array("I", [0]))
    with pytest.raises(SamplingAbort):
        _read(Invalid(), 1)


def test_verify_hash_resource_failure_returns_false(issued, monkeypatch):
    from experiments.research.candidates.sageloli import backend as module
    from experiments.research.candidates.sageloli.uniform import UniformSamplingAbort
    backend, public, _, key = issued
    signature = backend.sign(key, b"resource")
    def abort(*args):
        raise UniformSamplingAbort("injected hash budget exhaustion")
    monkeypatch.setattr(module, "sis_h1" if backend.route == "sis" else "rsis_h1", abort)
    assert backend.verify(public, key.identity, b"resource", signature) is False
