"""Structured MP12 research math, finite sampling and fixed issuance controls."""

import json

import pytest
pytest.importorskip("sage.all", reason="use prescribed WSL ~/miniconda3/envs/sage")
from sage.all import QQ, RR, ZZ, matrix, vector, identity_matrix

from ibme.core.randomness import DeterministicRandom
from experiments.research.chkp_basis import gram_schmidt_squared_lengths
from ibme.lattice.matrix_sampling import mp12_structured as tool


class ForbiddenEntropy:
    def __init__(self): self.calls = 0
    def read(self, count):
        self.calls += 1
        raise AssertionError("unexpected sampling during validation/restoration/reuse")


@pytest.fixture(scope="module")
def root():
    return tool.generate_structured_root(2, 257, 16,
        rng=DeterministicRandom(b"structured-tests-real-Gaussian-root"))


@pytest.fixture(scope="module")
def issued(root):
    tail = tuple(tuple((7*i+3*j+5) % root.q for j in range(root.w)) for i in range(root.n))
    state = tool.StructuredDelegator(root)
    key = state.issue(b"Bob", tail, rng=DeterministicRandom(b"structured-tests-real-DelTrap"))
    return state, key, tail


@pytest.mark.parametrize("q", [3, 5, 17, 257, 65537, 2**61-1])
def test_gadget_block_is_complete_and_has_constant_GS_bound(q):
    block = tool.gadget_block(q)
    k = (q-1).bit_length()
    b = matrix(block.basis_rows)
    assert block.public.ncols == k and abs(b.det()) == q
    assert max(gram_schmidt_squared_lengths(b)) <= 5
    assert not any(int(x) % q for x in (matrix(block.public.rows)*b).list())


def test_schur_precision_equals_dense_covariance_and_keeps_cross_terms():
    t = tool.StructuredTrapdoor(1, 5, ((1, 3),), ((1, -1, 2), (0, 1, -1)), 8)
    sampler = tool.StructuredPreimageSampler(t)
    transform = matrix(t.r).stack(identity_matrix(3))
    covariance = sampler.output_squared*identity_matrix(5)-sampler.gadget_squared*transform*transform.transpose()
    correction = matrix(QQ, covariance).inverse()-identity_matrix(QQ, 5)/sampler.output_squared
    assert covariance.det()/QQ(sampler.output_squared)**5 >= QQ(1)/2
    assert sampler.output_squared >= 7*sampler.r_squared*(1+t.frobenius_squared_bound)
    assert QQ(sampler.public_certificate()["public_perturbation_trace_bound_ratio"]) <= QQ(1)/2
    assert any(correction[i, j] for i in range(5) for j in range(i))
    for values in ((0,)*5, (1, 2, -3, 4, -5), (500, -312, 54, 1, -900)):
        v = vector(ZZ, values)
        assert sampler.precision_correction(values) == v.dot_product(correction*v)
    assert sampler.public_certificate()["all_proposal_precision_rational_paths_admitted"]


def test_spherical_output_moment_and_coset_diagnostics():
    # Public toy trapdoor with nonzero covariance cross terms. This check is
    # statistical QA of a fixed test stream, not a distribution proof.
    t = tool.StructuredTrapdoor(1, 17, ((1,),), ((1, -1, 1, -1, 1),), 5)
    sampler = tool.StructuredPreimageSampler(t)
    rng = DeterministicRandom(b"structured-tests-distribution-diagnostic")
    squared = []
    for i in range(128):
        target = i % 17
        x = sampler.sample((target,), rng=rng)
        assert sum(a*b for a, b in zip(t.public.rows[0], x)) % 17 == target
        squared.append(sum(v*v for v in x))
    ratio = RR(sum(squared))*2*RR.pi()/(128*t.dimension*sampler.output_squared)
    assert RR("0.70") < ratio < RR("1.30")


def test_only_shared_gadget_basis_is_expanded(root, monkeypatch):
    original = tool.MatrixFiniteGPV
    seen = []
    def block_only(basis, *args, **kwargs):
        seen.append(basis.public.ncols)
        assert basis.public.nrows == 1 and basis.public.ncols == 9
        return original(basis, *args, **kwargs)
    monkeypatch.setattr(tool, "MatrixFiniteGPV", block_only)
    sampler = tool.StructuredPreimageSampler(root)
    first = sampler.sample((0, 256), rng=DeterministicRandom(b"structured-first-sample"))
    repeated = sampler.sample((0, 256), rng=DeterministicRandom(b"structured-first-sample"))
    assert first == repeated and seen == [9]
    cert = sampler.public_certificate()
    assert cert["expanded_full_kernel_bases"] == 0 and cert["schur_dimension"] == 4
    assert cert["full_sample_TV_or_failure_upper"] is None
    assert cert["security_claim"] == "none" and cert["backend_admitted"] is False


@pytest.mark.parametrize("target", [(1,), (1, 2, 3), (-1, 0), (257, 0), (True, 0), (1.0, 0), "12"])
def test_bad_syndrome_rejected_before_entropy(root, target):
    guard = ForbiddenEntropy()
    with pytest.raises(ValueError):
        tool.StructuredPreimageSampler(root).sample(target, rng=guard)
    assert guard.calls == 0


def test_no_norm_or_width_gate_is_lowered(root):
    with pytest.raises(ValueError, match="norm bound"):
        tool.StructuredTrapdoor(root.n, root.q, root.a_bar, root.r, 0)
    with pytest.raises(ValueError):
        tool.StructuredPreimageSampler(root, r_squared=1)
    with pytest.raises(ValueError):
        tool.StructuredPreimageSampler(root, output_squared=1)
    with pytest.raises(ValueError):
        tool.StructuredTrapdoor(root.n, 256, root.a_bar, root.r, root.frobenius_squared_bound)


def test_actual_Algorithm4_extension_and_fresh_sample(issued, root):
    state, key, tail = issued
    assert key.a_bar == root.public.rows
    assert tuple(tuple(row[root.dimension:]) for row in key.public.rows) == tail
    sampler = tool.StructuredPreimageSampler(key)
    rng = DeterministicRandom(b"structured-delegated-sampling")
    a = sampler.sample((7, 21), rng=rng)
    b = sampler.sample((7, 21), rng=rng)
    assert a != b
    for x in (a, b):
        assert tuple(sum(c*v for c, v in zip(row, x)) % key.q for row in key.public.rows) == (7, 21)


def test_strict_snapshot_and_fixed_reuse_without_sampling(issued, monkeypatch):
    state, key, tail = issued
    root_raw, raw = state.trapdoor.to_bytes(), state.to_bytes()
    def forbidden(*args, **kwargs):
        raise AssertionError("restore/reuse constructed a sampler")
    monkeypatch.setattr(tool, "StructuredPreimageSampler", forbidden)
    restored = tool.StructuredDelegator.from_bytes(raw)
    guard = ForbiddenEntropy()
    assert restored.issue(b"Bob", tail, rng=guard).to_bytes() == key.to_bytes()
    assert restored.to_bytes() == raw and guard.calls == 0
    assert tool.StructuredTrapdoor.from_bytes(root_raw).to_bytes() == root_raw
    changed = tuple(tuple((x+1) % 257 for x in row) for row in tail)
    with pytest.raises(ValueError, match="another extension"):
        restored.issue(b"Bob", changed, rng=guard)
    for malformed in (raw[:-1], raw+b"x", raw+raw, raw.replace(b'"max_addresses":2', b'"max_addresses":2,"max_addresses":2')):
        with pytest.raises(ValueError):
            tool.StructuredDelegator.from_bytes(malformed)


def test_failed_address_persists_and_rejects_entropy_on_reuse(root, issued):
    _, _, tail = issued
    pending = []
    state = tool.StructuredDelegator(root, persist_pending=lambda s: pending.append(s.to_bytes()))
    guard = ForbiddenEntropy()
    with pytest.raises(AssertionError, match="unexpected sampling"):
        state.issue(b"failed", tail, rng=guard)
    assert len(pending) == 1 and guard.calls == 1
    assert state.to_bytes() == pending[0]
    restored = tool.StructuredDelegator.from_bytes(pending[0])
    guard = ForbiddenEntropy()
    with pytest.raises(tool.SamplingAbort, match="no reissue"):
        restored.issue(b"failed", tail, rng=guard)
    assert guard.calls == 0


def test_cross_root_or_bound_cache_tampering_rejected(issued):
    state, _, _ = issued
    record = json.loads(state.to_bytes())
    record["entries"][0]["key"]["frobenius_squared_bound"] += 1
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ValueError, match="binding"):
        tool.StructuredDelegator.from_bytes(raw)


def test_perturbation_exhaustion_propagates_and_never_returns_zero(root, monkeypatch):
    sampler = tool.StructuredPreimageSampler(root, max_trials=1)
    monkeypatch.setattr(sampler, "precision_correction", lambda p: QQ(1000))
    with pytest.raises(tool.SamplingAbort, match="trials exhausted"):
        sampler.sample((1, 2), rng=DeterministicRandom(b"structured-finite-failure"))
    assert sampler.last_trace["status"] == "aborted"
    assert sampler.last_trace["private_entropy_bytes"] > 0


def test_concurrent_same_address_performs_one_real_delegation(root, issued):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    _, _, tail = issued
    state = tool.StructuredDelegator(root)
    barrier = Barrier(2)
    calls = [0, 0]
    def worker(i):
        rng = DeterministicRandom(b"structured-concurrent"+bytes([i]))
        class Counted:
            def read(self, n):
                calls[i] += 1
                return rng.read(n)
        barrier.wait(timeout=10)
        return state.issue(b"same-address", tail, rng=Counted()).to_bytes()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, i) for i in range(2)]
        results = [f.result(timeout=60) for f in futures]
    assert results[0] == results[1]
    assert sorted(x > 0 for x in calls) == [False, True]


@pytest.mark.parametrize("raw", [b'{"x":NaN}', b'{"x":1.0}', b'{} ', b'{"x":1,"x":2}'])
def test_noncanonical_or_noninteger_snapshots_rejected(raw):
    with pytest.raises(ValueError):
        tool.StructuredTrapdoor.from_bytes(raw)


def test_actual_high_dimension_input_screen_has_only_root_role_and_no_entropy(monkeypatch):
    from experiments.research.matrix_structured_parameter_screen import input_row
    def forbidden(*args, **kwargs):
        raise AssertionError("public input screening attempted sampling")
    monkeypatch.setattr(tool.SecureRandom, "read", forbidden)
    monkeypatch.setattr(tool.MatrixFiniteGaussian, "sample", forbidden)
    row = input_row(128, 65537, 529)
    assert row["total_dimension"] == 2432 and row["root_R_entries"] == 557056
    assert row["ciphertext_lwe"] is None and row["root_lwe"]["m"] == 128
    assert row["root_lwe"]["independent_columns"] == 2176
    assert row["root_or_key_generated"] is False and row["entropy_bytes"] == 0
    assert row["finite_R_support_injective_mod_q"]
