"""Preimage-only leaf gate, preserved failure controls, no HIBE claims."""

from dataclasses import fields
import hashlib
import json

import pytest
pytest.importorskip("sage.all", reason="Run in prescribed WSL Sage; skip is not pass")
from sage.all import ZZ, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research import chkp_leaf_audit as audit
from experiments.research import chkp_leaf_reference as leafref
from experiments.research import chkp_width_audit as old
from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.gaussian_reference import SamplingAbort


@pytest.fixture
def small_sampler():
    basis = complete_kernel_basis(ModMatrixReference([[1, 0]], 2))
    return CHKPGPVSampler(basis, 512, epsilon_bits=16)


@pytest.mark.parametrize("seed", audit.SEEDS)
def test_leaf_path_passes_without_second_randbasis(seed, monkeypatch):
    calls = []
    original = audit.CHKPRandBasis
    def guarded(sampler, **kw):
        calls.append(sampler.dimension)
        assert sampler.dimension == 20, "Leaf must never invoke RandBasis"
        return original(sampler, **kw)
    monkeypatch.setattr(audit, "CHKPRandBasis", guarded)
    result = audit.run_attempt(seed)
    assert result["outcome"] == "leaf_preimage_path_completed"
    assert calls == [20]
    assert [s["width_squared"] for s in result["stages"]] == ["9064", "15952640"]
    leaf = result["stages"][1]
    assert leaf["all_syndromes_exact"] == [True, True]
    assert leaf["leaf_integer_count"] == 60 and leaf["leaf_preimage_count"] == 2
    assert not leaf["leaf_basis_retained"] and not leaf["norm_filter_applied"]
    assert leaf["observed_norms_within_reference"]
    assert leaf["leaf_batch_tape_bytes"] == 18812800
    assert leaf["counterfactual_randbasis_tape_bytes"] > leaf["leaf_batch_tape_cap_bytes"]


def test_exact_same_rng_prefix_as_old_rejected_path(monkeypatch):
    sources = []
    class Tracked:
        def __init__(self, seed):
            self.rng, self.digest, self.count = DeterministicRandom(seed), hashlib.sha256(), 0
            sources.append(self)
        def read(self, n):
            data = self.rng.read(n)
            self.digest.update(n.to_bytes(8, "big") + data)
            self.count += n
            return data
    monkeypatch.setattr(old, "DeterministicRandom", Tracked)
    monkeypatch.setattr(audit, "DeterministicRandom", Tracked)
    previous = old.run_attempt(audit.SEEDS[0], postprocess=True)
    current = audit.run_attempt(audit.SEEDS[0])
    assert previous["stopped_at"] == "level_2_RandBasis"
    assert current["outcome"] == "leaf_preimage_path_completed"
    assert sources[0].count == sources[1].count
    assert sources[0].digest.digest() == sources[1].digest.digest()
    for lhs, rhs in zip(previous["stages"], current["stages"]):
        for field in ("input_algebra", "width_squared", "SampleD", "all_syndromes_exact"):
            assert lhs[field] == rhs[field]


@pytest.mark.parametrize("seed", audit.SEEDS)
def test_omission_does_not_fix_unreduced_basis(seed):
    result = audit.run_attempt(seed, postprocess=False)
    assert result["outcome"] == "admission_rejected"
    assert result["stopped_at"] == "level_2_SampleD_admission"


def test_batch_returns_only_vectors_and_public_context(small_sampler):
    leaf = leafref.sample_leaf_preimages(small_sampler, [(0,), (1,), (1,)],
                                       rng=DeterministicRandom(b"leaf-batch"))
    assert {f.name for f in fields(leaf)} == {"public", "targets", "preimages", "security_claim", "backend_admitted"}
    for y, x in zip(leaf.targets, leaf.preimages):
        assert tuple(int(v) % 2 for v in matrix(ZZ, leaf.public.rows)*vector(ZZ, x)) == y
    assert "preimages=" not in repr(leaf)
    assert leaf.security_claim == "none" and not leaf.backend_admitted


@pytest.mark.parametrize("targets", [[], None, "x", [(0,)]*33, [()], [(0, 1)],
                                          [(True,)], [(1.0,)], [(-1,)], [(2,)], [(0,), (2,)]])
def test_bad_targets_rejected_before_any_sampling(small_sampler, targets, monkeypatch):
    def forbidden(*args, **kw):
        raise AssertionError("Bad input consumed sampling")
    monkeypatch.setattr(small_sampler, "sample", forbidden)
    with pytest.raises(leafref.LeafAdmissionError):
        leafref.sample_leaf_preimages(small_sampler, targets)


def test_batch_budget_not_relaxed_and_checked_before_sampling(small_sampler, monkeypatch):
    monkeypatch.setattr(small_sampler, "random_tape_bytes", leafref.MAX_LEAF_TAPE_BYTES//2+1)
    monkeypatch.setattr(small_sampler, "sample", lambda *a, **k: pytest.fail("budget bypass"))
    with pytest.raises(leafref.LeafAdmissionError, match="tape exceeds"):
        leafref.sample_leaf_preimages(small_sampler, [(0,), (1,)])


def test_zero_is_not_rejected(small_sampler, monkeypatch):
    monkeypatch.setattr(small_sampler, "sample", lambda *a, **k: (0, 0))
    assert leafref.sample_leaf_preimages(small_sampler, [(0,)]).preimages == ((0, 0),)


def test_math_defect_not_swallowed(small_sampler, monkeypatch):
    monkeypatch.setattr(small_sampler, "sample", lambda *a, **k: (0, 0))
    with pytest.raises(ArithmeticError, match="equation"):
        leafref.sample_leaf_preimages(small_sampler, [(1,)])


def test_abort_no_retry_or_partial_return(small_sampler, monkeypatch):
    calls = []
    def sample(y, **kw):
        calls.append(y)
        if len(calls) == 2:
            raise SamplingAbort("forced leaf abort")
        return (0, 0)
    monkeypatch.setattr(small_sampler, "sample", sample)
    with pytest.raises(SamplingAbort, match="forced leaf"):
        leafref.sample_leaf_preimages(small_sampler, [(0,), (1,)])
    assert len(calls) == 2


def test_lll_abort_not_hidden(monkeypatch):
    def fail(*args, **kw):
        raise SamplingAbort("forced LLL abort")
    monkeypatch.setattr(audit, "reduce_basis", fail)
    result = audit.run_attempt(audit.SEEDS[0])
    assert result["outcome"] == "explicit_abort" and result["stopped_at"] == "level_1_LLL"


@pytest.mark.parametrize("dimension,level", [(20, 1), (30, 2)])
def test_bad_rng_is_execution_error_not_admission(monkeypatch, dimension, level):
    original = CHKPGPVSampler.sample
    calls = []
    class ShortRead:
        def read(self, n):
            calls.append(n)
            return b""  # real scalar sampler rejects this malformed source
    def broken(self, y, *, rng=None):
        return original(self, y, rng=ShortRead() if self.dimension == dimension else rng)
    monkeypatch.setattr(CHKPGPVSampler, "sample", broken)
    result = audit.run_attempt(audit.SEEDS[0])
    assert result["outcome"] == "execution_error"
    assert result["stopped_at"] == f"level_{level}_SampleD_execution"
    assert "Random source" in result["reason"] and len(calls) == 1


def test_randbasis_execution_valueerror_not_admission(monkeypatch):
    def fail(*a, **kw):
        raise ValueError("forced execution error")
    monkeypatch.setattr(audit.CHKPRandBasis, "sample", fail)
    result = audit.run_attempt(audit.SEEDS[0])
    assert result["outcome"] == "execution_error"
    assert result["stopped_at"] == "level_1_RandBasis_execution"


def test_leaf_batch_admission_classified_separately(monkeypatch):
    monkeypatch.setattr(leafref, "MAX_LEAF_TAPE_BYTES", 1)
    result = audit.run_attempt(audit.SEEDS[0])
    assert result["outcome"] == "admission_rejected"
    assert result["stopped_at"] == "level_2_LeafBatch_admission"


@pytest.mark.parametrize("passed,code", [(True, 0), (False, 2)])
def test_cli_exit_is_scoped_to_sampling_not_T2(monkeypatch, capsys, passed, code):
    monkeypatch.setattr(audit, "build_report", lambda: {
        "counts": {}, "declared_leaf_sampling_gate_passed": passed, "T2_complete": False})
    monkeypatch.setattr("sys.argv", ["chkp_leaf_audit"])
    assert audit.main() == code
    assert not json.loads(capsys.readouterr().out)["T2_complete"]
