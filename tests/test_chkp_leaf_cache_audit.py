"""Fresh-process restore and honest audit failure gates (public tiny fixtures)."""

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")

from ibme.core.randomness import DeterministicRandom
from experiments.research import chkp_leaf_cache_audit as audit
from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
from experiments.research.chkp_gpv import CHKPGPVSampler
from experiments.research.chkp_leaf_cache_types import CacheScope, LeafPlan


def test_new_process_restores_without_sampler(monkeypatch):
    def tiny(seed):
        sampler = CHKPGPVSampler(complete_kernel_basis(ModMatrixReference([[1, 0]], 2)),
                                 512, epsilon_bits=16)
        return (sampler, LeafPlan.from_sampler(sampler, [(0,), (1,)]),
                DeterministicRandom(seed.encode("ascii")), CacheScope(b"tiny-public-context", b"rcv", 2, 2))
    monkeypatch.setattr(audit, "prepare", tiny)
    # Running the CLI binds __name__ to __main__; worker module must be explicit.
    monkeypatch.setattr(audit, "__name__", "__main__")
    result = audit.run_attempt("cache-worker-test")
    assert result["outcome"] == "cache_restore_passed"
    assert result["fresh_process_exit"] == 0
    assert result["preimage_count"] == 2 and result["dimension"] == 2
    assert result["fresh_process_identical_snapshot"]
    assert result["repeated_and_restored_vectors_identical"]
    assert not result["private_snapshot_published"]


@pytest.mark.parametrize("fail", [False, True])
def test_gate_keeps_declared_failure_and_never_admits_backend(monkeypatch, fail):
    calls = []
    monkeypatch.setattr(audit, "SEEDS", ("one", "two"))
    def attempt(seed):
        calls.append(seed)
        if seed == "one" and fail:
            raise ValueError("private diagnostic not to publish")
        return {"seed": seed, "outcome": "cache_restore_passed"}
    monkeypatch.setattr(audit, "run_attempt", attempt)
    report = audit.build_report()
    assert calls == ["one", "two"]
    assert report["fixed_cache_gate_passed"] is (not fail)
    assert report["security_claim"] == "none"
    assert not report["backend_admitted"] and not report["T2_complete"] and not report["T3_complete"]
    assert not report["seed_search_or_retry"]
    if fail:
        assert report["attempts"][0] == {"seed": "one", "outcome": "error", "error_type": "ValueError"}
