"""Regression checks for the terminal CHKP leaf path from §5.2."""

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")

from experiments.research import chkp_leaf_audit as audit


def test_terminal_leaf_uses_one_randomized_parent_and_no_second_randbasis(monkeypatch):
    calls = []
    original = audit.CHKPRandBasis

    class CountedRandBasis(original):
        def __init__(self, *args, **kwargs):
            calls.append(1)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(audit, "CHKPRandBasis", CountedRandBasis)
    result = audit.run_attempt("chkp-t2-chain-0", postprocess=True)

    assert result["outcome"] == "leaf_preimage_path_completed"
    assert result["level2_randbasis_calls"] == 0
    assert calls == [1]
    assert result["stages"][0]["level"] == 1
    assert result["stages"][1]["level"] == 2
    assert result["stages"][1]["leaf_preimage_count"] == 2
    assert result["stages"][1]["all_syndromes_exact"] == [True, True]
