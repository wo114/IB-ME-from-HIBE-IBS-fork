import os
import shutil
import pytest

from experiments.research.reuse.latte_scalar_probe import source_check,run_probe


def test_pinned_latte_source_fills_but_does_not_read_fresh_box_muller_buffer():
    result=source_check()
    assert result["fresh_box_muller_buffer_filled"]
    assert not result["fresh_box_muller_buffer_read"]
    assert result["reused_comparison_buffer_read"]


def test_real_native_latte_entropy_flow_counterexample(tmp_path):
    if os.name!="posix" or not shutil.which("gcc"):
        pytest.skip("bounded C counterexample runs in WSL; skip is not pass")
    result=run_probe(tmp_path)
    assert result["upstream_ignores_changed_fresh_box_muller_bytes"]
    assert result["buffer_edit_restores_dependence"]
    assert not result["production_patch_admitted"]
