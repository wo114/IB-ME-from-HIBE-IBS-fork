"""Contract test for the WIP Wang-PW numeric sampler (Sage required)."""
import pytest

pytest.importorskip("sage.all")


def test_numeric_block_delegation_n4(capsys):
    from experiments.research.wang_pw_numeric.numeric_gpv_ibs import main

    main(4, 65521)
    out = capsys.readouterr().out
    assert "eq True" in out
