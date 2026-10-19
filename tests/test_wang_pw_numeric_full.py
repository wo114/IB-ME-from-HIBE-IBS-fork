"""End-to-end n=16 regression for the q32 numeric full path."""
import pytest

pytest.importorskip("sage.all")


def test_numeric_full_n16(capsys):
    from experiments.research.wang_pw_numeric.numeric_gpv_np_mp import run

    run(16, workers=4)
    out = capsys.readouterr().out
    assert "'eq': True" in out
    assert "sigma_sign" in out


def test_numeric_full_n16_s0_2(capsys):
    from experiments.research.wang_pw_numeric.numeric_gpv_np_mp import run

    run(16, workers=4, s0=2)
    out = capsys.readouterr().out
    assert "'eq': True" in out
    assert "sigma_sign" in out
