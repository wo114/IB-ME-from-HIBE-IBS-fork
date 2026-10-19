"""Reproduction checks for the SRGG paper's Table 5 Core-SVP estimates."""
import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_core_svp_reproduction import (
    build_report, core_svp_bits, delta_beta, forgery_beta, forgery_rhs,
    key_recovery_beta,
)
from experiments.research.candidates.srgg.paper_profiles import profiles


def test_core_svp_conversion_matches_paper_bits():
    assert core_svp_bits(352)["classical"] == 103
    assert core_svp_bits(352)["quantum"] == 93
    assert core_svp_bits(586)["classical"] == 171
    assert core_svp_bits(586)["quantum"] == 155
    assert core_svp_bits(828)["classical"] == 242
    assert core_svp_bits(828)["quantum"] == 219
    assert 1 < delta_beta(586) < 1.01


def test_key_recovery_and_forgery_betas_are_near_the_author_values():
    for profile in profiles:
        kb, m, d, q, norm = key_recovery_beta(profile)
        fb, fm, fd, modulus, gamma = forgery_beta(profile)
        assert m == profile.rank * profile.degree
        assert d == 2*m + 1
        assert q == profile.Q
        assert fd == ((2 + profile.digits) * profile.rank + 1) * profile.degree
        assert modulus == 2*profile.Q
        assert abs(kb - profile.author_report.key_recovery_bkz) <= 8
        assert abs(fb - profile.author_report.forgery_bkz) <= 4
        assert forgery_rhs(fb, fd, fm, modulus) <= gamma
        assert forgery_rhs(fb-1, fd, fm, modulus) > gamma


def test_param_ii_meets_128_bit_classical_and_quantum_forgery():
    report = build_report()
    rows = {row["profile"]: row for row in report["rows"]}
    selected = rows["PARAM-II"]
    assert selected["forgery_reproduced_classical"] == 171
    assert selected["forgery_reproduced_quantum"] == 155
    assert selected["meets_128_classical_euf_cma"] is True
    assert selected["forgery_reproduced_classical"] >= 128
    assert selected["forgery_reproduced_quantum"] >= 128
    assert rows["PARAM-I"]["meets_128_classical_euf_cma"] is False
    assert report["target"]["selected_meets_target"] is True
    assert report["selected_profile"] == "PARAM-II"


def test_report_keeps_scope_and_known_gaps_explicit():
    report = build_report()
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    gaps = "\n".join(report["known_gaps"])
    assert "q>2*gamma" in gaps
    assert "native strong" in gaps
    assert "NIST" in gaps
    assert "EUF-CMA" in report["target"]["claim"]
    assert report["reproduction_assessment"]["forgery_matches_within_beta"] <= 4
