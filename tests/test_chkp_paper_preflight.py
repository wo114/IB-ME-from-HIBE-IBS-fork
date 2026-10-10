"""Tests for the CHKP paper-parameter preflight, not a security test."""

from experiments.research.chkp_paper_preflight import PaperCandidate, screen_candidate


def test_current_toy_profile_is_retained_as_a_nonformal_negative_baseline():
    report = screen_candidate(PaperCandidate(
        n=1, m=10, q=2, s1_squared=9064, s2_squared=15952640,
    ))
    assert not report["known_static_conditions_passed"]
    assert report["parameters_are_formal"] is False
    assert report["security_claim"] == "none"
    assert not report["paper_relations"]["q_ge_4_s_t_m_t_plus_1"]["level_2_leaf"]["passed"]


def test_candidate_with_known_numeric_conditions_passes_only_static_screen():
    report = screen_candidate(PaperCandidate(
        n=1, m=32, q=1000003, s1_squared=1, s2_squared=1,
    ))
    assert report["known_static_conditions_passed"]
    assert report["dimensions"] == {"root": 32, "level_1": 64, "level_2_leaf": 96}
    assert report["backend_admitted"] is False
    assert report["paper_relations"]["alpha_condition"]["status"] == "not_evaluated"


def test_depth_two_leaf_dimension_cap_rejects_m_over_64():
    report = screen_candidate(PaperCandidate(
        n=1, m=65, q=1000003, s1_squared=1, s2_squared=1,
    ))
    assert not report["known_static_conditions_passed"]
    assert report["implementation_constraints"]["dimension_cap_passed"] is False


def test_composite_q_is_rejected_even_when_size_conditions_pass():
    report = screen_candidate(PaperCandidate(
        n=1, m=32, q=1000000, s1_squared=1, s2_squared=1,
    ))
    assert report["implementation_constraints"]["q_prime"] is False
    assert not report["known_static_conditions_passed"]
