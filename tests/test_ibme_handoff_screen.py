"""Cross-component gates; source constants are read without executing code."""

import pytest

from experiments.research.chkp_paper_preflight import PaperCandidate
from experiments.research.ibme_handoff_screen import minimum_ap09_layout, screen_handoff


def test_paper_only_positive_candidate_still_fails_actual_delivery_gates():
    report = screen_handoff(PaperCandidate(2, 64, 65537, 256, 4096))
    assert report["paper_preflight"]["known_static_conditions_passed"]
    layout = report["minimum_finite_ap09_layout"]
    assert (layout["root_dimension"], layout["leaf_dimension"]) == (173, 519)
    assert layout["hadamard_scale"] == 18
    assert not report["candidate_root_fits_minimum_ap09_layout"]
    assert not report["minimum_ap09_leaf_fits_current_gpv_cap"]
    assert not report["hypothetical_minimum_layout_sufficient_widths"]["same_q_meets_sufficient_leaf_correctness_relation"]
    payload = report["payload_contract"]
    assert payload["seed_bits_lower_bound"] == 256
    assert payload["current_cache_capacity_bits"] == payload["current_leaf_batch_bits"] == 32
    assert not payload["current_single_cache_covers_seed_lower_bound"]
    assert report["security_claim"] == "none" and not report["backend_admitted"]


def test_toy_layout_is_in_range_but_paper_correctness_remains_negative():
    report = screen_handoff(PaperCandidate(1, 10, 2, 9064, 15952640))
    assert report["candidate_root_fits_minimum_ap09_layout"]
    assert report["minimum_ap09_leaf_fits_current_gpv_cap"]
    assert not report["paper_preflight"]["known_static_conditions_passed"]
    widths = report["hypothetical_minimum_layout_sufficient_widths"]
    assert not widths["actual_basis_or_sampling_executed"]
    assert not widths["necessary_width_or_impossibility_claim"]


@pytest.mark.parametrize("bits", [True, 1, 4097, 16.0, "16"])
def test_invalid_error_budget_not_silently_coerced(bits):
    with pytest.raises(ValueError):
        screen_handoff(PaperCandidate(2, 64, 65537, 256, 4096), epsilon_bits=bits)


@pytest.mark.parametrize("n,q", [(1, 2), (2, 65537)])
def test_minimum_layout_matches_delivered_ap09_parameter_constructor(n, q):
    pytest.importorskip("sage.all", reason="constructor comparison needs prescribed WSL Sage")
    from experiments.research.chkp_genbasis import AP09Parameters
    layout = minimum_ap09_layout(n, q)
    params = AP09Parameters(**{key: layout[key] for key in
                               ("n", "q", "random_rows", "m1", "m2", "hadamard_scale")})
    assert params.gs_squared_bound == layout["gs_squared_certificate_upper"]
