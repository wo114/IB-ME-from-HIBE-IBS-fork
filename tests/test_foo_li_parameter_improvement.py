"""Contracts for the Foo-Li parameter-improvement search (research, sage-gated).

The search itself is evidence tooling; these tests pin the core-SVP model's
sanity, the float-window pre-filter's agreement with the exact screen and the
delivered backend gates, and the published evidence artifact's internal
consistency.  Nothing here admits a backend or claims security.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="improvement search requires WSL ~/miniconda3/envs/sage")

from experiments.research.foo_li_parameter_improvement import (
    core_svp_delta, core_svp_sis, exact_case, float_window, in_gate_exhaustive)

EVIDENCE = Path("docs/research/2026-10-19-parameters/fooli-improvement-search.json")


@pytest.mark.parametrize('blocksize,expected', [
    (53, 1.0118866752138085), (100, 1.0092587210363348),
    (500, 1.0034040267850965),
])
def test_root_hermite_factor_matches_published_reference(blocksize, expected):
    # lattice-estimator e4333d9, estimator/reduction.py:72. These are root-
    # Hermite factors; omitting the 1/2 in the exponent squares the factor.
    assert core_svp_delta(blocksize) == pytest.approx(expected, rel=1e-13)


def test_unbracketed_attack_does_not_become_an_exact_cost_at_the_search_cap():
    cost, blocksize, dimension = core_svp_sis(2**127-1, 2048, 780304, 0.01)
    assert cost == float('inf')
    assert blocksize is dimension is None


def test_search_declares_the_backend_parameters_it_does_not_cover():
    from ibme.ibs.foo_li.params import FooLiParams

    # This input shape is legal in the delivered class but absent from the
    # n<=4 / nine-width probe grid. Empty heuristic windows cannot refute it.
    admitted_shape = FooLiParams(q=7, n=5, m_bar=15, user_quality=1_000_000)
    result = in_gate_exhaustive()
    coverage = result['coverage']
    assert admitted_shape.n > coverage['n_max']
    assert admitted_shape.generation_width_squared not in coverage['generation_width_squared']
    assert coverage['all_backend_parameters_covered'] is False
    assert coverage['prefilter_is_rigorous'] is False
    assert result['conclusion'] == 'no_candidate_window_in_declared_grid'


def test_core_svp_model_decreases_in_target_norm_above_the_floor():
    # Raising beta (the SIS norm bound) only helps the attacker, so hardness
    # decreases with log2_beta; far above the reachable norm both sit at the
    # documented b=53 floor.
    at_floor, b_small, _ = core_svp_sis(2**31 - 1, 4, 400, 30.0)
    also_floor, _, _ = core_svp_sis(2**31 - 1, 4, 400, 60.0)
    assert at_floor == also_floor == 0.292 * 52
    assert b_small == 53
    # In the large-n band the model is well above the floor and ordered.
    tighter, _, _ = core_svp_sis(2**127 - 1, 2048, 780304, 61.8)
    looser, _, _ = core_svp_sis(2**127 - 1, 2048, 780304, 78.0)
    assert tighter > looser > at_floor
    quantum, _, _ = core_svp_sis(2**127 - 1, 2048, 780304, 78.0, quantum=True)
    assert quantum < looser


def test_float_window_shuts_the_in_gate_family_even_with_width_lever():
    # The audit family (q=65537, n=1) had no window at the fixed width 16;
    # the generation-width lever must not open one either.
    for g in (16, 2**12, 2**20, 2**28):
        assert float_window(65537, 1, g, 160) is None
    # Oversized dimension families never reach the window stage.
    assert float_window(65537, 4, 2**12, 160) is None


def test_exact_case_rejects_in_gate_points_through_real_backend_gates():
    case = exact_case(65537, 1, 2**12, 34, 160)
    assert not case["analytic_prescreen_pass"]
    assert not case["backend_gates_pass"]
    # The mirror's derived-width gates are a strict superset of the delivered
    # class's input-field gates; agreement is asserted on the shared checks.
    from ibme.ibs.foo_li.params import FooLiParams

    epsilon0 = f"1/{2**160}"

    def build(reject_case):
        return FooLiParams(q=reject_case["q"], n=reject_case["n"],
                           m_bar=reject_case["m_bar"],
                           master_quality=reject_case["master_quality_squared"],
                           user_quality=reject_case["user_quality_squared"],
                           generation_width_squared=reject_case["g"],
                           master_r_squared=reject_case["r_squared"],
                           user_r_squared=reject_case["r_squared"],
                           gamma=5, epsilon0=epsilon0)

    # Derived-width-only failures need not make FooLiParams raise: the class
    # has no s^2/t^2 output gate, so case (width_caps/sigma_cap failures) is
    # accepted by the class while the mirror rejects it.  That documents the
    # superset relationship instead of hiding it.
    build(case)
    with pytest.raises(ValueError):
        # Input quality bounds are shared: m_bar=60 pushes the derived
        # user_quality past 10^12, which both sides must reject.
        shared = exact_case(65537, 1, 2**12, 60, 160)
        assert "quality_caps" in shared["failed_gates"]
        build(shared)


def test_dimension_cap_rejection_agrees_between_mirror_and_backend():
    from ibme.ibs.foo_li.params import FooLiParams

    with pytest.raises(ValueError, match="dimension"):
        FooLiParams(q=65537, n=4, m_bar=120, master_quality=8,
                    user_quality=10**11, generation_width_squared=1,
                    master_r_squared=9, user_r_squared=9, gamma=5,
                    epsilon0=f"1/{2**160}")


def test_published_search_artifact_is_self_consistent():
    if not EVIDENCE.exists():
        pytest.skip("search artifact not generated in this checkout")
    report = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    assert report["security_claim"] == "none"
    assert report["parameters_are_formal"] is False
    assert report['core_svp_model']['delta_exponent'] == '1/(2*(b-1))'
    gate = report["in_gate_search"]
    assert gate['coverage']['all_backend_parameters_covered'] is False
    assert gate['coverage']['prefilter_is_rigorous'] is False
    assert gate["stats"]["k_n_width_probes"] >= 600
    assert gate["stats"]["windows_found"] == 0 == gate["analytic_and_gates_pass"]
    target = report["target_search"]
    assert target["candidates"] == sum(target["by_stage"].values())
    assert target["candidates"] == len(target["all_cases"])
    # The published beyond-gate crossover: >=128-bit core-SVP targets exist
    # only in the large-n band, and every target violates the backend gates.
    assert target["targets_128bit"] >= 1
    for point in target["smallest"]:
        assert point["core_svp_classical_bits"] >= 128
        assert point["failed_gates"]  # never claim backend admission
        assert point["lll_bound_excludes"] is False
