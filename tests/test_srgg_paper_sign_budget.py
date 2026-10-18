"""One-attempt entropy accounting and unchanged Algorithm 7 scalar classes."""
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.paper_sign_budget import (
    MAX_BYTES, SCHEMA, signature_attempt_certificate, signature_call_envelope,
)


def test_one_cap_overflow_implies_u_cap_overflow_for_every_history():
    # Independent finite paths, including perturbations that consume less
    # than their hard cap. No independence of these two costs is required.
    p_cap, u_cap = 3, 5
    paths = [(p, u) for p in range(4) for u in range(10)]
    for p, u in paths:
        if p + u > p_cap + u_cap:
            assert u > u_cap
    # This toy joint law deliberately correlates P and U.
    law = {(0, 1): Fraction(1, 4), (3, 8): Fraction(1, 2), (0, 9): Fraction(1, 4)}
    overflow = sum(mass for (p, u), mass in law.items() if p + u > p_cap + u_cap)
    u_overflow = sum(mass for (_, u), mass in law.items() if u > u_cap)
    assert overflow <= u_overflow


def test_call_envelope_is_an_exact_adaptive_union_not_a_lifetime_claim():
    fixture = {"schema": SCHEMA, "admitted": True, "selected_cap_bytes": 17,
        "extra_attempt_cap_abort_upper_exact": "1/1024",
        "u_internal_abort_upper_including_aggregate_exact": "1/512"}
    result = signature_call_envelope(fixture)
    assert result["one_sign_call_hard_cap_bytes"] == 64 * 17
    assert Fraction(result["extra_attempt_cap_abort_union_upper_exact"]) == Fraction(1, 16)
    assert Fraction(result["u_internal_abort_union_upper_exact"]) == Fraction(1, 8)
    assert result["global_service_lifetime_entropy_cap_bytes"] is None
    saturated = signature_call_envelope(fixture, max_attempts=1024)
    assert saturated["u_internal_abort_union_upper_exact"] == "1"


@pytest.mark.parametrize("cap", [True, 0, -1, 1.5, MAX_BYTES + 1])
def test_invalid_perturbation_caps_fail_before_sampler_import_or_entropy(cap):
    with pytest.raises(ValueError):
        signature_attempt_certificate(None, cap, None)


@pytest.mark.parametrize("kwargs", [
    {"max_bytes": 0}, {"max_bytes": MAX_BYTES + 1}, {"max_bytes": True},
    {"error_bits": True}, {"error_bits": 7}, {"error_bits": 513},
])
def test_invalid_attempt_budgets_fail_before_sampler_import_or_entropy(kwargs):
    with pytest.raises(ValueError):
        signature_attempt_certificate(None, 1, None, **kwargs)


@pytest.mark.parametrize("changes", [
    {"schema": "wrong"}, {"admitted": False}, {"selected_cap_bytes": True},
    {"selected_cap_bytes": MAX_BYTES + 1}, {"extra_attempt_cap_abort_upper_exact": "2"},
    {"extra_attempt_cap_abort_upper_exact": "0/0"},
    {"u_internal_abort_upper_including_aggregate_exact": 0.25},
])
def test_call_envelope_rejects_unadmitted_caps_and_invalid_probabilities(changes):
    fixture = {"schema": SCHEMA, "admitted": True, "selected_cap_bytes": 17,
        "extra_attempt_cap_abort_upper_exact": "1/1024",
        "u_internal_abort_upper_including_aggregate_exact": "1/512"}
    fixture.update(changes)
    with pytest.raises(ValueError):
        signature_call_envelope(fixture)


@pytest.fixture(scope="module", params=("table-standard-deviation", "literal-density-width"))
def actual_scalar(request):
    pytest.importorskip("sage.all", reason="actual unchanged scalar constructors require prescribed WSL Sage")
    from experiments.research.candidates.srgg.paper_backend import Backend
    from experiments.research.candidates.srgg.paper_parameters import PaperParams

    class NoEntropy:
        reads = 0
        def read(self, count):
            self.reads += 1
            raise AssertionError("sign-budget preparation must not draw entropy")

    params, source = PaperParams("PARAM-I", request.param), NoEntropy()
    backend = Backend(rng=source)
    _, scalar = backend._components(params)
    return params, scalar, source


def test_real_scalar_batch_total_and_added_failure_are_exact(actual_scalar):
    params, scalar, source = actual_scalar
    perturbation_cap = 12345  # Public hard-cap premise, not a sampled plan.
    result = signature_attempt_certificate(params, perturbation_cap, scalar)
    batch = result["u_batch"]
    assert batch["count"] == result["u_scalar_count"] == 512
    assert result["selected_cap_bytes"] == perturbation_cap + batch["selected_cap_bytes"]
    assert result["admitted"] and result["selected_cap_bytes"] < MAX_BYTES
    assert result["extra_attempt_cap_abort_upper_exact"] == batch["aggregate_budget_abort_upper_exact"]
    assert Fraction(result["extra_attempt_cap_abort_upper_exact"]) <= Fraction(1, 2**192)
    assert result["u_scalar_kernel_tv_including_aggregate_exact"] == batch["scalar_kernel_tv_including_aggregate_exact"]
    assert batch["naive_all_path_bytes"] == 512 * scalar.random_tape_bytes
    call = signature_call_envelope(result)
    old_call_cap = 64 * (perturbation_cap + batch["naive_all_path_bytes"])
    assert old_call_cap > 16_000_000_000
    assert call["one_sign_call_hard_cap_bytes"] < old_call_cap
    assert result["global_service_lifetime_entropy_cap_bytes"] is None
    assert result["all_widths_and_scalar_trial_limits_retained"]
    assert not result["cap_installed_by_this_function"]
    assert not result["norm_retry_failure_and_infrastructure_faults_bounded"]
    assert result["security_claim"] == "none"
    assert not result["backend_admitted"] and not result["parameters_are_formal"]
    assert result["nist_security_category"] is None
    assert source.reads == result["actual_entropy_bytes"] == 0


def test_actual_binary_challenge_zeta_centers_match_the_four_admitted_values(actual_scalar):
    params, scalar, source = actual_scalar
    # Independently expand (1-X^(n/2))*c, using each possible binary pair.
    # The first half includes a plus from wrapping X^n=-1; the second does not.
    centers = {Fraction(-(first + second), 2) for first, second in product((0, 1), repeat=2)}
    centers |= {Fraction(-(second - first), 2) for first, second in product((0, 1), repeat=2)}
    assert centers == {Fraction(-1), Fraction(-1, 2), Fraction(0), Fraction(1, 2)}
    result = signature_attempt_certificate(params, 12345, scalar)
    assert set(map(Fraction, result["u_reachable_centers_exact"])) == centers
    assert source.reads == 0


def test_valid_but_too_large_total_is_not_admitted(actual_scalar):
    params, scalar, source = actual_scalar
    result = signature_attempt_certificate(params, MAX_BYTES, scalar)
    assert not result["admitted"] and result["selected_cap_bytes"] > MAX_BYTES
    with pytest.raises(ValueError, match="admitted"):
        signature_call_envelope(result)
    assert source.reads == 0


def test_wrong_scalar_width_class_is_rejected_before_any_draw(actual_scalar):
    params, scalar, source = actual_scalar
    from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian
    other = WideScalarGaussian(2 * params.r_squared, 2 * params.r_squared, options=scalar.options)
    with pytest.raises(ValueError, match="squared width"):
        signature_attempt_certificate(params, 12345, other)
    assert source.reads == 0
