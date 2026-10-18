"""Source-boundary counterexamples and exact algebra, not statistical tests."""

import pytest

from experiments.research.candidates.srgg.algebra import Params, PublicRelation, constant
from experiments.research.candidates.srgg.source_correspondence import (
    build_report, hnf_check, source_smoothing_check, zeta_check,
)


@pytest.mark.parametrize("degree", [2, 4, 8])
def test_zeta_factor_two_is_coefficient_space_identity(degree):
    result = zeta_check(degree)
    assert result["zeta_times_star_is_two"]
    assert result["operator_times_transpose_is_two_identity"]
    assert not result["discrete_covariance_claimed"]


def test_hnf_wrap_preserves_equation_but_not_integer_error_difference():
    report = build_report()
    clean, wrap = report["hnf"]["no_wrap_fixture"], report["hnf"]["wrap_fixture"]
    assert clean["integer_head_correction_equals_error"]
    assert not wrap["integer_head_correction_equals_error"]
    assert wrap["centered_reduction_changed_coefficients"] == 2
    assert all(item["exact_relation"] and item["tail_preserved"] and
               item["general_coarse_norm_bound_holds"] for item in (clean, wrap))


def test_hnf_centering_bound_with_exhaustive_signed_scalar_heads():
    p = Params(degree=2, p=5, base=3, digits=1)
    zero = constant(p, 0)
    public = PublicRelation(p, ((zero,),), ((zero,),))
    for value in range(-2*p.modulus, 2*p.modulus+1):
        for error in range(p.p):
            raw = ((value, -value),) + (zero,) * (p.columns-1)
            target = (((value+error) % p.modulus, (-value+error) % p.modulus),)
            checked = hnf_check(public, target, raw, ((error, error),))
            assert checked["exact_relation"]
            assert checked["general_coarse_norm_bound_holds"]
    with pytest.raises(ValueError, match="canonical unsigned"):
        hnf_check(public, (zero,), (zero,)*p.columns, ((-1, 0),))
    with pytest.raises(ValueError, match="approximate extraction"):
        hnf_check(public, ((1, 0),), (zero,)*p.columns, (zero,))


def test_literal_source_smoothing_and_odd_modulus_obstructions():
    report = build_report()
    assert report["paper"]["matches_reviewed_version"]
    for row in report["source_parameter_rows"]:
        assert row["Q_is_odd"] and not row["twice_Q_is_odd"]
        assert not row["literal_Q_gt_2gamma"]
        assert not row["literal_2Q_gt_2gamma"]
    smoothing = source_smoothing_check()
    assert smoothing["epsilon"] == "1/16777216"
    assert smoothing["pi_r_squared_less_than_five"]
    assert smoothing["necessary_smoothing_condition_fails_for_literal_r"]
    assert not report["strong_security_proof_verified"]
    assert not report["full_tv_certificate"]
