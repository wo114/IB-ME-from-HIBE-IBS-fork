"""Exact convolution identities and conditional normalizer-TV propagation."""

from fractions import Fraction as F
from itertools import product as cartesian
import json

import pytest

from experiments.research.candidates.srgg.convolution_bridge import (
    bridge_certificate, build_report, c_shape_lower_bound,
    center_normalizer_certificate, normalizer_ratio_tv_upper,
    normalizer_tv_upper, public_cbd1_t_squared_upper,
)


def inverse(matrix):
    n = len(matrix)
    a = [[F(v) for v in row]+[F(i == j) for j in range(n)]
         for i, row in enumerate(matrix)]
    for i in range(n):
        pivot = next(j for j in range(i, n) if a[j][i])
        a[i], a[pivot] = a[pivot], a[i]
        divisor = a[i][i]
        a[i] = [v/divisor for v in a[i]]
        for j in range(n):
            if i != j:
                factor = a[j][i]
                a[j] = [v-factor*w for v, w in zip(a[j], a[i])]
    return tuple(tuple(row[n:]) for row in a)


def transpose(a):
    return tuple(zip(*a))


def multiply(a, b):
    return tuple(tuple(sum(x*y for x, y in zip(row, column))
                       for column in transpose(b)) for row in a)


def add(a, b, factor=1):
    return tuple(tuple(x+factor*y for x, y in zip(row, other))
                 for row, other in zip(a, b))


def eye(n, scale=1):
    return tuple(tuple(F(scale)*int(i == j) for j in range(n)) for i in range(n))


@pytest.mark.parametrize("target,t,noise,s_min,beta", [
    (eye(2, 20), ((1,), (2,)), F(2), F(20), F(5)),
    (((20, 2, 0), (2, 18, 1), (0, 1, 14)),
     ((1, 2), (0, 1), (1, -1)), F(1), F(12), F(8)),
])
def test_woodbury_matches_exact_inverse_with_rectangular_rank_deficient_noise(
        target, t, noise, s_min, beta):
    # TT^T is rank deficient: this deliberately does not call a theorem that
    # requires that second shape to be positive definite.
    m = len(t[0])
    residual = add(target, multiply(t, transpose(t)), -noise)
    direct = inverse(add(eye(m, 1/noise), multiply(
        multiply(transpose(t), inverse(residual)), t)))
    woodbury = add(eye(m, noise), multiply(
        multiply(transpose(t), inverse(target)), t), -noise*noise)
    assert direct == woodbury
    lower = c_shape_lower_bound(noise, s_min, beta)
    difference = add(direct, eye(m, lower), -1)
    if m == 1:
        assert difference == ((0,),)  # spectral bound can attain equality
    else:
        assert difference[0][0] > 0
        assert difference[0][0]*difference[1][1]-difference[0][1]**2 > 0


def test_completed_square_identity_with_nonzero_center_is_exact():
    target = ((20, 2), (2, 15))
    t, noise = ((1,), (2,)), F(2)
    residual = add(target, multiply(t, transpose(t)), -noise)
    c = inverse(add(eye(1, 1/noise), multiply(multiply(transpose(t), inverse(residual)), t)))
    u, x = ((F(3),), (F(-2),)), ((F(4),),)
    mean = multiply(multiply(multiply(c, transpose(t)), inverse(residual)), u)
    perturbation, centered = add(u, multiply(t, x), -1), add(x, mean, -1)
    lhs = multiply(multiply(transpose(perturbation), inverse(residual)), perturbation)[0][0]
    lhs += multiply(transpose(x), x)[0][0]/noise
    rhs = multiply(multiply(transpose(u), inverse(target)), u)[0][0]
    rhs += multiply(multiply(transpose(centered), inverse(c)), centered)[0][0]
    assert lhs == rhs


def test_fractional_shape_is_never_rounded_up_to_a_smoothing_certificate():
    certificate = center_normalizer_certificate(1, F(3, 4))
    assert certificate["lambda_min_lower_floor"] == 0
    assert certificate["relative_error_upper_exact"] is None
    assert certificate["sufficient_smoothing_condition_passes"] is False
    assert center_normalizer_certificate(3, F(17, 8))["integer_shape_used"] == 2


@pytest.mark.parametrize("dimension,squared", [(1, 1), (3, 2), (20, 3)])
def test_theta_bound_dominates_truncated_dual_gaussian_majorant(dimension, squared):
    certificate = center_normalizer_certificate(dimension, squared)
    a = F(1, 2**(4*squared))
    finite_theta = (1+2*sum(a**(k*k) for k in range(1, 8)))**dimension-1
    assert finite_theta <= F(certificate["relative_error_upper_exact"])
    assert certificate["all_centers"] is True


def test_large_dimension_certificate_does_not_claim_a_geometric_sum_when_it_diverges():
    assert center_normalizer_certificate(100, 1)["relative_error_upper_exact"] is None


def test_huge_shape_certificate_is_capped_down_and_stays_json_serializable():
    certificate = center_normalizer_certificate(2**32, 10**15)
    assert certificate["integer_shape_used"] == 1024
    assert F(certificate["relative_error_upper_exact"]) < F(1, 2**256)
    json.dumps(certificate)


@pytest.mark.parametrize("eps_f,eps_c", [(F(0), F(0)), (F(1, 8), F(0)),
                                         (F(0), F(1, 7)), (F(1, 8), F(1, 7))])
def test_symmetric_normalizer_errors_propagate_both_terms(eps_f, eps_c):
    expected = min(F(1), (eps_f+eps_c)/((1-eps_f)*(1-eps_c)))
    assert normalizer_tv_upper(eps_f, eps_c) == expected


def test_tv_bound_covers_exact_final_normalization_for_finite_rational_reweights():
    q = (F(1, 10), F(1, 5), F(7, 10))
    fl, fu, cl, cu = F(7, 8), F(9, 8), F(6, 7), F(8, 7)
    bound = normalizer_ratio_tv_upper(fl, fu, cl, cu)
    # Exhaust all endpoint choices, with a deliberately nonunit E_Q[a].
    nonunit_normalization_seen = False
    for fibers in cartesian((fl, fu), repeat=3):
        for centers in cartesian((cl, cu), repeat=3):
            a = tuple(c/f for c, f in zip(centers, fibers))
            normalizer = sum(probability*factor for probability, factor in zip(q, a))
            nonunit_normalization_seen |= normalizer != 1
            p = tuple(probability*factor/normalizer for probability, factor in zip(q, a))
            actual_tv = sum(abs(x-y) for x, y in zip(p, q))/2
            assert actual_tv <= bound
    assert nonunit_normalization_seen


def test_unknown_fiber_mass_and_custom_witness_caps_do_not_gain_admission():
    arguments = dict(degree=2, rank=1, base=3, digits=1, r_squared=2,
                     master_minimum_squared=400)
    certificate = bridge_certificate(**arguments)
    assert certificate["ideal_raw_to_union_gaussian_tv_upper_exact"] is None
    assert certificate["actual_witness_cap_verified"] is False
    with pytest.raises(ValueError):
        bridge_certificate(**arguments, t_squared_upper=2)
    certificate = bridge_certificate(**arguments, t_squared_upper=2,
        witness_bound_origin="explicit external norm-cap assumption")
    assert certificate["witness_class_bound_derived_here"] is False
    assert certificate["actual_witness_cap_verified"] is False
    assert certificate["C_lambda_min_lower_exact"] == str(F(18)*(400-36)/400)


def test_default_profiles_distinguish_raw_bridge_from_psf_and_security():
    report = build_report()
    assert len(report["profiles"]) == 5
    for row in report["profiles"]:
        assert row["security_claim"] == "none"
        assert row["parameters_are_formal"] is False
        assert row["backend_admitted"] is False
        assert "not exact PSF fiber" in row["reference"]
        assert row["sufficient_residual_positive"] is True
        if row["parameters"]["degree"] == 512:
            assert row["center_normalizer"]["lambda_min_lower_floor"] == 0
            assert row["ideal_raw_to_union_gaussian_tv_upper_exact"] is None
        else:
            assert row["ideal_raw_bridge_has_nontrivial_bound"] is True
    assert json.loads(json.dumps(report))["schema"].endswith("/1")


def test_explicit_larger_shape_margin_can_satisfy_c_smoothing_without_security_claim():
    beta = public_cbd1_t_squared_upper(512, 2, 8)
    row = bridge_certificate(degree=512, rank=2, base=31, digits=8, r_squared=64,
        master_minimum_squared=2*31**2*64*beta, fiber_lower=F(1)-F(1, 2**90),
        fiber_upper=F(1)+F(1, 2**90))
    assert row["center_normalizer"]["sufficient_smoothing_condition_passes"] is True
    assert F(row["ideal_raw_to_union_gaussian_tv_upper_exact"]) < F(1, 2**88)
    assert row["backend_admitted"] is False


@pytest.mark.parametrize("call", [
    lambda: c_shape_lower_bound(True, 20, 5),
    lambda: c_shape_lower_bound(2, 10, 5),
    lambda: c_shape_lower_bound(2.0, 20, 5),
    lambda: center_normalizer_certificate(True, 4),
    lambda: center_normalizer_certificate(3, F(-1)),
    lambda: center_normalizer_certificate(3, 4, 257),
    lambda: normalizer_tv_upper(F(1), F(0)),
    lambda: normalizer_tv_upper(F(0), F(2)),
    lambda: normalizer_ratio_tv_upper(0, 1, 1, 1),
    lambda: normalizer_ratio_tv_upper(2, 1, 1, 1),
    lambda: normalizer_ratio_tv_upper(1, 1, 2, 1),
    lambda: normalizer_tv_upper(F(1 << 32768), F(0)),
])
def test_invalid_or_inexact_inputs_are_rejected(call):
    with pytest.raises(ValueError):
        call()
