"""Checks of certificate arithmetic and scope, not empirical security tests."""
from dataclasses import replace
import json

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage is required")
from sage.all import QQ, RealIntervalField

from experiments.research.candidates.srgg import sampling_error as se
from experiments.research.candidates.srgg.full_sampling import FullSamplingOptions, prepare_f


def test_numerical_bound_remains_nontrivial_for_actual_large_public_envelope():
    result = se.numerical_rounding_bound(8, 2**37, FullSamplingOptions())
    assert 0 < QQ(result["numerical_to_ideal_rounding_tv_upper"]) < QQ(1)/10000
    assert result["continuous_intermediate_tv"].startswith("1 ")


def test_selected_proof_parameter_minimizes_the_exact_public_bound():
    opts = FullSamplingOptions()
    best = se.numerical_rounding_bound(4, 2**20, opts)
    bound = QQ(best["numerical_to_ideal_rounding_tv_upper"])
    assert all(bound <= QQ(se.numerical_rounding_bound(4, 2**20, opts, bad_bits=t)[
        "numerical_to_ideal_rounding_tv_upper"]) for t in range(1, opts.ticket_bits+1))


def test_more_ticket_and_precision_bits_reduce_the_bound():
    opts = FullSamplingOptions()
    def bound(o):
        return QQ(se.numerical_rounding_bound(8, 2**37, o)["numerical_to_ideal_rounding_tv_upper"])
    assert bound(replace(opts, ticket_bits=192, precision_bits=256)) < bound(opts)
    # With the same tickets only the numerical term improves.
    assert bound(replace(opts, precision_bits=256)) <= bound(opts)


@pytest.mark.parametrize("dimension,envelope,t", [(0, 4, 2), (129, 4, 2), (True, 4, 2),
                                                  (2, 0, 2), (2, 4, 0), (2, 4, 129)])
def test_bad_public_classes_fail(dimension, envelope, t):
    with pytest.raises(ValueError):
        se.numerical_rounding_bound(dimension, envelope, FullSamplingOptions(), bad_bits=t)


def test_directed_dyadic_rounding_never_loses_a_positive_bound():
    for value in [QQ(0), QQ(1)/2**700, QQ(1)/3, QQ(1), QQ(2)]:
        actual = se._upper(value)
        assert min(value, 1) <= actual <= min(value+QQ(1)/2**se.CERTIFICATE_BITS, 1)


def test_smoothing_bound_covers_shortest_dual_vectors_and_improves_with_width():
    f = RealIntervalField(512)
    narrow, wide = se.smoothing_epsilon(8, 4), se.smoothing_epsilon(8, 16)
    shortest_lower = QQ((16*(-4*f.pi()).exp()).lower())
    assert shortest_lower < narrow < QQ(1)/1000
    assert 0 < wide < narrow
    assert se.smoothing_epsilon(1, 4) < narrow


def test_large_rounding_width_uses_monotone_envelope_without_underflow():
    assert 0 < se.smoothing_epsilon(100000, 10**12) == se.smoothing_epsilon(100000, 128)


def test_peikert_term_is_not_erased_by_more_arithmetic_precision():
    opts = FullSamplingOptions()
    ordinary = se.sample_f_class(2, 64, 4, opts)
    precise = se.sample_f_class(2, 64, 4, replace(opts, precision_bits=256))
    assert ordinary["ideal_rounding_to_target_discrete_gaussian_tv_upper"] == precise[
        "ideal_rounding_to_target_discrete_gaussian_tv_upper"]
    assert QQ(ordinary["ideal_rounding_to_target_discrete_gaussian_tv_upper"]) > 0


def test_real_plan_and_certificate_compare_the_same_public_shape_class():
    opts = FullSamplingOptions()
    plan = prepare_f(((64, -12), (-12, 32)), (QQ(1)/3, QQ(-2)/5), 4, options=opts)
    cert = se.sample_f_class(2, 64, 4, opts)
    public = plan.public_certificate()
    assert QQ(cert["rounding_scalar_tv_upper_including_abort"]) >= QQ(public[
        "rounding_scalar_tv_upper_including_abort"])
    assert public["full_target_tv_upper_including_abort"] is None
    assert cert["target"].endswith("uniformly in exact center")


def test_schur_normalizer_bias_is_explicit_and_increases_with_blocks():
    opts = FullSamplingOptions()
    one = se.sample_p_class(2, 2, 64, 4, opts)
    many = se.sample_p_class(8, 2, 64, 4, opts)
    assert 0 < QQ(one["ideal_schur_chain_partition_bias_tv_upper"]) < QQ(many[
        "ideal_schur_chain_partition_bias_tv_upper"])
    with pytest.raises(ValueError):
        se.sample_p_class(7, 2, 64, 4, opts)


def test_lifecycle_report_does_not_upgrade_reference_or_export_private_shape():
    result = se.build_report()
    assert not result["raw_extraction_convolution_identified"]
    assert not result["hnf_exact_preimage_distribution_identified"]
    assert not result["signature_output_gaussian_identified"]
    assert not result["strong_unforgeability_established"]
    assert result["security_claim"] == "none"
    assert not result["parameters_are_formal"] and not result["backend_admitted"]
    assert 0 < QQ(result["sign_attempt_vs_sequential_ideal_sampler_tv_upper_including_abort"]) < 1
    encoded = json.dumps(result)
    for forbidden in ['"private_shape"', '"center"', '"factor"', '"seed"', '"signature"']:
        assert forbidden not in encoded
