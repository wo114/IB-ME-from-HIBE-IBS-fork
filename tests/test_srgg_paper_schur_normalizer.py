"""The normalizer tilt uses actual TV on independent finite examples."""
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_schur_normalizer import (
    fixed_root_normalizer_certificate, ideal_normalizer_bias,
)
from experiments.research.candidates.srgg.paper_schur_numerical import SchurNumericalAudit
from experiments.research.candidates.srgg.paper_schur_samplef import PaperSchurSampleF
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry


def test_independent_two_point_tilt_stays_below_normalizer_range_bound():
    epsilon = Fraction(1, 10)
    record = ideal_normalizer_bias(dimension=4, stages=2,
                                   relative_normalizer_error=epsilon)
    low, high = (1-epsilon)**2, (1+epsilon)**2
    for mass in (Fraction(1, 10), Fraction(1, 4), Fraction(1, 2), Fraction(3, 4)):
        mean = mass*low+(1-mass)*high
        tilted_low = mass*low/mean
        tv = abs(mass-tilted_low)
        bits = record["ideal_sequential_vs_joint_integer_tv_dyadic_bits"]
        assert tv <= (high-low)/(high+low) <= Fraction(1, 2**bits)


def test_small_exact_geometry_certifies_only_ideal_fixed_root_scope():
    g = StructuredGeometry(4, (((1, -1, 0, 1), (0, 1, 0, -1)),
                                ((-1, 0, 1, 0), (1, 1, -1, 0))),
                           (160, 192), 120, 3, 9)
    audit = SchurNumericalAudit(PaperSchurSampleF(g))
    report = fixed_root_normalizer_certificate(audit)
    assert report["ideal_pivot_density_shape_lower"] == 64
    assert report["ideal_sequential_vs_joint_integer_tv_dyadic_bits"] > 100
    assert report["source_schur_finite_output_tv_upper"] is None
    assert report["bound_scope"] == "every_plan_passing_complete_gate_set"
    assert report["guard_built_into_backend"] is True
    assert report["HNF_key_or_signature_law_certified"] is False


@pytest.mark.parametrize("value", [0, 1, -1, 0.1, True])
def test_missing_or_invalid_relative_error_does_not_certify_bias(value):
    with pytest.raises(ValueError):
        ideal_normalizer_bias(dimension=4, stages=2,
                              relative_normalizer_error=value)
