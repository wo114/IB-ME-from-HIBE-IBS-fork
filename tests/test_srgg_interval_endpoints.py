"""Independent enclosures catch Sage's short-rational endpoint approximation.

These compare low-precision implementation bounds with independently computed
higher-precision intervals. They do not test only a helper against itself.
"""
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ, RealIntervalField

from experiments.research.candidates.srgg.paper_parameters import PaperParams, pi_enclosure
from experiments.research.candidates.srgg.paper_samplef import PaperSampleF
from experiments.research.candidates.srgg.sampling_error import smoothing_epsilon
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry
from experiments.research.candidates.srgg.structured_samplef import StructuredSampleF


def _interval(field, value):
    value = Fraction(value)
    return field(value.numerator)/value.denominator


def test_pi_endpoints_have_nonzero_width_and_enclose_independent_1024_bit_pi():
    low, high = pi_enclosure()
    field = RealIntervalField(1024)
    reference = field.pi()
    assert low < high
    assert low.denominator & (low.denominator-1) == 0
    assert high.denominator & (high.denominator-1) == 0
    assert _interval(field, low).upper() < reference.lower()
    assert reference.upper() < _interval(field, high).lower()
    assert high-low < Fraction(1, 2**508)
    convention = PaperParams().numerical_convention()
    assert Fraction(convention["pi_scale_absolute_error_upper"]) > 0
    scale = Fraction(convention["density_scale"])
    # True 2*pi differs from the chosen rational midpoint by <= high-low.
    difference = abs(2*reference-_interval(field, scale))
    assert difference.upper() <= _interval(field, high-low).lower()


def test_structured_scale_nonzero_error_contains_higher_precision_truth():
    geometry = StructuredGeometry(2, (((1, -1),),), (2**20,), 2**20, 4, 64)
    plan = StructuredSampleF(geometry, bound_kind="cbd1")
    error = Fraction(plan.series["scale_absolute_error_upper_exact"])
    assert error > 0
    field = RealIntervalField(1536)
    reference = (field(2**20-64)/(2*field.pi())).sqrt()
    difference = abs(reference-field(plan.scale))
    assert difference.upper() <= _interval(field, error).lower()


def test_paper_scale_nonzero_error_contains_higher_precision_truth():
    geometry = StructuredGeometry(2, (((1, -1),),), (64,), 48, 9, 9)
    plan = PaperSampleF(geometry)
    propagated = Fraction(plan.series["scale_absolute_error_upper_exact"])
    diagonal = max(plan.diagonal)
    exact_diagonal = Fraction(int(diagonal.numerator()), int(diagonal.denominator()))
    error = propagated/(2*exact_diagonal)
    assert error > 0
    field = RealIntervalField(1536)
    reference = 1/(2*field.pi()).sqrt()
    difference = abs(reference-field(plan.scale))
    assert difference.upper() <= _interval(field, error).lower()
    assert plan.public_certificate()["interval_endpoint_conversion"] == "exact binary endpoint rational"


@pytest.mark.parametrize("dimension,width", [(1, 2), (1024, 16), (8704, 64)])
def test_smoothing_return_is_above_independent_high_precision_theta_expression(dimension, width):
    bound = smoothing_epsilon(dimension, width)
    field = RealIntervalField(1536)
    term = (-field.pi()*width).exp()
    theta = 2*term/(1-term**3)
    reference = (1+theta)**dimension-1
    assert field(bound).lower() >= reference.upper()
    assert 0 < bound <= QQ(1)
