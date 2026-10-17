"""Independent exact operators, strict gates, and real structured SampleF draws."""
from dataclasses import replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ, RealIntervalField, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry
from experiments.research.candidates.srgg.structured_samplef import (
    SeriesOptions, StructuredSampleF, series_certificate,
)
from experiments.research.candidates.srgg.wide_scalar import WideScalarOptions


def _geometry(*, witness=(1, -1), top=2**20, target=2**20, noise=4, rounding=64):
    return StructuredGeometry(2, ((witness,),), (top,), target, noise, rounding)


def _plan(**kwargs):
    return StructuredSampleF(_geometry(), bound_kind="cbd1", **kwargs)


def _flat(polynomials):
    return vector(QQ, [poly[i] for poly in polynomials for i in range(2)])


@pytest.mark.parametrize("bound_kind", ["cbd1", "public-norm-cap"])
def test_h_action_matches_independent_negacyclic_block_matrix_for_every_basis(bound_kind):
    kwargs = {"witness_norm_squared_cap": 2} if bound_kind == "public-norm-cap" else {}
    plan = StructuredSampleF(_geometry(), bound_kind=bound_kind, **kwargs)
    # Multiplication by 1-X mod X^2+1, derived directly on (1,X).
    v = matrix(QQ, [[1, 1], [-1, 1]])
    t = v.stack(identity_matrix(QQ, 2))
    expected = QQ(4)/(2**20-64)*t*t.transpose()
    for index in range(4):
        flat = vector(QQ, [int(i == index) for i in range(4)])
        polynomials = (tuple(flat[:2]), tuple(flat[2:]))
        assert _flat(plan.h_apply(polynomials)) == expected*flat
    assert expected.is_symmetric()


def test_sqrt_action_encloses_exact_dense_polynomial_with_reported_rounding_bound():
    plan = _plan()
    v = matrix(QQ, [[1, 1], [-1, 1]])
    t = v.stack(identity_matrix(QQ, 2))
    h = QQ(4)/(2**20-64)*t*t.transpose()
    # Generalized binomial coefficients are obtained independently from Sage.
    from sage.all import binomial
    polynomial = identity_matrix(QQ, 4)
    for j in range(1, plan.terms+1):
        polynomial += binomial(QQ(1)/2, j)*(-h)**j
    flat = vector(QQ, [QQ(-7)/3, QQ(5)/11, 13, -19])
    actual = _flat(plan.sqrt_series_apply((tuple(flat[:2]), tuple(flat[2:]))))
    difference = actual-polynomial*flat
    bound = QQ(plan.public_certificate()["series"]["operator_vector_rounding_l2_error_upper"])
    assert sum(x*x for x in difference) <= bound*bound
    tail = QQ(plan.public_certificate()["series"]["sqrt_series_operator_error_upper"])
    residual = polynomial*polynomial-(identity_matrix(QQ, 4)-h)
    assert max(abs(x) for x in residual.list()) <= 2*tail+tail*tail


def test_zero_witness_reduces_to_independent_analytic_square_root_blocks():
    plan = StructuredSampleF(_geometry(witness=(0, 0)), bound_kind="cbd1")
    actual = _flat(plan.sqrt_series_apply(((1, -2), (3, -5))))
    assert tuple(actual[:2]) == (1, -2)
    intervals = RealIntervalField(768)
    root = (1-intervals(QQ(4)/(2**20-64))).sqrt()
    tail = intervals(QQ(plan.series["sqrt_series_operator_error_upper"]))
    rounding = intervals(QQ(plan.series["operator_vector_rounding_l2_error_upper"]))
    for coefficient, received in zip((3, -5), actual[2:]):
        delta = intervals(received)-coefficient*root
        assert abs(delta).upper() <= (abs(coefficient)*tail+rounding).upper()


def test_real_same_stream_draws_repeat_and_integer_translation_commutes():
    plan = _plan()
    seed = b"srgg-structured-independent-test"
    first = plan.sample(rng=DeterministicRandom(seed))
    assert first == plan.sample(rng=DeterministicRandom(seed))
    assert len(first) == 4 and all(type(x) is int for x in first)
    offset = (17, -23, 101, -103)
    translated = _plan(center=offset).sample(rng=DeterministicRandom(seed))
    assert translated == tuple(x+y for x, y in zip(first, offset))


def test_one_system_random_draw_is_an_integer_vector_without_persisting_output():
    value = _plan().sample(rng=SecureRandom())
    assert len(value) == 4 and all(type(x) is int for x in value)


def test_certificate_is_public_class_only_redacted_and_defensively_copied():
    plan = _plan(center=(123457, 0, 0, 0))
    other = StructuredSampleF(_geometry(witness=(0, 0)), bound_kind="cbd1")
    certificate = plan.public_certificate()
    assert certificate == other.public_certificate()
    assert "redacted" in repr(plan) and "123457" not in repr(plan)
    assert "123457" not in str(certificate)
    certificate["series"]["terms"] = 0
    assert plan.public_certificate()["series"]["terms"] > 0
    assert plan.public_certificate()["series"]["normal_input_further_quantized"]
    assert not certificate["dense_coefficient_matrix_materialized"]
    assert not certificate["legacy_schur_law_equal"]
    assert certificate["security_claim"] == "none"
    assert not certificate["backend_admitted"] and not certificate["parameters_are_formal"]
    assert Fraction(certificate["full_target_integer_tv_upper_including_abort"]) <= Fraction(1, 2**96)


@pytest.mark.parametrize("change", [
    {"precision_bits": True}, {"ticket_bits": 0}, {"ticket_bits": 769},
    {"vector_dyadic_bits": 0}, {"series_error_bits": 513},
    {"max_terms": 1025}, {"max_ring_products": 0},
    {"max_entropy_bytes": 256*1024*1024+1}, {"max_center_bits": 1025},
])
def test_option_resource_constraints_are_exact_and_explicit(change):
    with pytest.raises(ValueError):
        SeriesOptions(**change)


@pytest.mark.parametrize("kwargs", [
    {"center": (0,)}, {"center": (0, 0, 0, 0.25)},
    {"center": (0, 0, 0, True)}, {"center": (0, 0, 0, 2**1024)},
    {"options": SeriesOptions(max_terms=1)},
    {"options": SeriesOptions(max_ring_products=1)},
    {"options": SeriesOptions(max_entropy_bytes=1)},
    {"options": SeriesOptions(max_dimension=2)},
    {"scalar_options": replace(WideScalarOptions(), rational_bits=256)},
])
def test_plan_gates_reject_invalid_centers_and_unaffordable_whole_paths(kwargs):
    with pytest.raises(ValueError):
        _plan(**kwargs)


@pytest.mark.parametrize("geometry,kwargs", [
    (_geometry(top=2**20+1), {"bound_kind": "cbd1"}),
    (_geometry(witness=(2, 0)), {"bound_kind": "cbd1"}),
    (_geometry(witness=(QQ(1)/2, 0)), {"bound_kind": "public-norm-cap", "witness_norm_squared_cap": 1}),
    (_geometry(), {"bound_kind": "cbd1", "witness_norm_squared_cap": 2}),
    (_geometry(), {"bound_kind": "public-norm-cap", "witness_norm_squared_cap": 1}),
    (_geometry(), {"bound_kind": "public-norm-cap", "witness_norm_squared_cap": Fraction(5, 2)}),
    (_geometry(), {"bound_kind": "unknown"}),
    (_geometry(target=128, top=128, noise=63), {"bound_kind": "cbd1"}),
])
def test_declared_public_classes_require_support_and_contraction(geometry, kwargs):
    with pytest.raises(ValueError):
        StructuredSampleF(geometry, **kwargs)


def test_malformed_entropy_source_fails_on_its_first_read_without_fallback():
    class ShortSource:
        calls = 0
        def read(self, size):
            self.calls += 1
            return bytes(size-1)
    source = ShortSource()
    with pytest.raises(ValueError, match="byte count"):
        _plan().sample(rng=source)
    assert source.calls == 1


def test_public_signature_perturbation_fixture_is_explicitly_not_an_ibs_lifecycle():
    from experiments.research.srgg_structured_samplef_execution import execute
    receipt = execute(mode="signature", degree=2, rank=1, digits=1)
    result = receipt["result"]
    assert not result["full_ibs_executed"]
    assert not result["production_randomness"]
    assert result["fixture_norm_squared"] <= int(result["declared_public_user_norm_squared_cap"])
    assert result["certificate"]["dimension"] == 8
    assert len(result["draws"]) == 1 and result["draws"][0]["coefficients"] == 8
    assert receipt["loaded_sources_unchanged_during_run"]
    assert receipt["process_peak_rss_kib"] > 0
    assert "experiments/research/candidates/srgg/structured_samplef.py" in receipt["source_sha256"]
    assert receipt["identity_bytes"] is None and receipt["message_bytes"] is None


@pytest.mark.parametrize("rho", [Fraction(0), Fraction(1), Fraction(2), Fraction(2**40-1, 2**40)])
def test_series_rejects_noncontraction_and_outward_rounding_to_one(rho):
    with pytest.raises(ValueError):
        series_certificate(dimension=4, rho=rho, scale_upper=1, scale_error=0, options=SeriesOptions())
