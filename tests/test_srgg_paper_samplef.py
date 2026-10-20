"""Independent anisotropic operator/covariance checks and actual finite draws."""
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import ComplexIntervalField, QQ, RealField, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.candidates.srgg.paper_samplef import (
    PaperSampleF, PaperScalarOptions, PaperSeriesOptions, WitnessGeometryError)
from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian, WideScalarOptions
from experiments.research.candidates.srgg.paper_samplef import _negacyclic_spectrum
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry
from experiments.research.candidates.srgg.structured_samplef import SeriesOptions


def _geometry(*, top=64, lower=48, noise=9, rounding=9, witness=(1, -1)):
    return StructuredGeometry(2, ((witness,),), (top,), lower, noise, rounding)


def _flat(polynomials):
    return vector(QQ, [p[i] for p in polynomials for i in range(2)])


def _dense():
    v = matrix(QQ, [[1, 1], [-1, 1]])
    t = v.stack(identity_matrix(QQ, 2))
    return matrix.diagonal(QQ, [64, 64, 48, 48])-9*t*t.transpose()


def test_whitened_anisotropic_action_matches_independent_dense_every_basis():
    plan = PaperSampleF(_geometry())
    scales = [scale for scale in plan.diagonal for _ in range(2)]
    inv = matrix.diagonal(QQ, [1/x for x in scales])
    residual = _dense()-9*identity_matrix(QQ, 4)
    h = identity_matrix(QQ, 4)-inv*residual*inv
    assert h.is_symmetric()
    # This fixture exercises the centered interval, including a negative
    # eigenvalue of H. Its factor still reconstructs the unchanged R.
    assert any(x < 0 for x in h.diagonal())
    for j in range(4):
        basis = vector(QQ, [int(i == j) for i in range(4)])
        assert _flat(plan.h_apply((tuple(basis[:2]), tuple(basis[2:])))) == h*basis
    # Anisotropic D does not commute with TT*. This checks the orientation L S,
    # rather than the incorrect S L (or assuming a symmetric factor).
    factor = matrix(QQ, 4, 4)
    for j in range(4):
        basis = [int(i == j) for i in range(4)]
        factor.set_column(j, _flat(plan.residual_factor_apply((tuple(basis[:2]), tuple(basis[2:])))))
    tail = QQ(plan.series["sqrt_series_operator_error_upper"])
    rounding = QQ(plan.series["operator_vector_rounding_l2_error_upper"])
    bound = max(scales)*(tail+rounding)
    error = factor*factor.transpose()-residual
    assert max(abs(x) for x in error.list()) <= 20*max(scales)*bound+4*bound**2
    assert factor != factor.transpose()


def test_actual_same_stream_draws_translation_and_explicit_density_convention():
    seed = b"SRGG-original-anisotropic-independent-draw-v1"
    plan = PaperSampleF(_geometry())
    first = plan.sample(rng=DeterministicRandom(seed))
    assert first == plan.sample(rng=DeterministicRandom(seed))
    offset = (17, -23, 101, -103)
    shifted = PaperSampleF(_geometry(), center=offset).sample(rng=DeterministicRandom(seed))
    assert shifted == tuple(x+y for x, y in zip(first, offset))
    assert len(first) == 4 and all(type(x) is int for x in first)
    certificate = plan.public_certificate()
    assert "Sigma/(2*pi)" in certificate["density_convention"]
    assert not certificate["parameter_widths_changed"]
    assert certificate["witness_redraws"] == 0
    assert not certificate["dense_coefficient_matrix_materialized"]
    assert Fraction(certificate["full_target_integer_tv_upper_including_abort"]) < Fraction(1, 2**24)


def test_fixed_stream_empirical_covariance_checks_nonzero_cross_terms_and_two_widths():
    # This checks an actual finite sampler, not its certificate formulas.
    # Monte Carlo evidence is not a distributional or security proof.
    plan = PaperSampleF(_geometry())
    source = DeterministicRandom(b"SRGG-paper-SampleF-fixed-empirical-covariance-v1")
    draws = [plan.sample(rng=source) for _ in range(1024)]
    field = RealField(100)
    means = [sum(row[i] for row in draws)/field(len(draws)) for i in range(4)]
    expected = _dense().change_ring(field)/(2*field.pi())
    for i in range(4):
        assert abs(means[i]) < field(0.5)
        for j in range(4):
            actual = sum((row[i]-means[i])*(row[j]-means[j]) for row in draws)/len(draws)
            assert abs(actual-expected[i, j]) < field(1.6)


def test_one_secure_rng_draw_and_public_private_diagnostics_boundary():
    plan = PaperSampleF(_geometry(), center=(123457, 0, 0, 0))
    result = plan.sample(rng=SecureRandom())
    assert len(result) == 4 and all(type(x) is int for x in result)
    certificate = plan.public_certificate()
    assert "123457" not in str(certificate) and "123457" not in repr(plan)
    assert "redacted" in repr(plan)
    assert "series" not in certificate and "rho" not in certificate
    certificate["scalar_batch"]["count"] = -1
    assert plan.public_certificate()["scalar_batch"]["count"] == 4
    assert certificate["security_claim"] == "none"
    assert not certificate["parameters_are_formal"] and not certificate["backend_admitted"]


@pytest.mark.parametrize("kwargs", [
    {"center": (0,)}, {"center": (0, 0, 0, 0.5)},
    {"center": (0, 0, 0, True)}, {"center": (0, 0, 0, 2**1024)},
    {"options": SeriesOptions(max_terms=1)},
    {"options": SeriesOptions(max_ring_products=1)},
    {"options": SeriesOptions(max_dimension=2)},
    {"options": SeriesOptions(max_entropy_bytes=1)},
])
def test_invalid_inputs_and_work_budgets_fail_before_drawing(kwargs):
    with pytest.raises(ValueError):
        PaperSampleF(_geometry(), **kwargs)


def test_nonpositive_fixed_witness_is_explicit_not_silently_resampled():
    geometry = _geometry(witness=(100, 0))
    with pytest.raises(WitnessGeometryError, match="certified negative"):
        PaperSampleF(geometry)


def test_negative_schur_pivot_with_positive_diagonals_is_certified():
    # Every original residual diagonal is positive, but the two-column
    # Fourier Schur complement has a negative direction.
    geometry = StructuredGeometry(2, (((1, 0), (1, 0)),), (64,), 48, 20, 9)
    with pytest.raises(WitnessGeometryError, match="certified negative"):
        PaperSampleF(geometry)


def test_inconclusive_bound_is_not_a_license_to_resample_a_witness(monkeypatch):
    from experiments.research.candidates.srgg import paper_samplef
    monkeypatch.setattr(paper_samplef, "_fourier_weighted_bound", lambda *args: QQ(2))
    with pytest.raises(ValueError, match="inconclusive") as caught:
        PaperSampleF(_geometry())
    assert not isinstance(caught.value, WitnessGeometryError)


def test_interval_fft_encloses_independent_horner_at_every_conjugate_pair():
    degree = 16
    geometry = StructuredGeometry(degree, ((tuple(i-8 for i in range(degree)),),),
                                  (2**30,), 2**29, 9, 9)
    poly = geometry.witness[0][0]
    field = ComplexIntervalField(256)
    high = ComplexIntervalField(512)
    received = _negacyclic_spectrum(poly, degree, field)
    for k, value in enumerate(received):
        angle = high.real_field().pi()*QQ(2*k+1)/degree
        root = high(angle.cos(), angle.sin())
        expected = high(0)
        for coefficient in reversed(poly.list()):
            expected = expected*root+coefficient
        assert value.real().lower() <= expected.real().lower() <= expected.real().upper() <= value.real().upper()
        assert value.imag().lower() <= expected.imag().lower() <= expected.imag().upper() <= value.imag().upper()


def test_zero_witness_anisotropic_diagonal_factor_matches_analytic_shapes():
    plan = PaperSampleF(_geometry(witness=(0, 0)))
    field = RealField(300)
    received = _flat(plan.residual_factor_apply(((1, -2), (3, -5))))
    expected = [field(55).sqrt(), -2*field(55).sqrt(), 3*field(30).sqrt(), -5*field(30).sqrt()]
    assert max(abs(field(x)-y) for x, y in zip(received, expected)) < field(2)**-240


def test_malformed_entropy_has_no_fallback_or_witness_retry():
    class ShortSource:
        calls = 0
        def read(self, size):
            self.calls += 1
            return bytes(size-1)
    source = ShortSource()
    with pytest.raises(ValueError, match="byte count"):
        PaperSampleF(_geometry()).sample(rng=source)
    assert source.calls == 1


def test_paper_computational_term_reserve_does_not_change_legacy_options():
    assert PaperSeriesOptions(max_terms=8192).max_terms == 8192
    with pytest.raises(ValueError):
        SeriesOptions(max_terms=1025)
    for kwargs in ({"max_terms": True}, {"max_terms": 8193}, {"ticket_bits": True},
                   {"precision_bits": 128}, {"max_entropy_bytes": 0}):
        with pytest.raises(ValueError):
            PaperSeriesOptions(**kwargs)


def test_paper_scalar_reserve_accepts_long_exact_centers_without_relaxing_legacy():
    center = QQ(1)/2**9000
    ordinary = WideScalarGaussian(1, 1)
    paper = WideScalarGaussian(1, 1, options=PaperScalarOptions())
    with pytest.raises(ValueError):
        ordinary.checked_inputs(1, center)
    assert paper.checked_inputs(1, center)[2] == center
    assert WideScalarOptions().rational_bits == 8192


def test_paper_scalar_reserve_preserves_the_exact_finite_law_for_existing_inputs():
    ordinary = WideScalarGaussian(1, 1)
    paper = WideScalarGaussian(1, 1, options=PaperScalarOptions())
    assert paper.finite_distribution(1, QQ(1)/3) == ordinary.finite_distribution(1, QQ(1)/3)


@pytest.mark.parametrize('kwargs', [dict(rational_bits=True), dict(rational_bits=127),
    dict(rational_bits=32769), dict(max_uniform_trials=0), dict(tail_bits=7)])
def test_paper_scalar_reserve_retains_explicit_resource_gates(kwargs):
    with pytest.raises(ValueError):
        PaperScalarOptions(**kwargs)
