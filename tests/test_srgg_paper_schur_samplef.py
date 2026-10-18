"""Independent coefficient-dense checks of source-order ring sampling."""
from dataclasses import replace

import pytest
pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import ComplexField, QQ, RealField, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry
from experiments.research.candidates.srgg.structured_samplef import SeriesOptions
from experiments.research.candidates.srgg.paper_ring_schur import RingSchurPlan
from experiments.research.candidates.srgg.paper_schur_fourier import FourierSchurPlan, forward, inverse
from experiments.research.candidates.srgg.paper_schur_samplef import PaperSchurSampleF
from experiments.research.candidates.srgg.paper_samplef import WitnessGeometryError


def fixture():
    return StructuredGeometry(4, (((1, -1, 0, 1), (0, 1, 0, -1)),
                                  ((-1, 0, 1, 0), (1, 1, -1, 0))),
                              (160, 192), 120, 3, 9)


def dense_poly(poly, n):
    return matrix(QQ, n, n, lambda i, j: poly[i-j] if i >= j else -poly[n+i-j])


def full_dense(g):
    n, rows, cols = g.degree, g.upper_polynomials, g.lower_polynomials
    v = matrix(QQ, rows*n, cols*n)
    for i, row in enumerate(g.witness):
        for j, poly in enumerate(row):
            v.set_block(i*n, j*n, dense_poly(poly, n))
    t = v.stack(identity_matrix(QQ, cols*n))
    diag = [width for width in g.top_squared+(g.lower_squared,)*cols for _ in range(n)]
    return matrix.diagonal(QQ, diag)-g.noise_squared*t*t.transpose()


def test_fft_sign_twist_and_roundtrip_against_direct_evaluation():
    field, n = ComplexField(384), 8
    values = (3, -2, 7, 0, 1, -4, 5, -8)
    actual = forward(values, field)
    for k, value in enumerate(actual):
        angle = field(0).real().parent().pi()*(2*k+1)/n
        z = field(angle.cos(), angle.sin())
        assert abs(value-sum(values[j]*z**j for j in range(n))) < QQ(1)/2**350
    restored = inverse(actual, field)
    assert max(abs(x-y) for x, y in zip(restored, values)) < QQ(1)/2**350


def test_each_fourier_stage_matches_exact_ring_reference_and_dense_leaf_covariance():
    g = fixture()
    plan = PaperSchurSampleF(g)
    exact = RingSchurPlan(g)
    field = RealField(384)
    for stage, reference, leaf in zip(plan.plan.stages, exact.stages, plan.leaves):
        assert stage.index == reference.index
        for got, expected in zip(stage.gains, reference.gains):
            assert max(abs(got[i]-expected[i]) for i in range(g.degree)) < QQ(1)/2**250
        factor = matrix(field, g.degree, g.degree)
        for j in range(g.degree):
            factor.set_column(j, leaf.factor_apply([int(i == j) for i in range(g.degree)]))
        expected = (dense_poly(reference.pivot, g.degree)-g.rounding_squared*identity_matrix(QQ, g.degree))/(2*field.pi())
        assert max(abs(x) for x in (factor*factor.transpose()-expected).list()) < QQ(1)/2**300
    lower = ((3, -7, 0, 2), (0, 11, -5, 1))
    centers = plan.plan.initial_center(lower)
    reference_centers = exact.initial_center(lower)
    stage, reference = plan.plan.stages[0], exact.stages[0]
    sampled = (7, -13, 9, 1)
    got = plan.plan.update_center(stage, centers, sampled)
    expected = exact.update_center(reference, reference_centers, sampled)
    assert max(abs(a[i]-b[i]) for a, b in zip(got, expected) for i in range(g.degree)) < QQ(1)/2**240


def test_actual_sampler_order_shape_covariance_and_privacy():
    g, field = fixture(), RealField(100)
    plan = PaperSchurSampleF(g)
    assert plan.plan.sampling_order == (1, 0)
    assert plan.plan.output_order == (0, 1)
    seed = b"SRGG-source-Schur-real-draws-v1"
    first = plan.sample(rng=DeterministicRandom(seed))
    assert first == plan.sample(rng=DeterministicRandom(seed))
    assert len(first) == 16 and all(type(x) is int for x in first)
    source = DeterministicRandom(b"SRGG-source-Schur-independent-covariance-v1")
    draws = [plan.sample(rng=source) for _ in range(384)]
    means = [sum(draw[i] for draw in draws)/field(len(draws)) for i in range(16)]
    expected = full_dense(g).change_ring(field)/(2*field.pi())
    for i in range(16):
        assert abs(means[i]) < field(1.3)
    # Lower and cross terms exercise orientation, sign, block order and density
    # conversion. Moments do not distinguish a broad discrete law from its
    # continuous approximation; the discrete-kernel call is checked in code.
    for i, j in ((0, 0), (4, 4), (8, 8), (12, 12), (0, 8), (1, 8), (5, 15)):
        covariance = sum((row[i]-means[i])*(row[j]-means[j]) for row in draws)/len(draws)
        assert abs(covariance-expected[i, j]) < field(4.0)
    cert = plan.public_certificate()
    assert cert["lower_step_is_discrete_gaussian"]
    assert not cert["parameter_widths_changed"]
    assert cert["full_target_integer_tv_upper_including_abort"] is None
    assert not cert["joint_sampler_law_certificate_reused"]
    assert cert["security_claim"] == "none"
    assert "witness" not in cert and "gains" not in cert and "pivot_spectrum" not in cert
    assert all("redacted" in repr(obj) for obj in (plan, plan.plan, *plan.leaves, *plan.plan.stages))
    cert["lower_batch"]["count"] = -1
    assert plan.public_certificate()["lower_batch"]["count"] == 8


@pytest.mark.parametrize("options", [SeriesOptions(max_entropy_bytes=1), SeriesOptions(max_dimension=2)])
def test_resource_gates_fail_during_plan_preparation(options):
    with pytest.raises(ValueError):
        PaperSchurSampleF(fixture(), options=options)


def test_negative_direction_is_distinct_from_inconclusive_and_has_no_fallback(monkeypatch):
    g = replace(fixture(), witness=(((100, 0, 0, 0), (100, 0, 0, 0)),)*2)
    with pytest.raises(WitnessGeometryError, match="negative"):
        PaperSchurSampleF(g)
    from experiments.research.candidates.srgg import paper_schur_fourier
    monkeypatch.setattr(paper_schur_fourier, "_ldl_status", lambda *args: "inconclusive")
    with pytest.raises(ValueError, match="inconclusive") as error:
        PaperSchurSampleF(fixture())
    assert not isinstance(error.value, WitnessGeometryError)


def test_bad_rng_fails_call_instead_of_silently_drawing_again():
    class BrokenSource:
        def __init__(self): self.calls = 0
        def read(self, size):
            self.calls += 1
            return b""
    source = BrokenSource()
    with pytest.raises(ValueError, match="entropy byte"):
        PaperSchurSampleF(fixture()).sample(rng=source)
    assert source.calls == 1
