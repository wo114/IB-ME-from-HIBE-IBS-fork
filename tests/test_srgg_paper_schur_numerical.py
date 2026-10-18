"""Directed local numerical checks for original-order Schur sampling."""
from dataclasses import replace

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ

from experiments.research.candidates.srgg.paper_ring_schur import RingSchurPlan
from experiments.research.candidates.srgg.paper_schur_numerical import SchurNumericalAudit
from experiments.research.candidates.srgg.paper_schur_samplef import PaperSchurSampleF
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry


def geometry():
    return StructuredGeometry(4, (((1, -1, 0, 1), (0, 1, 0, -1)),
                                  ((-1, 0, 1, 0), (1, 1, -1, 0))),
                              (160, 192), 120, 3, 9)


def test_local_bounds_cover_exact_ring_schur_adaptive_centers():
    sampler = PaperSchurSampleF(geometry())
    audit = SchurNumericalAudit(sampler)
    exact = RingSchurPlan(sampler.geometry)
    lower = ((3, -7, 0, 2), (0, 11, -5, 1))
    approx_centers = sampler.plan.initial_center(lower)
    exact_centers = exact.initial_center(lower)
    assert approx_centers == exact_centers

    # Compare actual adaptive updates against an independent exact-QQ Schur
    # plan, not just against the certificate's own recurrence.
    samples = {1: (7, -13, 9, 1), 0: (4, -2, 6, -3)}
    for approximate, reference, bounds in zip(
            sampler.plan.stages, exact.stages, audit.private_bounds()):
        assert approximate.index == reference.index == bounds["index"]
        sampled = samples[approximate.index]
        approx_centers = sampler.plan.update_center(approximate, approx_centers, sampled)
        exact_centers = exact.update_center(reference, exact_centers, sampled)
        assert len(approx_centers) == len(exact_centers) == len(bounds["center_coefficient_errors_after"])
        for estimate, ideal, error in zip(approx_centers, exact_centers,
                                           bounds["center_coefficient_errors_after"]):
            assert max(abs(estimate[i]-ideal[i]) for i in range(sampler.geometry.degree)) <= error

    public = audit.public_certificate()
    assert public["center_recurrence_covers_all_successful_residuals_within_prepared_envelopes"]
    assert public["full_target_integer_tv_upper_including_abort"] is None
    assert public["finite_fft_arithmetic_all_inputs_error_upper"] is None
    assert public["security_claim"] == "none" and not public["backend_admitted"]
    assert "private" in repr(audit) and "<redacted>" in repr(audit)
    assert "gain_coefficient_errors" not in public
    public["degree"] = -1
    assert audit.public_certificate()["degree"] == 4


def test_explicit_finite_fft_witness_is_bounded_but_not_a_uniform_claim():
    audit = SchurNumericalAudit(PaperSchurSampleF(geometry()))
    for vector in ((1, 0, 0, 0), (3, -2, 7, -5), (QQ(1)/7, 0, -QQ(2)/9, 1)):
        for stage in range(2):
            result = audit.check_factor_application(stage, vector)
            assert result["sampling_stage_index"] == 1-stage
            assert result["scope"] == "one supplied coefficient vector only"
            assert not result["all_vectors_certified"]
            assert result["full_target_integer_tv_upper_including_abort"] is None
    with pytest.raises(ValueError, match="exact rational"):
        audit.check_factor_application(0, (1.0, 0, 0, 0))
    with pytest.raises(ValueError, match="fixed-degree"):
        audit.check_factor_application(0, (1, 0))
    with pytest.raises(ValueError, match="bounded exact integer"):
        audit.check_factor_application(True, (1, 0, 0, 0))


def test_independent_replay_rejects_tampered_prepared_gain_and_factor():
    sampler = PaperSchurSampleF(geometry())
    stage = sampler.plan.stages[0]
    forged_gain = stage.gains[0]+sampler.geometry._ring([QQ(1)/2**16])
    sampler.plan.stages = (replace(stage, gains=(forged_gain,)),)+sampler.plan.stages[1:]
    with pytest.raises(ValueError, match="gain exceeds"):
        SchurNumericalAudit(sampler)

    sampler = PaperSchurSampleF(geometry())
    leaf = sampler.leaves[0]
    leaf.factors = (leaf.factors[0]+leaf.field(1)/2**16,)+leaf.factors[1:]
    with pytest.raises(ValueError, match="factor exceeds"):
        SchurNumericalAudit(sampler)
