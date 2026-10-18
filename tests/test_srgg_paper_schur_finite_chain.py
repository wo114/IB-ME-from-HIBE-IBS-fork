"""Fixed-root finite source-Schur versus exact Algorithm 3--4 chain bounds."""

from dataclasses import replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ, ComplexField, RealField

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_samplef import PaperSeriesOptions
from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend
from experiments.research.candidates.srgg.paper_schur_finite_chain import (
    _dyadic_bits, fixed_root_finite_chain_certificate,
)
from experiments.research.candidates.srgg.paper_schur_numerical import SchurNumericalAudit
from experiments.research.candidates.srgg.paper_schur_samplef import PaperSchurSampleF
from experiments.research.candidates.srgg.structured_samplef import SeriesOptions
from experiments.research.candidates.srgg.structured_geometry import StructuredGeometry
from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian


def _geometry(*, fractional_witness=False):
    first = QQ(1)/2 if fractional_witness else 1
    return StructuredGeometry(4, (((first, -1, 0, 1), (0, 1, 0, -1)),
                                  ((-1, 0, 1, 0), (1, 1, -1, 0))),
                              (160, 192), 120, 3, 9)


@pytest.fixture(scope="module")
def audited():
    return SchurNumericalAudit(PaperSchurSampleF(_geometry()))


def test_exact_dyadic_upper_rounds_outward():
    assert _dyadic_bits(Fraction(1, 2**80)) == 80
    assert _dyadic_bits(Fraction(1, 2**80)+Fraction(1, 2**200)) == 79
    assert _dyadic_bits(Fraction(3, 8)) == 1
    with pytest.raises(ValueError, match="subunit"):
        _dyadic_bits(Fraction(0))


def test_local_all_ticket_chain_bound_is_nontrivial_and_narrow(audited):
    result = fixed_root_finite_chain_certificate(audited)
    assert result["degree"] == 4 and result["upper_leaf_count"] == 2
    assert result["finite_vs_exact_algorithm34_tv_dyadic_upper"] == "2^-80"
    assert result["all_midpoint_tickets_covered"]
    assert result["normal_ticket_invariant_abort_upper"] == "0"
    assert result["leaf_noise_and_output_invariant_abort_upper"] == "0"
    assert result["scalar_magnitude_checked_inputs_abort_upper"] == "0"
    assert result["scalar_rational_bit_abort_upper"] != "0"
    assert result["aggregate_and_scalar_abort_included_in_batch_tv"]
    assert result["accepted_setup_root_distribution_bound"] is None
    assert result["finite_vs_joint_integer_gaussian_tv_upper"] is None
    assert result["security_claim"] == "none"
    assert not result["backend_admitted"] and not result["parameters_are_formal"]


def test_stale_factor_and_changed_profile_cannot_reuse_audit(audited):
    sampler = audited.sampler
    leaf = sampler.leaves[0]
    original = leaf.factors
    try:
        leaf.factors = (original[0]+leaf.field(1)/2**16,)+original[1:]
        with pytest.raises(ValueError, match="factor exceeds|factor changed"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        leaf.factors = original
    old_stages = sampler.plan.stages
    try:
        stage = old_stages[0]
        gain = stage.gains[0]+sampler.geometry._ring([QQ(1)/2**16])
        sampler.plan.stages = (replace(stage, gains=(gain,)),)+old_stages[1:]
        with pytest.raises(ValueError, match="gain exceeds"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        sampler.plan.stages = old_stages
    old_options = sampler.options
    try:
        sampler.options = replace(old_options, ticket_bits=256)
        with pytest.raises(ValueError, match="B512/P768"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        sampler.options = old_options


def test_rational_witness_does_not_inherit_integer_center_gate():
    audit = SchurNumericalAudit(PaperSchurSampleF(_geometry(fractional_witness=True)))
    with pytest.raises(ValueError, match="integer witness"):
        fixed_root_finite_chain_certificate(audit)


def test_backend_dyadic_256_profile_is_admitted():
    options = SeriesOptions(vector_dyadic_bits=256)
    audit = SchurNumericalAudit(PaperSchurSampleF(_geometry(), options=options))
    result = fixed_root_finite_chain_certificate(audit)
    assert result["finite_vs_exact_algorithm34_tv_dyadic_bits"] >= 79


def test_leaf_runtime_components_cannot_diverge_from_audited_parent(audited):
    sampler, leaf = audited.sampler, audited.sampler.leaves[0]
    old_field, old_options, old_scalar = leaf.field, leaf.options, leaf.scalar
    try:
        leaf.field = ComplexField(192)
        with pytest.raises(ValueError, match="leaf field/options"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        leaf.field = old_field
    try:
        leaf.field = RealField(768)
        with pytest.raises(ValueError, match="leaf field/options"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        leaf.field = old_field
    try:
        leaf.options = replace(old_options, ticket_bits=256)
        with pytest.raises(ValueError, match="leaf field/options"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        leaf.options = old_options
    try:
        leaf.scalar = WideScalarGaussian(sampler.geometry.rounding_squared,
                                         sampler.geometry.rounding_squared)
        with pytest.raises(ValueError, match="leaf field/options"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        leaf.scalar = old_scalar


def test_parent_caps_and_scalar_field_cannot_change_after_preparation(audited):
    sampler = audited.sampler
    old_bytes = sampler.ticket_bytes
    try:
        sampler.ticket_bytes -= 64
        with pytest.raises(ValueError, match="entropy caps"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        sampler.ticket_bytes = old_bytes
    scalar, old_field = sampler.rounding_scalar, sampler.rounding_scalar.field
    try:
        from sage.all import RealIntervalField
        scalar.field = RealIntervalField(96)
        with pytest.raises(ValueError, match="scalar parameter/field"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        scalar.field = old_field
    try:
        scalar.field = RealField(scalar.options.precision_bits)
        with pytest.raises(ValueError, match="scalar parameter/field"):
            fixed_root_finite_chain_certificate(audited)
    finally:
        scalar.field = old_field


def test_real_table4_backend_profile_binds_and_rejects_low_precision_leaf():
    profile, interpretation = "PARAM-I", "table-standard-deviation"
    params = PaperParams(profile, interpretation)
    seed = ("paper-baseline-"+profile+"-"+interpretation).encode("ascii")
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    _, master = backend.setup(params)
    sampler = backend._master_plan(params, master.witness)
    assert type(sampler.options) is PaperSeriesOptions
    assert sampler.options.vector_dyadic_bits == 256
    audit = SchurNumericalAudit(sampler)
    certificate = fixed_root_finite_chain_certificate(audit)
    assert certificate["degree"] == 512
    assert certificate["finite_vs_exact_algorithm34_tv_dyadic_bits"] >= 70
    leaf, old_field = sampler.leaves[0], sampler.leaves[0].field
    try:
        leaf.field = ComplexField(192)
        with pytest.raises(ValueError, match="leaf field/options"):
            fixed_root_finite_chain_certificate(audit)
    finally:
        leaf.field = old_field
