"""Real paper-plan binding, without sampling or claiming setup reproduction.

The all-zero CBD1-support witness is a deliberate public fixture. It tests
actual PARAM-I/Sage plan construction and certificate binding, not a draw
from the paper's setup distribution or an IBS lifecycle.
"""
from dataclasses import replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_backend import Backend
from experiments.research.candidates.srgg.paper_issuance_bridge import issuance_certificate
from experiments.research.candidates.srgg.paper_parameters import PaperParams
from experiments.research.candidates.srgg.paper_samplef import PaperSampleF
from experiments.research.candidates.srgg.structured_geometry import signature_operator


class NoEntropy:
    reads = 0

    def read(self, count):
        self.reads += 1
        raise AssertionError("binding fixtures must not draw entropy")


@pytest.fixture(scope="module")
def prepared():
    params, source = PaperParams("PARAM-I"), NoEntropy()
    backend = Backend(rng=source)
    witness = tuple(tuple((0,) * params.degree for _ in range(params.rank * params.digits))
                    for _ in range(2 * params.rank))
    plan = backend._master_plan(params, witness)
    gadget, _ = backend._components(params)
    assert source.reads == 0
    return params, backend, plan, gadget, source


def test_actual_param_i_zero_support_plan_keeps_exact_sage_shape(prepared):
    params, _, plan, gadget, source = prepared
    # This Sage rational must not be passed directly to Python Fraction:
    # the designated runtime can retain bound methods instead of integers.
    sage_shape = plan.geometry.rounding_squared
    assert callable(sage_shape.numerator) and callable(sage_shape.denominator)
    expected_shape = Fraction(int(sage_shape.numerator()), int(sage_shape.denominator()))
    assert expected_shape == params.r_squared
    result = issuance_certificate(params, plan, gadget)
    assert Fraction(result["tight_rounding_theta"]["density_shape_lower_exact"]) == expected_shape
    assert result["perturbation_sampler"]["dimension"] == params.columns * params.degree
    assert result["c_gate"]["dimension"] == params.rank * params.digits * params.degree
    assert result["c_gate"]["certified"] and result["certified"]
    assert 0 < Fraction(result["complete_law_tv_upper_including_abort"]) < 1
    assert result["gadget_fiber_bias_counted_once"] and result["no_extra_hnf_or_tail_tv_cost"]
    assert not result["finite_object_guards_verified_by_this_function"]
    assert not result["trapdoor_public_relation_verified_by_this_function"]
    assert result["requires_valid_fixed_public_root_relation"]
    assert result["law_space"] == "mathematical_vectors_plus_abort"
    assert not result["all_setup_roots_certified"] and not result["full_signature_law_certified"]
    assert result["sampler_draws"] == result["root_redraws"] == source.reads == 0
    assert result["security_claim"] == "none"
    assert not result["backend_admitted"] and not result["parameters_are_formal"]
    assert result["nist_security_category"] is None


def test_actual_other_parameter_and_gadget_objects_cannot_relabel_plan(prepared):
    params, backend, plan, gadget, source = prepared
    other = PaperParams("PARAM-II")
    other_gadget, _ = backend._components(other)
    with pytest.raises(ValueError, match="original master shape"):
        issuance_certificate(other, plan, other_gadget)
    with pytest.raises(ValueError, match="original master shape"):
        issuance_certificate(params, plan, other_gadget)
    assert gadget.params == params and source.reads == 0


def test_prepared_changed_master_target_is_rejected(prepared):
    params, backend, plan, gadget, source = prepared
    # This is a valid prepared Gaussian plan at a different target shape,
    # rather than an invalid object or a forged certificate dictionary.
    changed = replace(plan.geometry, top_squared=tuple(2 * value for value in plan.geometry.top_squared))
    alternate = PaperSampleF(changed, options=backend.series_options, scalar_options=backend.scalar_options)
    with pytest.raises(ValueError, match="original master shape"):
        issuance_certificate(params, alternate, gadget)
    assert source.reads == 0


def test_prepared_signature_geometry_cannot_be_used_as_issuance(prepared):
    params, backend, _, gadget, source = prepared
    # The zero user vector is an operator fixture, not an extracted key.
    geometry = signature_operator(degree=params.degree, rank=params.rank, digits=params.digits,
        user_vector=((0,) * params.degree,) * params.columns,
        first_squared=params.signature_first_squared, second_squared=params.signature_second_squared,
        r_squared=params.r_squared, noise_factor=1)
    signature_plan = PaperSampleF(geometry, options=backend.series_options, scalar_options=backend.scalar_options)
    with pytest.raises(ValueError, match="original master shape"):
        issuance_certificate(params, signature_plan, gadget)
    assert source.reads == 0


def test_prepared_nonzero_master_center_cannot_claim_zero_center_law(prepared):
    params, backend, plan, gadget, source = prepared
    shifted = PaperSampleF(plan.geometry, center=(1,) + (0,) * (plan.dimension - 1),
        options=backend.series_options, scalar_options=backend.scalar_options)
    with pytest.raises(ValueError, match="original master shape"):
        issuance_certificate(params, shifted, gadget)
    assert source.reads == 0
