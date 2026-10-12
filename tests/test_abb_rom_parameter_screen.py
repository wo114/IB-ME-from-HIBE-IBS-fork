"""Public same-group bounds are checked without generating/retrying secrets."""

from fractions import Fraction

import pytest
pytest.importorskip("sage.all", reason="use prescribed WSL Sage; skip is not pass")
from sage.all import QQ, ZZ

from ibme.core.errors import InvalidParameterError
from ibme.hibe.abb_rom import ABBTrapGenParams, abb_parameter_screen


def test_same_group_bounds_dimension_growth_and_phase_failure():
    root = ABBTrapGenParams(1, 549755813911, 56, 56, 192, hadamard_scale=32)
    report = abb_parameter_screen(root)
    m = root.dimension
    radius = report["finite_R_support_radius"]
    factor = (2 * m * (1 + 2**128) - 1).bit_length()
    s1 = int(report["sigma1_squared"])
    s2 = int(report["sigma2_squared"])
    assert report["root_parent_leaf_dimensions"] == [248] * 3
    assert s1 == 4 * root.gs_squared_bound * m**2 * radius**2 * factor
    assert s2 == 4 * (s1 * m) * m**2 * radius**2 * factor
    assert int(report["decryption_tau_squared"]) == 4 * s2 * m * factor
    assert not report["conditional_noise_sufficient"]
    assert report["conditional_ideal_noise_lifetime_upper"] is None
    assert "BasisDel/ToBasis existing hard dimension 192" in report["blockers"]
    assert "at least one leaf GPV scalar exceeds squared width 2^80" in report["blockers"]
    assert report["raw_seed_coefficient_wire_lower_bound_bytes"] == 256 * 249 * 5
    assert report["measured"] is False


def test_sufficient_noise_at_larger_q_does_not_bypass_missing_tools():
    q = int(ZZ(2**159).next_prime())
    root = ABBTrapGenParams(1, q, 320, 320, 960, hadamard_scale=56)
    report = abb_parameter_screen(root)
    assert report["conditional_noise_sufficient"]
    assert Fraction(report["conditional_phase_error_upper"]) < Fraction(q, 5)
    assert Fraction(report["conditional_ideal_noise_lifetime_upper"]) == Fraction(256 * 2**20, 2**128)
    assert "existing SampleR hard modulus 2^61-1" in report["blockers"]
    assert "public finite GPV existing hard dimension 256" in report["blockers"]
    assert report["available_complete_execution"] is False
    assert QQ(report["root"]["output_vs_uniform_tv_upper_including_abort"]) < QQ(1)/2**64
    assert not report["paper_Theorem3_omega_constants_verified"]
    assert not report["backend_admitted"] and not report["parameters_are_formal"]


@pytest.mark.parametrize("change", [{"epsilon_bits": True}, {"error_bits": 0},
    {"seed_bytes": 0}, {"seed_bytes": 33}, {"encapsulations": 2**33}])
def test_screen_invalid_input_has_no_key_generation(change):
    root = ABBTrapGenParams(1, 5, 6, 6, 24, hadamard_scale=8)
    with pytest.raises(InvalidParameterError):
        abb_parameter_screen(root, **change)
