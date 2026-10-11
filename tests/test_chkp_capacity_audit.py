"""Finite implementation refusals remain distinct from security conclusions."""

from fractions import Fraction

import pytest

from experiments.research.chkp_capacity_audit import audit, minimum_entropy_columns, projection


def test_current_seed_capacity_and_profile_are_consistent():
    report = audit()
    assert report["current"]["dimensions"] == [127,254,381]
    assert report["current"]["seed_mode_plaintext_bytes"] == 32
    assert report["current"]["seed_positions"] == 256
    assert report["current"]["framed_mode_plaintext_bytes"] == 28
    assert report["random_bytes_consumed"] == 0
    assert report["large_matrices_allocated"] is False


@pytest.mark.parametrize("n", [2,16,64,128])
def test_root_entropy_columns_have_exact_sufficiency_and_minimality(n):
    row = projection(n)
    q, k, mb = row["q"], row["k"], row["m_bar"]
    threshold = (n*k)**2*q**n*2**128
    assert 31**mb >= threshold
    assert 31**(mb-1) < threshold
    assert Fraction(row["root_regularity_upper_conditional"]) <= Fraction(1,2**64)
    assert row["seed_positions"] == 256
    assert row["private_integer_wire_lower_bytes"]["leaf_preimages"] == 256*row["dimensions"]["leaf"]*6
    assert row["n_does_not_name_security_bits"]
    assert row["backend_admitted"] is False


def test_formal_size_rows_are_blocked_by_current_explicit_caps():
    current = projection(2)
    assert current["resource_status"] == "static_caps_fit"
    assert current["current_params_constructor_accepts"]
    for n in (16,64,128):
        row = projection(n)
        assert row["resource_status"] == "blocked"
        assert row["dimensions"]["leaf"] > 512
        assert not row["current_params_constructor_accepts"]
        assert row["constructor_rejection"]
        assert not row["actual_geometry_or_sampling_executed"]
        assert not row["parameters_are_formal"]


@pytest.mark.parametrize("n", [True,0,-1,129,2.0])
def test_unbounded_or_noninteger_comparisons_are_rejected(n):
    with pytest.raises(ValueError):
        minimum_entropy_columns(n,1099511627791)
