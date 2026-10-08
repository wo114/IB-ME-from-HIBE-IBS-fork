"""Checks against independently transcribed paper values and unsafe readings."""

import pytest

from experiments.research.primitive_spec_audit import (
    LUO_ROWS, SRGG_ROWS, build_report, chkp_payload_cost,
    coefficient_bits, compatible_moduli, luo_row, srgg_row,
)


def test_power_of_two_modulus_encoding_does_not_add_a_bit():
    assert coefficient_bits(256) == 8
    assert coefficient_bits(257) == 9


@pytest.mark.parametrize("q", [1, 0, -2, True, 2.0])
def test_bad_modulus_is_not_accepted(q):
    with pytest.raises(ValueError):
        coefficient_bits(q)


def test_rounding_and_ntt_conditions_are_separate():
    # 13 has the requested bit width and alpha=4 divides 12, but 2n=8 does not.
    assert compatible_moduli(4, 4, degree=4) == [9]
    # These outputs are not asserted prime: 9 is a useful counterexample.


def test_unknown_primality_and_source_modulus_are_not_security_passes():
    row = luo_row(LUO_ROWS[0])
    assert row["compatible_moduli"]
    assert all(x["prime"] is None for x in row["compatible_moduli"])
    assert not row["exact_paper_modulus_known"]
    assert not row["backend_admitted"]


@pytest.mark.parametrize("row", LUO_ROWS)
def test_luo_table_norm_relations(row):
    result = luo_row(row)
    assert result["beta2_relation_ok"]
    assert result["key_acceptance_bound"] > 0
    assert result["sign_acceptance_bound_strict"] > 0


def test_136_bit_label_does_not_mean_128_bit_quantum_cost():
    result = luo_row(LUO_ROWS[1])
    assert result["classical_core_svp_exponent_from_source"] == "137.240"
    assert result["quantum_core_svp_exponent_from_source"] == "124.550"
    assert not result["reduction_query_loss_accounted"]


def test_published_modulus_range_cannot_be_truncated_into_legacy_params():
    from ibme.core.errors import InvalidParameterError
    from ibme.lattice.params import Params

    candidates = luo_row(LUO_ROWS[0])["compatible_moduli"]
    assert not any(item["legacy_uint32_params_compatible"] for item in candidates)
    with pytest.raises(InvalidParameterError, match="2\\*\\*32"):
        Params("source-range", 1, 4, 8, candidates[0]["q"], 1, 1, 1, 16, 32)


@pytest.mark.parametrize("row,expected", tuple(zip(SRGG_ROWS, [12320, 27680, 49184])))
def test_srgg_public_matrix_dimensions_match_table4_not_summary(row, expected):
    result = srgg_row(row)
    assert result["modulus_Q"] == 15744063
    assert result["public_fixed_bit_packing_plus_seed_bytes"] == expected
    assert result["table4_matches_this_public_matrix_layout"]
    assert not result["table1_table4_public_sizes_equal"]
    assert not result["table1_table4_signature_sizes_equal"]


@pytest.mark.parametrize("row", SRGG_ROWS)
def test_srgg_literal_theorem_condition_cannot_be_marked_satisfied(row):
    result = srgg_row(row)
    assert not result["literal_Q_gt_2gamma"]
    assert not result["literal_2Q_gt_2gamma"]
    assert not result["underlying_strong_signature_condition_verified"]
    assert not result["backend_admitted"]


def test_published_amortization_keeps_key_and_syndrome_costs_visible():
    result = chkp_payload_cost(m=4, payload_bytes=1, modulus_bits=7)
    assert result["padded_preamble_coefficients"] == 12
    assert result["independent_bit_ciphertext_coefficients"] == 104
    assert result["amortized_ciphertext_coefficients"] == 20
    assert result["independent_bit_packed_bytes"] == 91
    assert result["amortized_packed_bytes"] == 18
    assert result["decryption_preimage_coefficients_if_materialized"] == 96
    assert result["amortized_distinct_syndromes"] == 8
    assert not result["parameter_admitted"]


@pytest.mark.parametrize("payload", [0, -1, True])
def test_empty_payload_needs_framing_before_counting(payload):
    with pytest.raises(ValueError):
        chkp_payload_cost(4, payload, 7)


def test_report_does_not_admit_a_backend_or_claim_measured_performance():
    report = build_report()
    assert report["security_claim"] == "none"
    assert not report["backend_admitted"]
    assert not report["hardware_or_performance_result"]
    assert report["chkp_layout"]["child_columns_multiplier"] == 3
