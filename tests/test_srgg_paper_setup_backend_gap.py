"""The zero-atom bound must replay the real original-parameter Setup path."""

from fractions import Fraction

import pytest

from experiments.research.candidates.srgg.paper_setup_backend_gap import (
    INTERPRETATIONS, _AllZeroBytes, build_report, zero_atom_row,
)


@pytest.mark.parametrize("profile,rank", (("PARAM-I", 2), ("PARAM-II", 3), ("PARAM-III", 4)))
@pytest.mark.parametrize("interpretation", INTERPRETATIONS)
def test_original_table4_zero_atom(profile, rank, interpretation):
    row = zero_atom_row(profile, interpretation)
    count = 2 * rank * (2 * rank) * 512
    assert row["witness_coefficient_count"] == count
    assert row["first_attempt_entropy_requests_bytes"] == [32, count]
    assert Fraction(row["positive_gate_threshold_squared_exact"]) > 0
    assert row["zero_witness_fourier_operator_norm_squared"] == 0
    assert row["complete_zero_seed_zero_witness_setup_accepted"] is True
    assert row["zero_witness_probability_exact"] == f"2^-{count}"
    assert row["plan_gap_probability_upper_exact"] == f"1-2^-{count}"
    assert row["full_first_attempt_gap_probability_upper_exact"] == f"1-2^-{count + 256}"
    assert row["numerically_useful_for_64_attempt_abort"] is False
    assert row["actual_backend_all_accepted_roots_gap_closed"] is False
    assert row["all_positive_roots_uniform_numerical_acceptance_bound"] is None
    assert row["useful_64_attempt_abort_upper"] is None
    assert row["complete_fault_history_law_upper"] is None
    assert row["security_claim"] == "none"
    assert row["backend_admitted"] is False


def test_report_retains_scope_and_no_retry_exponentiation():
    report = build_report()
    assert len(report["rows"]) == 6
    assert report["first_seed_drawn_once_for_all_setup_retries"] is True
    assert report["non_geometry_preparation_errors_terminate_setup"] is True
    assert report["cannot_raise_first_attempt_failure_bound_to_64th_power"] is True
    assert report["all_positive_roots_uniform_numerical_acceptance_bound"] is None
    assert report["useful_64_attempt_abort_upper"] is None
    assert report["complete_fault_history_law_upper"] is None
    assert report["security_claim"] == "none"
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None


def test_invalid_input_and_tape_requests_rejected():
    for name, interpretation in (("PARAM-IV", INTERPRETATIONS[0]),
                                 ("PARAM-I", "unspecified")):
        with pytest.raises(ValueError):
            zero_atom_row(name, interpretation)
    tape = _AllZeroBytes()
    with pytest.raises(AssertionError):
        tape.read(-1)
