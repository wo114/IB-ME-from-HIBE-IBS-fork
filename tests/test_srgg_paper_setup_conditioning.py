"""Independent finite-algebra checks for the Table 4 Setup preflight."""
from fractions import Fraction
from itertools import product
from math import comb

import pytest

from experiments.research.candidates.srgg.paper_setup_conditioning import (
    build_report, matrix_bernstein_preflight, residual_threshold_squared,
    sparse_l1_gate,
)


def test_strict_schur_gate_matches_exhaustive_negacyclic_n2_matrix():
    sage = pytest.importorskip("sage.all", reason="exact positive-definiteness requires Sage")
    q = sage.QQ
    first, second, rounding, base = Fraction(8), Fraction(20), Fraction(1), 2
    threshold = residual_threshold_squared(first, second, rounding, base)
    assert threshold == Fraction(105, 76)
    for a, b in product((-1, 0, 1), repeat=2):
        # Multiplication by a+bX modulo X^2+1, independently expanded.
        convolution = sage.matrix(q, [[a, -b], [b, a]])
        top = sage.block_matrix(q, [[convolution], [sage.identity_matrix(q, 2)]])
        diagonal = sage.diagonal_matrix(q, [q(first-rounding)]*2+[q(second-rounding)]*2)
        residual = diagonal-q(base**2*rounding)*top*top.transpose()
        direct = residual.is_positive_definite()
        assert direct == (a*a+b*b < threshold)
    assert threshold < 2  # One nonzero coefficient passes; two do not.


def test_sparse_gate_probability_is_independent_cbd1_binomial_event():
    # In n=2, each of two CBD1 coefficients is nonzero with probability 1/2.
    threshold = Fraction(105, 76)
    gate = sparse_l1_gate(degree=2, rows=1, columns=1,
        threshold_squared=threshold, attempts=3)
    assert gate["polynomial_nonzero_cap"] == 1
    # Enumerate the actual three-point product law, without using binomial sums.
    law = {-1: Fraction(1, 4), 0: Fraction(1, 2), 1: Fraction(1, 4)}
    exact = sum(law[a]*law[b] for a, b in product(law, repeat=2)
                if (a != 0)+(b != 0) <= 1)
    assert exact == Fraction(3, 4)
    assert gate["one_polynomial_binomial_numerator"] == "3"
    assert gate["one_attempt_success_lower_formula"] == "(3/2^2)^1"
    assert gate["retry_exhaustion_upper_formula"] == "(1-(3/2^2)^1)^3"
    assert (1-exact)**3 == Fraction(1, 64)


def test_independent_dilation_variance_count_for_small_rectangular_ring():
    sage = pytest.importorskip("sage.all", reason="exact matrix arithmetic requires Sage")
    q = sage.QQ
    degree, rows, columns = 2, 2, 1
    shifts = (sage.identity_matrix(q, 2), sage.matrix(q, [[0, -1], [1, 0]]))
    left = sage.zero_matrix(q, rows*degree)
    right = sage.zero_matrix(q, columns*degree)
    for i, j, k in product(range(rows), range(columns), range(degree)):
        one = sage.zero_matrix(q, rows*degree, columns*degree)
        one[i*degree:(i+1)*degree, j*degree:(j+1)*degree] = shifts[k]
        left += one*one.transpose()/2
        right += one.transpose()*one/2
    assert left == sage.identity_matrix(q, rows*degree) * q(Fraction(columns*degree, 2))
    assert right == sage.identity_matrix(q, columns*degree) * q(Fraction(rows*degree, 2))
    assert max(tuple(left.diagonal())+tuple(right.diagonal())) == q(Fraction(rows*degree, 2))


@pytest.fixture(scope="module")
def original_report():
    pytest.importorskip("sage.all", reason="original PaperParams require WSL Sage")
    return build_report()


def test_original_table4_thresholds_cancel_common_pi_scale(original_report):
    from experiments.research.candidates.srgg.paper_parameters import PaperParams
    from experiments.research.candidates.srgg.paper_profiles import profiles

    for source, row in zip(profiles, original_report["rows"]):
        bare = residual_threshold_squared(Fraction(source.master_first_stddev)**2,
            Fraction(source.master_second_stddev)**2,
            source.r_stddev**2, source.base)
        assert Fraction(row["threshold_squared_exact"]) == bare
        for interpretation in row["interpretations"]:
            params = PaperParams(source.name, interpretation)
            assert residual_threshold_squared(params.master_first_squared,
                params.master_second_squared, params.r_squared, params.base) == bare
        assert row["root_polynomial_shape"] == [2*source.rank, source.digits*source.rank]
        assert row["degree"] == source.degree == 512


def test_original_sparse_floor_is_positive_but_unusable(original_report):
    assert [row["profile"] for row in original_report["rows"]] == [
        "PARAM-I", "PARAM-II", "PARAM-III"]
    assert [row["sparse_l1_alternative"]["polynomial_nonzero_cap"]
            for row in original_report["rows"]] == [19, 15, 13]
    assert [row["sparse_l1_alternative"]["dyadic_bits"]
            for row in original_report["rows"]] == [6371, 15031, 27375]
    for row in original_report["rows"]:
        gate = row["sparse_l1_alternative"]
        k, blocks = gate["polynomial_nonzero_cap"], gate["polynomial_count"]
        numerator = sum(comb(512, j) for j in range(k+1))
        assert int(gate["one_polynomial_binomial_numerator"]) == numerator
        assert blocks == (2*row["rank"])**2
        assert blocks*k*k < Fraction(row["threshold_squared_exact"])
        assert blocks*(k+1)**2 >= Fraction(row["threshold_squared_exact"])
        assert Fraction(numerator**blocks, 2**(512*blocks)) >= Fraction(1, 2**gate["dyadic_bits"])
        assert not gate["retry_exhaustion_target_2_minus_128_certified"]
        assert gate["conditioned_accepted_root_law_distance"] is None
        assert gate["actual_numerical_sampler_success_lower"] is None
        assert not gate["useful_for_original_table4_acceptance_budget"]


def test_bernstein_fails_to_bound_original_setup_failure(original_report):
    for row in original_report["rows"]:
        d = row["rank"]
        bound = matrix_bernstein_preflight(degree=512, rows=2*d,
            columns=2*d, threshold_squared=Fraction(row["threshold_squared_exact"]))
        assert bound == row["matrix_bernstein"]
        assert Fraction(bound["variance_exact"]) == 512*d
        assert bound["dilation_dimension"] == 4*d*512
        assert Fraction(bound["raw_tail_lower_using_e_less_than_4_exact"]) > 1
        assert bound["failure_upper"] == "1" and bound["success_lower"] == "0"
        assert not bound["informative_at_this_row"]


def test_original_setup_entropy_envelope_is_only_requested_bytes(original_report):
    for row in original_report["rows"]:
        d = row["rank"]
        assert row["CBD1_source_requested_bytes_per_attempt"] == 2*d*d*2*512
        assert row["maximum_setup_requested_bytes"] == 32+64*2*d*d*2*512
        assert row["retry_limit"] == 64
        assert row["runtime_success_probability_or_abort_budget"] is None
        assert row["accepted_setup_root_distribution_bound"] is None
        assert not row["setup_numerical_preparation_covered"]
    assert original_report["security_claim"] == "none"
    assert original_report["parameters_are_formal"] is False
    assert original_report["nist_security_category"] is None


@pytest.mark.parametrize("arguments", [
    (1, 4, 1, 2), (4, 1, 1, 2), (4, 4, 2, 2), (4, 4, 1, 0),
    (True, 4, 1, 2), (4, 4, 1, True), (4.0, 4, 1, 2),
])
def test_nonpositive_or_nonexact_residual_inputs_refused(arguments):
    with pytest.raises(ValueError):
        residual_threshold_squared(*arguments)
