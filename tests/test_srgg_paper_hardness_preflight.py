"""Independent arithmetic, finite rings and actual cyclotomic factor checks."""
from fractions import Fraction
from itertools import product
import json
from math import gcd

import pytest

from experiments.research.candidates.srgg.paper_hardness_preflight import (
    build_report, coefficient_crt, factor_integer, multiplicative_order,
    seed_support_boundary, uniform_matrix_unit_probability,
)


def unpack(record):
    return Fraction(int(record["numerator_hex"], 16), int(record["denominator_hex"], 16))


def test_full_original_modulus_factorization_retains_gadget_prime_power():
    modulus = 16383 * 31**2
    assert modulus == 15744063
    assert factor_integer(modulus) == ((3, 1), (31, 2), (43, 1), (127, 1))
    assert multiplicative_order(3, 1024) == 256
    assert multiplicative_order(31, 1024) == 32
    assert multiplicative_order(43, 1024) == 256
    assert multiplicative_order(127, 1024) == 8


def test_order_is_first_positive_modular_exponent_independently():
    for prime in (3, 31, 43, 127):
        order = multiplicative_order(prime, 1024)
        assert pow(prime, order, 1024) == 1
        assert all(pow(prime, exponent, 1024) != 1 for exponent in range(1, order))


def test_coefficient_crt_is_a_bijection_with_prime_power_components():
    # Exhaust a separate small modulus and every tuple of component residues.
    components = coefficient_crt(45)
    assert [item["prime_power"] for item in components] == [9, 5]
    restored = {}
    for residues in product(range(9), range(5)):
        value = sum(residue * component["idempotent_mod_Q"]
                    for residue, component in zip(residues, components)) % 45
        assert (value % 9, value % 5) == residues
        restored[value] = residues
    assert len(restored) == 45
    for left in range(45):
        for right in range(45):
            assert restored[left * right % 45] == tuple(a * b % q
                for a, b, q in zip(restored[left], restored[right], (9, 5)))


def test_original_scalar_idempotents_also_reconstruct_negacyclic_products():
    q = 15744063
    components = coefficient_crt(q)
    left, right = (1, -2, 33, 71), (-11, 0, 9, -5)

    def multiply(a, b, modulus):
        out = [0] * 4
        for i in range(4):
            for j in range(4):
                out[(i + j) % 4] += (1 if i + j < 4 else -1) * a[i] * b[j]
        return tuple(value % modulus for value in out)

    projected = [multiply(left, right, item["prime_power"]) for item in components]
    reconstructed = tuple(sum(values[j] * item["idempotent_mod_Q"]
        for values, item in zip(projected, components)) % q for j in range(4))
    assert reconstructed == multiply(left, right, q)


def test_uniform_square_matrix_unit_law_matches_all_z9_two_by_two_matrices():
    # Invertibility modulo 9 is checked by an actual determinant, without
    # fetching a finite-field or prime-power formula from the implementation.
    units = sum(gcd(a*d - b*c, 9) == 1 for a, b, c, d in product(range(9), repeat=4))
    assert units == 3888
    exact = Fraction(units, 9**4)
    result = uniform_matrix_unit_probability(prime=3, degree=1, factor_count=1, rank=2)
    assert result == exact == Fraction(16, 27)


def test_identity_hnf_surjection_and_free_tail_hold_over_a_composite_ring():
    # C=[1,2,3] over Z/9. Every syndrome has exactly 9^2 preimages,
    # and every kernel vector is determined by its two tail coordinates.
    fibers = {target: [] for target in range(9)}
    for head, first, second in product(range(9), repeat=3):
        fibers[(head + 2*first + 3*second) % 9].append((head, first, second))
    assert all(len(values) == 81 for values in fibers.values())
    assert set(fibers[0]) == {((-2*first - 3*second) % 9, first, second)
                            for first, second in product(range(9), repeat=2)}


def test_fixed_expander_support_bound_matches_an_independent_finite_law():
    # Four equally likely seeds give three images inside a nine-state grid.
    actual = {value: Fraction(0) for value in range(9)}
    for image in (0, 1, 1, 2):
        actual[image] += Fraction(1, 4)
    tv = sum(abs(mass - Fraction(1, 9)) for mass in actual.values()) / 2
    assert tv == Fraction(2, 3)
    result = seed_support_boundary(base=3, exponent=2, seed_bits=2)
    bits = result["tv_lower_dyadic"]["bits"]
    assert bits == 1 and tv >= 1 - Fraction(1, 2**bits)
    assert result["positive_support_obstruction_certified"]
    assert not result["computational_or_ROM_security_inferred"]
    uninformative = seed_support_boundary(base=3, exponent=2, seed_bits=4)
    assert not uninformative["positive_support_obstruction_certified"]
    assert uninformative["tv_lower_dyadic"]["bits"] == 0


@pytest.mark.parametrize("bad", [True, 0, 1, -1, 1.5, 2**32 + 1])
def test_factoring_refuses_nonexact_or_out_of_budget_input(bad):
    with pytest.raises(ValueError):
        factor_integer(bad)


@pytest.mark.parametrize("kwargs", [
    {"prime": 9}, {"prime": True}, {"degree": 0},
    {"factor_count": 513}, {"rank": 5},
])
def test_unit_probability_refuses_nonfields_and_unbounded_resources(kwargs):
    arguments = dict(prime=3, degree=2, factor_count=2, rank=2)
    arguments.update(kwargs)
    with pytest.raises(ValueError):
        uniform_matrix_unit_probability(**arguments)


@pytest.fixture(scope="module")
def report():
    pytest.importorskip("sage.all", reason="actual finite-field factorization requires prescribed WSL Sage")
    return build_report()


def test_factor_degrees_match_fresh_independent_sage_factorization(report):
    # Direct Sage arithmetic here does not call the module's factorization
    # helper or modular-order helper. It checks the actual degree-512 polys.
    from sage.all import GF, PolynomialRing

    expected = {3: (256, 2), 31: (32, 16), 43: (256, 2), 127: (8, 64)}
    for item in report["finite_field_factorizations"]:
        prime = item["prime"]
        ring = PolynomialRing(GF(prime), "z")
        polynomial = ring.gen()**512 + 1
        factorization = polynomial.factor()
        f, count = expected[prime]
        assert len(factorization) == count
        assert all(factor.degree() == f and exponent == 1 for factor, exponent in factorization)
        assert all(factor.is_irreducible() for factor, _ in factorization)
        assert factorization.value() == polynomial
        assert polynomial.gcd(polynomial.derivative()) == 1
        assert item["factor_degree"] == item["multiplicative_order"] == f
        assert item["factor_count"] == count
        assert item["actual_factor_degrees"] == [f] * count
        assert item["order_theorem_and_actual_factorization_agree"]
        assert not item["hensel_factor_polynomials_constructed"]


def test_original_hnf_shapes_include_extra_msis_polynomial_and_full_rank(report):
    assert [row["profile"] for row in report["rows"]] == ["PARAM-I", "PARAM-II", "PARAM-III"]
    for d, row in zip((2, 3, 4), report["rows"]):
        assert row["source_parameters"]["w"] == 2
        assert row["source_parameters"]["Q"] == 15744063
        public, sis = row["public_HNF_shape"], row["conditional_uniform_HNF_MSIS_shape"]
        assert public["coefficient_rows"] == sis["coefficient_rows"] == 512*d
        assert public["coefficient_columns"] == 4*d*512
        assert sis["coefficient_columns"] == (4*d + 1)*512
        assert sis["free_kernel_module_rank"] == 3*d + 1
        assert sis["integer_kernel_lattice_index_exact_power"] == {"base": 15744063, "exponent": 512*d}
        assert sis["surjective_for_every_U_because_of_identity_block"]
        assert sis["hypothetical_fixed_width_dense_payload_bytes"] == (512*d)*((4*d + 1)*512)*3
        assert not sis["matrix_materialized"]


def test_projected_resource_and_unit_laws_keep_seeded_model_separate(report):
    for row in report["rows"]:
        d = row["source_parameters"]["d"]
        whole = Fraction(1)
        for item in row["CRT_projections"]:
            prime, f, count = item["prime"], item["factor_degree"], item["factor_count"]
            # Independently count GL via sequential independent columns:
            # prod_(j=0)^(d-1) (q^d-q^j) / q^(d*d).
            q = prime**f
            one = Fraction(1, q**(d*d))
            for j in range(d):
                one *= q**d - q**j
            exact = one**count
            assert unpack(item["uniform_Ahat_unit_probability_all_factors_exact"]) == exact
            whole *= exact
            bits = item["uniform_Ahat_nonunit_probability_dyadic_upper"]["bits"]
            assert 1 - exact <= Fraction(1, 2**bits)
            assert 1 - exact > Fraction(1, 2**(bits + 1))
            shape = item["one_field_hnf_msis_shape"]
            assert shape["coefficient_rows"] == d*f
            assert shape["coefficient_columns"] == (4*d + 1)*f
            assert item["uniform_Ahat_model_only"]
            assert item["ring_hnf_or_mlwe_attack_cost"] is None
            assert item["full_Ahat_secret_error_residue_grid"]["states_enumerated"] == 0
            assert not item["full_Ahat_secret_error_residue_grid"]["fits_enumeration_limit"]
            if prime != 3:
                assert item["actual_projected_CBD1_law"] is None
                assert not item["prime_power_CBD1_law_certified"]
        assert unpack(row["uniform_whole_ring_Ahat_unit_probability_exact"]) == whole
        assert row["fixed_seed_whole_Ahat_marginal_support_boundary"]["positive_support_obstruction_certified"]


def test_original_mod3_columns_and_msis_failure_are_not_ibsignatures(report):
    for row in report["rows"]:
        d = row["source_parameters"]["d"]
        mod3 = row["mod3_joint_public_noisy_columns"]
        assert mod3["rank"] == d and mod3["columns"] == 2*d
        assert mod3["both_CRT_factors_jointly_covered"]
        assert not mod3["tv_bound_pointwise_for_every_Ahat"]
        assert row["setup_acceptance_conditioning_distance"] is None
        assert not row["projection_bound_transferred_to_accepted_setup_roots"]
        diagnostic = row["msis_Q_mapping_diagnostic"]
        assert diagnostic["trivial_Q_times_unit_vector_inside_difference_bound"]
        assert not diagnostic["Q_strictly_exceeds_difference_bound"]
        assert not diagnostic["IBS_direct_forgery_inferred"]
        assert not row["structure_attack_or_advantage_established"]


def test_receipt_never_upgrades_laws_into_costs_or_admission(report):
    assert report["actual_entropy_bytes"] == report["sampler_draws"] == report["attack_executions"] == 0
    assert not report["private_state_read"] and not report["estimator_invoked"] and not report["HIBE_involved"]
    assert all(value is None for value in report["unresolved_costs_and_laws"].values())
    for item in [report] + report["rows"]:
        assert item["security_claim"] == "none"
        assert not item["backend_admitted"] and not item["parameters_are_formal"]
        assert item["nist_security_category"] is None
    json.dumps(report)
