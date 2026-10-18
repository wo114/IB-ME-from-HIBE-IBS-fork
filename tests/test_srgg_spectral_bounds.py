"""Strict public class bounds, independent small exact checks and n512 screen."""

from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.algebra import Params, build_public
from experiments.research.candidates.srgg.psf_bridge import exact_gso_squared, exact_kernel_basis
from experiments.research.candidates.srgg.spectral_bounds import (
    build_report, ordered_kernel_gso_bound, private_energy_bound,
    public_support_class_bound, public_t_squared_upper,
)


def test_scalar_polygon_bound_covers_all_ternary_degree_four_polynomials_exactly():
    # For n=4, the true largest squared singular value is S+sqrt(2)*|t|.
    # Compare by squaring nonnegative rationals; no floating eigensolver.
    cert = public_support_class_bound(degree=4, rows=1, columns=1)
    bound = Fraction(cert["scalar_polynomial_spectral_squared_upper_exact"])
    assert Fraction(6828, 1000) < bound < Fraction(684, 100)
    for a, b, c, d in product((-1, 0, 1), repeat=4):
        energy = a*a+b*b+c*c+d*d
        cross = abs(a*b-a*d+b*c+c*d)
        assert bound >= energy
        assert (bound-energy)**2 >= 2*cross*cross


def test_degree_two_bound_is_attained_by_a_cbd1_matrix():
    # R has two copies of 1+X, each M(Rij)^T M(Rij)=2I.
    # Thus ||T||^2=1+4=5 exactly, rather than the old Frobenius bound 9.
    assert public_t_squared_upper(2, 1, 1) == 5
    actual = private_energy_bound((((1, 1),), ((1, 1),)), degree=2)
    assert Fraction(actual["t_spectral_squared_upper_exact"]) == 5
    assert actual["all_coefficients_in_cbd1_support"]
    assert not actual["public_support_class_certificate"]


def test_private_energy_is_distinct_from_a_public_support_class():
    witness = (((2, 0, 0, 0),), ((0, 0, 0, 0),))
    cert = private_energy_bound(witness, degree=4)
    assert cert["actual_coefficient_energy"] == 4
    assert Fraction(cert["t_spectral_squared_upper_exact"]) == 9
    assert not cert["all_coefficients_in_cbd1_support"]
    assert not cert["public_support_class_certificate"]


@pytest.mark.parametrize("degree,digits,rank", [(2,1,1), (4,2,1), (2,2,2)])
def test_ordered_kernel_bound_covers_actual_exact_gso(degree, digits, rank):
    p = Params(degree=degree, rank=rank, p=5, base=3, digits=digits)
    witness = tuple(tuple(tuple((i+2*j+k) % 3-1 for k in range(degree))
                           for j in range(rank*digits)) for i in range(2*rank))
    ahat = tuple(tuple(tuple((i+3*j+7*k+2) % p.modulus for k in range(degree))
                        for j in range(rank)) for i in range(rank))
    public = build_public(p, ahat, witness)
    norms = exact_gso_squared(exact_kernel_basis(public, witness))
    beta = public_t_squared_upper(degree, rank, digits)
    certificate = ordered_kernel_gso_bound(p=p.p, base=p.base,
                                           witness_spectral_squared_upper=beta)
    m, k = rank*digits*degree, rank*degree
    assert max(norms[:m]) <= beta*(p.base*p.base+1)
    assert max(norms[m:m+k]) <= p.p*p.p
    assert max(norms[m+k:]) <= 1
    assert max(norms) <= Fraction(certificate["basis_gso_squared_upper_exact"])


def test_old_n512_parameters_gain_C_and_kernel_certificates_but_keep_large_shift():
    rows = build_report()["existing_n512_candidates"]
    assert len(rows) == 3
    for row in rows:
        assert row["parameter_changes"] is None
        assert row["C_sufficient_smoothing_passes"]
        assert Fraction(row["new_C_lower_exact"]) > 36000
        assert Fraction(row["legacy_C_lower_exact"]) < 1
        assert Fraction(row["structured_binomial_operator_rho_upper_exact"]) < Fraction(406,1000)
        reference = row["reference_with_ordered_GSO"]
        assert reference["reference_certificate_available"]
        assert Fraction(reference["repaired_approximate_fiber_to_full_reference_tv_upper"]) > Fraction(1,2)
        assert not row["actual_root_or_sampler_executed"]
        assert not row["parameters_are_formal"] and row["security_claim"] == "none"


@pytest.mark.parametrize("change", [{"degree":3}, {"degree":True}, {"rows":0},
                                      {"columns":129}, {"degree":2**16,"rows":128}])
def test_public_class_shape_and_resource_checks(change):
    values = dict(degree=8, rows=2, columns=3)
    values.update(change)
    with pytest.raises(ValueError):
        public_support_class_bound(**values)


@pytest.mark.parametrize("bad", [(((True,0),),), (((1,),),), (((1.0,0),),)])
def test_private_coefficients_have_exact_types_and_fixed_degree(bad):
    with pytest.raises(ValueError):
        private_energy_bound(bad, degree=2)
