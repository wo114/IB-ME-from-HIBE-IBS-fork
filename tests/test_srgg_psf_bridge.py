from fractions import Fraction
from itertools import permutations

import pytest

from experiments.research.candidates.srgg.algebra import Params, build_public
from experiments.research.candidates.srgg.geometry import module_operator
from experiments.research.candidates.srgg.psf_bridge import (
    _sqrt_upper, build_report, complete_key_comparison, exact_gso_squared,
    exact_kernel_basis, kernel_basis_bound, norm_tail_upper, reference_certificate,
)


def fixture(degree=2, digits=1, base=3, p=5, rank=1):
    params = Params(degree=degree, rank=rank, p=p, base=base, digits=digits)
    r = tuple(tuple(tuple((i+j+k) % 3-1 for k in range(degree)) for j in range(rank*digits))
              for i in range(2*rank))
    ahat = tuple(tuple(tuple((17+i+3*j+k*k) % params.modulus for k in range(degree))
                       for j in range(rank)) for i in range(rank))
    return build_public(params, ahat, r), r


def determinant(columns):
    n = len(columns)
    total = 0
    for perm in permutations(range(n)):
        inversions = sum(perm[i] > perm[j] for i in range(n) for j in range(i+1,n))
        product = -1 if inversions % 2 else 1
        for row, col in enumerate(perm):
            product *= columns[col][row]
        total += product
    return total


def test_basis_is_full_kernel_by_relations_and_index():
    public, r = fixture()
    basis = exact_kernel_basis(public, r)
    a = module_operator(public.params, public.a)
    for col in basis:
        assert all(sum(x*y for x,y in zip(row,col)) % public.params.modulus == 0 for row in a)
    assert abs(determinant(basis)) == public.params.modulus**public.params.degree


@pytest.mark.parametrize("degree,digits", [(2,2),(4,1),(8,3),(8,4)])
def test_actual_gso_respects_uniform_all_root_column_bound(degree,digits):
    public, r = fixture(degree=degree,digits=digits)
    params = public.params
    beta = 2*digits*degree*degree+1
    bound = kernel_basis_bound(degree=degree,rank=1,p=params.p,base=3,digits=digits,
                               witness_spectral_squared_upper=beta)
    basis = exact_kernel_basis(public,r)
    norms = exact_gso_squared(basis)
    assert max(norms) <= bound["basis_gso_squared_upper"]
    product = Fraction(1)
    for norm in norms:
        product *= norm
    assert product == params.modulus**(2*degree)


@pytest.mark.parametrize("degree,digits,rank", [(2,1,1),(4,2,1),(2,2,2)])
def test_ordered_gso_removes_large_head_and_middle_lifts(degree,digits,rank):
    public, r = fixture(degree=degree,digits=digits,rank=rank)
    p = public.params
    beta = 2*rank*rank*digits*degree*degree+1
    bound = kernel_basis_bound(degree=degree,rank=rank,p=p.p,base=p.base,digits=digits,
                               witness_spectral_squared_upper=beta)
    basis = exact_kernel_basis(public,r)
    norms = exact_gso_squared(basis)
    k, m = rank*degree, rank*degree*digits
    assert max(norms[:m]) <= beta*(p.base*p.base+1)
    assert max(norms[m:m+k]) <= p.p*p.p
    assert max(norms[m+k:]) <= 1
    assert bound["basis_gso_squared_upper"] == max(beta*(p.base*p.base+1),p.p*p.p,1)
    assert bound["raw_column_squared_upper"] >= bound["basis_gso_squared_upper"]
    squared_determinant = Fraction(1)
    for norm in norms:
        squared_determinant *= norm
    assert squared_determinant == p.modulus**(2*k)


def test_bad_relation_and_dimension_rejected_before_algebra():
    public, r = fixture()
    bad = (((0,0),),((0,0),))
    with pytest.raises(ValueError,match="relation"):
        exact_kernel_basis(public,bad)
    with pytest.raises(ValueError):
        exact_gso_squared(((1,0),(1,0)))


@pytest.mark.parametrize("value", [Fraction(0),Fraction(1,10),Fraction(2,3),Fraction(1,10**400)])
def test_outward_sqrt_never_underflows(value):
    result = _sqrt_upper(value)
    assert result*result >= value
    if value:
        assert result > 0


def reference(**kwargs):
    args = dict(degree=8,rank=1,p=257,base=31,digits=3,first_squared=2**23,
                second_squared=2**23,basis_gso_squared_upper=10000,user_norm_squared=2**29)
    return reference_certificate(**dict(args,**kwargs))


def test_reference_tracks_shift_wrap_and_norm_as_separate_events():
    result = reference()
    assert result["reference_certificate_available"]
    assert Fraction(result["uniform_coset_relative_error_upper"]) < Fraction(1,2**128)
    assert Fraction(result["repaired_approximate_fiber_to_decoded_reference_tv_upper"]) < Fraction(1,2)
    assert Fraction(result["reference_head_wrap_probability_upper"]) < Fraction(1,2**128)
    assert Fraction(result["approximate_fiber_hnf_norm_reject"]["probability_upper"]) < Fraction(1,2**20)
    assert not result["source_psf_theorem_correspondence_established"]
    assert not result["parameters_are_formal"]


def test_kernel_smoothing_failure_is_explicit():
    result = reference(basis_gso_squared_upper=2**40)
    assert not result["reference_certificate_available"]
    assert "kernel smoothing" in result["blocker"]
    assert not complete_key_comparison(result,sampler_tv_including_abort=0,raw_convolution_tv=0)["available"]


def test_complete_comparison_requires_all_probabilities_and_norm_gate():
    result = reference()
    assert not complete_key_comparison(result,sampler_tv_including_abort=None,raw_convolution_tv=0)["available"]
    assert not complete_key_comparison(reference(user_norm_squared=None),
        sampler_tv_including_abort=0,raw_convolution_tv=0)["available"]
    complete = complete_key_comparison(result,sampler_tv_including_abort=Fraction(1,1000),
        raw_convolution_tv=Fraction(1,10000))
    assert complete["available"]
    assert complete["includes_sampler_abort_and_norm_reject"]
    assert not complete["infrastructure_failure_included"]
    assert not complete["strong_security_or_source_psf_admission"]
    assert not complete["success_conditioned"]
    assert "plus abort" in complete["comparison_space"]
    with pytest.raises(ValueError):
        complete_key_comparison(result,sampler_tv_including_abort=Fraction(-1),raw_convolution_tv=0)


def test_complete_law_keeps_abort_and_adds_unfiltered_reference_rejection_once():
    # Reference Q=(good:9/10,bad:1/10,abort:0). Before a common norm gate,
    # P=(good:17/20,bad:1/10,abort:1/20), with TV(P,Q)=1/20.
    # Filtering bad -> abort gives TV(G(P),Q)=3/20, attaining the triangle
    # bound eps + Q(bad). Against G(Q) it is just eps; that is a distinct
    # filtered-reference comparison, not a success-conditioned law.
    declared = {
        "reference_certificate_available": True,
        "repaired_approximate_fiber_to_full_reference_tv_upper": "0",
        "reference_norm_reject": {"probability_upper": "1/10"},
    }
    result = complete_key_comparison(declared,sampler_tv_including_abort=Fraction(1,20),
                                     raw_convolution_tv=0)
    actual_after_gate = (Fraction(17,20),Fraction(0),Fraction(3,20))
    unfiltered_reference = (Fraction(9,10),Fraction(1,10),Fraction(0))
    filtered_reference = (Fraction(9,10),Fraction(0),Fraction(1,10))
    tv = lambda p,q: sum(abs(x-y) for x,y in zip(p,q))/2
    assert tv(actual_after_gate,unfiltered_reference) == Fraction(3,20)
    assert tv(actual_after_gate,filtered_reference) == Fraction(1,20)
    assert Fraction(result["complete_key_law_to_unfiltered_full_reference_tv_upper"]) >= Fraction(3,20)
    assert not result["success_conditioned"]


def test_norm_bound_monotone_and_zero_limit_preserved():
    def bound(cap):
        return Fraction(norm_tail_upper(dimension=40,squared_cap=cap,
            largest_squared_width=100,smoothing_epsilon=Fraction(1,2**100))["probability_upper"])
    assert bound(100) == 1
    assert 0 < bound(10**50) <= bound(10000) < bound(5000) < 1


@pytest.mark.parametrize("bad", [True,0,-1,2.5,Fraction(1,2)])
def test_invalid_witness_bound_rejected(bad):
    with pytest.raises(ValueError):
        kernel_basis_bound(degree=8,rank=1,p=257,base=31,digits=3,witness_spectral_squared_upper=bad)


def test_existing_n512_points_pass_reference_smoothing_without_actual_sampler_admission():
    result = build_report()
    for candidate in result["existing_candidates"]:
        reference = candidate["reference"]
        assert reference["reference_certificate_available"]
        assert Fraction(reference["uniform_coset_relative_error_upper"]) < Fraction(1,2**80)
        assert "full coefficient kernel" in reference["smoothing_scope"]
        assert not reference["source_psf_theorem_correspondence_established"]
        assert candidate["actual_n512_implementation_tv"] is None
    assert result["security_claim"] == "none"
