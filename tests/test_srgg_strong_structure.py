"""Exhaustive small quotient checks and a nonzero-extraction counterexample."""
from fractions import Fraction
from itertools import product

import pytest

from experiments.research.candidates.srgg.strong_structure import (
    effective_challenge,quotient_certificate,same_challenge_coset,zeta_apply,
)


def multiply_schoolbook(x,y):
    out=[0]*len(x)
    for i,a in enumerate(x):
        for j,b in enumerate(y):
            out[(i+j)%len(x)]+=a*b*(-1 if i+j>=len(x) else 1)
    return tuple(out)


@pytest.mark.parametrize("n",[2,4,8])
def test_exhaustive_binary_classes_and_zero_response_count(n):
    groups={};zero=0;h=n//2
    adjoint=(1,)+(0,)*(h-1)+(-1,)+(0,)*(h-1)
    for c in product((0,1),repeat=n):
        key=effective_challenge(c);groups.setdefault(key,[]).append(c)
        actual=multiply_schoolbook(adjoint,c)
        assert actual==zeta_apply(c,adjoint=True)
        zero+=all(x%2==0 for x in actual)
    assert len(groups)==2**h and {len(v) for v in groups.values()}=={2**h}
    assert Fraction(zero,2**n)==Fraction(quotient_certificate(n)[
        "zero_response_zero_commitment_one_fresh_message_success_exact"])
    for values in groups.values():
        anchor=values[0]
        for other in values:
            assert same_challenge_coset(anchor,other)
            difference=tuple(a-b for a,b in zip(anchor,other))
            assert all(x%2==0 for x in multiply_schoolbook(adjoint,difference))


@pytest.mark.parametrize("n",[2,8,512])
def test_distinct_challenges_can_have_identical_response_and_commitment(n):
    first=(0,)*n;second=tuple(int(i in (0,n//2)) for i in range(n))
    assert first!=second and same_challenge_coset(first,second)
    diff=multiply_schoolbook((1,)+(0,)*(n//2-1)+(-1,)+(0,)*(n//2-1),second)
    assert diff==(2,)+(0,)*(n-1)
    for q in (3,17,13972913866395903):
        assert all((q*x)%(2*q)==0 for x in diff)
    # No assertion that one real fixed H2 returns both challenges at a point.


@pytest.mark.parametrize("n",[2,4,8])
def test_zeta_image_is_parity_lattice_and_product_is_two(n):
    for values in product((-1,0,1),repeat=n):
        image=zeta_apply(values)
        assert all((image[i]-image[i+n//2])%2==0 for i in range(n//2))
        assert zeta_apply(image,adjoint=True)==tuple(2*x for x in values)


@pytest.mark.parametrize("n",[True,0,3,8192])
def test_rejects_unsupported_degree(n):
    with pytest.raises(ValueError):quotient_certificate(n)


def test_large_count_is_exact_not_an_admission():
    row=quotient_certificate(512)
    assert row["effective_challenge_bits"]==256
    assert Fraction(row["independent_uniform_same_coset_probability_exact"])==Fraction(1,2**256)
    assert not row["large_parameter_attack_executed"] and not row["backend_admitted"]
