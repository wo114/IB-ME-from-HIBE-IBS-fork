"""Admission/negative controls for analytic bounds, not cryptographic proofs."""

from itertools import product

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage environment")
from sage.all import QQ, ZZ, RealIntervalField

from experiments.research.foo_li_parameter_screen import (
    regularity_bound, screen, sis_public_control,
)


@pytest.mark.parametrize("q,n,bar,width",[
    (4,1,2,16),(3,0,2,16),(3,1,0,16),(3,1,2,0),(True,1,2,16),
    (3,1,2,1.0),(3,1.0,2,16),
])
def test_regularity_refuses_wrong_domain(q,n,bar,width):
    with pytest.raises(ValueError):regularity_bound(q,n,bar,width)


def test_exact_small_public_distribution_below_regularity_bound():
    # Independent finite model of an infinite scalar Gaussian on residue classes.
    # 2^-600 tails are negligible relative to the large strict inequality below.
    q,bar=3,4
    f=RealIntervalField(256)
    mass=[f(0) for _ in range(q)]
    for z in range(-64,65):mass[z%q]+=(-f.pi()*z*z/16).exp()
    normal=sum(mass)
    pmf=[x/normal for x in mass]
    total=f(0)
    for a in product(range(q),repeat=bar):
        law=[f(1),f(0),f(0)]
        for coefficient in a:
            next_law=[f(0) for _ in range(q)]
            for x in range(q):
                for r in range(q):next_law[(x+coefficient*r)%q]+=law[x]*pmf[r]
            law=next_law
        # One-column toy primitive. Same public Abar is included in the distance.
        total+=sum(abs(x-f(QQ(1)/q)) for x in law)/2
    actual=total/q**bar
    record=regularity_bound(q,1,bar,16)
    bound=f(2)**f(QQ(record['ideal_public_tv']['log2_upper_exact']))
    assert actual.upper()<bound.lower()
    assert actual.lower()>0  # public zero base is retained, not conditioned away


def test_small_width_does_not_get_a_spurious_uniformity_certificate():
    r=regularity_bound(2147483659,1,1,1)
    assert QQ(r['ideal_public_tv']['log2_upper_exact'])==0
    assert QQ(r['residue_atom_upper'])==1


@pytest.mark.parametrize("q",[65537,2147483647,4294967291])
def test_full_reduction_norm_rejects_32bit_family(q):
    x=screen(q,64)
    assert x['beta_red_squared']>=q*q
    assert not x['analytic_checks']['nontrivial_SIS_norm']


def test_signature_bound_alone_cannot_admit_sis_parameters():
    q=2**61-1
    x=screen(q,64)
    assert x['signature_norm_bound_squared']<q*q
    assert x['beta_red_squared']>=q*q
    assert not x['analytic_checks']['nontrivial_SIS_norm']


@pytest.mark.parametrize("q",[2**61-1,2**89-1,2**127-1])
def test_numeric_pass_is_not_security_admission(q):
    x=screen(q,1)
    assert x['analytic_prescreen_pass']
    assert not x['known_reference_limits_pass']
    assert not x['admitted_backend']
    assert x['open_obligations']['SIS_classical_cost'] is None
    assert x['open_obligations']['actual_SampleD_total_TV'] is None
    assert x['security_claim']=='none'


@pytest.mark.parametrize("q,n",[(2**61-1,1),(2**127-1,1),(2**89-1,8),(2**89-1,64)])
def test_public_sis_control_checks_real_equation_norm_and_nonzero(q,n):
    x=screen(q,n)
    assert x['analytic_prescreen_pass']
    c=sis_public_control(x)
    assert c['equation_mod_q'] and c['nonzero']
    assert c['norm_squared']<=x['beta_red_squared']
    assert c['solves_SIS_at_reduction_bound']
    assert c['zero_padding_to_full_dimension_valid']
    assert not c['IBS_forgery_generated']


def test_component_budget_and_full_matrix_costs_are_explicit():
    x=screen(2**127-1,512)
    p,c=x['parameters'],x['costs']
    assert p['component_budget_bits']==160
    assert x['scalar_generation_options']['tail_bits']>160
    assert c['dense_geometry_8byte_cells_bytes']>256*2**30
    assert c['packed_user_R_bytes_upper']>32*2**30
    assert x['conditional_public_tv']['log2_upper_display']<=-160
    assert not x['known_reference_limits']['complete_output_dimension_at_most_128']
    assert not x['admitted_backend']


def test_positive_bounds_are_not_underflowed_to_zero():
    x=screen(2**127-1,64)
    for key in ['conditional_generation_tv','conditional_public_tv']:
        assert QQ(x[key]['log2_upper_exact']).denominator()>0
    assert QQ(x['ideal_MP12_convolution_upper'])>0


@pytest.mark.parametrize("n,q",[(1,2**61-1),(1,2**127-1),(8,2**61-1),(8,2**127-1)])
def test_low_dimensional_sis_has_an_analytic_polynomial_attack(n,q):
    x=screen(q,n)
    assert x['analytic_prescreen_pass']
    control=x['standard_LLL_attack_control']
    assert control['bound_fits_beta_red']
    assert QQ(control['leading_block_singular_probability_upper'])==QQ(n)/q
    assert not control['Lean_formalized']
    assert QQ(3)/4-(QQ(501)/1000)**2>QQ(1)/3


@pytest.mark.parametrize("kwargs",[{"bits":True},{"bits":0},{"bits":513},
    {"m_bar":False},{"m_bar":0},{"generation_width_squared":0}])
def test_parameter_family_input_validation(kwargs):
    with pytest.raises(ValueError):screen(3,1,**kwargs)
