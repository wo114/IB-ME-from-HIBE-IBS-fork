"""Sage-only independent general-q lattice/sampling checks; no security claim."""

from itertools import product
import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all",reason="Use the prescribed WSL Sage environment")
from sage.all import QQ, ZZ, RealField, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import (PowerOfTwoGadgetSampler,
    SamplingAbort, build_gaussian_table, build_gaussian_table_squared, interval_bounds)
from experiments.research.general_gadget_reference import (GeneralModulusGadgetSampler,
    finite_general_gadget_distribution, gadget_basis)
from experiments.research.general_gadget_audit import finite_box_comparison


def test_squared_width_preserves_legacy_tables_and_archived_fingerprints():
    saved=json.loads(Path("docs/research/2026-10-04-round4/sampling-reference-results.json").read_text())
    for case in saved["scalar_cases"].values():
        original=case["certificate"]
        table=build_gaussian_table(**original["config"])
        assert table.certificate()["cdf_sha256"] == original["cdf_sha256"]
        config=table.config_record()
        config["s_squared"]=str(table.s_squared)
        del config["s"]
        squared=build_gaussian_table_squared(**config)
        assert squared.masses == table.masses and squared.support == table.support
        assert interval_bounds(squared.normalizer) == interval_bounds(table.normalizer)


def test_irrational_coordinate_width_uses_exact_squared_parameter_and_roundtrip():
    table=build_gaussian_table_squared("144/5",center="2/5")
    assert table.s is None and table.s_squared == QQ(144)/5
    again=build_gaussian_table_squared(**json.loads(json.dumps(table.config_record())))
    assert again.certificate()["cdf_sha256"] == table.certificate()["cdf_sha256"]
    f=RealField(320)
    weights={x:(-f.pi()*(f(x)-f(QQ(2)/5))**2/f(QQ(144)/5)).exp() for x in range(-60,61)}
    total=sum(weights.values())
    tv=sum(abs(f(table.probability(x))-w/total) for x,w in weights.items())/2
    assert tv <= f(table.tv_upper)


@pytest.mark.parametrize("value",[0,-1,True,0.5,"NaN", "1/0"])
def test_invalid_squared_width_is_rejected(value):
    with pytest.raises(ValueError):
        build_gaussian_table_squared(value)


def test_complete_basis_for_every_small_modulus_and_selected_larger_primes():
    for q in list(range(2,65))+[257,65537]:
        geometry=gadget_basis(q)
        assert geometry.k == (q-1).bit_length()
        assert abs(geometry.basis.det()) == q
        assert all(sum((1 << i)*geometry.basis[i,j] for i in range(geometry.k))%q==0
                   for j in range(geometry.k))
        # Kernel inclusion plus determinant q establishes completeness since
        # the parity-check map is onto (its first entry equals one).
        assert geometry.basis.is_immutable()


@pytest.mark.parametrize("q",[3,5,6,7,9,11,13,17,31,257])
def test_forward_gram_schmidt_matches_mp12_closed_form(q):
    geometry=gadget_basis(q)
    expected=[QQ(4**(i+2)-1)/(4**(i+1)-1) for i in range(geometry.k-1)]
    expected.append(QQ(3*q*q)/(4**geometry.k-1))
    assert list(geometry.norm_squared) == expected
    assert max(expected) <= 5 and expected[-1] < 3
    assert all(geometry.orthogonal[i].dot_product(geometry.orthogonal[j])==0
               for i in range(geometry.k) for j in range(i))


def test_power_of_two_boundary_uses_nonzero_last_column_and_correct_order():
    forward=gadget_basis(8)
    reverse=gadget_basis(8,order="reverse")
    assert forward.basis.column(2) == vector(ZZ,[0,0,2])
    assert forward.norm_squared == (5,QQ(21)/5,QQ(64)/21)
    assert reverse.norm_squared == (4,4,4)
    assert reverse.center_denominators == (2,2,2)
    assert gadget_basis(2).norm_squared == (4,)


@pytest.mark.parametrize("q",[3,5,8,17,257])
def test_all_integer_coset_vectors_have_unique_integer_basis_coordinates(q):
    geometry=gadget_basis(q)
    for u in range(min(q,8)):
        for j in range(10):
            x=vector(ZZ,[(-1)**i*(j+3*i) for i in range(geometry.k)])
            x[0] += (u-sum((1 << i)*x[i] for i in range(geometry.k)))%q
            offset=vector(ZZ,[u]+[0]*(geometry.k-1))
            coefficients=geometry.basis.solve_right(x-offset)
            assert all(c in ZZ for c in coefficients)
            assert geometry.basis*coefficients+offset == x


@pytest.fixture(scope="module")
def prime_sampler():
    return GeneralModulusGadgetSampler(17,144)


def test_exact_center_classes_cover_extreme_signed_integer_paths(prime_sampler):
    sampler=prime_sampler
    assert sampler.geometry.center_denominators == (5,21,85,341,17)
    assert sampler.certificate()["center_classes_checked"] == 469
    for u in range(17):
        for i in range(sampler.k):
            later=[(-1)**j*(10**50+j*1234567) for j in range(sampler.k-i-1)]
            center,shift,table=sampler.coordinate_table(i,u,later)
            remaining=vector(QQ,[u]+[0]*(sampler.k-1))
            for j,c in enumerate(later,start=i+1):
                remaining += c*sampler.geometry.basis.column(j)
            direct=-remaining.dot_product(sampler.geometry.orthogonal[i])/sampler.geometry.norm_squared[i]
            assert center == direct and table.center == center-shift
            assert 0 <= table.center < 1


def test_uniform_budget_really_checks_every_center_class(prime_sampler):
    sampler=prime_sampler
    for family in sampler.families:
        assert len(family.tables) == family.denominator
        for center,table in family.tables.items():
            low,high=interval_bounds(table.normalizer)
            assert family.normalizer_lower <= low <= high <= family.normalizer_upper
            assert table.tv_upper <= family.max_scalar_tv
            assert table.center == center
    certificate=sampler.certificate(2)
    assert certificate["finite_table_options"] == {"tail_bits":80,"mass_bits":128,
        "precision_bits":192,"max_trials":128,"max_radius":512}
    assert QQ(certificate["tv_upper_including_abort"]) < QQ(1)/(1 << 70)
    assert certificate["uniform_in_syndrome_and_all_integer_paths"]
    assert certificate["output_space_includes_abort"] and certificate["security_claim"] == "none"


def test_prime_all_syndromes_multiblock_equations_and_fresh_entropy(prime_sampler):
    sampler=prime_sampler
    rng=DeterministicRandom(b"round5-all-prime-u")
    for u in range(17):
        for _ in range(32):
            target=(u,(u+7)%17)
            values=sampler.sample(target,rng=rng)
            assert len(values)==10
            assert all(sum((1 << j)*values[b*5+j] for j in range(5))%17==target[b] for b in range(2))
    a,b=DeterministicRandom(b"round5-repro"),DeterministicRandom(b"round5-repro")
    first=[sampler.sample((1,),rng=a) for _ in range(12)]
    assert first == [sampler.sample((1,),rng=b) for _ in range(12)]
    assert first != [sampler.sample((1,),rng=a) for _ in range(12)]
    assert len(set(first))>2


@pytest.mark.parametrize("q",[6,9,15])
def test_non_power_composite_moduli_sample_all_syndromes(q):
    sampler=GeneralModulusGadgetSampler(q,36)
    rng=DeterministicRandom(f"round5-composite-{q}".encode())
    for u in range(q):
        target=(u,(u+1)%q)
        for _ in range(8):
            values=sampler.sample(target,rng=rng)
            assert len(values)==2*sampler.k
            assert all(sum((1 << j)*values[b*sampler.k+j] for j in range(sampler.k))%q==target[b]
                       for b in range(2))


@pytest.mark.parametrize("q",[2,4,8,16])
def test_reverse_order_exactly_matches_previous_parity_sampler_on_same_entropy(q):
    general=GeneralModulusGadgetSampler(q,9,order="reverse")
    parity=PowerOfTwoGadgetSampler(q,3)
    a,b=DeterministicRandom(b"round5-equivalence"),DeterministicRandom(b"round5-equivalence")
    for u in range(q):
        for _ in range(16):
            assert general.sample((u,(u+1)%q),rng=a) == parity.sample((u,(u+1)%q),rng=b)


def test_exact_finite_law_and_independent_nontrivial_spherical_gap():
    sampler=GeneralModulusGadgetSampler(3,"9/4",tail_bits=16,mass_bits=64,precision_bits=128)
    for u in range(3):
        law=finite_general_gadget_distribution(sampler,u)
        assert sum(law.values())==1
        assert all((v[0]+2*v[1])%3==u for v in law)
    comparison=finite_box_comparison(sampler,0)
    assert comparison["cdf_total_probability"] == "1"
    point=QQ(comparison["zero_vector_cdf_probability"])
    target=comparison["zero_vector_box_target_probability"]
    witness=max(QQ(0),QQ(target["lower"])-point,point-QQ(target["upper"]))
    assert witness>QQ(1)/1000
    assert QQ(comparison["finite_box_tv_interval"]["lower"]) >= witness


def test_vector_statistics_against_independent_spherical_coset_weights():
    sampler=GeneralModulusGadgetSampler(3,36)
    rng=DeterministicRandom(b"round5-prime-moments")
    samples=[sampler.sample((0,),rng=rng) for _ in range(8000)]
    f=RealField(192)
    weights={(a,b):(-f.pi()*(a*a+b*b)/36).exp() for a,b in product(range(-20,21),repeat=2)
             if (a+2*b)%3==0}
    total=sum(weights.values())
    expected_norm=sum(w*(a*a+b*b) for (a,b),w in weights.items())/total
    observed_norm=sum(a*a+b*b for a,b in samples)/len(samples)
    assert abs(observed_norm-float(expected_norm)) < 0.6
    assert all(abs(sum(v[i] for v in samples)/len(samples))<0.15 for i in range(2))
    assert sum(a*a+b*b>36 for a,b in samples)>0


def test_uniform_certificate_dominates_independent_wide_finite_box_comparison():
    sampler=GeneralModulusGadgetSampler(3,36)
    comparison=finite_box_comparison(sampler,0)
    upper=QQ(comparison["finite_box_tv_interval"]["upper"])
    assert comparison["cdf_total_probability"] == "1"
    assert 0 < upper < QQ(sampler.certificate()["tv_upper_including_abort"]) < QQ(1)/10**8
    # The target here is conditioned on the explicit box, not a measured
    # infinite-coset distance; the uniform certificate has the latter scope.


@pytest.mark.parametrize("kwargs",[dict(q=1,s_squared=9),dict(q=True,s_squared=9),
    dict(q=3,s_squared=0),dict(q=3,s_squared=3.0),dict(q=3,s_squared=9,order="reverse"),
    dict(q=3,s_squared=9,step=2),dict(q=3,s_squared=9,max_center_classes=1)])
def test_invalid_or_unadmitted_sampler_options_fail_explicitly(kwargs):
    with pytest.raises(ValueError):
        GeneralModulusGadgetSampler(**kwargs)


def test_large_modulus_no_partial_center_certificate():
    with pytest.raises(ValueError,match="max_center_classes"):
        GeneralModulusGadgetSampler(257,144)


@pytest.mark.parametrize("syndrome",[[],[-1],[17],[True],[0.5]])
def test_bad_syndrome_rejected_before_sampling(prime_sampler,syndrome):
    with pytest.raises(ValueError):
        prime_sampler.sample(syndrome)


def test_readonly_tables_and_entropy_abort_are_explicit(prime_sampler):
    with pytest.raises(TypeError):
        prime_sampler.families[0].tables[QQ(0)] = None
    class Reject:
        def read(self,n):
            return b"\xff"*n
    sampler=GeneralModulusGadgetSampler(3,9,max_trials=1)
    with pytest.raises(SamplingAbort):
        sampler.sample((0,),rng=Reject())


def test_finite_enumeration_guard_does_not_return_partial_pmf():
    with pytest.raises(ValueError,match="max_states"):
        finite_general_gadget_distribution(GeneralModulusGadgetSampler(3,9),0,max_states=1)
