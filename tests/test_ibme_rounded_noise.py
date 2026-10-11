"""Actual chi_alpha CDF, independent quadrature, entropy and tail accounting."""

from collections import Counter
from dataclasses import FrozenInstanceError
from fractions import Fraction

import pytest
pytest.importorskip("sage.all",reason="rounded-noise CDF requires prescribed WSL Sage")

import mpmath as mp
from sage.all import RealBallField

from ibme.core.errors import InvalidParameterError,RandomnessError
from ibme.core.randomness import DeterministicRandom
from experiments.research.ibme_rounded_noise import build_rounded_noise,cdf_integer_interval,RoundedNoiseTable
from experiments.research.ibme_noise_budget import RoundedNoiseParams,attach_finite_noise_budget
from experiments.research.ibme_joint_parameters import plan_numeric_candidate


@pytest.fixture(scope="module")
def table():
    return build_rounded_noise(RoundedNoiseParams(q=17,alpha=Fraction(1,17)))


def test_one_byte_exhaustive_distribution_matches_all_integer_masses():
    t=build_rounded_noise(RoundedNoiseParams(q=17,alpha=Fraction(1,17),tail_bits=8,mass_bits=8))
    counts=Counter(t.map_word(word) for word in range(256))
    assert tuple(counts[z] for z in range(-t.radius,t.radius+1))==t.masses
    assert sum(t.masses)==256 and any(m==0 for m in t.masses)
    assert counts[0]>counts[1]>counts[2]


@pytest.mark.parametrize("width", [Fraction(1,16),Fraction(1),Fraction(4),Fraction(32)])
def test_table_vs_independent_continuous_cell_integrals_is_within_certificate(width):
    q=257
    t=build_rounded_noise(RoundedNoiseParams(q=q,alpha=width/q,tail_bits=32,mass_bits=64,precision_bits=192))
    with mp.workdps(100):
        w=mp.mpf(width.numerator)/width.denominator
        density=lambda x:mp.exp(-mp.pi*x*x/(w*w))/w
        actual=mp.mpf(0)
        for z,mass in zip(range(-t.radius,t.radius+1),t.masses):
            # Independent integration, not reuse of the builder's erf balls.
            exact=mp.quad(density,[mp.mpf(z)-mp.mpf('0.5'),mp.mpf(z)+mp.mpf('0.5')])
            actual+=abs(mp.mpf(mass)/t.total-exact)
        tail=mp.erfc(mp.sqrt(mp.pi)*(t.radius+mp.mpf('0.5'))/w)
        measured=(actual+tail)/2
        upper=Fraction(t.certificate()["tv_upper_including_abort"])
        assert measured<=mp.mpf(upper.numerator)/upper.denominator


def test_rounded_continuous_is_not_integer_discrete_gaussian(table):
    with mp.workdps(80):
        rounded_zero=mp.quad(lambda x:mp.exp(-mp.pi*x*x),[-mp.mpf('0.5'),0,mp.mpf('0.5')])
        discrete_zero=1/mp.fsum(mp.exp(-mp.pi*z*z) for z in range(-20,21))
        table_zero=mp.mpf(table.masses[table.radius])/table.total
        assert abs(table_zero-rounded_zero)<mp.mpf('1e-35')
        assert abs(table_zero-discrete_zero)>mp.mpf('0.1')


def test_outward_integer_cdf_encloses_independent_erf_values():
    field=RealBallField(192)
    with mp.workdps(100):
        for half in (-31,-3,-1,1,3,31):
            lower,upper=cdf_integer_interval(field,1,half,2**64)
            value=2**64*(1+mp.erf(mp.sqrt(mp.pi)*half/2))/2
            assert lower<=value<=upper


@pytest.mark.parametrize("word", [-1,True,1.0,None,2**128])
def test_invalid_word_cannot_wrap_or_select_a_default(table,word):
    with pytest.raises(RandomnessError):
        table.map_word(word)


@pytest.mark.parametrize("result", [b"",b"x",b"x"*17,"x"*16,bytearray(16)])
def test_bad_entropy_type_or_length_never_falls_back(table,result):
    class Bad:
        def read(self,count):
            return result
    with pytest.raises(RandomnessError):
        table.sample_signed(rng=Bad())


def test_entropy_exception_propagates(table):
    class Failing:
        def read(self,count):
            raise OSError("entropy unavailable")
    with pytest.raises(OSError,match="entropy"):
        table.sample_mod_q(rng=Failing())


def test_default_source_is_the_system_source(table,monkeypatch):
    import experiments.research.ibme_rounded_noise as module
    calls=[]
    class SystemSource:
        def read(self,count):
            calls.append(count)
            return bytes(count)
    monkeypatch.setattr(module,"SecureRandom",SystemSource)
    assert table.sample_signed()==table.map_word(0)
    assert calls==[16]


def test_non_byte_aligned_uniform_word_masks_only_unused_bits():
    t=build_rounded_noise(RoundedNoiseParams(q=17,alpha=Fraction(1,17),tail_bits=8,mass_bits=9))
    class Source:
        def __init__(self,raw):self.raw=raw
        def read(self,n):assert n==2;return self.raw
    assert t.sample_signed(rng=Source(b"\x00\x03"))==t.sample_signed(rng=Source(b"\xfe\x03"))


@pytest.mark.parametrize("count", [-1,True,1.0,65537])
def test_vector_budget_precedes_entropy(table,count):
    class NoEntropy:
        def read(self,n):pytest.fail("invalid vector sampled entropy")
    with pytest.raises(InvalidParameterError):
        table.sample_vector(count,rng=NoEntropy())


def test_modulo_projection_and_fixed_stream_match_signed_sampling(table):
    a=table.sample_vector(128,rng=DeterministicRandom(b"noise-shared"))
    b=table.sample_vector(128,rng=DeterministicRandom(b"noise-shared"),mod_q=True)
    assert tuple(v%17 for v in a)==b and all(0<=v<17 for v in b)
    assert table.sample_vector(0)==()
    with pytest.raises(FrozenInstanceError):table.params=table.params


def test_actual_target_profile_attaches_to_large_candidate_without_admission():
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))
    t=build_rounded_noise(p)
    b=attach_finite_noise_budget(plan_numeric_candidate(n=1,q=p.q)["conditional_noise"],t.certificate())
    assert b["scalar_noise_draws"]==1668284416
    assert Fraction(b["joint_noise_coupling_upper"])<Fraction(1,2**49)
    assert Fraction(b["lifetime_noise_upper_if_key_norm_good"])>Fraction(1,2**36)
    assert not b["backend_admitted"] and b["security_claim"]=="none"


def test_high_precision_profile_reduces_coupling_error():
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33),tail_bits=160,mass_bits=192,precision_bits=320)
    t=build_rounded_noise(p)
    b=attach_finite_noise_budget(plan_numeric_candidate(n=1,q=p.q)["conditional_noise"],t.certificate())
    assert Fraction(b["joint_noise_coupling_upper"])<Fraction(1,2**129)


def test_narrow_supported_noise_is_certified_without_zero_fallback():
    t=build_rounded_noise(RoundedNoiseParams(q=257,alpha=Fraction(1,2**16)))
    assert t.radius==1 and t.masses[t.radius]>t.total-4
    assert Fraction(t.certificate()["tv_upper_including_abort"])>0


def test_full_word_zero_mass_boundaries_and_last_word_are_valid(table):
    for cutoff in table.thresholds:
        for word in (cutoff-1,cutoff):
            if 0<=word<table.total:
                value=table.map_word(word)
                index=value+table.radius
                previous=table.thresholds[index-1] if index else 0
                assert previous<=word<table.thresholds[index]
    assert -table.radius<=table.map_word(table.total-1)<=table.radius


@pytest.mark.parametrize("kind", ["shape","order","total","units","float"])
def test_malformed_cdf_table_is_rejected(table,kind):
    cuts=list(table.thresholds)
    units=table.interval_error_units
    if kind=="shape":cuts.pop()
    elif kind=="order":cuts[0],cuts[-1]=cuts[-1],cuts[0]
    elif kind=="total":cuts[-1]-=1
    elif kind=="units":units=0
    else:cuts[0]=0.0
    with pytest.raises(InvalidParameterError):
        RoundedNoiseTable(table.params,tuple(cuts),units)


def test_small_audit_records_all_draws_and_checks_an_independent_pmf():
    from experiments.research.ibme_rounded_noise_audit import audit_profile
    result=audit_profile("unit-test",RoundedNoiseParams(q=17,alpha=Fraction(1,17)),count=128)
    assert result["samples"]==128 and result["actual_entropy_bytes"]==128*16
    assert sum(result["histogram"].values())==128
    assert result["independent_pmf_check"]["numeric_tv_below_certificate"]
    assert result["independent_pmf_check"]["numerical_check_is_not_certificate"]


@pytest.mark.parametrize("count", [0,True,65537])
def test_audit_rejects_bad_counts_before_any_samples(count):
    from experiments.research.ibme_rounded_noise_audit import audit_profile
    with pytest.raises(InvalidParameterError):
        audit_profile("invalid",RoundedNoiseParams(q=17,alpha=Fraction(1,17)),count=count)


def test_uncertifiable_cdf_does_not_retry_with_more_precision(monkeypatch):
    import experiments.research.ibme_rounded_noise as module
    calls=[]
    def wide(*args):
        calls.append(1)
        return 0,5
    monkeypatch.setattr(module,"cdf_integer_interval",wide)
    with pytest.raises(InvalidParameterError,match="precision"):
        build_rounded_noise(RoundedNoiseParams(q=17,alpha=Fraction(1,17)))
    assert calls==[1]


def test_falsey_supplied_entropy_source_is_not_replaced(table,monkeypatch):
    import experiments.research.ibme_rounded_noise as module
    class Source:
        def __bool__(self):return False
        def read(self,n):return bytes(n)
    def forbidden():pytest.fail("supplied entropy source was replaced")
    monkeypatch.setattr(module,"SecureRandom",forbidden)
    assert table.sample_signed(rng=Source())==table.map_word(0)
