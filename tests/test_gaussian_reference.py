"""Sage-only mathematical reference checks; no IBS/HIBE security claim."""

from collections import Counter
import json

import pytest

pytest.importorskip("sage.all", reason="Run sampling reference tests in the specified WSL Sage environment")
from sage.all import QQ, RealField, RealIntervalField

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import (PowerOfTwoGadgetSampler, SamplingAbort,
    build_gaussian_table, draw_uniform_integer, finite_gadget_distribution, interval_bounds)
from experiments.research.sampling_reference_audit import finite_spherical_comparison


class BytesSequence:
    def __init__(self, values):
        self.values = iter(values)

    def read(self, size):
        return next(self.values).to_bytes(size, "big")


def test_s_equals_sigma_times_sqrt_2pi_not_same_number():
    f = RealField(256)
    s = f(3)
    sigma = s/(2*f.pi()).sqrt()
    assert abs((-f.pi()/s**2).exp()-(-1/(2*sigma**2)).exp()) < f(2)**-240
    assert abs(s-sigma) > 1


def test_exact_parameter_serialization_roundtrip():
    t = build_gaussian_table("3/2", center="1/3", step=2, residue=1)
    again = build_gaussian_table(**json.loads(json.dumps(t.config_record())))
    assert again.certificate()["cdf_sha256"] == t.certificate()["cdf_sha256"]
    assert again.s == QQ(3)/2 and again.center == QQ(1)/3


@pytest.mark.parametrize("config", [dict(s=0), dict(s=-1), dict(s=0.5),
    dict(s=3, center=0.1), dict(s=3, step=0), dict(s=3, mass_bits=0),
    dict(s=3, precision_bits=32), dict(s=3, tail_bits=0), dict(s=10000),
    dict(s=3, max_radius=-1)])
def test_invalid_or_out_of_scope_parameters_rejected(config):
    with pytest.raises(ValueError):
        build_gaussian_table(**config)


def test_tail_target_cannot_silently_fail():
    with pytest.raises(ValueError, match="Tail target not achieved"):
        build_gaussian_table(3, tail_bits=80, max_radius=0)


def test_scalar_certificate_bounds_independent_high_precision_target():
    t = build_gaussian_table(3, center="1/3")
    real = RealField(320)
    weights = {x: (-real.pi()*(real(x)-real(QQ(1)/3))**2/9).exp() for x in range(-45, 46)}
    total = sum(weights.values())
    distance = sum(abs(real(t.probability(x))-w/total) for x, w in weights.items())/2
    assert distance <= real(t.tv_upper)
    assert t.tail_tv_upper <= QQ(1)/(1 << 80)
    assert t.tv_upper < QQ(1)/(1 << 75)
    low, high = interval_bounds(t.normalizer)
    assert real(low) <= total <= real(high)


def test_geometric_tail_dominates_explicit_far_tail():
    t = build_gaussian_table("3/2", center="1/3", step=2, residue=1, tail_bits=20)
    f = RealField(256)
    closest_sq = min((QQ(x)-t.center)**2 for x in t.support)
    outside = [1+2*k for k in range(-30, 31) if 1+2*k not in t.support]
    explicit_tail = sum((-f.pi()*f(((QQ(x)-t.center)**2-closest_sq)/t.s**2)).exp() for x in outside)
    assert explicit_tail <= f(t.tail_relative_upper)


def test_interval_endpoints_enclose_true_weights_and_quantization_error():
    t = build_gaussian_table("3/2", center="1/3", mass_bits=32, precision_bits=96)
    f = RealField(256)
    d0 = min((QQ(x)-t.center)**2 for x in t.support)
    weights = [(-f.pi()*f(((QQ(x)-t.center)**2-d0)/t.s**2)).exp() for x in t.support]
    total = sum(weights)
    distance = sum(abs(f(QQ(m)/t.total_mass)-w/total) for m,w in zip(t.masses,weights))/2
    assert distance <= f(t.quantization_tv_upper)
    for lower, upper, w, mass in zip(t.relative_weight_lower,t.relative_weight_upper,weights,t.masses):
        assert f(lower) <= w <= f(upper)
        assert QQ(mass)/(1 << 32) <= lower


def test_zero_mass_cdf_intervals_are_never_selected():
    t = build_gaussian_table(1, center="1/2", tail_bits=9, mass_bits=3, precision_bits=96)
    assert t.support == (-1, 0, 1, 2) and t.masses == (0, 8, 8, 0)
    results = [t.sample(rng=BytesSequence([ticket])) for ticket in range(16)]
    assert Counter(results) == {0: 8, 1: 8}


def test_uniform_integer_rejects_excess_bits_without_modulo_bias():
    assert draw_uniform_integer(BytesSequence([255, 254]), 3) == 2
    assert [draw_uniform_integer(BytesSequence([x]), 3) for x in (0,1,2)] == [0,1,2]
    assert draw_uniform_integer(BytesSequence([]), 1) == 0


def test_bounded_rejection_abort_is_explicit():
    with pytest.raises(SamplingAbort):
        draw_uniform_integer(BytesSequence([3,3,3]), 3, max_trials=3)


@pytest.mark.parametrize("data", [b"", b"ab", "x"])
def test_invalid_random_source_reads_rejected(data):
    class Bad:
        def read(self, n):
            return data
    with pytest.raises(ValueError, match="invalid byte"):
        draw_uniform_integer(Bad(), 3)


def test_system_entropy_and_fixed_test_entropy_remain_separate():
    with pytest.raises(TypeError):
        SecureRandom(b"seed")
    t = build_gaussian_table(3)
    a,b = DeterministicRandom(b"round4-test"), DeterministicRandom(b"round4-test")
    first = [t.sample(rng=a) for _ in range(64)]
    assert first == [t.sample(rng=b) for _ in range(64)]
    assert first != [t.sample(rng=a) for _ in range(64)]
    assert len(set(first)) > 2
    assert t.sample() in t.support  # Smoke check of the system source, no fixed output.


def test_discrete_statistics_against_independent_theoretical_weights():
    t = build_gaussian_table(3)
    rng = DeterministicRandom(b"round4-moments")
    values = [t.sample(rng=rng) for _ in range(12000)]
    observed_mean = sum(values)/len(values)
    observed_variance = sum(x*x for x in values)/len(values)-observed_mean**2
    f = RealField(160)
    weights = {x: (-f.pi()*x*x/9).exp() for x in range(-20,21)}
    target_variance = sum(w*x*x for x,w in weights.items())/sum(weights.values())
    assert abs(observed_mean) < 0.06
    assert abs(observed_variance-float(target_variance)) < 0.10
    assert sum(abs(x) >= 3 for x in values) > 0


@pytest.mark.parametrize("q", [2,4,8,16])
def test_all_syndromes_and_block_dimensions_match_gadget_equation(q):
    sampler = PowerOfTwoGadgetSampler(q, 3)
    rng = DeterministicRandom(f"round4-all-u-{q}".encode())
    for u in range(q):
        for _ in range(8):
            syndrome = (u,(u+1)%q)
            z = sampler.sample(syndrome, rng=rng)
            assert len(z) == 2*sampler.k
            for block,target in enumerate(syndrome):
                assert sum((1 << j)*z[block*sampler.k+j] for j in range(sampler.k))%q == target


@pytest.mark.parametrize("q", [0,1,3,7,257])
def test_general_modulus_not_silently_treated_as_power_of_two(q):
    with pytest.raises(ValueError):
        PowerOfTwoGadgetSampler(q, 3)


@pytest.mark.parametrize("syndrome", [[], [-1], [8], [True], [0.5]])
def test_invalid_syndrome_rejected(syndrome):
    with pytest.raises(ValueError):
        PowerOfTwoGadgetSampler(8,3).sample(syndrome)


def test_exact_small_gadget_law_sums_to_one_and_is_supported_on_coset():
    sampler = PowerOfTwoGadgetSampler(4, "3/2", tail_bits=16, mass_bits=32, precision_bits=96)
    for u in range(4):
        law = finite_gadget_distribution(sampler,u)
        assert sum(law.values()) == 1
        assert all((v[0]+2*v[1])%4 == u for v in law)


def test_small_s_has_visible_parity_normalizer_bias_despite_modular_correctness():
    sampler = PowerOfTwoGadgetSampler(8,"3/2",tail_bits=40,mass_bits=96,precision_bits=160)
    result = finite_spherical_comparison(sampler,0)
    lower = QQ(result["finite_box_tv_interval"]["lower"])
    # A point-event witness supplies an independent lower bound on TV. The
    # intended counterexample is a visible gap, not the earlier unsupported 1%.
    witness = (QQ(result["zero_vector_spherical_probability"]["lower"])
               - QQ(result["zero_vector_cdf_probability"]))
    assert witness > QQ(1)/200
    assert lower >= witness and lower > QQ(1)/200
    assert result["cdf_total_probability"] == "1"
    certificate = sampler.certificate()
    assert QQ(certificate["ideal_parity_to_spherical_tv_upper"]) > QQ(1)/100


def test_wider_reference_width_has_small_uniform_gadget_bound():
    sampler = PowerOfTwoGadgetSampler(16,12)
    certificate = sampler.certificate(2)
    assert QQ(certificate["tv_upper_including_abort"]) < QQ(1)/(1 << 70)
    assert certificate["scalar_draws_per_vector"] == 8
    assert certificate["bound_uniform_in_syndrome"]
    assert certificate["security_claim"] == "none"


def test_enum_resource_guard_is_explicit():
    with pytest.raises(ValueError,match="max_states"):
        finite_gadget_distribution(PowerOfTwoGadgetSampler(16,3),0,max_states=1)
