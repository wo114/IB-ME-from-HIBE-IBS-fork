"""Proved aggregate counts, real unchanged draws and strict budget aborts."""
from fractions import Fraction
from math import comb

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")
from sage.all import QQ

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.candidates.srgg.aggregate_budget import (
    MAX_BYTES, AggregateByteSource, batch_certificate, phase_certificate,
    sample_batch, success_count_bound,
)
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian, conditional_widths


class NoEntropy:
    def read(self, size): raise AssertionError("invalid plan consumed entropy")


@pytest.mark.parametrize("count,p,bits", [(1, Fraction(1, 2), 8), (2, Fraction(3, 4), 8),
                                         (3, Fraction(1, 3), 12), (5, Fraction(2, 3), 8)])
def test_binary_mgf_bound_encloses_independent_exact_binomial_tail(count, p, bits):
    cert = success_count_bound(count, p, bits)
    t = cert["trials"]
    exact = sum((Fraction(comb(t, k))*p**k*(1-p)**(t-k) for k in range(count)), Fraction(0))
    assert exact <= Fraction(cert["overflow_upper_exact"]) <= Fraction(1, 2**(bits+1))
    assert cert["dyadic_exponent"] == count-1-(p*t/2).__floor__()


def test_conditional_bound_encloses_exact_history_dependent_process_without_iid():
    p = Fraction(1, 2)
    cert = success_count_bound(2, p, 8)
    # The next success probability depends on the previous outcome. This is
    # deliberately not an independent Bernoulli sequence.
    distribution = {(0, False): Fraction(1)}
    for _ in range(cert["trials"]):
        next_distribution = {}
        for (successes, previous), mass in distribution.items():
            conditional = Fraction(3, 4) if previous else p
            for success, probability in ((True, conditional), (False, 1-conditional)):
                state = (successes+success, success)
                next_distribution[state] = next_distribution.get(state, Fraction(0))+mass*probability
        distribution = next_distribution
    assert sum(distribution.values()) == 1
    mgf = sum((mass*Fraction(1, 2**successes)
               for (successes, _), mass in distribution.items()), Fraction(0))
    tail = sum((mass for (successes, _), mass in distribution.items() if successes < 2), Fraction(0))
    assert mgf <= (1-p/2)**cert["trials"]
    assert tail <= Fraction(cert["overflow_upper_exact"])


@pytest.mark.parametrize("rank", [2, 3, 4])
def test_every_actual_n512_width_and_phase_count_fits_existing_total_byte_cap(rank):
    c = conditional_candidate(rank=rank)
    for name, width in conditional_widths(c).items():
        count = {"rounding_and_signing_u": (2*rank+c.columns+1)*512,
                 "master_lower": 8*rank*512, "signature_lower": 512}[name]
        cert = batch_certificate(WideScalarGaussian(width, width), count)
        assert cert["admitted"] and cert["uses_probabilistic_cap"]
        assert cert["selected_cap_bytes"] < cert["naive_all_path_bytes"]
        assert Fraction(cert["aggregate_budget_abort_upper_exact"]) <= Fraction(1, 2**128)
        assert Fraction(cert["scalar_kernel_tv_including_aggregate_exact"]) <= Fraction(1, 2**96)
    master = phase_certificate(c, phase="master")
    signature = phase_certificate(c, phase="signature")
    retry_signature = phase_certificate(c, phase="signature", sign_attempts=16)
    assert master["groups"]["master_lower"]["count"] == 8*rank*512
    assert master["groups"]["rounding_and_signing_u"]["count"] == 2*rank*512
    assert master["groups"]["gadget_CDF"]["count"] == 8*rank*512
    assert signature["groups"]["signature_lower"]["count"] == 512
    assert signature["groups"]["rounding_and_signing_u"]["count"] == (c.columns+1)*512
    assert retry_signature["groups"]["signature_lower"]["count"] == 16*512
    for phase in (master, signature, retry_signature):
        assert phase["admitted_under_256MiB"]
        assert phase["naive_all_path_bytes"] > MAX_BYTES
        assert Fraction(phase["aggregate_budget_abort_upper_exact"]) <= Fraction(1, 2**128)
        assert not phase["implemented_n512_phase"]


@pytest.mark.parametrize("name", ["rounding_and_signing_u", "master_lower", "signature_lower"])
def test_real_batch_is_exactly_the_same_unmodified_finite_law_on_the_same_stream(name):
    width = conditional_widths(conditional_candidate())[name]
    sampler = WideScalarGaussian(width, width)
    centers = tuple(QQ((i % 7)-3)/5 for i in range(64))
    source = AggregateByteSource(DeterministicRandom(b"aggregate-real-batch"), MAX_BYTES)
    actual = sample_batch(sampler, width, centers, rng=source)
    plain = DeterministicRandom(b"aggregate-real-batch")
    expected = tuple(sampler.sample(width, center, rng=plain) for center in centers)
    assert actual == expected
    assert 0 < source.used <= batch_certificate(sampler, len(centers))["selected_cap_bytes"]


def test_added_cap_aborts_before_a_read_and_never_falls_back_or_returns_partial_batch():
    class Counter:
        calls = 0
        def read(self, size): self.calls += 1; return bytes(size)
    source = Counter()
    aggregate = AggregateByteSource(source, 5)
    assert aggregate.read(3) == bytes(3)
    with pytest.raises(SamplingAbort, match="aggregate scalar"):
        aggregate.read(3)
    assert source.calls == 1 and aggregate.used == 3


def test_real_scalar_batch_reaches_the_new_cap_before_original_scalar_limits():
    sampler = WideScalarGaussian(64, 64)
    assert sampler.gaussian_trials > 500
    assert sampler.candidate_bytes == 1

    class ForcedLateAcceptance:
        """Nonuniform test source: accept exactly the 500th proposal per scalar."""
        proposals = 0
        completed = 0
        bytes_read = 0
        candidate_next = True

        def read(self, size):
            self.bytes_read += size
            if self.candidate_next:
                assert size == sampler.candidate_bytes
                self.proposals += 1
                chosen = sampler.radius if self.proposals % 500 == 0 else 0
                self.candidate_next = False
                return chosen.to_bytes(size, "big")
            assert size == sampler.bernoulli_bytes
            self.candidate_next = True
            self.completed += self.proposals % 500 == 0
            return b"\xff"*size

    source = ForcedLateAcceptance()
    cap = batch_certificate(sampler, 64)["selected_cap_bytes"]
    with pytest.raises(SamplingAbort, match="aggregate scalar"):
        sample_batch(sampler, 64, (0,)*64, rng=source)
    assert 0 < source.completed < 64
    assert source.proposals <= 64*500
    assert source.bytes_read <= cap
    # This forced source validates only the abort path, not a probability claim.


@pytest.mark.parametrize("centers,kwargs", [([], {}), ((0, 0.1), {}), ((0, 2**2000), {}),
    ((0,), {"max_bytes": 1}), ((0,), {"error_bits": True}), ((0,), {"max_bytes": MAX_BYTES+1})])
def test_every_batch_preflight_rejection_precedes_entropy(centers, kwargs):
    with pytest.raises(ValueError):
        sample_batch(WideScalarGaussian(1, 1), 1, centers, rng=NoEntropy(), **kwargs)


def test_deterministic_full_worst_case_cap_is_used_if_it_is_smaller():
    sampler = WideScalarGaussian(1, 1)
    cert = batch_certificate(sampler, 1, error_bits=512)
    assert not cert["uses_probabilistic_cap"]
    assert cert["selected_cap_bytes"] == cert["naive_all_path_bytes"]
    assert Fraction(cert["aggregate_budget_abort_upper_exact"]) == 0


@pytest.mark.parametrize("count,p,bits", [(0, Fraction(1, 2), 8), (1, Fraction(0), 8),
    (1, Fraction(3, 2), 8), (1, 0.5, 8), (1, Fraction(1, 2), 0)])
def test_invalid_chernoff_inputs_are_rejected(count, p, bits):
    with pytest.raises(ValueError):
        success_count_bound(count, p, bits)
