"""Sage SRGG gadget sampling checks; no complete IBS or safe parameter claim."""

from fractions import Fraction
from collections import Counter

import pytest

pytest.importorskip("sage.all", reason="SRGG interval sampling requires the specified WSL Sage")
from sage.all import QQ, RealField

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import build_gaussian_table_squared
from experiments.research.candidates.srgg.algebra import (
    Params, add, matvec, reconstruct_vector, scale,
)
from experiments.research.candidates.srgg.audit import example
from experiments.research.candidates.srgg.sampling import (
    GadgetSampler, GadgetSamplingAbort, TableOptions, extract_with_gadget,
)


@pytest.mark.parametrize("params", [Params(degree=2, digits=1), Params(), Params(rank=2, p=7), Params(degree=8, digits=4)])
def test_all_scalar_residues_and_randomized_module_extraction(params):
    sampler = GadgetSampler(params, 36)
    rng = DeterministicRandom(b"srgg-actual-gadget-equations")
    for u in range(params.modulus):
        z, error = sampler.sample_scalar(u, rng=rng)
        assert error == u % params.p
        assert (params.p * sum(params.base**i*x for i,x in enumerate(z))-u+error) % params.modulus == 0
    public, r, target, supplied_perturb = example(params, b"randomized-extraction")
    trace = extract_with_gadget(public, r, target, supplied_perturb, sampler, rng=rng)
    assert matvec(params, public.a, trace.raw_vector, params.modulus) == tuple(
        add(h, scale(e, -1), params.modulus) for h,e in zip(target, trace.error))
    assert matvec(params, public.a, reconstruct_vector(public, target, trace.tail), params.modulus) == target
    assert "redacted" in repr(trace)


def test_recurrence_is_randomized_and_not_canonical_digits():
    sampler = GadgetSampler(Params(), 36)
    source = DeterministicRandom(b"srgg-randomized-law")
    vectors = [sampler.sample_scalar(0, rng=source)[0] for _ in range(128)]
    assert len(set(vectors)) > 1
    assert any(x < 0 for z in vectors for x in z)


@pytest.mark.parametrize("residue", [0, 1, 2])
def test_scaled_SampleZ_recipe_has_width_br_not_r(residue):
    p, rf = Params(), RealField(320)
    output = GadgetSampler(p, 36).tables[residue]
    scalar = build_gaussian_table_squared(4, center=Fraction(-residue, p.base))
    shifted = {p.base*t+residue: QQ(weight)/scalar.total_mass
               for t, weight in zip(scalar.support, scalar.masses)}
    support = set(output.support) | set(shifted)
    distance = sum(abs(output.probability(z)-shifted.get(z, QQ(0))) for z in support)/2
    assert distance <= output.tv_upper + scalar.tv_upper
    literal = GadgetSampler(p, 4).tables[residue]
    literal_difference = sum(abs(output.probability(z)-literal.probability(z))
                             for z in set(output.support) | set(literal.support))/2
    assert rf(literal_difference) > rf("0.15")


@pytest.mark.parametrize("u", list(range(9)))
def test_exact_finite_recurrence_laws_normalize_and_keep_syndrome(u):
    p = Params()
    sampler = GadgetSampler(p, 36)
    law = sampler.finite_scalar_distribution(p.p*u)
    assert sum(law.values(), QQ(0)) == 1
    assert all(sum(p.base**i*x for i,x in enumerate(z)) % p.gadget_modulus == u for z in law)
    assert sampler.finite_scalar_distribution(p.p*u+1) == law


def test_partition_bias_and_error_budgets_are_separate():
    p = Params()
    narrow, wide = GadgetSampler(p, 4), GadgetSampler(p, 144)
    assert QQ(narrow.certificate()["ideal_recurrence_to_spherical_fiber_tv_upper"]) > QQ(1)/10
    record = wide.certificate(blocks=p.degree*p.rank)
    assert QQ(record["total_fiber_tv_upper_including_abort"]) < QQ(1)/2**65
    assert record["scalar_draws"] == p.degree*p.rank*p.digits
    assert record["security_claim"] == "none" and record["backend_admitted"] is False


def test_empirical_scalar_mean_variance_and_tail_match_integer_law():
    sampler = GadgetSampler(Params(), 36)
    table, samples = sampler.tables[1], 4096
    rng = DeterministicRandom(b"srgg-statistics-check")
    counts = Counter(table.sample(rng=rng) for _ in range(samples))
    expected_mean = sum(QQ(x*m)/table.total_mass for x,m in zip(table.support,table.masses))
    expected_variance = sum(QQ(m)/table.total_mass*(x-expected_mean)**2 for x,m in zip(table.support,table.masses))
    mean = QQ(sum(x*n for x,n in counts.items()))/samples
    variance = sum(QQ(n)/samples*(x-mean)**2 for x,n in counts.items())
    assert abs(mean-expected_mean) < QQ(1)/4
    assert abs(variance-expected_variance) < QQ(4)/5
    assert sum(n for x,n in counts.items() if abs(x) >= 12) <= 12


class BadSource:
    def __init__(self, kind):
        self.kind, self.calls = kind, 0

    def read(self, size):
        self.calls += 1
        return b"\xff"*size if self.kind == "reject" else b""


@pytest.mark.parametrize("kind", ["reject", "short"])
def test_entropy_error_and_explicit_abort_have_no_fallback(kind):
    sampler = GadgetSampler(Params(), 36, TableOptions(max_trials=2))
    source = BadSource(kind)
    exception = GadgetSamplingAbort if kind == "reject" else ValueError
    with pytest.raises(exception):
        sampler.sample_scalar(0, rng=source)
    assert source.calls == (2 if kind == "reject" else 1)


@pytest.mark.parametrize("target", [True, -1, 45, 1.0])
def test_invalid_scalar_target_rejected_before_entropy(target):
    source = BadSource("short")
    with pytest.raises(ValueError):
        GadgetSampler(Params(), 36).sample_scalar(target, rng=source)
    assert source.calls == 0


@pytest.mark.parametrize("config", [
    {"tail_bits":True}, {"mass_bits":31}, {"precision_bits":96},
    {"max_trials":0}, {"max_radius":129},
])
def test_sampling_resources_fail_explicitly(config):
    with pytest.raises(ValueError):
        TableOptions(**config)


@pytest.mark.parametrize("width", [True, 0.5, "NaN", -1, 100000, Fraction(1,1000000)])
def test_exact_width_and_scale_admission(width):
    with pytest.raises(ValueError):
        GadgetSampler(Params(), width)


def test_invalid_module_and_parameter_pairing_fail_before_entropy():
    p = Params()
    sampler = GadgetSampler(p, 36)
    source = BadSource("short")
    with pytest.raises(ValueError):
        sampler.sample_module((), rng=source)
    public, r, target, perturb = example(p, b"wrong-config")
    with pytest.raises(ValueError):
        extract_with_gadget(public, r, target, perturb, GadgetSampler(Params(p=7), 36), rng=source)
    assert source.calls == 0


def test_distribution_enumeration_limit_and_cdf_admission_fail_explicitly():
    with pytest.raises(ValueError, match="state budget"):
        GadgetSampler(Params(), 36).finite_scalar_distribution(0, max_states=1)
    with pytest.raises(ValueError, match="Tail target"):
        GadgetSampler(Params(), 36, TableOptions(max_radius=0))


def test_abort_after_first_digit_does_not_return_a_partial_vector():
    class PrefixThenReject:
        calls = 0

        def read(self, size):
            self.calls += 1
            return (b"\x00" if self.calls == 1 else b"\xff") * size

    source = PrefixThenReject()
    with pytest.raises(GadgetSamplingAbort):
        GadgetSampler(Params(), 36, TableOptions(max_trials=2)).sample_scalar(0, rng=source)
    assert source.calls == 3


def test_default_system_source_and_supplied_falsey_source_are_separate(monkeypatch):
    import experiments.research.candidates.srgg.sampling as sampling
    defaults = []

    def system_source():
        defaults.append(True)
        return DeterministicRandom(b"system-source-call-test")

    class FalseySource:
        def __init__(self):
            self.source = DeterministicRandom(b"explicit-source-call-test")
            self.calls = 0

        def __bool__(self): return False

        def read(self, size):
            self.calls += 1
            return self.source.read(size)

    monkeypatch.setattr(sampling, "SecureRandom", system_source)
    sampler = GadgetSampler(Params(), 36)
    sampler.sample_module(((0,)*4,))
    assert len(defaults) == 1
    explicit = FalseySource()
    sampler.sample_scalar(0, rng=explicit)
    assert explicit.calls > 0 and len(defaults) == 1
