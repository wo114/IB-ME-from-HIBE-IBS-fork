"""Real SRGG correlated perturbation tests, without an IBS security claim."""

from importlib import import_module, util
from itertools import product
import json

import pytest

pytest.importorskip("sage.all", reason="SRGG perturbations require the specified WSL Sage")
from sage.all import QQ, ZZ, RealField, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research.candidates.srgg.algebra import Params, build_public
from experiments.research.candidates.srgg.geometry import Widths
from experiments.research.candidates.srgg.sampling import GadgetSampler
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions


def api():
    name = "experiments.research.candidates.srgg.perturbation"
    assert util.find_spec(name) is not None, "real correlated SRGG perturbation component is missing"
    return import_module(name)


def case():
    p = Params(degree=2, digits=1)
    r = (((1, 1),), ((1, -1),))
    public = build_public(p, (((4, 7),),), r)
    return p, r, public, ((1, 7),)


def perturbation(**kwargs):
    p, r, _, _ = case()
    return api().MasterPerturbation(p, r, Widths(512, 128, 4), **kwargs)


def flat(values):
    return vector(ZZ, [coefficient for polynomial in values for coefficient in polynomial])


def independent_a(public):
    # Explicit X^2=-1 coefficient blocks; do not call the implementation's
    # polynomial or module operator when checking extraction equations.
    return matrix(ZZ, [[x for a, b in public.a[0] for x in (a, -b)],
                       [x for a, b in public.a[0] for x in (b, a)]])


def test_complete_private_shape_keeps_the_correlation_and_density_scale():
    sampler = perturbation()
    top = matrix(QQ, [[1, -1], [1, 1], [1, 1], [-1, 1]])
    j = top.stack(identity_matrix(QQ, 2))
    target = matrix.diagonal(QQ, [512] * 4 + [128] * 2)
    expected = target - 36 * j * j.transpose()
    assert sampler._sampler.covariance == expected
    assert expected[0, 4] == -36
    assert sampler.public_certificate()["density"] == "exp(-pi*x^T*Sigma_p^-1*x)"


def test_public_width_class_covers_every_degree_two_CBD1_master_witness():
    p = Params(degree=2, digits=1)
    for coefficients in product((-1, 0, 1), repeat=4):
        r = ((coefficients[:2],), (coefficients[2:],))
        sampler = api().MasterPerturbation(p, r, Widths(512, 128, 4))
        cov = sampler._sampler.covariance
        assert (cov - 64 * identity_matrix(QQ, 6)).is_positive_definite()
        assert (512 * identity_matrix(QQ, 6) - cov).is_positive_semidefinite()


def test_actual_perturbations_have_nonzero_cross_covariance():
    sampler = perturbation()
    rng = DeterministicRandom(b"srgg-correlated-target-diagnostic")
    count = 1024
    products = QQ(0)
    for _ in range(count):
        values = flat(sampler.sample(rng=rng))
        products += values[0] * values[4]
    expected = -RealField(192)(36) / (2 * RealField(192).pi())
    # A seeded moment diagnostic distinguishes an independent-coordinate
    # substitute. This is not a proof of the infinite Gaussian distribution.
    assert abs(RealField(192)(products / count) - expected) < 3


def test_real_perturbation_and_gadget_extraction_have_two_separate_relations():
    p, _, public, target = case()
    sampler, gadget = perturbation(), GadgetSampler(p, 36)
    a = independent_a(public)
    changed = 0
    source_p = DeterministicRandom(b"srgg-perturbation-equations")
    source_g = DeterministicRandom(b"srgg-gadget-equations")
    for _ in range(32):
        result = api().extract_with_perturbation(public, target, sampler, gadget,
                                               perturbation_rng=source_p, gadget_rng=source_g)
        assert all(x % p.modulus == 0 for x in a * flat(result.raw.raw_vector)
                   - flat(target) + flat(result.raw.error))
        assert all(x % p.modulus == 0 for x in a * flat(result.reconstructed) - flat(target))
        changed += result.reconstructed[0] != result.raw.raw_vector[0]
        assert "redacted" in repr(result)
    assert changed > 0, "HNF correction must not be silently treated as the raw Gaussian vector"


def test_separate_random_sources_replay_the_whole_component():
    p, _, public, target = case()
    sampler, gadget = perturbation(), GadgetSampler(p, 36)
    def run():
        return api().extract_with_perturbation(public, target, sampler, gadget,
            perturbation_rng=DeterministicRandom(b"srgg-independent-p"),
            gadget_rng=DeterministicRandom(b"srgg-independent-g"))
    assert run() == run()


class BadSource:
    def __init__(self, output="short"):
        self.output, self.calls = output, 0

    def read(self, count):
        self.calls += 1
        return b"" if self.output == "short" else b"\xff" * count


@pytest.mark.parametrize("output,error", [("short", ValueError), ("reject", SamplingAbort)])
def test_entropy_failure_or_abort_never_returns_a_partial_perturbation(output, error):
    sampler = perturbation(options=OnlineOptions(max_uniform_trials=2))
    source = BadSource(output)
    with pytest.raises(error):
        sampler.sample(rng=source)
    assert source.calls == (1 if output == "short" else 2)


@pytest.mark.parametrize("bad_target", [(), ((True, 0),), ((15, 0),), ((0,),)])
def test_invalid_target_is_rejected_before_either_random_source(bad_target):
    p, _, public, _ = case()
    source_p, source_g = BadSource(), BadSource()
    with pytest.raises(ValueError):
        api().extract_with_perturbation(public, bad_target, perturbation(), GadgetSampler(p, 36),
                                       perturbation_rng=source_p, gadget_rng=source_g)
    assert source_p.calls == source_g.calls == 0


def test_wrong_master_relation_and_wrong_gadget_recipe_fail_before_entropy():
    p, _, _, target = case()
    public = build_public(p, (((4, 7),),), (((0, 0),), ((0, 0),)))
    for pub, gadget in ((public, GadgetSampler(p, 36)),
                        (case()[2], GadgetSampler(p, 4)),
                        (case()[2], GadgetSampler(Params(degree=2, digits=1, p=7), 36))):
        source_p, source_g = BadSource(), BadSource()
        with pytest.raises(ValueError):
            api().extract_with_perturbation(pub, target, perturbation(), gadget,
                                           perturbation_rng=source_p, gadget_rng=source_g)
        assert source_p.calls == source_g.calls == 0


def test_falsey_injected_source_is_used_instead_of_system_randomness(monkeypatch):
    module = api()
    def forbidden_default():
        raise AssertionError("explicit random source was discarded")
    monkeypatch.setattr(module, "SecureRandom", forbidden_default)
    class FalseySource:
        def __init__(self):
            self.source, self.calls = DeterministicRandom(b"srgg-falsey-perturbation"), 0
        def __bool__(self): return False
        def read(self, count):
            self.calls += 1
            return self.source.read(count)
    source = FalseySource()
    perturbation().sample(rng=source)
    assert source.calls > 0


@pytest.mark.parametrize("kwargs", [
    {"width_min_squared": 513, "width_max_squared": 514},
    {"width_min_squared": 0},
    {"width_max_squared": 10**12 + 1},
    {"options": OnlineOptions(max_radius=1)},
    {"options": OnlineOptions(max_tape_bytes=1)},
])
def test_public_resource_and_shape_gates_reject_unsuitable_classes(kwargs):
    with pytest.raises(ValueError):
        perturbation(**kwargs)


def test_required_shifted_floor_is_checked_in_addition_to_positive_shape():
    p, _, _, _ = case()
    zero = (((0, 0),), ((0, 0),))
    # Lower block 37-36=1 is SPD, but is below the declared r^2=4 floor.
    with pytest.raises(ValueError, match="positive|margin"):
        api().MasterPerturbation(p, zero, Widths(512, 37, 4))


def test_secret_repr_and_public_certificate_do_not_export_private_geometry():
    sampler = perturbation()
    assert "redacted" in repr(sampler)
    public = sampler.public_certificate()
    assert set(public) == {
        "algorithm", "density", "dimension", "public_width_class_squared",
        "public_tape_bytes", "target_tv_upper_including_abort", "paper_noise_squared",
        "smoothing_floor_squared", "literal_SampleF_implemented", "full_IBS_implemented",
        "constant_time", "security_claim", "backend_admitted",
    }
    assert public["literal_SampleF_implemented"] is False
    assert public["full_IBS_implemented"] is False
    assert QQ(public["target_tv_upper_including_abort"]) < QQ(1) / 2**65
    encoded = json.dumps(public)
    assert all(word not in encoded for word in ("squared_parameter_matrix", "inverse_metric", "center_operator", "trapdoor"))
    public["public_width_class_squared"][0] = "changed"
    assert sampler.public_certificate()["public_width_class_squared"] == ["64", "512"]


def test_public_audit_separates_the_two_equations_without_exporting_vectors():
    name = "experiments.research.candidates.srgg.perturbation_audit"
    assert util.find_spec(name) is not None, "SRGG perturbation public audit is missing"
    report = import_module(name).audit(repetitions=8, rng=DeterministicRandom(b"srgg-public-audit"))
    assert set(report) == {"schema", "parameters", "perturbation", "raw_approximate", "hnf_reconstructed",
                           "observed_aborts", "literal_SampleF_implemented", "full_IBS_implemented",
                           "security_claim", "backend_admitted"}
    assert report["raw_approximate"]["equation_passes"] == 8
    assert report["hnf_reconstructed"]["equation_passes"] == 8
    assert report["hnf_reconstructed"]["same_Gaussian_claim"] is False
    assert report["observed_aborts"] == 0
    assert report["full_IBS_implemented"] is False
    assert report["security_claim"] == "none"
    encoded = json.dumps(report)
    assert all(word not in encoded for word in ("raw_vector", "reconstructed_vector", "center_operator", "squared_parameter_matrix", "seed", "witness"))
