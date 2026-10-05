"""Sage-only independent laws, algebra, resources and aborts for online MP12."""

from dataclasses import replace
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import QQ, ZZ, RealIntervalField, identity_matrix, matrix, vector

from experiments.research import gaussian_reference as legacy_scalar
from experiments.research import general_gadget_reference as legacy_gadget
from experiments.research import mp12_sampled_reference as legacy_mp12
from experiments.research import online_gaussian_reference as scalar_module
from experiments.research import online_mp12_reference as online_module
from experiments.research.gaussian_reference import SamplingAbort, interval_bounds
from experiments.research.mp12_sampled_reference import FiniteByteTape, MP12SampleD
from experiments.research.mp12_trapdoor_chain import delegate_from_tape
from experiments.research.online_gaussian_reference import OnlineOptions, OnlineScalarGaussian
from experiments.research.online_mp12_reference import (OnlineGadgetSampler,
    OnlineGaussianGenTrap, OnlineMP12SampleD, OnlineNonSphericalSampler,
    delegate_stream, exact_psd_pivots, quality_stage, sampler_for_quality)
from experiments.research.online_sampling_audit import (AuditRandom, audit_report,
    finite_online_nonspherical, non_spherical_comparison, public_generation_bias,
    recover_debug_master_trapdoor)


class NoEntropy:
    def read(self, _):
        raise AssertionError("Invalid public input or abort consumed fallback entropy")


@pytest.fixture(scope="module")
def parent():
    return OnlineMP12SampleD(3, [[1]], [[1, -1]], r_squared=9,
        sigma_squared=24, perturbation_scalar=OnlineScalarGaussian(64, 216))


@pytest.fixture(scope="module")
def saved():
    path = Path(__file__).resolve().parents[1]/"docs/research/2026-10-05-round10/online-sampling-results.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("width,center", [(1, 0), (1, QQ(1)/3), (4, QQ(1)/2),
    (25, QQ(-7)/3), (25, QQ(17)/2)])
def test_scalar_law_against_independently_normalized_infinite_gaussian(width, center):
    online = OnlineScalarGaussian(width, width)
    law = online.finite_distribution(width, center)
    assert sum(law.values()) == 1
    # Independent legacy partition enclosure, at higher precision. Include the
    # infinite target mass outside the new finite support, rather than renormalize.
    reference = legacy_scalar.build_gaussian_table_squared(width, center,
        tail_bits=128, mass_bits=192, precision_bits=256)
    field = RealIntervalField(256)
    inside, difference = field(0), field(0)
    for x, probability in law.items():
        target = (-field.pi()*field((x-center)**2/QQ(width))).exp()/reference.normalizer
        inside += target
        difference += abs(field(probability)-target)
    distance = (difference+1-inside)/2
    assert interval_bounds(distance)[1] <= online.tv_upper
    assert interval_bounds(1-inside)[1] >= 0


def test_huge_rational_center_translation_and_fixed_tape_replay():
    sampler = OnlineScalarGaussian(9, 15)
    fraction = QQ(1)/(10**100+123)
    shift = 10**500
    tape = AuditRandom(b"round10-translate").read(sampler.random_tape_bytes)
    small = sampler.sample_from_tape(12, fraction, tape)
    big = sampler.sample_from_tape(12, shift+fraction, tape)
    assert big-small == shift
    assert big == sampler.sample_from_tape(12, shift+fraction, tape)
    assert sampler.certificate()["CDF_tables"] == 0
    assert not hasattr(sampler, "tables")


@pytest.mark.parametrize("width,center", [(1.0, 0), (True, 0), (1, 0.1),
    (1, True), (0, 0), (3, 0), (1, QQ(1)/2**8200)])
def test_invalid_scalar_inputs_fail_before_entropy(width, center):
    with pytest.raises(ValueError):
        OnlineScalarGaussian(1, 2).sample(width, center, rng=NoEntropy())


@pytest.mark.parametrize("low,high,options", [(0, 1, None), (2, 1, None),
    (1, 10**12+1, None), (1, 10**12, None),
    (1, 1, OnlineOptions(max_radius=1)),
    (1, 1, OnlineOptions(max_gaussian_trials=1)),
    (1, 1, OnlineOptions(max_tape_bytes=1))])
def test_public_class_and_resource_rejections(low, high, options):
    with pytest.raises(ValueError):
        OnlineScalarGaussian(low, high, options=options)


def test_equal_wide_width_is_supported_without_support_enumeration(saved):
    sampler = OnlineScalarGaussian(10**12, 10**12)
    assert sampler.radius > 4096
    assert sampler.gaussian_trials < 1000
    assert sampler.certificate()["support_or_centers_precomputed"] == 0
    sampler.sample(10**12, QQ(1)/10**100, rng=AuditRandom(b"round10-wide-check"))
    with pytest.raises(ValueError, match="enumeration"):
        sampler.finite_distribution(10**12)
    experiment = saved["wide_scalar_experiment"]
    assert experiment["samples"] == 1024
    # A loose diagnostic checks the convention Var ~ width^2/(2*pi).
    assert 0.14 < experiment["variance"]/10**12 < 0.18


def test_clipped_weights_do_not_call_exp_and_are_in_error_budget(monkeypatch):
    sampler = OnlineScalarGaussian(1, 100)
    def forbidden(*_):
        raise AssertionError("Clipped exponent was evaluated")
    monkeypatch.setattr(scalar_module, "capped_exp_minus_pi", forbidden)
    assert sampler.integer_weight(sampler.radius, QQ(1), QQ(0), 0) == 0
    assert sampler.quantization_error >= sampler.max_support_count/QQ(2)**sampler.options.mass_bits


def test_interval_weight_enclosures_and_pivot_mass():
    sampler = OnlineScalarGaussian(1, 25)
    independent = RealIntervalField(256)
    scale = QQ(2)**sampler.options.mass_bits
    for width, center in ((QQ(1), QQ(1)/3), (QQ(25), QQ(1)/2)):
        closest = 0 if center <= QQ(1)/2 else 1
        assert sampler.integer_weight(closest, width, center, closest) == scale
        for x in range(-sampler.radius, sampler.radius+2):
            argument = ((x-center)**2-(closest-center)**2)/width
            target = (-independent.pi()*independent(argument)).exp()
            approximation = QQ(sampler.integer_weight(x, width, center, closest))/scale
            lo, hi = interval_bounds(target)
            assert approximation <= hi
            assert hi-approximation <= sampler.weight_width+1/scale
            assert lo >= 0


def test_uniform_and_outer_gaussian_aborts_are_explicit_and_do_not_retry(monkeypatch):
    opts = OnlineOptions(tail_bits=8, mass_bits=32, precision_bits=96,
        gaussian_abort_bits=8, max_uniform_trials=8)
    sampler = OnlineScalarGaussian(1, 1, options=opts)
    monkeypatch.setattr(scalar_module, "SecureRandom", lambda: NoEntropy())
    class RejectUniform:
        calls = 0
        def read(self, n):
            self.calls += 1
            return b"\xff"*n
    rng = RejectUniform()
    with pytest.raises(SamplingAbort, match="Uniform-integer"):
        sampler.sample(1, rng=rng)
    assert rng.calls == opts.max_uniform_trials
    class RejectGaussian:
        reads = []
        def read(self, n):
            self.reads.append(n)
            return bytes(n) if n == sampler.candidate_bytes else b"\xff"*n
    rng = RejectGaussian()
    with pytest.raises(SamplingAbort, match="Gaussian rejection"):
        sampler.sample(1, rng=rng)
    assert rng.reads == [sampler.candidate_bytes, sampler.bernoulli_bytes]*sampler.gaussian_trials
    with pytest.raises(ValueError, match="fixed length"):
        sampler.sample_from_tape(1, 0, b"")


def test_fresh_random_consumption_and_certificate_copy():
    sampler = OnlineScalarGaussian(1, 1)
    class Tracked:
        def __init__(self):
            self.source = AuditRandom(b"round10-fresh")
            self.reads = []
        def read(self, n):
            data = self.source.read(n)
            self.reads.append(data)
            return data
    rng = Tracked()
    sampler.sample(1, rng=rng)
    before = len(rng.reads)
    sampler.sample(1, rng=rng)
    assert before >= 2 and len(rng.reads) >= before+2
    assert b"".join(rng.reads[:before]) != b"".join(rng.reads[before:])
    cert = sampler.certificate()
    cert["finite_options"]["mass_bits"] = 1
    assert sampler.options.mass_bits == 128
    assert sampler.certificate()["finite_options"]["mass_bits"] == 128
    gadget = OnlineGadgetSampler(3, 45)
    certificate = gadget.certificate()
    certificate["path_resources"]["integer_coefficient_absolute_bounds"][0] = -1
    assert gadget.certificate()["path_resources"]["integer_coefficient_absolute_bounds"][0] > 0


@pytest.mark.parametrize("matrix_input,strict", [([[0, 1], [1, 0]], False),
    ([[1, 2], [2, 1]], False), ([[1, 0], [0, 0]], True),
    ([[1, 1], [0, 1]], False), ([[1.0]], False), ([[True]], False)])
def test_psd_invalid_inputs(matrix_input, strict):
    with pytest.raises(ValueError):
        exact_psd_pivots(matrix_input, strict=strict)


def test_psd_immutable_input_copy_regression():
    value = matrix(QQ, [[2, 1], [1, 2]])
    value.set_immutable()
    assert exact_psd_pivots(value, strict=True) == (2, QQ(3)/2)
    assert exact_psd_pivots([[0, 0], [0, 1]]) == (0, 1)
    assert value == matrix(QQ, [[2, 1], [1, 2]]) and value.is_immutable()


@pytest.mark.parametrize("q", [3, 17, 257, 65537, 2147483659])
def test_general_gadget_equations_and_actual_path_resource_bounds(q):
    sampler = OnlineGadgetSampler(q, 45)
    rng = AuditRandom(f"round10-q-{q}".encode())
    for syndrome in range(q) if q <= 17 else (0, 1, q-1):
        x = sampler.sample((syndrome,), rng=rng)
        assert sum((1 << i)*v for i, v in enumerate(x)) % q == syndrome
        coefficients = sampler.geometry.basis.inverse()*(vector(ZZ, x)-vector(ZZ, [syndrome]+[0]*(sampler.k-1)))
        assert all(c.denominator() == 1 for c in coefficients)
        coefficients = tuple(int(c) for c in coefficients)
        resources = sampler.resources
        assert all(abs(c) <= bound for c, bound in zip(coefficients, resources["integer_coefficient_absolute_bounds"]))
        for i in range(sampler.k):
            center = sampler.center(i, syndrome, coefficients[i+1:])
            assert resources["center_denominators"][i] % center.denominator() == 0
            assert max(abs(int(center.numerator())).bit_length(), int(center.denominator()).bit_length()) <= sampler.scalar.options.rational_bits
    cert = sampler.certificate()
    assert cert["centers_or_CDFs_precomputed"] == 0
    assert QQ(cert["tv_upper_including_abort"]) < QQ(1)/10**6
    if q >= 257:
        assert cert["basis"]["center_classes_total"] > 20000
        with pytest.raises(ValueError, match="All-center"):
            legacy_gadget.GeneralModulusGadgetSampler(q, 45)


def test_no_legacy_cdf_builders_used_and_independent_inverse_metric_geometry(monkeypatch):
    def forbidden(*_, **__):
        raise AssertionError("Online construction called a CDF builder")
    monkeypatch.setattr(legacy_gadget, "build_gaussian_table_squared", forbidden)
    monkeypatch.setattr(legacy_mp12, "build_gaussian_table_squared", forbidden)
    OnlineGadgetSampler(257, 45)
    covariance = matrix(QQ, [[9, 3], [3, 6]])
    new = OnlineNonSphericalSampler(covariance, OnlineScalarGaussian(3, 12))
    # Compute the metric Gram-Schmidt independently with dense matrix products.
    orthogonal, norms = [], []
    for j, e in enumerate(identity_matrix(QQ, 2).columns()):
        current = e
        for i in range(j):
            mu = (e*covariance.inverse()*orthogonal[i])/norms[i]
            assert mu == new.mu[j][i]
            current = current-mu*orthogonal[i]
        norms.append(current*covariance.inverse()*current)
        orthogonal.append(current)
    assert tuple(norms) == new.norm_squared
    for x in product(range(-3, 4), repeat=2):
        v = vector(QQ, x)
        factored = sum(new.norm_squared[i]*(x[i]-new.center(i, x[i+1:]))**2 for i in range(2))
        assert v*covariance.inverse()*v == factored


def test_nonspherical_infinite_distribution_comparison_and_old_law():
    comparison = non_spherical_comparison()
    assert comparison["exact_total_probability"] == "1"
    assert comparison["online_support_points"] > 700
    assert QQ(comparison["online_to_old_CDF_TV"]) < QQ(1)/10**25
    assert QQ(comparison["online_to_infinite_target_TV"]["upper"]) <= QQ(comparison["online_certificate"]["tv_upper_including_abort"])
    sampler = OnlineNonSphericalSampler([[9, 3], [3, 6]], OnlineScalarGaussian(3, 12))
    with pytest.raises(ValueError, match="enumeration"):
        finite_online_nonspherical(sampler, max_states=1)
    with pytest.raises(ValueError):
        OnlineNonSphericalSampler([[9, 3], [3, 6]], OnlineScalarGaussian(5, 10))


@pytest.mark.parametrize("tag,syndrome", [(1, 0), (1, 1), (1, 2), (2, 0), (2, 1), (2, 2)])
def test_full_sampled_trace_and_old_covariance(parent, tag, syndrome):
    trace = parent.sample_trace((syndrome,), tag=[[tag]], rng=AuditRandom(f"round10-trace-{tag}-{syndrome}".encode()))
    a = parent.public_matrix([[tag]])
    assert int((a*vector(ZZ, trace.output))[0]) % 3 == syndrome
    assert vector(ZZ, trace.output) == vector(ZZ, trace.perturbation)+parent.j*vector(ZZ, trace.gadget_preimage)
    assert sum((1 << i)*z for i, z in enumerate(trace.gadget_preimage)) % 3 == trace.gadget_syndrome[0]
    old = MP12SampleD(3, [[1]], [[1, -1]], r_squared=9, sigma_squared=24)
    assert parent.perturbation_covariance == old.perturbation_covariance
    assert parent.perturbation.mu == old.perturbation.mu
    assert parent.perturbation.norm_squared == old.perturbation.norm_squared


def test_streamed_delegation_matches_flat_disjoint_tapes_and_foo_li_sign(parent):
    tape = AuditRandom(b"round10-delegation-equivalence").read(parent.w*parent.random_tape_bytes)
    flat = delegate_from_tape(parent, [[0, 2]], tape, parent_tag=[[2]], new_tag=[[1]])
    streamed, hashes = delegate_stream(parent, [[0, 2]], rng=FiniteByteTape(tape), parent_tag=[[2]], new_tag=[[1]])
    assert streamed == flat
    assert hashes == [sha256(tape[i*parent.random_tape_bytes:(i+1)*parent.random_tape_bytes]).hexdigest() for i in range(parent.w)]
    a = parent.public_matrix([[2]])
    assert (a*streamed.foo_li_R_id+parent.g-streamed.extension).apply_map(lambda x: x % 3).is_zero()
    # q=3 exposes negation errors hidden by q=2.
    assert not (a*streamed.trapdoor+parent.g-streamed.extension).apply_map(lambda x: x % 3).is_zero()
    user = OnlineMP12SampleD(3, a, streamed.trapdoor, r_squared=9,
        sigma_squared=7*(streamed.norm_squared+1),
        perturbation_scalar=quality_stage(5, streamed.norm_squared)[0])
    assert user.public_matrix() == a.augment(streamed.extension)


def test_public_quality_class_covers_all_small_signed_trapdoors_with_fixed_length():
    lengths = set()
    for pair in product(range(-2, 3), repeat=2):
        if sum(x*x for x in pair) > 4:
            continue
        profile, sampler = sampler_for_quality(3, [[1]], [pair], 4)
        assert profile["status"] == "admitted"
        resources = sampler.perturbation.resources
        stage = profile["stage"]
        assert resources["max_center_numerator_bits"] <= stage["uniform_center_numerator_bit_upper"]
        assert resources["max_center_denominator_bits"] <= stage["uniform_center_denominator_bit_upper"]
        lengths.add(sampler.random_tape_bytes)
    assert len(lengths) == 1
    _, stage = quality_stage(65, 4324320)
    assert stage["all_qualified_trapdoors_covered"]
    assert stage["uniform_center_numerator_bit_upper"] < 8192


def test_quality_rejection_is_before_sampler_and_public_class_budget_is_universal(monkeypatch):
    monkeypatch.setattr(online_module, "OnlineMP12SampleD", lambda *_, **__: pytest.fail("Rejected quality instantiated a sampler"))
    profile, sampler = sampler_for_quality(3, [[1]], [[10, 10]], 4)
    assert sampler is None and profile["status"] == "quality_rejected"
    assert profile["norm_squared"] == 200
    with pytest.raises(ValueError, match="canonical"):
        sampler_for_quality(3, [[-1]], [[10, 10]], 4)
    # Even an easy zero key cannot bypass rejection of the whole public class.
    with pytest.raises(ValueError, match="Entire qualified class"):
        sampler_for_quality(17, [[0]], [[0, 0, 0, 0, 0]], 10**6,
            options=replace(OnlineOptions(), rational_bits=128))


@pytest.mark.parametrize("q,n,mbar,tag", [(3, 1, 2, [[2]]),
    (5, 2, 2, [[1, 2], [0, 3]]), (2147483659, 1, 1, [[1]])])
def test_real_gaussian_generation_and_replay(q, n, mbar, tag):
    generator = OnlineGaussianGenTrap(q, n, mbar)
    tape = AuditRandom(f"round10-gen-{q}".encode()).read(generator.random_tape_bytes)
    generated = generator.generate_from_tape(tape, tag=tag)
    assert generated == generator.generate_from_tape(tape, tag=tag)
    assert (generated.public*generated.trapdoor.stack(identity_matrix(ZZ, generator.w))-generated.tag*generated.gadget).apply_map(lambda x: x % q).is_zero()
    assert all(0 <= x < q for x in generated.public.list())
    assert all(m.is_immutable() for m in (generated.a_bar, generated.public, generated.trapdoor, generated.gadget, generated.tag))
    law = generator.scalar.finite_distribution(1)
    assert law[0] > 20*law[1]


@pytest.mark.parametrize("args", [(4, 1, 1), (3.0, 1, 1), (True, 1, 1),
    (3, 0, 1), (3, 1, 0), (3, 64, 1)])
def test_generation_rejects_invalid_and_excessive_dimensions(args):
    with pytest.raises(ValueError):
        OnlineGaussianGenTrap(*args)


def test_bad_tags_extensions_lengths_and_syndromes_fail_before_entropy(parent):
    generator = OnlineGaussianGenTrap(3, 1, 1)
    for tag in ([[0]], [[3]], [[True]], [[1, 0]]):
        with pytest.raises(ValueError):
            generator.generate(tag=tag, rng=NoEntropy())
        with pytest.raises(ValueError):
            parent.sample((0,), tag=tag, rng=NoEntropy())
        with pytest.raises(ValueError):
            delegate_stream(parent, [[0, 0]], new_tag=tag, rng=NoEntropy())
    for extension in ([[3, 0]], [[0, -1]], [[True, 0]], [[0]]):
        with pytest.raises(ValueError):
            delegate_stream(parent, extension, rng=NoEntropy())
    for target in ((3,), (-1,), (True,), (0, 0), ()):
        with pytest.raises(ValueError):
            parent.sample(target, rng=NoEntropy())
    for sampler, invoke in ((generator, lambda tape: generator.generate_from_tape(tape)),
        (parent, lambda tape: parent.sample_from_tape((0,), tape))):
        for offset in (-1, 1):
            with pytest.raises(ValueError, match="fixed length"):
                invoke(bytes(sampler.random_tape_bytes+offset))


def test_debug_public_generation_is_provably_insecure_and_recoverable(saved):
    generator = OnlineGaussianGenTrap(2147483659, 1, 1)
    bias = public_generation_bias(generator)
    assert QQ(bias["public_to_uniform_TV_lower"]) > QQ(999)/1000
    assert not bias["master_quality_filter_applied"] and not bias["near_uniform_gate_passed"]
    for row in saved["connected"]["all_attempts"]:
        recovered, valid = recover_debug_master_trapdoor(matrix(ZZ, row["A"]), generator.q)
        assert valid and recovered == matrix(ZZ, row["R0"])
    zero_base = matrix(ZZ, [[0]+[(1 << i) % generator.q for i in range(generator.w)]])
    recovered, valid = recover_debug_master_trapdoor(zero_base, generator.q)
    assert valid and recovered.is_zero()


def test_saved_connected_attempts_and_archived_public_relations(saved):
    data = saved["connected"]
    q, w = data["q"], data["w"]
    assert (q, w, data["master_dimension"], data["user_dimension"]) == (2147483659, 32, 33, 65)
    assert [r["attempt"] for r in data["all_attempts"]] == [0, 1, 2]
    counts = data["counts"]
    assert counts["qualified_users"] == 3 and counts["materialized_users"] == 1
    assert counts["user_sample_attempts"] == 64
    assert counts["user_sample_abort"] == counts["user_equation_errors"] == 0
    assert not data["failed_attempts_discarded_or_retried"]
    g = matrix(ZZ, [[(1 << j) % q for j in range(w)]])
    for row in data["all_attempts"]:
        a, r = matrix(ZZ, row["A"]), matrix(ZZ, row["R0"])
        delegated, extension = matrix(ZZ, row["delegated_R"]), matrix(ZZ, row["extension"])
        assert (a*r.stack(identity_matrix(ZZ, w))-g).apply_map(lambda x: x % q).is_zero()
        assert (a*delegated+extension-g).apply_map(lambda x: x % q).is_zero()
        assert sum(int(x)**2 for x in delegated.list()) == row["delegated_norm_squared"]
        assert row["debug_public_master_trapdoor_recovery_valid"]
        if row["materialization_requested_by_public_prefix"]:
            user_public = a.augment(extension)
            for sample in row["first_user_outputs"]:
                assert int((user_public*vector(ZZ, sample["x"]))[0]) % q == sample["syndrome"]
            assert row["user_replay_equal"]
            assert int((user_public*vector(ZZ, row["user_replay_output"]))[0]) % q == 12345
        else:
            assert "first_user_outputs" not in row
    gate = data["SIS_norm_gate"]
    assert gate["passed"] and QQ(gate["beta_reduction_squared"]) < q*q
    assert not gate["security_level_estimated"] and saved["security_claim"] == "none"
    assert saved["production_keys_or_IBS_signatures_generated"] == 0


def test_audit_stream_chunking_domain_separation_and_input_limits():
    a, b = AuditRandom(b"round10-chunks"), AuditRandom(b"round10-chunks")
    assert a.read(70000) == b.read(17)+b.read(65536)+b.read(4447)
    assert a.read(16) != AuditRandom(b"round10-other-domain").read(16)
    for n in (-1, True, 1.0, 256*1024*1024+1):
        with pytest.raises(ValueError):
            a.read(n)
    for seed in (b"", "seed", b"x"*4097):
        with pytest.raises(ValueError):
            AuditRandom(seed)


@pytest.mark.parametrize("kwargs", [{"attempts": 0}, {"attempts": 17},
    {"attempts": True}, {"user_prefix": 4}, {"samples_per_syndrome": 0}])
def test_invalid_audit_sizes_fail_before_running_experiments(kwargs, monkeypatch):
    monkeypatch.setattr(online_module, "SecureRandom", lambda: NoEntropy())
    with pytest.raises(ValueError):
        audit_report(**kwargs)
