"""Sage-only MP12 covariance/distribution/tape checks; no security level."""

from itertools import product

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import QQ, ZZ, RealField, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import interval_bounds
from experiments.research.mp12_sampled_reference import (FiniteByteTape, MP12SampleD,
    NonSphericalGaussianSampler, SamplingAbort, finite_nonspherical_distribution,
    finite_sampled_distribution, psd_pivots, table_byte_bound)
from experiments.research.mp12_sampled_audit import (factorized_infinite_target_comparison,
    research_fixtures)


@pytest.fixture(scope="module")
def stages():
    return research_fixtures()


@pytest.mark.parametrize("value", [[[1, 2], [2, 1]], [[0, 1], [1, 0]],
    [[1, 0], [0, -QQ(1)/2**200]], [[1, 1], [0, 1]], [[1, 0, 0]],
    [[1.0]], [[True]], [], [[1], [1, 2]]])
def test_exact_psd_validation_rejects_indefinite_inexact_and_bad_shapes(value):
    with pytest.raises(ValueError):
        psd_pivots(value)


def test_exact_psd_handles_singular_boundary_without_float_tolerance():
    assert psd_pivots([[1, 1], [1, 1]]) == (1, 0)
    assert psd_pivots([[0, 0], [0, 1]]) == (0, 1)
    with pytest.raises(ValueError):
        psd_pivots([[1, 1], [1, 1]], strict=True)
    with pytest.raises(ValueError):
        psd_pivots([[1, 1], [1, 1-QQ(1)/2**200]])


def test_inverse_metric_exponent_factorization_on_independent_integer_paths():
    sampler = NonSphericalGaussianSampler([[9, 3], [3, 6]])
    assert sampler.families[0].denominator == 2
    for x in product(range(-4, 5), repeat=2):
        v = vector(QQ, x)
        quadratic = v*sampler.inverse*v
        reconstructed = QQ(0)
        for i in range(2):
            center, _, _ = sampler.coordinate_table(i, x[i+1:])
            reconstructed += sampler.norm_squared[i]*(x[i]-center)**2
        assert reconstructed == quadratic


def test_all_fractional_centers_and_infinite_normalizers_are_covered(stages):
    for stage in stages.values():
        sampler = stage.perturbation
        certificate = sampler.certificate()
        assert certificate["uniform_in_all_integer_paths"]
        for i, family in enumerate(sampler.families):
            assert len(family.tables) == family.denominator
            for c, t in family.tables.items():
                assert t.s_squared == 1/sampler.norm_squared[i]
                low, high = interval_bounds(t.normalizer)
                assert family.normalizer_lower <= low <= high <= family.normalizer_upper
                assert t.center == c and t.tv_upper <= family.max_scalar_tv
            archived = certificate["center_families"][i]
            assert QQ(archived["infinite_normalizer_lower"]) == family.normalizer_lower
            assert QQ(archived["infinite_normalizer_upper"]) == family.normalizer_upper
        for i in range(sampler.dimension):
            later = tuple((-1)**j*(10**20+j) for j in range(sampler.dimension-i-1))
            center, shift, table = sampler.coordinate_table(i, later)
            assert center-shift == table.center


def test_independent_nonspherical_finite_law_matches_true_quadratic_weights():
    sampler = NonSphericalGaussianSampler([[9, 3], [3, 6]], tail_bits=30,
        mass_bits=96, precision_bits=192)
    law = finite_nonspherical_distribution(sampler)
    assert sum(law.values(), QQ(0)) == 1
    real = RealField(320)
    weights = {}
    for x in product(range(-30, 31), repeat=2):
        v = vector(QQ, x)
        weights[x] = (-real.pi()*real(v*sampler.inverse*v)).exp()
    total = sum(weights.values())
    distance = sum(abs(real(law.get(x, 0))-w/total) for x, w in weights.items())/2
    assert distance < real(QQ(sampler.certificate()["tv_upper_including_abort"]))
    # An off-diagonal second moment witnesses an actual non-spherical law.
    xy = sum(real(probability)*x[0]*x[1] for x, probability in law.items())
    target_xy = sum(w*x[0]*x[1] for x, w in weights.items())/total
    assert xy > real("0.45") and abs(xy-target_xy) < real("0.001")


def test_nonspherical_sampler_preserves_freshness_and_seed_reproducibility():
    sampler = NonSphericalGaussianSampler([[9, 3], [3, 6]])
    a, b = DeterministicRandom(b"round8-perturb"), DeterministicRandom(b"round8-perturb")
    first = [sampler.sample(rng=a) for _ in range(40)]
    assert first == [sampler.sample(rng=b) for _ in range(40)]
    assert first != [sampler.sample(rng=a) for _ in range(40)]
    assert len(set(first)) > 2


@pytest.mark.parametrize("covariance,options", [([[9, 3], [3, 6]], {"max_center_classes": 1}),
    ([[1, 1], [1, 1]], {}), ([[10000]], {}), ([[9]], {"center": "1/2"}),
    ([[9]], {"max_radius": 0})])
def test_nonspherical_resource_or_precision_failure_never_returns_partial_certificate(covariance, options):
    with pytest.raises(ValueError):
        NonSphericalGaussianSampler(covariance, **options)


def test_covariances_and_separate_master_user_widths_are_exact(stages):
    master, user = stages.values()
    assert master.r_squared*master.sigma_squared == 216
    assert user.r_squared*user.sigma_squared == 640
    assert master.perturbation.dimension == 3 and user.perturbation.dimension == 5
    for sampler in stages.values():
        jjt = sampler.j*sampler.j.transpose()
        sigma = sampler.sigma_squared*identity_matrix(QQ, sampler.dimension)
        assert sampler.perturbation_covariance+sampler.gadget_covariance*jjt == sigma
        assert psd_pivots(sampler.perturbation_covariance-2*jjt) == sampler.margin_pivots
        assert sampler.perturbation.covariance == sampler.r_squared*sampler.perturbation_covariance
        assert sampler.gadget.s_squared == sampler.r_squared*sampler.gadget_covariance


def test_exact_mp12_covariance_boundary_and_arbitrarily_small_violation():
    sampler = MP12SampleD(3, [[2]], [[1, -1]], r_squared=9, sigma_squared=21)
    assert 0 in sampler.margin_pivots
    assert all(x > 0 for x in psd_pivots(sampler.perturbation_covariance, strict=True))
    with pytest.raises(ValueError):
        MP12SampleD(3, [[2]], [[1, -1]], r_squared=9,
            sigma_squared=21-QQ(1)/2**200)


def test_foo_li_trapdoor_sign_adapter_and_master_equation(stages):
    master, user = stages.values()
    a = master.public_matrix()
    r_id = matrix(ZZ, [[1, -1], [1, 0], [0, 1]])
    h1 = a*r_id+user.g
    expected_f = a.augment(h1).apply_map(lambda x: x % 3)
    assert user.public_matrix() == expected_f
    assert user.trapdoor == -r_id
    assert user.public_matrix()*user.j == user.g or \
        (user.public_matrix()*user.j-user.g).apply_map(lambda x: x % 3).is_zero()
    wrong_j = r_id.stack(identity_matrix(ZZ, 2))
    assert not (expected_f*wrong_j-user.g).apply_map(lambda x: x % 3).is_zero()


def test_all_syndromes_and_invertible_tags_satisfy_full_sampled_equation(stages):
    rng = DeterministicRandom(b"round8-full-equation")
    for sampler in stages.values():
        for tag in (1, 2):
            a = sampler.public_matrix([[tag]])
            assert (a*sampler.j-tag*sampler.g).apply_map(lambda x: x % 3).is_zero()
            for u in range(3):
                for _ in range(32):
                    trace = sampler.sample_trace((u,), tag=[[tag]], rng=rng)
                    assert len(trace.output) == sampler.dimension
                    assert tuple(int(x) % 3 for x in a*vector(ZZ, trace.output)) == (u,)
                    assert vector(ZZ, trace.output) == vector(ZZ, trace.perturbation)+\
                        sampler.j*vector(ZZ, trace.gadget_preimage)


def test_multiblock_sampler_and_nondiagonal_tag_inverse():
    sampler = MP12SampleD(3, [[1], [2]], [[0, 0, 0, 0]],
        r_squared=9, sigma_squared=8)
    rng = DeterministicRandom(b"round8-multiblock")
    tag = [[1, 1], [0, 2]]
    a = sampler.public_matrix(tag)
    for u in product(range(3), repeat=2):
        trace = sampler.sample_trace(u, tag=tag, rng=rng)
        assert tuple(int(x) % 3 for x in a*vector(ZZ, trace.output)) == u


def test_smoothing_certificate_with_independent_higher_precision_arithmetic(stages):
    real = RealField(320)
    for sampler in stages.values():
        w = sampler.w
        for width, epsilon in ((sampler.r_squared, sampler.epsilon_j),
            (sampler.r_squared*sampler.gadget_covariance/
                max(sampler.gadget.geometry.norm_squared), sampler.epsilon_g)):
            exact_bound = 2*w/( (real.pi()*real(width)).exp()-2*w )
            assert exact_bound <= real(epsilon)
            assert real(width) >= (real(2*w)*(1+1/real(epsilon))).log()/real.pi()
        c = sampler.certificate()
        assert c["uniform_in_all_syndromes_and_invertible_tags"]
        assert c["security_claim"] == "none" and not c["constant_time"]
        assert QQ(c["tv_upper_including_abort"]) >= QQ(c["ideal_MP12_convolution_tv_upper"])
    assert QQ(stages["master_delegation_oracle"].certificate()["tv_upper_including_abort"]) < QQ(1)/10**10
    assert QQ(stages["user_signing_oracle"].certificate()["tv_upper_including_abort"]) < QQ(1)/10**20


def test_complete_pmf_against_independent_infinite_target():
    result = factorized_infinite_target_comparison()
    assert result["cdf_total_probability"] == "1" and result["all_vectors_satisfy_equation"]
    assert result["certificate_dominates_independent_distance"]
    assert 0 < QQ(result["infinite_target_tv_interval"]["lower"]) < QQ(1)/10
    assert QQ(result["target_mass_outside_finite_cdf_support_interval"]["lower"]) >= 0
    control = result["without_perturbation_negative_control"]
    assert control["all_unperturbed_gadget_outputs_satisfy_equation"]
    assert QQ(control["tv_lower_witness"]) > QQ(4)/5


def test_gaussian_zero_vector_is_not_silently_filtered_by_sampler(stages):
    for sampler in stages.values():
        tables = [f.tables[QQ(0)] for f in reversed(sampler.perturbation.families)]
        tables += [f.tables[QQ(0)] for _ in range(sampler.n) for f in reversed(sampler.gadget.families)]
        pieces = []
        for table in tables:
            i = table.support.index(0)
            ticket = table.cumulative[i]-table.masses[i]
            size = table_byte_bound(table)//table.max_trials
            pieces.append(int(ticket).to_bytes(size, "big"))
        tape = b"".join(pieces).ljust(sampler.random_tape_bytes, b"\0")
        assert sampler.sample_from_tape((0,), tape) == (0,)*sampler.dimension
        assert "not rejected" in sampler.certificate()["zero_vector_policy"]


@pytest.mark.parametrize("overrides", [dict(q=4), dict(q=True), dict(trapdoor=[[1]]),
    dict(a_bar=[[3]]), dict(trapdoor=[[0.5, 1]]), dict(r_squared=0),
    dict(r_squared=0.5), dict(sigma_squared=20), dict(gadget_covariance="3/2"),
    dict(r_squared="1/10"), dict(max_center_classes=1)])
def test_invalid_mp12_preconditions_rejected(overrides):
    params = dict(q=3, a_bar=[[2]], trapdoor=[[1, -1]], r_squared=9, sigma_squared=24)
    params.update(overrides)
    with pytest.raises(ValueError):
        MP12SampleD(**params)


@pytest.mark.parametrize("syndrome,tag", [([], None), ([3], None), ([-1], None),
    ([True], None), ([0], [[0]]), ([0], [[3]]), ([0], [[1.0]]), ([0], [[1, 0]])])
def test_invalid_online_inputs_do_not_consume_entropy(stages, syndrome, tag):
    class NeverRead:
        def read(self, n):
            raise AssertionError("Invalid input consumed entropy")
    with pytest.raises(ValueError):
        stages["master_delegation_oracle"].sample(syndrome, tag=tag, rng=NeverRead())


def test_fixed_tape_length_replay_and_prefix_equivalence(stages):
    for sampler in stages.values():
        source = DeterministicRandom(b"round8-tape")
        tape = source.read(sampler.random_tape_bytes)
        x = sampler.sample_from_tape((1,), tape)
        assert x == sampler.sample_from_tape((1,), tape)
        assert x == sampler.sample((1,), rng=FiniteByteTape(tape+b"unused bytes"))
        for bad in (tape[:-1], tape+b"x", "not bytes"):
            with pytest.raises(ValueError):
                sampler.sample_from_tape((1,), bad)
        expected = sampler.perturbation.random_tape_bytes+sampler.n*sum(
            max(table_byte_bound(t) for t in f.tables.values()) for f in sampler.gadget.families)
        assert expected == sampler.required_tape_bytes <= sampler.random_tape_bytes
        assert sampler.certificate()["tape_exhaustion_probability_at_certified_length"] == "0"


def test_public_tape_length_is_independent_of_trapdoor_and_cdf_center_geometry(stages):
    original = stages["master_delegation_oracle"]
    other = MP12SampleD(3, [[2]], [[0, 0]], r_squared=9, sigma_squared=24)
    assert other.perturbation.certificate()["center_classes_checked"] != \
        original.perturbation.certificate()["center_classes_checked"]
    assert other.random_tape_bytes == original.random_tape_bytes == 11520
    options = original.perturbation.table_options
    for sampler in (original, other):
        for family in sampler.perturbation.families+sampler.gadget.families:
            for table in family.tables.values():
                assert len(table.support) <= 2*options["max_radius"]+2
                assert table.total_mass <= (1 << options["mass_bits"])*(2*options["max_radius"]+2)
        assert sampler.certificate()["tape_length_depends_only_on_public_dimensions_and_table_options"]


def test_worst_case_successful_entropy_consumption_does_not_exhaust_certified_tape(stages):
    class LastTrialAccept:
        def __init__(self, tables):
            self.schedule = []
            self.position = 0
            for table in tables:
                size = table_byte_bound(table)//table.max_trials
                self.schedule.extend([b"\xff"*size]*(table.max_trials-1)+[b"\0"*size])
        def read(self, n):
            result = self.schedule.pop(0)
            assert len(result) == n
            self.position += n
            return result
    for sampler in stages.values():
        # Exercise every scalar table at its own longest rejection path; the
        # max-over-centers tape budget must dominate their summed byte counts.
        p_tables = [max(f.tables.values(), key=table_byte_bound) for f in sampler.perturbation.families]
        g_tables = [max(f.tables.values(), key=table_byte_bound) for f in sampler.gadget.families]
        tables = p_tables+g_tables*sampler.n
        source = LastTrialAccept(tables)
        for table in tables:
            table.sample(rng=source)
        assert source.position <= sampler.random_tape_bytes and not source.schedule


def test_exhaustion_and_rejection_abort_are_distinct_explicit_failures(stages):
    tape = FiniteByteTape(b"a")
    assert tape.read(1) == b"a"
    with pytest.raises(SamplingAbort, match="exhausted"):
        tape.read(1)
    sampler = stages["master_delegation_oracle"]
    with pytest.raises(SamplingAbort, match="rejection limit"):
        sampler.sample_from_tape((0,), b"\xff"*sampler.random_tape_bytes)
    c = sampler.certificate()
    assert QQ(c["random_rejection_abort_upper"]) == QQ(sampler.dimension+sampler.w)/2**128


def test_enumeration_caps_and_readonly_geometry():
    sampler = NonSphericalGaussianSampler([[9, 3], [3, 6]])
    with pytest.raises(ValueError, match="max_states"):
        finite_nonspherical_distribution(sampler, max_states=1)
    full = MP12SampleD(2, [[1]], [[1]], r_squared=1, sigma_squared=14)
    with pytest.raises(ValueError, match="max_states"):
        finite_sampled_distribution(full, 0, max_states=1)
    with pytest.raises(TypeError):
        sampler.families[0].tables[QQ(0)] = None
    with pytest.raises(ValueError):
        sampler.covariance[0, 0] = 0
