"""Sage-only genuine GenTrap/DelTrap, class admission and failure checks."""

from dataclasses import replace
from itertools import product
from math import lcm
import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage environment")
from sage.all import QQ, ZZ, RealField, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import SamplingAbort, interval_bounds
from experiments.research.mp12_sampled_reference import MP12SampleD
from experiments.research import mp12_trapdoor_chain as chain
from experiments.research.mp12_trapdoor_chain import (GaussianGenTrap,
    RankOneParameters, delegate, delegate_from_tape, make_master_sampler,
    make_user_sampler, rank_one_profile, sampling_class_certificate)
from experiments.research.mp12_trapdoor_chain_audit import (audit_report,
    delegated_quality_budget, generation_law)


@pytest.fixture(scope="module")
def connected():
    params = RankOneParameters()
    generator = GaussianGenTrap(2, 1, 1, 1, **params.table_options)
    prefix = b"ibme-round9:attempt:0"
    setup = DeterministicRandom(prefix+b":setup").read(generator.random_tape_bytes)
    generated = generator.generate_from_tape(setup)
    master = make_master_sampler(generated, params).sampler
    tape = DeterministicRandom(prefix+b":delegation").read(master.random_tape_bytes)
    delegated = delegate_from_tape(master, [[1]], tape)
    user = make_user_sampler(delegated, params).sampler
    return params, generator, generated, master, delegated, user


@pytest.fixture(scope="module")
def multi_column_parent():
    return MP12SampleD(3, [[1]], [[1, -1]], r_squared=9,
        sigma_squared=24, gadget_covariance=5)


@pytest.mark.parametrize("q,n,m_bar,tag", [(2, 1, 1, [[1]]),
    (3, 1, 2, [[2]]), (5, 2, 2, [[1, 2], [0, 3]])])
def test_gaussian_generated_trapdoor_relation_and_canonical_public_matrix(q, n, m_bar, tag):
    generator = GaussianGenTrap(q, n, m_bar, 4)
    tape = DeterministicRandom(f"round9-generic-{q}".encode()).read(generator.random_tape_bytes)
    generated = generator.generate_from_tape(tape, tag=tag)
    j = generated.trapdoor.stack(identity_matrix(ZZ, generator.w))
    assert (generated.public*j-generated.tag*generated.gadget).apply_map(lambda x: x % q).is_zero()
    assert generated.public.dimensions() == (n, m_bar+generator.w)
    assert generated.trapdoor.dimensions() == (m_bar, generator.w)
    assert all(0 <= x < q for x in generated.public.list())
    for value in (generated.a_bar, generated.public, generated.trapdoor, generated.gadget, generated.tag):
        assert value.is_immutable()
    assert generator.generate_from_tape(tape, tag=tag) == generated


@pytest.mark.parametrize("args", [(4, 1, 1, 1), (True, 1, 1, 1),
    (3.0, 1, 1, 1), (3, 0, 1, 1), (3, 1, 0, 1), (3, 8, 1, 1),
    (3, 1, 1, 1.0), (3, 1, 1, -1)])
def test_generation_rejects_composite_inexact_and_resource_inputs(args):
    with pytest.raises(ValueError):
        GaussianGenTrap(*args)


class NoEntropy:
    def read(self, _):
        raise AssertionError("Invalid public input consumed entropy")


def test_invalid_tags_and_fixed_lengths_fail_before_entropy(connected):
    _, generator, _, master, _, _ = connected
    for tag in ([[0]], [[2]], [[True]], [[1, 0]]):
        with pytest.raises(ValueError):
            generator.generate(tag=tag, rng=NoEntropy())
        with pytest.raises(ValueError):
            delegate(master, [[0]], new_tag=tag, rng=NoEntropy())
    for tape in (b"", bytes(generator.random_tape_bytes-1), bytes(generator.random_tape_bytes+1)):
        with pytest.raises(ValueError):
            generator.generate_from_tape(tape)
    for extension in ([[2]], [[-1]], [[True]], [[0, 0]]):
        with pytest.raises(ValueError):
            delegate(master, extension, rng=NoEntropy())
    with pytest.raises(ValueError):
        delegate_from_tape(master, [[0]], bytes(master.random_tape_bytes-1))


def test_generation_uses_fresh_source_and_never_falls_back_after_bounded_abort(connected, monkeypatch):
    _, generator, _, _, _, _ = connected

    class TrackedSource:
        def __init__(self):
            self.source = DeterministicRandom(b"round9-fresh-generation")
            self.reads = []

        def read(self, n):
            data = self.source.read(n)
            self.reads.append(data)
            return data

    rng = TrackedSource()
    generator.generate(rng=rng)
    boundary = len(rng.reads)
    generator.generate(rng=rng)
    # Independent draws can collide in this tiny output space. Freshness is
    # entropy consumption on both calls, rather than output inequality.
    assert boundary > 1 and len(rng.reads) > boundary+1
    assert b"".join(rng.reads[:boundary]) != b"".join(rng.reads[boundary:])
    monkeypatch.setattr(chain, "SecureRandom", lambda: NoEntropy())
    with pytest.raises(SamplingAbort):
        generator.generate_from_tape(b"\xff"*generator.random_tape_bytes)


def test_exact_generation_law_exposes_nonuniform_public_matrix_and_true_gaussian(connected):
    params, generator, _, _, _, _ = connected
    law = generation_law(generator, params.master_quality_squared)
    probabilities = {tuple(row["A"][0]): QQ(row["probability"]) for row in law["public_pmf"]}
    assert sum(probabilities.values()) == 1
    assert probabilities[(0, 0)] == 0 and probabilities[(0, 1)] == QQ(1)/2
    odd = sum((generator.table.probability(r) for r in generator.table.support if r % 2), QQ(0))
    assert probabilities[(1, 0)] == odd/2
    assert generator.table.probability(0) > 20*generator.table.probability(1)
    assert QQ(46)/100 < QQ(law["finite_CDF_public_to_uniform_TV"]) < QQ(47)/100
    assert not law["quality_filter_used_for_public_law"]
    assert 0 < QQ(law["master_quality_rejection_upper"]) < QQ(1)/10**11
    assert not law["satisfies_negligible_regularity"] and law["security_claim"] == "none"


@pytest.mark.parametrize("new_tag", [[[1]], [[2]]])
def test_multicolumn_delegation_relations_and_foo_li_negative_sign(multi_column_parent, new_tag):
    parent = multi_column_parent
    extension = [[0, 0]]
    tape = DeterministicRandom(b"round9-q3-delegation").read(parent.w*parent.random_tape_bytes)
    delegated = delegate_from_tape(parent, extension, tape, parent_tag=[[2]], new_tag=new_tag)
    public = parent.public_matrix([[2]])
    tag = matrix(ZZ, new_tag)
    assert (public*delegated.trapdoor-tag*parent.g).apply_map(lambda x: x % 3).is_zero()
    assert (public*delegated.foo_li_R_id+tag*parent.g).apply_map(lambda x: x % 3).is_zero()
    # An odd modulus catches the sign bug that binary checks cannot detect.
    assert not (public*delegated.trapdoor+tag*parent.g).apply_map(lambda x: x % 3).is_zero()
    assert delegated.trapdoor.is_immutable() and delegated.foo_li_R_id.is_immutable()
    expected_error = min(QQ(1), parent.w*QQ(parent.certificate()["tv_upper_including_abort"]))
    assert delegated.joint_tv_upper == expected_error
    replay = delegate_from_tape(parent, extension, tape, parent_tag=[[2]], new_tag=new_tag)
    assert replay == delegated


def test_each_delegation_column_gets_its_own_fixed_segment(multi_column_parent, monkeypatch):
    parent = multi_column_parent
    tape = DeterministicRandom(b"round9-disjoint-columns").read(parent.w*parent.random_tape_bytes)
    captured = []
    original = parent.sample_from_tape

    def capture(syndrome, segment, **kwargs):
        captured.append((syndrome, segment))
        return original(syndrome, segment, **kwargs)

    monkeypatch.setattr(parent, "sample_from_tape", capture)
    delegate_from_tape(parent, [[0, 2]], tape)
    assert len(captured) == 2
    assert [x[0] for x in captured] == [(1,), (0,)]
    assert b"".join(x[1] for x in captured) == tape
    assert all(len(x[1]) == parent.random_tape_bytes for x in captured)
    assert captured[0][1] != captured[1][1]
    with pytest.raises(ValueError):
        delegate_from_tape(parent, [[0, 2]], tape[:parent.random_tape_bytes])


def test_delegation_abort_is_preserved_without_entropy_fallback(connected, monkeypatch):
    _, _, _, master, _, _ = connected
    monkeypatch.setattr(chain, "SecureRandom", lambda: NoEntropy())
    with pytest.raises(SamplingAbort):
        delegate_from_tape(master, [[0]], b"\xff"*master.random_tape_bytes)


def independent_inverse_metric_geometry(r, params, stage):
    """Direct exact Gram-Schmidt; independent of the closed rank-one formula."""
    dimension, _, r_squared, sigma = params.stage(stage)
    a = vector(QQ, list(r)+[1])
    metric = (r_squared*(sigma*identity_matrix(QQ, dimension)-params.gamma*a.column()*a.row())).inverse()
    orthogonal, norms, mu = [], [], [[QQ(0)]*dimension for _ in range(dimension)]
    for j, e in enumerate(identity_matrix(QQ, dimension).columns()):
        b = e
        for i in range(j):
            mu[j][i] = (e*metric*orthogonal[i])/norms[i]
            b -= mu[j][i]*orthogonal[i]
        orthogonal.append(b)
        norms.append(b*metric*b)
    denominators = [lcm(1, *(int(mu[j][i].denominator())
        for j in range(i+1, dimension))) for i in range(dimension)]
    return denominators, [1/x for x in norms]


@pytest.mark.parametrize("stage", ["master", "user"])
def test_entire_qualified_rank_one_class_matches_independent_geometry(stage):
    params = RankOneParameters()
    bound = sampling_class_certificate(params, stage)
    dimension, quality, _, _ = params.stage(stage)
    radius = int(ZZ(quality).isqrt())
    count, maximum = 0, 0
    for r in product(range(-radius, radius+1), repeat=dimension-1):
        profile = rank_one_profile([[x] for x in r], params, stage)
        if sum(x*x for x in r) > quality:
            assert profile["status"] == "quality_rejected"
            continue
        count += 1
        assert profile["status"] == "qualified"
        denominators, widths = independent_inverse_metric_geometry(r, params, stage)
        assert profile["center_denominators"] == denominators
        assert [QQ(x) for x in profile["coordinate_widths_squared"]] == widths
        assert all(QQ(bound["coordinate_width_squared_range"][0]) <= x <=
            QQ(bound["coordinate_width_squared_range"][1]) for x in widths)
        maximum = max(maximum, sum(denominators))
    assert (count, maximum) == ((5, 7) if stage == "master" else (405, 1792))
    assert maximum <= bound["center_classes_uniform_max"] <= params.max_center_classes


@pytest.mark.parametrize("kwargs,stage", [({"max_center_classes": 1806}, "user"),
    ({"user_quality_squared": 200}, "user"), ({"max_radius": 20}, "user"),
    ({"master_r_squared": "1/100"}, "master")])
def test_class_admission_rejects_public_budget_even_if_a_selected_zero_key_is_easy(kwargs, stage):
    with pytest.raises(ValueError):
        sampling_class_certificate(RankOneParameters(**kwargs), stage)


@pytest.mark.parametrize("kwargs", [{"master_quality_squared": True}, {"gamma": 1},
    {"user_r_squared": 4.0}, {"max_radius": 0}, {"max_trials": 0}])
def test_class_parameters_reject_inexact_and_invalid_values(kwargs):
    with pytest.raises(ValueError):
        RankOneParameters(**kwargs)


def test_actual_generated_and_delegated_samplers_have_public_widths_and_tapes(connected):
    params, generator, generated, master, delegated, user = connected
    assert generated.public == master.public_matrix()
    assert user.public_matrix() == generated.public.augment(delegated.extension)
    assert delegated.foo_li_R_id == -delegated.trapdoor
    assert generator.random_tape_bytes == 2305
    for stage, sampler, width, tape_length in (("master", master, 140, 6912), ("user", user, 3612, 9216)):
        bound = sampling_class_certificate(params, stage)
        assert sampler.r_squared*sampler.sigma_squared == width
        assert sampler.required_tape_bytes <= sampler.random_tape_bytes == tape_length == bound["public_tape_bytes"]
        assert QQ(sampler.certificate()["tv_upper_including_abort"]) <= QQ(bound["uniform_SampleD_tv_upper"])
        assert bound["resource_rejection_given_quality_upper"] == "0"
        for u in range(2):
            tape = DeterministicRandom(f"round9-chain-replay-{stage}-{u}".encode()).read(tape_length)
            x = sampler.sample_from_tape((u,), tape)
            assert sampler.sample_from_tape((u,), tape) == x
            assert tuple(int(v) % 2 for v in sampler.public_matrix()*vector(ZZ, x)) == (u,)


def test_local_tables_are_inside_the_uniform_finite_arithmetic_and_partition_bounds(connected):
    params, _, _, master, _, user = connected
    for stage, sampler in (("master", master), ("user", user)):
        bound = sampling_class_certificate(params, stage)
        weight_width = QQ(bound["uniform_relative_weight_interval_width"])
        normalizer_width = QQ(bound["uniform_normalizer_interval_width"])
        for family in sampler.perturbation.families:
            for table in family.tables.values():
                assert all(hi-lo <= weight_width for lo, hi in
                    zip(table.relative_weight_lower, table.relative_weight_upper))
                lo, hi = interval_bounds(table.normalizer)
                assert hi-lo <= normalizer_width
                assert table.tv_upper <= QQ(bound["uniform_scalar_tv_upper"])
        cert = sampler.perturbation.certificate()
        assert QQ(cert["ideal_nearest_plane_to_nonspherical_tv_upper"]) <= QQ(bound["uniform_nearest_plane_tv_upper"])
        assert QQ(cert["tv_upper_including_abort"]) <= QQ(bound["uniform_perturbation_tv_upper"])


def test_quality_rejection_has_no_hidden_retry_or_sampler_allocation(connected, monkeypatch):
    params, _, generated, _, delegated, _ = connected
    bad_master = replace(generated, trapdoor=matrix(ZZ, [[3]]),
        public=generated.a_bar.augment(matrix(ZZ, [[1]])-3*generated.a_bar).apply_map(lambda x: x % 2))
    bad_user = replace(delegated, trapdoor=matrix(ZZ, [[0], [15]]), extension=matrix(ZZ, [[0]]))

    def forbidden(*args, **kwargs):
        raise AssertionError("Quality rejection allocated/resampled an actual sampler")

    monkeypatch.setattr(chain, "MP12SampleD", forbidden)
    assert make_master_sampler(bad_master, params).status == "master_quality_rejected"
    assert make_user_sampler(bad_user, params).status == "user_quality_rejected"
    with pytest.raises(ValueError):
        make_master_sampler(replace(generated, public=matrix(ZZ, [[0, 0]])), params)
    with pytest.raises(ValueError):
        make_user_sampler(replace(delegated, trapdoor=matrix(ZZ, [[0], [1]])), params)


def test_delegation_quality_tail_covers_all_parent_rows_and_syndromes(connected):
    params = connected[0]
    budget = delegated_quality_budget(params)
    assert budget["qualified_integer_vectors_enumerated"] == 405
    assert len(budget["cases"]) == 6
    assert budget["bound_uniform_in_parent_public_master_trapdoor_and_extension"]
    assert budget["no_rejection_resampling"]
    real = RealField(320)
    # Independent large finite box sanity check against each infinite-tail interval.
    weights = {(x, y): (-real.pi()*real(QQ(x*x+y*y)/140)).exp()
        for x, y in product(range(-70, 71), repeat=2)}
    for case in budget["cases"]:
        a = case["A"][0]
        u = case["syndrome"][0]
        relevant = [(x, w) for x, w in weights.items() if (a[0]*x[0]+a[1]*x[1]) % 2 == u]
        finite_tail = sum(w for x, w in relevant if x[0]**2+x[1]**2 > 128)/sum(w for _, w in relevant)
        interval = case["infinite_target_norm_rejection_interval"]
        assert real(QQ(interval["lower"]))-real("1e-45") < finite_tail < real(QQ(interval["upper"]))+real("1e-45")
    assert QQ(602)/10000 < QQ(budget["user_quality_rejection_upper"]) < QQ(603)/10000


def test_saved_full_attempts_keep_quality_failures_and_public_prefix():
    report = json.loads(Path("docs/research/2026-10-05-round9/mp12-trapdoor-chain-results.json").read_text(encoding="utf-8"))
    rows = report["experiment"]["all_attempts"]
    assert [r["attempt"] for r in rows] == list(range(128))
    failed = [(r["attempt"], r["user_profile"]["norm_squared"]) for r in rows if r["status"] == "user_quality_rejected"]
    assert failed == [(16, 148), (27, 225)]
    assert [r["attempt"] for r in rows if r["materialization_requested_by_public_prefix"]] == [0, 1, 2, 3]
    assert not report["experiment"]["failed_attempts_discarded_or_retried"]
    assert report["experiment"]["counts"]["user_equation_errors"] == 0
    assert report["experiment"]["counts"]["user_sample_attempts"] == 512
    assert report["SIS_gate"] == {"beta_reduction_squared": 5591376, "q_squared": 4, "passed": False}
    assert report["security_claim"] == "none"


@pytest.mark.parametrize("kwargs", [{"attempts": True}, {"attempts": 0},
    {"attempts": 1, "user_prefix": 2}, {"user_prefix": 9}, {"samples_per_user": 0}])
def test_audit_rejects_invalid_counts(kwargs):
    with pytest.raises(ValueError):
        audit_report(**kwargs)
