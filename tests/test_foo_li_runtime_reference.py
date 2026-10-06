"""Research wiring and initialization checks, not proof of IBS security."""

from dataclasses import replace
from itertools import product
import json

import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage environment")
from sage.all import QQ, ZZ, RealIntervalField, block_matrix, identity_matrix, matrix, vector

from ibme.core.randomness import DeterministicRandom
from experiments.research import foo_li_runtime_reference as runtime
from experiments.research.foo_li_runtime_reference import (
    AddressStream, DOMAINS, ResearchConfig, ResearchSession, ShakeOracleCandidate, canonical_json, prepare,
)
from experiments.research.foo_li_initialization import (
    check_initialized_state, initialization_budget, smoothing_from_quality,
)
from experiments.research.general_gadget_reference import gadget_basis
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions
from experiments.research.online_mp12_reference import OnlineGaussianGenTrap
from experiments.research.mp12_trapdoor_chain import GeneratedTrapdoor


class NoEntropy:
    def read(self, _):
        raise AssertionError("Unexpected entropy consumption")


def small_config():
    return ResearchConfig(options=OnlineOptions(tail_bits=24, mass_bits=64,
        precision_bits=128, gaussian_abort_bits=24, max_uniform_trials=64))


@pytest.fixture(scope="module")
def initialized():
    result = ResearchSession.setup(small_config(), b"test-epoch", rng=DeterministicRandom(b"runtime-master-0"))
    assert result.status == "ok"
    return result.value


@pytest.fixture
def session(initialized):
    return ResearchSession.restore(initialized.dump_secret_state())


def issued(session):
    result = session.extract(b"Alice", seed_rng=DeterministicRandom(b"runtime-user-Alice"))
    assert result.status == "ok"
    return result.value


def test_stream_chunking_crosses_block_and_exhaustion():
    length = 2*AddressStream.BLOCK+13
    a, b = AddressStream(b"test", length), AddressStream(b"test", length)
    assert a.read(1)+a.read(65540)+a.read(length-65541) == b.read(length)
    assert a.read(0) == b""
    with pytest.raises(SamplingAbort):
        a.read(1)


def test_five_domains_context_and_framing():
    oracle = ShakeOracleCandidate()
    def value(domain, context=b"context", fields=(b"a", b"bc")):
        return oracle.stream(domain, context, fields, 32).read(32)
    assert len({value(domain) for domain in DOMAINS}) == 5
    assert value(DOMAINS[0]) == value(DOMAINS[0])
    assert value(DOMAINS[0]) != value(DOMAINS[0], fields=(b"ab", b"c"))
    assert value(DOMAINS[0]) != value(DOMAINS[0], context=b"new-context")
    with pytest.raises(ValueError):
        oracle.stream(b"unknown", b"context", (), 1)


def test_actual_generation_certificate(initialized):
    state = initialized.init_state
    assert all(state["conditions"].values())
    assert state["InitGood_this_state"]
    assert not state["population_probability_inferred_from_one_state"]
    budget = initialized.init_budget
    assert QQ(budget["delta_init_upper"]) < QQ(1)/100000
    assert budget["public_A_to_uniform_tv_upper"] is None
    assert budget["OS_CSPRNG_information_theoretic_bound"] is None
    assert budget["smoothing"]["not_MP12_internal_epsilon"]


def test_initializer_tv_and_quality_are_added_once(initialized):
    b = initialized.init_budget
    scalar = initialized.generator.scalar
    d = initialized.config.m_bar*initialized.config.w
    exact_terms = QQ(b["base_uniform_abort_upper"])+d*scalar.tv_upper
    assert QQ(b["joint_generation_tv_including_abort_upper"]) >= exact_terms
    assert QQ(b["delta_init_upper"]) >= QQ(b["joint_generation_tv_including_abort_upper"])+QQ(b["ideal_master_quality_failure_upper"])
    f, a = RealIntervalField(256), b["first_bad_coordinate_absolute"]
    v = initialized.generator.width_squared
    independent = 2*d*(-f.pi()*a*a/v).exp()/(1-(-f.pi()*(2*a+1)/v).exp())
    assert QQ(b["ideal_coordinate_union_tail_upper"]) >= independent.upper().exact_rational()


@pytest.mark.parametrize("args", [(0, 8, 567, "1/4"), (3, -1, 567, "1/4"),
    (3, 8, 0, "1/4"), (3, 8, 1.2, "1/4"), (3, 8, 567, "0"), (3, 8, 567, "1/3")])
def test_invalid_certificate_inputs(args):
    with pytest.raises(ValueError):
        smoothing_from_quality(*args)


def test_insufficient_smoothing_is_unknown_not_zero():
    budget = initialization_budget(OnlineGaussianGenTrap(3, 1, 1), 8, 1, "1/65536")
    assert budget["delta_init_upper"] is None
    assert budget["status"] == "C2_sufficient_condition_not_certified"


def test_independent_basis_for_every_toy_master_in_quality_class():
    # All 75 (Abar,R0) pairs. MP12 5.3 order: gadget columns first.
    q, k, quality = 3, 2, 8
    g = matrix(ZZ, [[1, 2]])
    sg = gadget_basis(q).basis
    count = 0
    for base_entry in range(q):
        for pair in product(range(-2, 3), repeat=2):
            if sum(x*x for x in pair) > quality:
                continue
            r = matrix(ZZ, [pair])
            base = matrix(ZZ, [[base_entry]])
            public = base.augment(g-base*r).apply_map(lambda x: x % q)
            value = (-base_entry) % q
            w = matrix(ZZ, k, 1, [(value >> i) & 1 for i in range(k)])
            lift = block_matrix(ZZ, [[identity_matrix(ZZ, 1), r], [matrix(ZZ, k, 1), identity_matrix(ZZ, k)]])
            b = lift*block_matrix(ZZ, [[identity_matrix(ZZ, 1), matrix(ZZ, 1, k)], [w, sg]])
            assert abs(b.det()) == q and (public*b).apply_map(lambda x: x % q).is_zero()
            orthogonal = []
            for index in [1, 2, 0]:
                col = vector(QQ, b.column(index))
                for previous in orthogonal:
                    col -= col.dot_product(previous)/previous.dot_product(previous)*previous
                assert col.dot_product(col) <= 10*(quality+1)
                orthogonal.append(col)
            count += 1
    assert count == 75


def test_invalid_actual_relation_and_quality(initialized):
    g, c = initialized.generated, initialized.config
    altered = matrix(ZZ, g.public.nrows(), g.public.ncols(), g.public.list())
    altered[0, -1] = (altered[0, -1]+1) % c.q
    state = check_initialized_state(initialized.generator, replace(g, public=altered),
        c.master_quality, c.s_squared, c.epsilon0)
    assert not state["InitGood_this_state"] and not state["conditions"]["master_relation"]
    excessive = matrix(ZZ, [[20, 20]])
    public = g.a_bar.augment(g.gadget-g.a_bar*excessive).apply_map(lambda x: x % c.q)
    state = check_initialized_state(initialized.generator, replace(g, public=public, trapdoor=excessive),
        c.master_quality, c.s_squared, c.epsilon0)
    assert state["conditions"]["master_relation"] and not state["conditions"]["master_quality"]


def test_seed_consumption_cached_extraction_and_repr(session):
    class Tracker:
        reads = []
        def read(self, n):
            self.reads.append(n)
            return b"x"*n
    rng = Tracker()
    first = session.extract(b"Alice", seed_rng=rng)
    assert first.status == "ok" and rng.reads == [32]
    assert session.extract(b"Alice", seed_rng=NoEntropy()).value == first.value
    assert "xxxxxxxx" not in repr(first.value)


def test_actual_signature_replay_after_disk_restore(session, tmp_path):
    issued(session)
    messages = (b"", b"first", b"second", b"a\x00b")
    results = [session.sign_raw(b"Alice", message) for message in messages]
    assert all(result.status == "ok" for result in results)
    assert all(session.verify(b"Alice", message, result.value) for message, result in zip(messages, results))
    path = tmp_path/"research-secret.json"
    path.write_bytes(session.dump_secret_state())
    restored = ResearchSession.restore(path.read_bytes())
    assert restored.dump_secret_state() == session.dump_secret_state()
    assert restored.extract(b"Alice", seed_rng=NoEntropy()).value == session.users[b"Alice"]
    assert [restored.sign_raw(b"Alice", message) for message in messages] == results
    assert [session.sign_raw(b"Alice", message) for message in reversed(messages)] == list(reversed(results))


def test_epoch_config_and_public_matrix_are_bound(initialized):
    g, c = initialized.generated, initialized.config
    epoch = ResearchSession(c, b"different-epoch", g, initialized.k1, initialized.k2)
    cfg = ResearchSession(replace(c, max_users=17), initialized.epoch, g, initialized.k1, initialized.k2)
    assert len({initialized.context, epoch.context, cfg.context}) == 3
    assert initialized.generated.public == epoch.generated.public
    r = g.trapdoor
    base = matrix(ZZ, [[(int(g.a_bar[0, 0])+1) % c.q]])
    public = base.augment(g.gadget-base*r).apply_map(lambda x: x % c.q)
    changed = GeneratedTrapdoor(c.q, base, public, r, g.gadget, g.tag)
    pk = ResearchSession(c, initialized.epoch, changed, initialized.k1, initialized.k2)
    assert pk.context != initialized.context


@pytest.mark.parametrize("mutation", ["trailing", "duplicate", "extra", "badbit", "seed", "bool", "badtrapdoor", "version"])
def test_snapshot_rejects_malformed_input(session, mutation):
    issued(session)
    raw = session.dump_secret_state()
    data = json.loads(raw)
    if mutation == "trailing":
        invalid = raw+b" "
    elif mutation == "duplicate":
        data["users"].append(data["users"][0])
        invalid = canonical_json(data)
    else:
        if mutation == "extra": data["extra"] = 1
        if mutation == "badbit": data["users"][0]["bit"] ^= 1
        if mutation == "seed": data["users"][0]["seed"] = "00"
        if mutation == "bool": data["R0"][0][0] = True
        if mutation == "badtrapdoor": data["users"][0]["T"][0][0] += 1
        if mutation == "version": data["version"] = "wrong"
        invalid = canonical_json(data)
    with pytest.raises(ValueError):
        ResearchSession.restore(invalid)


def test_setup_abort_one_shot_without_seed_or_retry():
    c = small_config()
    generator, _, _, _ = prepare(c)
    class AllFF:
        calls = []
        def read(self, n):
            self.calls.append(n)
            return b"\xff"*n
    rng = AllFF()
    assert ResearchSession.setup(c, b"epoch", rng=rng).status == "setup_sampling_abort"
    assert rng.calls == [generator.random_tape_bytes]


@pytest.mark.parametrize("failure_domain,expected", [(DOMAINS[2], "identity_hash_abort"),
    (DOMAINS[1], "delegation_sampling_abort")])
def test_extraction_failure_persists_without_retry(session, failure_domain, expected, tmp_path):
    class FFOracle(ShakeOracleCandidate):
        def stream(self, domain, context, fields, length):
            if domain == failure_domain:
                from experiments.research.mp12_sampled_reference import FiniteByteTape
                return FiniteByteTape(b"\xff"*length)
            return super().stream(domain, context, fields, length)
    session.oracle = FFOracle()
    assert session.extract(b"Alice", seed_rng=NoEntropy()).status == expected
    path = tmp_path/"failed-secret.json"
    path.write_bytes(session.dump_secret_state())
    restored = ResearchSession.restore(path.read_bytes(), oracle=FFOracle())
    assert restored.extract(b"Alice", seed_rng=NoEntropy()).status == expected
    assert b"Alice" not in restored.users


def test_actual_signature_abort_stable_and_no_fallback(session):
    issued(session)
    class FFSign(ShakeOracleCandidate):
        def stream(self, domain, context, fields, length):
            if domain == DOMAINS[4]:
                from experiments.research.mp12_sampled_reference import FiniteByteTape
                return FiniteByteTape(b"\xff"*length)
            return super().stream(domain, context, fields, length)
    session.oracle = FFSign()
    assert session.sign_raw(b"Alice", b"m").status == "signature_sampling_abort"
    restored = ResearchSession.restore(session.dump_secret_state(), oracle=FFSign())
    assert restored.sign_raw(b"Alice", b"m").status == "signature_sampling_abort"


@pytest.mark.parametrize("exception", [ValueError, RuntimeError, AssertionError])
def test_unexpected_sampler_exception_not_swallowed(session, monkeypatch, exception):
    issued(session)
    def broken(*_, **__):
        raise exception("injected software error")
    monkeypatch.setattr(runtime, "delegate_stream", broken)
    with pytest.raises(exception, match="injected"):
        session.extract(b"Bob", seed_rng=NoEntropy())
    assert b"Bob" not in session.failures


def test_raw_sign_does_not_filter_zero_or_norm(session, monkeypatch):
    issued(session)
    sampler = session._user_sampler(session.users[b"Alice"])
    monkeypatch.setattr(session, "_user_sampler", lambda _: sampler)
    for x in [(0,)*(session.config.m+session.config.w), (10**9,)+(0,)*4]:
        calls = []
        def raw(*_, **__):
            calls.append(1)
            return x
        monkeypatch.setattr(sampler, "sample_from_tape", raw)
        outcome = session.sign_raw(b"Alice", b"raw")
        assert outcome.status == "ok" and outcome.value[0] == x and calls == [1]


def test_verification_boundaries_and_signed_integer_norm(session, monkeypatch):
    c = session.config
    monkeypatch.setattr(session, "identity_matrix", lambda *_: matrix(ZZ, c.n, c.w))
    monkeypatch.setattr(session, "syndrome", lambda *_: (0,))
    d = c.m+c.w
    assert session.verify(b"Alice", b"", ((0,)*d, 0))
    assert not session.verify(b"Alice", b"", ((0,)*d, True))
    assert not session.verify(b"Alice", b"", ((0,)*(d-1), 0))
    assert not session.verify(b"Alice", b"", ((10**9,)+(0,)*(d-1), 0))
    monkeypatch.setattr(session, "generated", replace(session.generated, public=matrix(ZZ, c.n, c.m)))
    monkeypatch.setattr(session, "config", replace(c, user_quality=34, user_r_squared=1))
    # D*t^2 = 5*7*35 = 1225 = 35^2. Dedicated verifier boundary only.
    assert session.verify(b"Alice", b"", ((-35, 0, 0, 0, 0), 0))
    assert not session.verify(b"Alice", b"", ((-36, 0, 0, 0, 0), 0))


def test_bad_configuration_fails_before_entropy():
    with pytest.raises(ValueError):
        ResearchSession.setup(replace(small_config(), user_quality=1), b"epoch", rng=NoEntropy())


def test_wrong_random_byte_count_is_not_sampling_abort(session):
    class Short:
        def read(self, n):
            return bytes(n-1)
    with pytest.raises(ValueError, match="byte type/length"):
        session.extract(b"Alice", seed_rng=Short())
    assert b"Alice" not in session.users and b"Alice" not in session.failures

def test_master_seed_calls_separate_and_no_secret_generation_during_reload(initialized, monkeypatch):
    class Tracked:
        def __init__(self):
            self.source = DeterministicRandom(b"runtime-master-0")
            self.calls = []
        def read(self, n):
            self.calls.append(n)
            return self.source.read(n)
    source = Tracked()
    result = ResearchSession.setup(small_config(), b"test-epoch", rng=source)
    assert result.status == "ok"
    assert source.calls == [result.value.generator.random_tape_bytes, 32, 32]
    monkeypatch.setattr(runtime, "SecureRandom", lambda: NoEntropy())
    assert ResearchSession.restore(result.value.dump_secret_state()).dump_secret_state() == initialized.dump_secret_state()


def test_quality_rejection_cached_not_retried(session, monkeypatch):
    real = runtime.delegate_stream
    calls = []
    def oversized(*args, **kwargs):
        value, hashes = real(*args, **kwargs)
        calls.append(1)
        return replace(value, trapdoor=matrix(ZZ, session.config.m, session.config.w, [10**6]*(session.config.m*session.config.w))), hashes
    monkeypatch.setattr(runtime, "delegate_stream", oversized)
    assert session.extract(b"Alice", seed_rng=NoEntropy()).status == "user_quality_rejected"
    assert session.extract(b"Alice", seed_rng=NoEntropy()).status == "user_quality_rejected"
    restored = ResearchSession.restore(session.dump_secret_state())
    assert restored.extract(b"Alice", seed_rng=NoEntropy()).status == "user_quality_rejected"
    assert calls == [1]


def test_h2_abort_separate_from_sampled_abort(session):
    issued(session)
    class FFMessage(ShakeOracleCandidate):
        def stream(self, domain, context, fields, length):
            if domain == DOMAINS[3]:
                from experiments.research.mp12_sampled_reference import FiniteByteTape
                return FiniteByteTape(b"\xff"*length)
            return super().stream(domain, context, fields, length)
    session.oracle = FFMessage()
    assert session.sign_raw(b"Alice", b"m").status == "public_hash_abort"
    assert not session.verify(b"Alice", b"m", ((0,)*5, 0))


def test_public_uniform_hash_full_band_lengths(session):
    class Recorded(ShakeOracleCandidate):
        def __init__(self):
            self.lengths = []
        def stream(self, domain, context, fields, length):
            self.lengths.append((domain, length))
            return super().stream(domain, context, fields, length)
    oracle = Recorded()
    session.oracle = oracle
    issued(session)
    session.sign_raw(b"Alice", b"m")
    assert (DOMAINS[0], 1) in oracle.lengths
    assert (DOMAINS[1], session.config.w*session.master.random_tape_bytes) in oracle.lengths
    assert (DOMAINS[2], session.config.n*session.config.w*session.config.options.max_uniform_trials) in oracle.lengths
    assert (DOMAINS[3], session.config.n*session.config.options.max_uniform_trials) in oracle.lengths
    assert (DOMAINS[4], session.user_tape_bytes) in oracle.lengths


def test_two_users_keep_distinct_seeds_and_sign_after_full_state_disclosure(session):
    issued(session)
    bob = session.extract(b"Bob", seed_rng=DeterministicRandom(b"runtime-user-Bob"))
    assert bob.status == "ok"
    assert bob.value.seed != session.users[b"Alice"].seed
    signatures = {identity: session.sign_raw(identity, b"same-message") for identity in (b"Alice", b"Bob")}
    restored = ResearchSession.restore(session.dump_secret_state())
    assert {identity: restored.sign_raw(identity, b"same-message") for identity in signatures} == signatures


def test_previous_large_modulus_gets_distinct_c2_certificate():
    generator = OnlineGaussianGenTrap(2147483659, 1, 1)
    budget = initialization_budget(generator, 64, 4095, "1/65536")
    assert budget["smoothing"]["C2_for_all_valid_quality_qualified_trapdoors"]
    assert budget["ideal_zero_center_radial_tail_upper"] == str(QQ(1)/2**32)
    assert QQ(budget["delta_init_upper"]) < QQ(1)/10**9
    assert budget["public_A_to_uniform_tv_upper"] is None
