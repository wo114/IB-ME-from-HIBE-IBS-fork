"""Oracle semantics/regression evidence, not tests of cryptographic randomness."""
import pytest

pytest.importorskip("sage.all", reason="Use prescribed WSL Sage environment")
from ibme.core.randomness import DeterministicRandom
from experiments.research.foo_li_runtime_reference import (
    AddressStream, DOMAINS, ResearchConfig, ResearchSession,
)
from experiments.research.foo_li_oracle_model import LazyBlockOracle
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.online_gaussian_reference import OnlineOptions


class CountingSource:
    def __init__(self):
        self.calls = 0

    def read(self, size):
        self.calls += 1
        return bytes([self.calls % 256])*size


def test_lazy_replay_prefix_chunking_and_no_entropy_at_zero():
    source = CountingSource()
    oracle = LazyBlockOracle(source)
    make = lambda n: oracle.stream(DOMAINS[0], b"ctx", (b"id",), n)
    a = make(65540)
    assert a.read(0) == b"" and source.calls == 0
    result = a.read(3)+a.read(65534)+a.read(3)
    assert source.calls == 2 and oracle.fresh_blocks == 2
    assert make(65540).read(65540) == result
    assert make(7).read(7) == result[:7]
    assert source.calls == 2
    with pytest.raises(SamplingAbort):
        a.read(1)


def test_domain_fields_context_counter_are_distinct_addresses():
    source = CountingSource()
    oracle = LazyBlockOracle(source)
    def read(d, c=b"ctx", f=(b"a", b"bc")):
        return oracle.stream(d, c, f, 1).read(1)
    for domain in DOMAINS:
        read(domain)
    assert source.calls == 5
    read(DOMAINS[0], f=(b"ab", b"c"))
    read(DOMAINS[0], c=b"ctx2")
    assert source.calls == 7
    read(DOMAINS[0])
    assert source.calls == 7
    with pytest.raises(ValueError):
        read(b"unknown")


def test_equal_answers_do_not_merge_addresses():
    class ZeroSource:
        def read(self, n):
            return bytes(n)
    oracle = LazyBlockOracle(ZeroSource())
    for domain in DOMAINS:
        assert oracle.stream(domain, b"c", (b"i",), 1).read(1) == b"\0"
    assert oracle.fresh_blocks == 5


def test_bad_entropy_length_is_not_cached_or_silently_retried():
    class ShortSource:
        def read(self, n):
            return bytes(n-1)
    oracle = LazyBlockOracle(ShortSource())
    with pytest.raises(ValueError):
        oracle.stream(DOMAINS[0], b"c", (), 1).read(1)
    assert oracle.fresh_blocks == 0


@pytest.mark.parametrize("seed", [b"oracle-model-0", b"oracle-model-1"])
def test_actual_lifecycle_with_shared_model_table(seed):
    config = ResearchConfig(options=OnlineOptions(tail_bits=24, mass_bits=64,
        precision_bits=128, gaussian_abort_bits=24, max_uniform_trials=64))
    oracle = LazyBlockOracle(DeterministicRandom(seed))
    setup = ResearchSession.setup(config, b"model-epoch",
        rng=DeterministicRandom(b"runtime-master-0"), oracle=oracle)
    assert setup.status == "ok"
    session = setup.value
    assert session.extract(b"Alice", seed_rng=DeterministicRandom(b"model-user")).status == "ok"
    signed = session.sign_raw(b"Alice", b"fixed-message")
    assert signed.status == "ok"
    assert session.verify(b"Alice", b"fixed-message", signed.value)
    count = oracle.fresh_blocks
    assert session.sign_raw(b"Alice", b"fixed-message") == signed
    restored = ResearchSession.restore(session.dump_secret_state(), oracle=oracle)
    assert restored.sign_raw(b"Alice", b"fixed-message") == signed
    assert oracle.fresh_blocks == count
    # The same model table is necessary; the secret snapshot does not contain it.
    assert len(signed.value[0]) == config.m+config.w
