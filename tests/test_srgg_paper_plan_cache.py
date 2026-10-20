"""Preparation reuse; algebra fixtures are NOT cryptographic setup evidence."""
from dataclasses import replace

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_runtime import Backend
from experiments.research.candidates.srgg.paper_algebra import PaperRing, public_matrix
from experiments.research.candidates.srgg.paper_objects import PublicKey, SigningKey
from experiments.research.candidates.srgg.paper_parameters import PaperParams


@pytest.fixture(scope="module")
def key():
    p = PaperParams()
    ring = PaperRing(p)
    seed = bytes(range(32))
    a = public_matrix(p, seed)
    witness = tuple((ring.constant(0),) * (p.rank*p.digits) for _ in range(2*p.rank))
    public = PublicKey(p, seed, a, ring.build_public(a, witness))
    return SigningKey(public, b"public-algebra-only", (ring.constant(0),)*((1+p.digits)*p.rank))


def test_plan_reuses_only_the_same_key_and_options(key, monkeypatch):
    backend = Backend(plan_cache_entries=2)
    built = []

    def build(value):
        plan = object()
        built.append((value, plan))
        return plan

    monkeypatch.setattr(backend, "_build_sign_plan", build)
    first = backend._sign_plan(key)
    assert backend._sign_plan(key) is first
    # Even a deserialized equal key must be prepared and validated separately.
    other = SigningKey.from_bytes(key.to_bytes())
    assert backend._sign_plan(other) is not first
    backend.series_options = replace(backend.series_options, precision_bits=800)
    assert backend._sign_plan(key) is not first
    backend.scalar_options = replace(backend.scalar_options, precision_bits=416)
    backend._sign_plan(key)
    assert len(built) == 4
    assert backend.sign_plan_cache_info() == dict(capacity=2, entries=2, hits=1, misses=4)


def test_lru_clear_and_disable_release_prepared_plans(key, monkeypatch):
    backend = Backend(plan_cache_entries=1)
    monkeypatch.setattr(backend, "_build_sign_plan", lambda value: object())
    first = backend._sign_plan(key)
    backend._sign_plan(SigningKey.from_bytes(key.to_bytes()))
    assert backend._sign_plan(key) is not first
    backend.clear_sign_plan_cache()
    assert backend.sign_plan_cache_info()["entries"] == 0
    backend.configure_sign_plan_cache(0)
    assert backend._sign_plan(key) is not backend._sign_plan(key)
    assert backend.sign_plan_cache_info() == dict(capacity=0, entries=0, hits=0, misses=2)


def test_failed_preparation_is_never_retained(key, monkeypatch):
    backend = Backend()

    def fail(_key):
        raise ArithmeticError("fixed-witness failure")

    monkeypatch.setattr(backend, "_build_sign_plan", fail)
    for _ in range(2):
        with pytest.raises(ArithmeticError):
            backend._sign_plan(key)
    assert backend.sign_plan_cache_info()["entries"] == 0


@pytest.mark.parametrize("capacity", (-1, 17, True, None, 1.5))
def test_preparation_capacity_is_bounded(capacity):
    with pytest.raises(ValueError):
        Backend(plan_cache_entries=capacity)


def test_reused_real_samplef_starts_a_fresh_entropy_budget():
    from ibme.core.randomness import DeterministicRandom

    class Counted:
        def __init__(self):
            self.source = DeterministicRandom(b"TEST-ONLY-SRGG-PREPARATION-EQUIVALENCE")
            self.count = 0

        def read(self, count):
            self.count += count
            return self.source.read(count)

    # The zero algebra key is not a valid SampleF witness. Generate an actual
    # paper root and user key with an explicitly TEST-ONLY deterministic stream.
    issuer = Backend(rng=DeterministicRandom(b"TEST-ONLY-SRGG-CACHE-ROOT"))
    public, master = issuer.setup(PaperParams())
    key = issuer.key_extract(master, b"plan-cache-user")
    cached, reference = Backend(), Backend(plan_cache_entries=0)
    left, right = Counted(), Counted()
    first = cached._sign_plan(key)
    for _ in range(2):
        assert cached._sign_plan(key).sample(rng=left) == reference._sign_plan(key).sample(rng=right)
        assert left.count == right.count > 0
    assert cached._sign_plan(key) is first
    assert cached.sign_plan_cache_info()["hits"] == 3
    cached.rng, reference.rng = left, right
    for message in (b"first", b"second"):
        a, b = cached.sign(key, message), reference.sign(key, message)
        assert a.to_bytes() == b.to_bytes()
        assert left.count == right.count
        assert cached.verify(public, key.identity, message, a)
