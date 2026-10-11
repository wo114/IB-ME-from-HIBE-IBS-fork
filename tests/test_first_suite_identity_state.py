"""H/G, canonical private state and lifecycle tests; toy vectors are not GPV."""

from dataclasses import replace
from fractions import Fraction
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys

import pytest

from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from experiments.research.first_suite.identity import ROHIBEContext, SEED_BITS
from experiments.research.first_suite.leaf_state import (FixedSeedKey, FixedSeedState,
                                                        SeedAddressBlocked, SeedPlan, SeedScope)
from experiments.research.first_suite.seed_kem import SeedCapsule, decode_phase, decapsulate_seed


def oracle():
    return ROHIBEContext(1, 3, 257, ((1, 7, 9),), b"TEST-ONLY/full-public-config", identity_bytes=64)


def scope():
    return SeedScope(oracle(), b"Bob", Fraction(4096), b"TEST-ONLY/PUBLIC-PIVOT-VECTOR/1")


def public_toy_vectors(plan):
    # Root column zero is 1, so these publicly recoverable vectors only exercise
    # state handling and exact equations. They have no Gaussian/secrecy claim.
    q = plan.scope.oracle.q
    return tuple((target[0] if target[0] <= q // 2 else target[0] - q,)
                 + (0,) * (plan.dimension - 1) for target in plan.targets)


def test_real_prefix_and_bit_oracles_are_reproducible_and_unambiguous():
    o = oracle()
    assert o.h((b"ab", b"c")) != o.h((b"a", b"bc"))
    assert o.h((b"Bob", b"Alice")) != o.h((b"Alice", b"Bob"))
    assert o.h((b"Bob",)) != o.h((b"Bob", b"Alice"))
    assert o.h((b"Bob",)) == ROHIBEContext.from_bytes(o.to_bytes()).h((b"Bob",))
    targets = o.targets(b"Bob", b"Alice")
    assert len(targets) == SEED_BITS == 256
    assert all(len(x) == o.n and all(0 <= y < o.q for y in x) for x in targets)
    assert targets != o.targets(b"Bob", b"Carol")
    changed = replace(o, root_rows=((1, 8, 9),))
    assert o.context != changed.context and targets != changed.targets(b"Bob", b"Alice")
    changed = replace(o, public_configuration=b"TEST-ONLY/changed-noise-or-width")
    assert o.context != changed.context and targets != changed.targets(b"Bob", b"Alice")
    assert o.leaf_rows(b"Bob", b"Alice")[0][:3] == o.root_rows[0]
    assert o.leaf_rows(b"Bob", b"Alice")[0][3:6] == o.h((b"Bob",))[0]
    assert o.leaf_rows(b"Bob", b"Alice")[0][6:] == o.h((b"Bob", b"Alice"))[0]


@pytest.mark.parametrize("bad", [(), (b"",), (b"x", b"y", b"z"), (b"x" * 65,), (1,), b"Bob"])
def test_oracle_rejects_invalid_paths(bad):
    with pytest.raises(EncodingError):
        oracle().h(bad)


@pytest.mark.parametrize("position", [-1, 256, True, 1.0])
def test_oracle_position_is_fixed_and_bounded(position):
    with pytest.raises(InvalidParameterError):
        oracle().g((b"Bob", b"Alice"), position)


def test_uniform_rejection_is_exact_and_has_no_modulo_fallback(monkeypatch):
    from experiments.research.first_suite import identity as module
    class Source:
        def __init__(self, domain, data): self.calls = 0
        def read(self, count):
            self.calls += 1
            return b"\xff" if self.calls == 1 else b"\x10"
    monkeypatch.setattr(module, "_OracleStream", Source)
    # 0xff masks to 31 and must be rejected for q=17, rather than become 14.
    assert module._residues(b"H", b"input", 17, 1) == (16,)
    class Exhausted(Source):
        def read(self, count): return b"\xff"
    monkeypatch.setattr(module, "_OracleStream", Exhausted)
    with pytest.raises(InvalidParameterError, match="exhausted"):
        module._residues(b"H", b"input", 17, 1)


def test_big_modulus_public_wire_does_not_truncate_to_uint32():
    q = 274877844481
    o = ROHIBEContext(1, 2, q, ((q - 1, 2**35),), b"TEST-ONLY/64-bit-public", identity_bytes=86)
    decoded = ROHIBEContext.from_bytes(o.to_bytes())
    assert decoded.q == q and decoded.root_rows == o.root_rows
    assert decoded.to_bytes() == o.to_bytes() and decoded.context == o.context


@pytest.mark.parametrize("change", ["truncate", "append", "version", "capacity", "coefficient"])
def test_public_context_strict_wire(change):
    o = oracle()
    raw = o.to_bytes()
    from experiments.research.first_suite.identity import MAGIC
    if change == "truncate": bad = raw[:-1]
    elif change == "append": bad = raw + b"\0"
    elif change == "version": bad = b"X" + raw[1:]
    elif change == "capacity": bad = raw[:len(MAGIC) + 20] + (32).to_bytes(4, "big") + raw[len(MAGIC) + 24:]
    else: bad = raw[:-2] + (257).to_bytes(2, "big")
    with pytest.raises(SerializationError):
        ROHIBEContext.from_bytes(bad)


def test_one_private_key_covers_all_fixed_positions_and_reuses_without_sampling():
    store = FixedSeedState(scope())
    calls = []
    def generate(plan):
        calls.append(plan)
        return public_toy_vectors(plan)
    first = store.resolve(b"Alice", generate)
    assert len(first.preimages) == 256 and len(calls) == 1
    assert store.resolve(b"Alice", generate) is first
    raw = store.to_bytes()
    loaded = FixedSeedState.from_bytes(raw, expected_scope=scope())
    def no_sampling(_):
        raise AssertionError("restored key attempted new sampling")
    second = loaded.resolve(b"Alice", no_sampling)
    assert second.preimages == first.preimages and loaded.to_bytes() == raw
    assert "preimages" not in repr(store) and "root_rows" not in repr(first)


def test_concurrent_requests_return_one_fixed_key_and_snapshot():
    store, calls = FixedSeedState(scope()), []
    def generate(plan):
        calls.append(1)
        return public_toy_vectors(plan)
    with ThreadPoolExecutor(max_workers=4) as pool:
        keys = list(pool.map(lambda _: store.resolve(b"Alice", generate), range(12)))
    assert len(calls) == 1 and all(key is keys[0] for key in keys)
    raw = store.to_bytes()
    assert FixedSeedState.from_bytes(raw, expected_scope=scope()).to_bytes() == raw


def test_address_is_already_failed_in_an_execution_time_snapshot():
    store, captured = FixedSeedState(scope()), []
    def generate(plan):
        captured.append(store.to_bytes())
        return public_toy_vectors(plan)
    store.resolve(b"Alice", generate)
    interrupted = FixedSeedState.from_bytes(captured[0], expected_scope=scope())
    with pytest.raises(SeedAddressBlocked): interrupted.lookup(b"Alice")
    assert store.lookup(b"Alice").preimages


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_failure_tombstone_survives_reload_and_forbids_automatic_retry(failure):
    store = FixedSeedState(scope())
    calls = []
    def generate(_):
        calls.append(1)
        raise failure("forced entropy/sampling failure")
    with pytest.raises(failure):
        store.resolve(b"Alice", generate)
    loaded = FixedSeedState.from_bytes(store.to_bytes(), expected_scope=scope())
    with pytest.raises(SeedAddressBlocked):
        loaded.resolve(b"Alice", generate)
    assert len(calls) == 1


@pytest.mark.parametrize("bad", ["count", "equation", "norm", "integer"])
def test_bad_sample_batch_leaves_a_persistent_failed_address(bad):
    store = FixedSeedState(scope())
    def generate(plan):
        rows = list(public_toy_vectors(plan))
        if bad == "count": rows.pop()
        elif bad == "equation": rows[0] = (rows[0][0] + 1,) + rows[0][1:]
        elif bad == "norm": rows[0] = (rows[0][0] + plan.scope.oracle.q * 10**6,) + rows[0][1:]
        else: rows[0] = (True,) + rows[0][1:]
        return rows
    with pytest.raises(InvalidParameterError):
        store.resolve(b"Alice", generate)
    loaded = FixedSeedState.from_bytes(store.to_bytes(), expected_scope=scope())
    with pytest.raises(SeedAddressBlocked):
        loaded.lookup(b"Alice")


@pytest.mark.parametrize("change", ["receiver", "root", "width", "profile", "capacity"])
def test_loading_requires_the_complete_trusted_scope(change):
    store = FixedSeedState(scope())
    store.resolve(b"Alice", public_toy_vectors)
    s = scope()
    alterations = dict(receiver={"receiver": b"Carol"}, root={"oracle": replace(s.oracle, root_rows=((1, 8, 9),))},
                       width={"width_squared": Fraction(8192)}, profile={"sampler_profile": b"another profile"},
                       capacity={"max_children": 7})
    with pytest.raises(SerializationError, match="scope"):
        FixedSeedState.from_bytes(store.to_bytes(), expected_scope=replace(s, **alterations[change]))


def test_private_wire_rejects_truncation_append_sign_range_and_equation_corruption():
    from experiments.research.first_suite.leaf_state import MAGIC
    from experiments.research.first_suite.identity import Reader
    store = FixedSeedState(scope())
    store.resolve(b"Alice", public_toy_vectors)
    raw = store.to_bytes()
    r = Reader(raw)
    r.take(len(MAGIC)); r.blob(16 * 2**20); r.number(); r.blob(64)
    status_pos = r.pos
    r.take(1)
    vector_pos = r.pos
    r.take(1)
    int_bytes = r.blob(32)
    end = r.pos
    errors = [raw[:-1], raw + b"\0", b"X" + raw[1:],
              raw[:status_pos] + b"\x02" + raw[status_pos + 1:],
              raw[:vector_pos] + b"\x02" + raw[vector_pos + 1:]]
    # Add q to a coefficient: the equation still holds, but the norm check must
    # catch an arbitrarily large representative rather than just check mod q.
    from ibme.core.encoding import encode_bytes
    huge = (int.from_bytes(int_bytes, "big") + 257 * 10**6).to_bytes(8, "big")
    errors.append(raw[:vector_pos] + b"\0" + encode_bytes(huge.lstrip(b"\0")) + raw[end:])
    errors.append(raw[:vector_pos] + b"\0" + encode_bytes(b"\0" + int_bytes) + raw[end:])
    errors.append(raw[:vector_pos] + b"\x01" + encode_bytes(b"\0") + raw[end:])
    for bad in errors:
        with pytest.raises(SerializationError):
            FixedSeedState.from_bytes(bad, expected_scope=scope())


def test_capacity_and_worst_wire_admission_happen_before_generation():
    s = replace(scope(), max_children=1)
    state = FixedSeedState(s)
    state.resolve(b"Alice", public_toy_vectors)
    before = state.to_bytes()
    with pytest.raises(InvalidParameterError, match="capacity"):
        state.resolve(b"Carol", lambda _: pytest.fail("capacity rejection consumed randomness"))
    assert state.to_bytes() == before
    huge = ROHIBEContext(1, 4096, 257, ((1,) + (0,) * 4095,), b"TEST-ONLY/full-public-config")
    state = FixedSeedState(SeedScope(huge, b"Bob", Fraction(4096), b"TEST-ONLY/large"))
    before = state.to_bytes()
    with pytest.raises(InvalidParameterError, match="wire"):
        state.resolve(b"Alice", lambda _: pytest.fail("wire rejection consumed randomness"))
    assert state.to_bytes() == before


def test_raw_seed_codec_and_odd_modulus_decoding_boundaries():
    assert [decode_phase(x, 17) for x in range(17)] == [0] * 4 + [1] * 9 + [0] * 4
    assert [decode_phase(x, 5) for x in range(5)] == [0, 1, 1, 1, 0]
    assert [decode_phase(x, 2) for x in range(2)] == [0, 1]
    o = oracle()
    capsule = SeedCapsule(o.context, o.q, (0,) * o.leaf_dimension, tuple([0, o.q // 2] * 128))
    assert SeedCapsule.from_bytes(capsule.to_bytes()).to_bytes() == capsule.to_bytes()
    key = FixedSeedKey(SeedPlan(scope(), b"Alice"), public_toy_vectors(SeedPlan(scope(), b"Alice")))
    assert decapsulate_seed(key, capsule) == b"\x55" * 32
    assert decapsulate_seed(key, replace(capsule, context=b"X" * 64)) is None
    for bad in [capsule.to_bytes()[:-1], capsule.to_bytes() + b"\0", b"X" + capsule.to_bytes()[1:]]:
        with pytest.raises(SerializationError): SeedCapsule.from_bytes(bad)


def test_private_state_is_reusable_in_a_fresh_process(tmp_path):
    state = FixedSeedState(scope())
    state.resolve(b"Alice", public_toy_vectors)
    path = tmp_path / "private-seed-state.bin"
    path.write_bytes(state.to_bytes())
    script = """
from fractions import Fraction
from pathlib import Path
import sys
sys.path.insert(0, str(Path('src').resolve()))
from experiments.research.first_suite.identity import ROHIBEContext
from experiments.research.first_suite.leaf_state import SeedScope, FixedSeedState
o = ROHIBEContext(1, 3, 257, ((1, 7, 9),), b'TEST-ONLY/full-public-config', identity_bytes=64)
s = SeedScope(o, b'Bob', Fraction(4096), b'TEST-ONLY/PUBLIC-PIVOT-VECTOR/1')
p = Path(sys.argv[1])
r = FixedSeedState.from_bytes(p.read_bytes(), expected_scope=s)
def no_draw(plan): raise RuntimeError('fresh process tried to resample')
assert len(r.resolve(b'Alice', no_draw).preimages) == 256
assert r.to_bytes() == p.read_bytes()
print('restored 256 fixed positions; new draws=0')
"""
    result = subprocess.run([sys.executable, "-c", script, str(path)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "new draws=0" in result.stdout
