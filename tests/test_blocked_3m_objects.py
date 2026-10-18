"""Independent version/scope binding and zero-entropy private state restoration."""

from math import isqrt
from unittest.mock import patch
import pytest

pytest.importorskip("sage.all")
from ibme.core.randomness import SecureRandom, DeterministicRandom
from ibme.core.errors import SerializationError, EncodingError
from ibme.hibe.mp12_structured.blocked_prototype import (
    PrototypeParams, PrototypeContext, dump_trapdoor, load_trapdoor, dump_leaf, load_leaf,
)
from ibme.lattice.matrix_sampling.mp12_blocked import generate_root, delegate, BlockedPreimageSampler
from ibme.lattice.matrix_sampling.packed import PackedMatrix

R, S = b"receiver", b"sender"


@pytest.fixture(scope="module")
def chain():
    p = PrototypeParams(q=1099511627689)
    entropy = DeterministicRandom(b"TEST-ONLY:blocked-object-fixed-chain")
    root = generate_root(p.n, p.q, p.root_r_squared, options=p.options(), rng=entropy)
    context = PrototypeContext.create(p, root.public)
    h = PackedMatrix.from_rows(context.h((R,)), p.q-1, False)
    parent = delegate(root, h, options=p.options(), epsilon_bits=p.epsilon_bits, rng=entropy)
    return p, context, root, parent, entropy


def test_public_and_independent_keys_roundtrip_without_entropy(chain):
    p, c, root, parent, _ = chain
    root_wire, parent_wire = dump_trapdoor(c, root), dump_trapdoor(c, parent, R)
    def forbidden(*args, **kwargs): pytest.fail("restore consumed private entropy")
    with patch.object(SecureRandom, "read", forbidden):
        fresh = PrototypeContext.from_bytes(c.to_bytes())
        assert fresh.to_bytes() == c.to_bytes()
        assert dump_trapdoor(fresh, load_trapdoor(root_wire, fresh)) == root_wire
        assert dump_trapdoor(fresh, load_trapdoor(parent_wire, fresh, R), R) == parent_wire
    assert root_wire not in parent_wire
    with pytest.raises(ValueError): load_trapdoor(parent_wire, c)
    with pytest.raises(ValueError): load_trapdoor(parent_wire, c, b"other")


@pytest.mark.parametrize("change", ["truncated", "appended", "duplicate", "version"])
def test_key_parser_rejects_invalid_full_frames(chain, change):
    _, c, _, parent, _ = chain
    raw = dump_trapdoor(c, parent, R)
    if change == "truncated": raw = raw[:-1]
    if change == "appended": raw += b"!"
    if change == "duplicate": raw += raw
    if change == "version": raw = b"X"+raw[1:]
    with pytest.raises((ValueError, SerializationError, EncodingError)):
        # EncodingError/SerializationError are the public strict Reader errors.
        load_trapdoor(raw, c, R)


def test_fixed_256_leaf_roundtrip_and_identity_scope(chain):
    p, c, _, parent, entropy = chain
    h = PackedMatrix.from_rows(c.h((R, S)), p.q-1, False)
    sampler = BlockedPreimageSampler(parent, h, epsilon_bits=p.epsilon_bits, options=p.options())
    samples = PackedMatrix.from_columns(3*p.m, 256, isqrt(3*p.m*p.leaf_width_squared), True,
        (sampler.sample(target, rng=entropy) for target in c.targets(R, S)))
    raw = dump_leaf(c, R, S, samples)
    def forbidden(*args, **kwargs): pytest.fail("leaf restore attempted sampling")
    with patch.object(BlockedPreimageSampler, "sample", forbidden), patch.object(SecureRandom, "read", forbidden):
        restored = load_leaf(raw, c, R, S)
        assert restored.to_bytes() == samples.to_bytes()
    with pytest.raises(ValueError): load_leaf(raw, c, R, b"wrong")


def test_resource_and_noise_conditions_precede_large_allocation():
    with pytest.raises(ValueError, match="entry budget"):
        PrototypeParams(n=4096, root_r_squared=32768)
    for n in (2, 4, 8, 16):
        p = PrototypeParams(n=n, root_r_squared=8*n)
        assert p.q_alpha*p.q_alpha > 4*n
        assert p.noise_budget()["conditional_noise_sufficient"]


def test_failed_parent_slot_stays_occupied_on_disk_and_is_not_reissued(chain, tmp_path, monkeypatch):
    import json
    from experiments.research import blocked_3m_probe as probe
    from experiments.research.gaussian_reference import SamplingAbort
    p, _, root, _, _ = chain
    calls = []
    monkeypatch.setattr(probe, "generate_root", lambda *args, **kwargs: root)
    def fail(*args, **kwargs):
        calls.append("single-attempt")
        raise SamplingAbort("TEST-ONLY deliberate parent abort")
    monkeypatch.setattr(probe, "delegate", fail)
    directory = tmp_path/"occupied"
    with pytest.raises(SamplingAbort): probe.run(directory, p)
    assert (directory/"parent.pending").is_file()
    assert (directory/"root.done").is_file() and (directory/"root.bin").is_file()
    assert not (directory/"parent.bin").exists()
    failure = json.loads((directory/"failure.json").read_bytes())
    assert failure["failure_stage"] == "parent" and failure["no_outer_retry"]
    with pytest.raises(FileExistsError): probe.run(directory, p)
    assert calls == ["single-attempt"]
