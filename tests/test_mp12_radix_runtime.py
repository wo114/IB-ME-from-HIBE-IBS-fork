"""Opt-in high-radix real sampling, complete delegation and strict profiles."""

from dataclasses import asdict
import json
from math import isqrt
from pathlib import Path
from unittest.mock import patch

import pytest
pytest.importorskip("sage.all", reason="use WSL ~/miniconda3/envs/sage")
from sage.all import QQ, ZZ, matrix, vector, identity_matrix

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.hibe.mp12_structured.blocked_prototype import (
    PrototypeParams, PrototypeContext, RadixPrototypeParams, RadixPrototypeContext,
    dump_trapdoor, load_trapdoor, dump_leaf, load_leaf,
)
from ibme.lattice.chkp.joint_parameters import smoothing_factor
from ibme.lattice.chkp.basis import gram_schmidt_squared_lengths
from ibme.lattice.matrix_sampling.prime_gadget import PrimeGadgetSampler, prime_gadget_kernel
from ibme.lattice.matrix_sampling.mp12_blocked import generate_root, delegate, BlockedPreimageSampler
from ibme.lattice.matrix_sampling.packed import PackedMatrix
from experiments.research.structured_radix_screen import width_group

Q = 5998976077229064136548861031
R, S = b"receiver", b"sender"


def entropy(label):
    return DeterministicRandom(b"TEST-ONLY:high-radix-runtime:"+label)


@pytest.mark.parametrize("bits", (2, 10, 12, 32))
def test_real_radix_gadget_cosets_and_complete_public_kernel(bits):
    block = prime_gadget_kernel(Q, radix_bits=bits)
    basis = matrix(ZZ, block.basis_rows)
    assert abs(basis.det()) == Q
    assert max(gram_schmidt_squared_lengths(block.basis_rows)) <= (1 << (2*bits))+1
    w = 2*basis.nrows()
    sampler = PrimeGadgetSampler(2, Q, 4*((1 << (2*bits))+1)*smoothing_factor(w, 192),
        epsilon_bits=192, options=PrototypeParams().options(), radix_bits=bits)
    for rng in (entropy(str(bits).encode()), None):
        result = sampler.sample((0, Q-1), rng=rng)
        assert len(result) == 2*basis.nrows()
        for i, target in enumerate((0, Q-1)):
            assert sum((1 << (bits*j))*result[i*sampler.k+j] for j in range(sampler.k)) % Q == target
    assert sampler.public_certificate()["radix_bits"] == bits


@pytest.mark.parametrize("bits", (True, 0, -1, 33, 12.0))
def test_invalid_radix_never_reads_entropy_or_allocates_a_kernel(monkeypatch, bits):
    import ibme.lattice.matrix_sampling.prime_gadget as module
    def forbidden(*args, **kwargs): pytest.fail("invalid radix did private work")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(module, "matrix", forbidden)
    with pytest.raises(ValueError): generate_root(2, Q, 9, radix_bits=bits)
    with pytest.raises(ValueError): prime_gadget_kernel(Q, radix_bits=bits)


@pytest.fixture(scope="module")
def chain():
    params = RadixPrototypeParams(n=2, q=Q, root_r_squared=9, radix_bits=12)
    rng = entropy(b"independent-parent")
    root = generate_root(2, Q, 9, radix_bits=12, options=params.options(), rng=rng)
    context = RadixPrototypeContext.create(params, root.public)
    h = PackedMatrix.from_rows(context.h((R,)), Q-1, False)
    parent = delegate(root, h, options=params.options(), rng=rng)
    return params, context, root, parent, rng


def test_radix_widths_and_shape_match_the_frozen_public_projection(chain):
    p, _, root, parent, _ = chain
    g = width_group(p.n, Q.bit_length(), p.radix_bits)
    assert (root.w, root.dimension, parent.prefix, parent.dimension) == (g["w"],g["m"],g["parent_sample_dimension"],2*g["m"])
    assert (p.parent_width_squared, p.parent_bound, p.leaf_width_squared) == (g["parent_width_squared"],g["parent_R_bound"],g["leaf_width_squared"])
    assert not any(value is root for value in vars(parent).values())
    assert any(value for col in parent.r.columns() for value in col[root.dimension:])


def test_high_radix_exact_precision_interval_matches_full_covariance_inverse(chain):
    p, _, root, _, _ = chain
    h = PackedMatrix.from_rows(((1, 2), (3, 4)), Q-1, False)
    sampler = BlockedPreimageSampler(root, h, options=p.options())
    j = matrix(ZZ, root.r.rows()).stack(identity_matrix(ZZ, root.w))
    j = j.stack(matrix(ZZ, 2, root.w))
    covariance = sampler.output_squared*identity_matrix(ZZ, sampler.dimension)-sampler.gadget_squared*j*j.transpose()
    values = tuple((-1)**i*10**6 for i in range(sampler.dimension))
    v = vector(QQ, values)
    exact = v.dot_product(covariance.change_ring(QQ).inverse()*v)-v.dot_product(v)/sampler.output_squared
    lo, hi = sampler.correction_interval(values)
    assert lo <= exact <= hi
    assert hi-lo <= sampler.scalar.weight_width/16


def test_real_256_target_leaf_and_independent_keys_restore_without_sampling(chain):
    p, context, root, parent, rng = chain
    h2 = PackedMatrix.from_rows(context.h((R,S)), Q-1, False)
    sampler = BlockedPreimageSampler(parent, h2, options=p.options())
    assert sampler.dimension == 3*p.m and sampler.output_squared == p.leaf_width_squared
    limit = 3*p.m*p.leaf_width_squared
    leaf = PackedMatrix.from_columns(3*p.m, 256, isqrt(limit), True,
        (sampler.sample(target, rng=rng) for target in context.targets(R,S)))
    wires = (context.to_bytes(), dump_trapdoor(context, root), dump_trapdoor(context, parent, R), dump_leaf(context,R,S,leaf))
    def forbidden(*args, **kwargs): pytest.fail("restore regenerated a key or preimage")
    with patch.object(SecureRandom,"read",forbidden), patch.object(BlockedPreimageSampler,"sample",forbidden):
        restored = RadixPrototypeContext.from_bytes(wires[0])
        assert restored.to_bytes() == wires[0]
        assert dump_trapdoor(restored,load_trapdoor(wires[1],restored)) == wires[1]
        assert dump_trapdoor(restored,load_trapdoor(wires[2],restored,R),R) == wires[2]
        assert load_leaf(wires[3],restored,R,S).to_bytes() == leaf.to_bytes()
    assert wires[1] not in wires[2]
    with pytest.raises(ValueError): load_leaf(wires[3],context,R,b"wrong")


@pytest.mark.parametrize("change", ("truncated","appended","version","wrong-identity","binary-reader"))
def test_radix_frames_refuse_malformed_scope_or_profile(chain, change):
    _, context, _, parent, _ = chain
    raw = dump_trapdoor(context,parent,R)
    if change == "truncated": raw=raw[:-1]
    if change == "appended": raw+=b"!"
    if change == "version": raw=b"X"+raw[1:]
    if change == "binary-reader":
        with pytest.raises((ValueError,EncodingError,SerializationError)):
            PrototypeContext.from_bytes(context.to_bytes())
        return
    with pytest.raises((ValueError,EncodingError,SerializationError)):
        load_trapdoor(raw,context,b"wrong" if change == "wrong-identity" else R)


def test_binary_parameter_snapshot_and_version_remain_byte_identical():
    root = Path(__file__).resolve().parents[1]
    receipt = json.loads((root/"docs/research/team-a-delivery/2026-10-18-3m-feasibility/evidence/n2-q80.json").read_bytes())
    old = receipt["parameters"]
    params = PrototypeParams(**old["parameters"])
    assert params.record() == old
    assert "radix_bits" not in asdict(params)
    assert params.radix_bits == 1
    with pytest.raises(ValueError): RadixPrototypeParams(radix_bits=1)


def test_same_shape_different_radix_does_not_share_key_context(chain):
    p, context, root, _, _ = chain
    other = RadixPrototypeParams(n=p.n,q=p.q,root_r_squared=p.root_r_squared,radix_bits=13)
    assert other.m == p.m
    different = RadixPrototypeContext.create(other,root.public)
    assert different.context != context.context
    with pytest.raises(ValueError,match="scope"):
        load_trapdoor(dump_trapdoor(context,root),different)
    with pytest.raises(ValueError,match="radix mismatch"):
        dump_trapdoor(different,root)


def test_target_hardware_candidates_are_retained_but_not_silently_admitted_to_this_probe():
    with pytest.raises(ValueError,match="entry budget"):
        RadixPrototypeParams(n=4096,q=Q,root_r_squared=4*4096+1,radix_bits=12)


def test_radix_cli_transfers_the_complete_parameter_tuple_before_generation(monkeypatch,tmp_path):
    from experiments.research import blocked_3m_probe as probe
    import sys
    seen = []
    def capture(directory,params,**options):
        seen.append((directory,params.n,params.q,params.root_r_squared,params.radix_bits))
    monkeypatch.setattr(probe,"run",capture)
    monkeypatch.setattr(sys,"argv",["blocked_3m_probe","--private-directory",str(tmp_path/"new-state"),
        "--n","2","--q",str(Q),"--root-r-squared","9","--radix-bits","12"])
    probe.main()
    assert seen == [(tmp_path/"new-state",2,Q,9,12)]
    assert RadixPrototypeParams(2,Q,9,radix_bits=12).n == 2
    assert not (tmp_path/"new-state").exists()
