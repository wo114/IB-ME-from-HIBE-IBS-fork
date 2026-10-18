"""Real wide-q KEM roundtrip for the MP12-radix 3m engineering variant."""

from math import isqrt

import pytest

pytest.importorskip("sage.all", reason="use WSL ~/miniconda3/envs/sage")

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.mp12_structured.blocked_prototype import (
    RadixPrototypeContext, RadixPrototypeParams, dump_leaf,
)
from ibme.hibe.mp12_structured.radix_kem import (
    MAGIC, NOISE_OPTIONS, RadixSeedCapsule, WideRoundedNoiseParams,
    build_radix_noise, decapsulate_seed, encapsulate_seed,
)
from ibme.lattice.chkp.rounded_noise import RoundedNoiseTable
from ibme.lattice.matrix_sampling.mp12_blocked import BlockedPreimageSampler, delegate, generate_root
from ibme.lattice.matrix_sampling.packed import PackedMatrix

Q = 5998976077229064136548861031  # validated 93-bit prime in the radix profile
RECEIVER, SENDER = b"receiver", b"sender"
SEED = bytes(range(32))


def entropy(label):
    return DeterministicRandom(b"TEST-ONLY:radix-seed-kem:" + label)


@pytest.fixture(scope="module")
def real_leaf():
    p = RadixPrototypeParams(n=2, q=Q, root_r_squared=9, radix_bits=10)
    rng = entropy(b"complete-private-chain")
    root = generate_root(p.n, p.q, p.root_r_squared,
                         radix_bits=p.radix_bits, options=p.options(), rng=rng)
    context = RadixPrototypeContext.create(p, root.public)
    first = PackedMatrix.from_rows(context.h((RECEIVER,)), Q - 1, False)
    parent = delegate(root, first, options=p.options(), rng=rng)
    second = PackedMatrix.from_rows(context.h((RECEIVER, SENDER)), Q - 1, False)
    sampler = BlockedPreimageSampler(parent, second, options=p.options())
    limit = context.leaf_dimension * p.leaf_width_squared
    leaf = PackedMatrix.from_columns(context.leaf_dimension, 256, isqrt(limit), True,
        (sampler.sample(target, rng=rng) for target in context.targets(RECEIVER, SENDER)))
    return context, dump_leaf(context, RECEIVER, SENDER, leaf)


def test_real_93_bit_roundtrip_with_all_3m_coefficients_and_256_targets(real_leaf):
    context, leaf_wire = real_leaf
    noise = build_radix_noise(context)
    assert noise.params.q == Q
    assert noise.params.scaled_width == context.params.q_alpha
    assert noise.params.mass_bits == NOISE_OPTIONS["mass_bits"]
    assert any(mass for value, mass in zip(range(-noise.radius, noise.radius + 1), noise.masses)
               if value != 0)
    zero_error_substitute = RoundedNoiseTable(
        noise.params, (0,) * noise.radius + (noise.total,) * (noise.radius + 1),
        2 * noise.radius)
    with pytest.raises(InvalidParameterError, match="actual rounded Gaussian"):
        encapsulate_seed(context, RECEIVER, SENDER, SEED, noise=zero_error_substitute,
                         rng=entropy(b"must-not-be-used"))
    capsule = encapsulate_seed(context, RECEIVER, SENDER, SEED,
                               noise=noise, rng=entropy(b"encapsulation"))
    assert len(capsule.preamble) == context.leaf_dimension == 3 * context.m
    assert len(capsule.terminals) == 256
    raw = capsule.to_bytes()
    assert RadixSeedCapsule.from_bytes(raw).to_bytes() == raw
    assert decapsulate_seed(context, RECEIVER, SENDER, leaf_wire, capsule) == SEED
    assert (capsule.security_claim, capsule.backend_admitted,
            capsule.parameters_are_formal) == ("none", False, False)
    with pytest.raises(ValueError, match="scope"):
        decapsulate_seed(context, RECEIVER, b"wrong", leaf_wire, capsule)
    assert decapsulate_seed(context, RECEIVER, SENDER, leaf_wire,
                           RadixSeedCapsule(b"x" * 64, Q, capsule.preamble,
                                            capsule.terminals)) is None


@pytest.mark.parametrize("change", ("truncated", "appended", "version", "even-q",
                                    "dimension", "residue"))
def test_capsule_wire_rejects_malformed_inputs_without_private_work(change):
    capsule = RadixSeedCapsule(b"c" * 64, Q, (0, 1, 2), (0,) * 256)
    raw = bytearray(capsule.to_bytes())
    if change == "truncated":
        raw.pop()
    elif change == "appended":
        raw.append(0)
    elif change == "version":
        raw[0] ^= 1
    elif change == "even-q":
        raw[len(MAGIC) + 64 + 31] ^= 1
    elif change == "dimension":
        raw[len(MAGIC) + 64 + 32 + 3] = 4
    else:
        start = len(MAGIC) + 64 + 32 + 4
        raw[start:start + capsule.residue_bytes] = Q.to_bytes(capsule.residue_bytes, "big")
    with pytest.raises(SerializationError):
        RadixSeedCapsule.from_bytes(bytes(raw))


def test_wide_noise_and_capsule_reject_wrong_parameter_profiles():
    for q in (2**61 - 1, 2**256, Q + 1):
        with pytest.raises(InvalidParameterError):
            WideRoundedNoiseParams(q, "5/" + str(q), **NOISE_OPTIONS)
    with pytest.raises(InvalidParameterError):
        RadixSeedCapsule(b"c" * 64, Q, (0, 1, 2), (0,) * 255)
    with pytest.raises(InvalidParameterError):
        RadixSeedCapsule(b"c" * 64, Q, (0, 1, 2), (Q,) * 256)
