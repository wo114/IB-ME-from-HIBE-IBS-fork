"""2011 author-manuscript depth-one KEM tests; toy inputs are not secure."""

from dataclasses import replace
from fractions import Fraction

import pytest

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.chkp.identity import ROHIBEContext, SEED_BITS
from ibme.lattice.chkp.level1_kem import (
    Level1Preimages, decapsulate_level1, encapsulate_level1,
    sample_level1_preimages, validate_level1_preimages,
)
from ibme.lattice.chkp.noise_budget import RoundedNoiseParams
from ibme.lattice.chkp.rounded_noise import build_rounded_noise
from ibme.lattice.chkp.seed_kem import SeedCapsule


RECEIVER = b"receiver"
SEED = bytes(range(32))


def _fixture(*, q=65537, m=4):
    # Public algebra control: a short one-coordinate solution is manufactured
    # for every G target. This is NOT a Gaussian secret-key distribution.
    oracle = ROHIBEContext(1, m, q, ((1,) + (0,) * (m - 1),),
                           b"TEST-ONLY:CHKP-LEVEL1-ALGEBRA:v1")
    row = oracle.parent_rows(RECEIVER)[0]
    pivot = next(j for j, value in enumerate(row) if value % q)
    inverse = pow(row[pivot], -1, q)
    dimension = 2 * m
    vectors = []
    for position in range(SEED_BITS):
        target = oracle.g((RECEIVER,), position)[0]
        value = target * inverse % q
        if value > q // 2:
            value -= q
        vector = [0] * dimension
        vector[pivot] = value
        vectors.append(tuple(vector))
    width = q * q
    return oracle, validate_level1_preimages(oracle, RECEIVER, tuple(vectors), width)


def _actual_noise(q):
    # Very narrow continuous noise keeps this toy algebra control correct;
    # the CDF and draws are still the real rounded-continuous implementation.
    params = RoundedNoiseParams(q, Fraction(1, 256 * q), tail_bits=8,
                                mass_bits=64, precision_bits=128, max_radius=8)
    return build_rounded_noise(params)


def test_level1_real_noise_capsule_pads_to_3m_and_decaps_uses_2m():
    oracle, key = _fixture()
    noise = _actual_noise(oracle.q)
    capsule = encapsulate_level1(oracle, RECEIVER, SEED, noise,
                                 rng=DeterministicRandom(b"level1-real-noise"))
    assert isinstance(capsule, SeedCapsule)
    assert len(capsule.preamble) == 3 * oracle.m
    assert len(capsule.terminals) == SEED_BITS
    assert decapsulate_level1(oracle, RECEIVER, key,
                              SeedCapsule.from_bytes(capsule.to_bytes())) == SEED
    other = encapsulate_level1(oracle, RECEIVER, SEED, noise,
                               rng=DeterministicRandom(b"level1-other"))
    assert capsule.preamble[2 * oracle.m:] != other.preamble[2 * oracle.m:]
    # The same key must ignore all anonymity padding during decoding.
    changed = replace(capsule, preamble=capsule.preamble[:2 * oracle.m]
                      + tuple((x + 1) % oracle.q for x in capsule.preamble[2 * oracle.m:]))
    assert decapsulate_level1(oracle, RECEIVER, key, changed) == SEED


def test_level1_binding_norm_and_shape_are_checked_before_use():
    oracle, key = _fixture()
    assert isinstance(key, Level1Preimages)
    assert key.security_claim == "none" and key.backend_admitted is False
    with pytest.raises(InvalidParameterError, match="G target"):
        pivot = next(j for j, x in enumerate(oracle.parent_rows(RECEIVER)[0]) if x)
        first = list(key.preimages[0])
        first[pivot] += 1
        changed = (tuple(first),) + key.preimages[1:]
        validate_level1_preimages(oracle, RECEIVER, changed, key.width_squared)
    with pytest.raises(InvalidParameterError, match="width bound"):
        validate_level1_preimages(oracle, RECEIVER, key.preimages, Fraction(1, 1000))
    with pytest.raises(InvalidParameterError, match="dimension"):
        validate_level1_preimages(oracle, RECEIVER,
                                  (key.preimages[0][:-1],) + key.preimages[1:],
                                  key.width_squared)
    with pytest.raises(InvalidParameterError, match="G target"):
        validate_level1_preimages(oracle, b"other-receiver", key.preimages,
                                  key.width_squared)


def test_level1_wrong_context_and_receiver_return_none():
    oracle, key = _fixture()
    noise = _actual_noise(oracle.q)
    capsule = encapsulate_level1(oracle, RECEIVER, SEED, noise,
                                 rng=DeterministicRandom(b"binding"))
    assert decapsulate_level1(oracle, b"other-receiver", key, capsule) is None
    assert decapsulate_level1(oracle, RECEIVER, key,
                              replace(capsule, context=b"x" * 64)) is None
    assert decapsulate_level1(oracle, RECEIVER, key,
                              replace(capsule, preamble=capsule.preamble[:-1])) is None
    with pytest.raises(TypeError):
        decapsulate_level1(oracle, RECEIVER, key.preimages, capsule)


def test_level1_invalid_inputs_do_not_request_randomness():
    oracle, _ = _fixture()

    class NoEntropy:
        def read(self, count):
            pytest.fail("invalid level-one input consumed entropy")

    noise = _actual_noise(oracle.q)
    with pytest.raises(InvalidParameterError, match="32 bytes"):
        encapsulate_level1(oracle, RECEIVER, b"short", noise, rng=NoEntropy())
    with pytest.raises(InvalidParameterError, match="noise"):
        encapsulate_level1(oracle, RECEIVER, SEED, object(), rng=NoEntropy())


def test_level1_real_extbasis_sampling_and_pre_entropy_budget():
    pytest.importorskip("sage.all", reason="CHKP exact GPV requires prescribed WSL Sage")
    from ibme.lattice.chkp.basis import ModMatrixReference, complete_kernel_basis
    from ibme.lattice.chkp.finite_gaussian import FirstFiniteOptions

    oracle = ROHIBEContext(1, 5, 17, ((1, 0, 0, 0, 0),),
                           b"TEST-ONLY:CHKP-LEVEL1-REAL-GPV:v1")
    root = complete_kernel_basis(ModMatrixReference(oracle.root_rows, oracle.q))
    options = FirstFiniteOptions()

    class NoEntropy:
        def read(self, count):
            pytest.fail("over-budget level-one sampling consumed entropy")

    with pytest.raises(InvalidParameterError, match="entropy budget"):
        sample_level1_preimages(root, oracle, RECEIVER, 2**20,
                                epsilon_bits=16, options=options,
                                entropy_budget=1, rng=NoEntropy())
    foreign = complete_kernel_basis(ModMatrixReference(((2, 0, 0, 0, 0),), oracle.q))
    with pytest.raises(InvalidParameterError, match="public A0"):
        sample_level1_preimages(foreign, oracle, RECEIVER, 2**20,
                                epsilon_bits=16, options=options,
                                entropy_budget=2**32, rng=NoEntropy())
    samples = sample_level1_preimages(root, oracle, RECEIVER, 2**20,
                                      epsilon_bits=16, options=options,
                                      entropy_budget=2**32,
                                      rng=DeterministicRandom(b"level1-real-gpv"))
    assert len(samples) == SEED_BITS
    assert validate_level1_preimages(oracle, RECEIVER, samples, 2**20).preimages == samples
