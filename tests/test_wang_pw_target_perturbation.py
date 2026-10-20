"""Perturbation (MP12 SampleD) signing route on debug dimensions.

These tests exercise the real sampling chain (native Gaussian + gadget GPV)
and check the equation, norm gate, and covariance of the ideal coset
Gaussian.  Debug parameters only; never security evidence.
"""
import numpy as np
import pytest

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.wang_pw_target import Backend, small_params
from ibme.ibs.wang_pw_target.hashing import (identity_matrix, inner_identity,
                                             inner_message, message_vector)
from ibme.ibs.wang_pw_target.math import gadget, matmul_mod
from ibme.ibs.wang_pw_target.native import draw_gaussian
from ibme.ibs.wang_pw_target.objects import Signature, SigningKey
from ibme.ibs.wang_pw_target.perturbation import (GADGET_SIGMA, _covariance,
                                                  gadget_kernel_basis,
                                                  perturbation_factor,
                                                  sample_perturbation,
                                                  trapdoor_spectral_norm)


@pytest.fixture(scope="module")
def perturbed():
    backend = Backend(rng=DeterministicRandom(b"perturbation-lifecycle"),
                      test_only=True, sampler="perturbation")
    p = small_params(threads=2)
    pk, master = backend.setup(p)
    key = backend.key_extract(master, b"alice")
    sig = backend.sign(key, b"message")
    assert backend.verify(pk, b"alice", b"message", sig)
    return backend, pk, key, sig


def _f_id(pk, key):
    p = pk.params
    x = inner_identity(p, key.identity, key.identity_salt)
    return np.hstack((pk.a, identity_matrix(pk, x)))


def test_gadget_kernel_basis_is_complete():
    for q in (17, 257, 4294967291):
        k = (q - 1).bit_length()
        basis = gadget_kernel_basis(k, q)
        g = gadget(1, q)[0]
        assert np.all((g @ basis) % q == 0)
        assert abs(round(np.linalg.det(basis.astype(float)))) == q
        rng = np.random.default_rng(1)
        for _ in range(10):
            x = rng.integers(-40, 41, size=k).astype(np.int64)
            x[0] = int((-(x[1:] @ g[1:])) % q)
            c = np.linalg.solve(basis.astype(float), x.astype(float))
            assert np.max(np.abs(c - np.rint(c))) < 1e-6


def test_spectral_norm_estimate_matches_svd():
    rng = np.random.default_rng(2)
    x = rng.normal(0.0, 10.0, size=(48, 24))
    lam = trapdoor_spectral_norm(np.rint(x).astype(np.int64), iterations=200)
    exact = float(np.linalg.norm(np.vstack((x, np.eye(24))), 2))
    assert 0.85 * exact <= lam <= 1.15 * exact


def test_perturbation_covariance_is_psd_and_factors():
    rng = np.random.default_rng(3)
    x = rng.integers(-100, 100, size=(24, 12)).astype(np.int64)
    s, lower = perturbation_factor(x, GADGET_SIGMA)
    dim = 36
    assert lower.shape == (dim, dim)
    assert np.allclose(lower, np.tril(lower))
    sigma = _covariance(x, s, GADGET_SIGMA)
    scale = max(1.0, float(np.abs(sigma).max()))
    assert np.allclose(lower @ lower.T, sigma, atol=1e-6 * scale)


def test_perturbation_samples_match_trace():
    rng = np.random.default_rng(4)
    x = rng.integers(-800, 800, size=(48, 24)).astype(np.int64)
    s, lower = perturbation_factor(x, GADGET_SIGMA)
    sigma = _covariance(x, s, GADGET_SIGMA)
    expected = float(np.trace(sigma))
    draws = []
    for _ in range(8):
        g = draw_gaussian(lower.shape[0], sigma=1.0, seed=rng.bytes(32), test_only=True, threads=2)
        p = np.rint(lower @ g.astype(np.float64)).astype(np.int64)
        draws.append(float(p @ p))
    ratio = float(np.mean(draws)) / expected
    assert 0.4 <= ratio <= 2.5, ratio


def test_perturbation_signature_equation_and_norm(perturbed):
    backend, pk, key, sig = perturbed
    p = pk.params
    x = inner_identity(p, key.identity, key.identity_salt)
    y = inner_message(p, b"message", sig.message_salt)
    h2 = message_vector(pk, x, y)
    f = _f_id(pk, key)
    left = matmul_mod(f, sig.z.reshape(-1, 1), p.q)[:, 0]
    assert np.array_equal(left, h2)
    norm = sum(int(v) * int(v) for v in sig.z)
    assert 0 < norm <= p.verify_bound_sq


def test_perturbation_honest_lifecycle_multi_identity():
    backend = Backend(rng=DeterministicRandom(b"perturbation-multi"),
                      test_only=True, sampler="perturbation")
    p = small_params()
    pk, master = backend.setup(p)
    for identity in (b"alice", b"bob", b"carol", b"dave"):
        key = backend.key_extract(master, identity)
        for message in (b"one", b"two", b"three"):
            sig = backend.sign(key, message)
            assert backend.verify(pk, identity, message, sig)
            assert not backend.verify(pk, identity, message + b"x", sig)


def test_perturbation_restored_key_signs(perturbed):
    backend, pk, key, _ = perturbed
    restored = SigningKey.from_bytes(key.to_bytes())
    signer = Backend(rng=DeterministicRandom(b"perturbation-restored"),
                     test_only=True, sampler="perturbation")
    sig = signer.sign(restored, b"restored message")
    assert signer.verify(pk, b"alice", b"restored message", sig)


def test_perturbation_covariance_scales_with_ideal_width(perturbed):
    backend, pk, key, _ = perturbed
    p = pk.params
    s, lower = perturbation_factor(key.trapdoor, GADGET_SIGMA)
    del lower
    # Cov(z) = s^2 I (std-dev convention); the ideal coset Gaussian has
    # E||z||^2 = dim * s^2.  The rho width is s*sqrt(2*pi).
    expected = p.dimension * s * s
    rng = DeterministicRandom(b"perturbation-norm")
    backend2 = Backend(rng=rng, test_only=True, sampler="perturbation")
    pk2, master2 = backend2.setup(p)
    key2 = backend2.key_extract(master2, b"norm-test")
    norms = []
    for i in range(12):
        sig = backend2.sign(key2, ("m%d" % i).encode())
        norms.append(sum(int(v) * int(v) for v in sig.z))
    ratio = float(np.mean(norms)) / expected
    assert 0.2 <= ratio <= 3.0, ratio


def test_perturbation_rejects_tampered_signatures(perturbed):
    backend, pk, key, sig = perturbed
    p = pk.params
    tampered = Signature(sig.context, sig.identity_salt, sig.message_salt, sig.z + 1)
    assert not backend.verify(pk, b"alice", b"message", tampered)
    assert not backend.verify(pk, b"bob", b"message", sig)
    zero = Signature(sig.context, sig.identity_salt, sig.message_salt,
                     np.zeros(p.dimension, dtype=np.int64))
    assert not backend.verify(pk, b"alice", b"message", zero)



