"""Independent algorithmic regressions for the corrected full-basis GPV path."""
import math
from fractions import Fraction

import pytest

from ibme.core import DeterministicRandom, InvalidParameterError, RandomnessError
from ibme.ibs import wang_pw as w


def test_gpv_center_sign_original_vector_update_and_coordinate_width(monkeypatch):
    calls = []
    def nearest(stream, sigma, center):
        calls.append((sigma, center))
        return round(center)
    monkeypatch.setattr(w, "_sample_gaussian_z", nearest)
    result = w.sample_coset(None, [[2, 0], [1, 3]], [1, 2], 6.0)
    assert result == [0, -1]
    assert calls == [(2.0, Fraction(-2, 3)), (3.0, Fraction(0))]


@pytest.mark.parametrize("basis,particular", [([[1], [2]], [0]), ([[1, 0]], [0]),
                                             ([[0, 0]], [0, 0]), ([[1.5]], [0])])
def test_gpv_rejects_invalid_basis(basis, particular):
    with pytest.raises(InvalidParameterError):
        w.sample_coset(None, basis, particular, 1.0)


def test_narrow_gaussian_half_integer_terminates_with_both_nearest_points():
    stream = w._Stream(DeterministicRandom(b"narrow-half-regression"))
    values = [w._sample_gaussian_z(stream, 0.01, Fraction(1, 2)) for _ in range(160)]
    assert set(values) == {0, 1}
    assert 50 < sum(values) < 110


def test_gaussian_and_uniform_exhaustion_raise_instead_of_looping():
    class Zero:
        def read(self, n):
            return bytes(n)
    class Ones:
        def read(self, n):
            return b"\xff" * n
    with pytest.raises(RandomnessError):
        w._sample_gaussian_z(w._Stream(Zero()), 0.01, Fraction(1, 2), max_attempts=3)
    with pytest.raises(RandomnessError):
        w._Stream(Ones()).below(3)


def test_uniform_draws_support_more_than_64_bits():
    stream = w._Stream(DeterministicRandom(b"wide-integer-regression"))
    values = [stream.below((1 << 100) + 19) for _ in range(20)]
    assert all(0 <= x < (1 << 100) + 19 for x in values)
    assert any(x >= 1 << 64 for x in values)


@pytest.mark.parametrize("q", [0, 1, 4, 9, True, 1 << 64])
def test_public_lattice_helpers_reject_unsupported_moduli(q):
    with pytest.raises(InvalidParameterError):
        w.gadget_matrix(1, q)
    assert not w.verify_kernel_basis_is_complete([[1]], [[1]], q)
    assert not w.check_kernel_saturation([[1]], [[1]], q)


def test_public_trapdoor_helper_rejects_bad_dimensions():
    with pytest.raises(InvalidParameterError):
        w.public_key_from_trapdoor([[1, 2]], [[0, 0]], 3)
    with pytest.raises(InvalidParameterError):
        w.public_key_from_trapdoor([[3]], [[0, 0]], 3)


@pytest.mark.parametrize("basis", [[], [[0]], [[1], [2]], [[10**400]]])
def test_basis_width_rejects_invalid_or_unrepresentable_inputs(basis):
    with pytest.raises(InvalidParameterError):
        w.basis_width(basis)


def test_hash_transcript_binds_full_public_matrix_without_digest_collision_assumption(monkeypatch):
    p = w.WangPWParams(n=1, q=3, m_bar=2)
    pk, _ = w.setup(p, rng=DeterministicRandom(b"hash-transcript"))
    rows = pk.matrix()
    rows[0][0] = (rows[0][0] + 1) % p.q
    other = w.PublicKey(p, rows)
    calls = []
    original = w._uniform_field_coefficients
    def capture(domain, data, q, *, label):
        calls.append((domain, data, label))
        return original(domain, data, q, label=label)
    monkeypatch.setattr(w, "_uniform_field_coefficients", capture)
    for key in (pk, other):
        w.hash_identity_matrix(key, b"alice")
        w.hash_message_vector(key, b"alice", b"msg")
    assert calls[0][1] != calls[2][1]
    assert calls[1][1] != calls[3][1]
    assert calls[0][0] != calls[1][0]
    for index, key in enumerate((pk, other)):
        assert key.to_bytes() in calls[2*index][1]
        assert key.to_bytes() in calls[2*index+1][1]


def test_modular_gadget_sampler_includes_nonzero_q_shift():
    # Uniform proposal index selecting (-1,0,0); acceptance draw = 0.
    q, k, radius = 7, 3, 1
    import itertools
    points = [v for v in itertools.product(range(-radius, radius+1), repeat=k)
              if sum((1 << i)*x for i, x in enumerate(v)) % q == 6]
    class Select:
        def below(self, bound):
            assert bound == len(points)
            return points.index((-1, 0, 0))
        def word64(self):
            return 0
    z = w._sample_gadget_block(Select(), 6, 1.0, 3, 7, tail_width=1)
    assert z == [-1, 0, 0]
    assert sum((1 << i)*x for i, x in enumerate(z)) == -1


@pytest.mark.parametrize("q,m_bar", [(3, 2), (5, 3), (11, 4)])
def test_real_lifecycle_at_several_small_moduli(q, m_bar, monkeypatch):
    p = w.WangPWParams(n=1, q=q, m_bar=m_bar)
    rng = DeterministicRandom(b"multi-modulus" + bytes([q]))
    pk, msk = w.setup(p, rng=rng)
    original = w._trapdoor_kernel_basis
    used = []
    def capture(a, r, modulus):
        used.append((a, r))
        return original(a, r, modulus)
    monkeypatch.setattr(w, "_trapdoor_kernel_basis", capture)
    key = w.key_extract_pw(msk, b"alice", rng=rng)
    assert used[0] == (pk.matrix(), msk.r_a())
    del msk
    r, s, sig = w.sign_pw(key, b"standalone", rng=rng)
    assert w.verify_pw(pk, b"alice", b"standalone", r, s, sig)
    assert used[1] == (key.inner.identity_matrix(),
                       [[-x for x in row] for row in key.inner.r_x()])
    assert len(used) == 2
    assert not hasattr(key.inner, "r_a_rows")


def test_sign_zero_and_overbound_budget_is_enforced(monkeypatch):
    p = w.WangPWParams(n=1, q=3, m_bar=2)
    rng = DeterministicRandom(b"sign-exhaustion")
    pk, msk = w.setup(p, rng=rng)
    sk = w.key_extract(msk, b"alice", rng=rng)
    message = next(bytes([i]) for i in range(256)
                   if w.hash_message_vector(pk, b"alice", bytes([i])) == [0])
    # Both vectors are in the zero syndrome coset; neither is acceptable.
    for output in ([0]*p.signature_dim, [3*10**6] + [0]*(p.signature_dim-1)):
        calls = []
        def fake(*args):
            calls.append(1)
            return output
        monkeypatch.setattr(w, "sample_coset", fake)
        with pytest.raises(RandomnessError):
            w.sign(sk, message, rng=rng, max_attempts=2)
        assert len(calls) == 2
