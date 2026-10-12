"""Public fixed-stream equality, including exact masses and entropy reads.

The fixtures below are synthetic public matrices/test streams. They are not
real root, parent or leaf keys and establish no cryptographic security level.
"""

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, vector

from ibme.core.randomness import DeterministicRandom
from ibme.lattice.chkp.entropy import CheckedEntropy
from ibme.lattice.chkp.basis import ModMatrixReference
from ibme.lattice.chkp.extended_gpv import ExtendedGPV
from ibme.lattice.chkp.finite_gaussian import (
    FirstFiniteGaussian, capped_exp_minus_pi, interval_bounds,
)
from ibme.lattice.chkp.finite_gpv import FirstFiniteGPV
from ibme.lattice.chkp.gaussian import SamplingAbort
from ibme.lattice.chkp.root_basis import private_root_basis


class RecordingSource:
    def __init__(self, seed, *, constant=None):
        self.source = DeterministicRandom(seed)
        self.requests = []
        self.constant = constant

    def read(self, count):
        self.requests.append(count)
        return (self.source.read(count) if self.constant is None
                else bytes([self.constant])*count)


class LegacyGaussian(FirstFiniteGaussian):
    def integer_weight(self, value, width, fractional, closest):
        argument = ((value-fractional)**2-(closest-fractional)**2)/width
        assert argument >= 0
        if argument >= self.options.mass_bits:
            return 0
        weight = capped_exp_minus_pi(argument, self.field, self.cap_bits)
        lower = interval_bounds(weight)[0]
        return int((2**self.options.mass_bits*lower).floor())


CENTERS = (
    QQ(0), -QQ(17)/7, QQ(1)/2,
    QQ(1)/2-QQ(1)/(2**2048+1),
    QQ(1)/2+QQ(1)/(2**2048+1),
    QQ(2**2048)+QQ(1)/(2**4096+1),
    -QQ(2**2048)-QQ(1)/(2**4096+1),
)


@pytest.mark.parametrize("width", [QQ(9), QQ(1024)/3, QQ(2**60)])
def test_expanded_exponent_has_identical_integer_weights(width):
    current, old = FirstFiniteGaussian(width, width), LegacyGaussian(width, width)
    for center in CENTERS:
        w, shift, fractional, closest, low, high = current.checked_inputs(width, center)
        for value in (low, -3, -1, 0, 1, 3, high):
            assert current.integer_weight(value, w, fractional, closest) == old.integer_weight(
                value, w, fractional, closest)


@pytest.mark.parametrize("center", CENTERS)
def test_scalar_fixed_stream_output_and_every_entropy_request_match(center):
    width = QQ(1024)/3
    current, old = FirstFiniteGaussian(width, width), LegacyGaussian(width, width)
    left, right = RecordingSource(b"public-scalar-equality"), RecordingSource(b"public-scalar-equality")
    assert [current.sample(width, center, rng=left) for _ in range(3)] == [
        old.sample(width, center, rng=right) for _ in range(3)]
    assert left.requests == right.requests


def test_scalar_abort_consumes_identical_entropy_and_does_not_retry():
    current, old = FirstFiniteGaussian(9, 9), LegacyGaussian(9, 9)
    left, right = RecordingSource(b"abort", constant=255), RecordingSource(b"abort", constant=255)
    with pytest.raises(SamplingAbort) as new_error:
        current.sample(9, -QQ(3)/7, rng=left)
    with pytest.raises(SamplingAbort) as old_error:
        old.sample(9, -QQ(3)/7, rng=right)
    assert str(new_error.value) == str(old_error.value)
    assert left.requests == right.requests


@pytest.fixture(scope="module")
def gpv():
    # Public deterministic MP12 algebra fixture, not a generated trapdoor.
    basis = private_root_basis([[1, 3]],
        [[1, -2, 1, 0, 2], [-1, 0, 2, 1, -2]], 17)
    return FirstFiniteGPV(basis, 2**28, epsilon_bits=128)


def _legacy_gpv_sample(sampler, scalars, syndrome, source):
    target = sampler._syndrome(syndrome)
    t = sampler._lift(target)
    center, accumulated = -t, vector(ZZ, sampler.dimension)
    checked = CheckedEntropy(source, sampler.random_tape_bytes)
    for i in reversed(range(sampler.dimension)):
        projected = sum((x*w for x,w in zip(center, sampler._weights[i])), QQ(0))
        z = scalars[i].sample(sampler._widths[i], projected, rng=checked)
        step = z*sampler._columns[i]
        center -= step
        accumulated += step
    return tuple(int(x) for x in t+accumulated)


def test_integer_projection_equals_rational_sum_at_large_signed_centers(gpv):
    centers = [vector(ZZ, [(2**4096-1)*(-1)**(i+j)+j for j in range(gpv.dimension)])
               for i in range(2)]
    centers.append(vector(ZZ, gpv.dimension))
    for center in centers:
        for weights, (numerators, denominator), resource in zip(
                gpv._weights, gpv._integer_weights, gpv._path_resources):
            assert denominator == resource[0]
            assert tuple(QQ(x)/denominator for x in numerators) == weights
            assert QQ(center.dot_product(numerators))/denominator == sum(
                (x*w for x,w in zip(center, weights)), QQ(0))


@pytest.mark.parametrize("syndrome", [(0,), (1,), (8,), (16,)])
def test_gpv_fixed_stream_output_and_every_entropy_request_match(gpv, syndrome):
    old_scalars = tuple(LegacyGaussian(w, w, options=s.options)
                        for w,s in zip(gpv._widths, gpv.scalars))
    left, right = RecordingSource(b"public-gpv-equality"), RecordingSource(b"public-gpv-equality")
    for _ in range(3):
        assert gpv.sample(syndrome, rng=left) == _legacy_gpv_sample(gpv, old_scalars, syndrome, right)
    assert left.requests == right.requests


def test_gpv_abort_and_entropy_requests_match(gpv):
    old_scalars = tuple(LegacyGaussian(w, w, options=s.options)
                        for w,s in zip(gpv._widths, gpv.scalars))
    left, right = RecordingSource(b"abort", constant=255), RecordingSource(b"abort", constant=255)
    with pytest.raises(SamplingAbort) as new_error:
        gpv.sample((16,), rng=left)
    with pytest.raises(SamplingAbort) as old_error:
        _legacy_gpv_sample(gpv, old_scalars, (16,), right)
    assert str(new_error.value) == str(old_error.value)
    assert left.requests == right.requests


def test_extended_gpv_preserves_full_appended_then_parent_stream(gpv):
    extension = ModMatrixReference(((3, 8),), 17)
    current = ExtendedGPV(gpv.basis, extension, 2**28, epsilon_bits=128)
    old_scalar = LegacyGaussian(current.width_squared, current.width_squared,
                                options=current.scalar.options)
    old_parent_scalars = tuple(LegacyGaussian(w, w, options=s.options)
        for w,s in zip(current.parent._widths, current.parent.scalars))
    left, right = RecordingSource(b"public-extension-equality"), RecordingSource(b"public-extension-equality")
    for target in (0, 8, 16):
        old_source = CheckedEntropy(right, current.random_tape_bytes)
        appended = tuple(old_scalar.sample(current.width_squared, 0, rng=old_source)
                         for _ in range(extension.ncols))
        adjusted = ((target-sum(x*y for x,y in zip(extension.rows[0], appended))) % 17,)
        expected = _legacy_gpv_sample(current.parent, old_parent_scalars, adjusted, old_source) + appended
        assert current.sample((target,), rng=left) == expected
    assert left.requests == right.requests


@pytest.mark.parametrize("center", [True, QQ(2**8192), QQ(1)/(2**8192+1)])
def test_invalid_center_rejected_before_entropy_in_both_versions(center):
    left, right = RecordingSource(b"invalid"), RecordingSource(b"invalid")
    with pytest.raises(ValueError):
        FirstFiniteGaussian(9, 9).sample(9, center, rng=left)
    with pytest.raises(ValueError):
        LegacyGaussian(9, 9).sample(9, center, rng=right)
    assert left.requests == right.requests == []
