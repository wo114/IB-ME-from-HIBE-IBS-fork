"""Real full-block structured extension, checked against independent algebra."""

import pytest
pytest.importorskip("sage.all", reason="requires prescribed WSL Sage environment")
from sage.all import matrix, vector, ZZ, QQ, identity_matrix
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.matrix_sampling import mp12_structured as tools
from ibme.lattice.matrix_sampling.mp12_extension import StructuredLeftSampler, delegate_extension


class NoEntropy:
    calls = 0
    def read(self, count):
        self.calls += 1
        raise AssertionError("unexpected private entropy")


@pytest.fixture(scope="module")
def root():
    return tools.generate_structured_root(2, 257, 16,
        rng=DeterministicRandom(b"full-H-block-extension-test-root"))


def extension(t, count):
    return tuple(tuple((7*i+13*j+31) % t.q for j in range(count)) for i in range(t.n))


@pytest.mark.parametrize("count", [0, 1, 4, 22])
def test_every_sample_coordinate_and_complete_original_order(root, count):
    extra = extension(root, count)
    sampler = StructuredLeftSampler(root, extra)
    rng = DeterministicRandom(b"full-H-block-extension-test-sampling")
    x = sampler.sample((17, 212), rng=rng)
    public = matrix(ZZ, root.public.rows).augment(matrix(ZZ, root.n, count, sum((list(r) for r in extra), [])))
    assert len(x) == root.dimension+count
    assert tuple(int(v) % root.q for v in public*vector(x)) == (17, 212)
    if count:
        assert any(x[root.dimension:])
    assert sampler.public_certificate()["expanded_full_kernel_bases"] == 0
    assert sampler.public_certificate()["zero_padded_output_coordinates"] is False


def test_extended_precision_is_actual_dense_covariance_in_permuted_order(root):
    sampler = StructuredLeftSampler(root, extension(root, 3))
    t, inner = sampler.inner.trapdoor, sampler.inner
    transform = matrix(ZZ, t.r).stack(identity_matrix(ZZ, t.w))
    covariance = inner.output_squared*identity_matrix(ZZ, t.dimension)-inner.gadget_squared*transform*transform.transpose()
    correction = matrix(QQ, covariance).inverse()-identity_matrix(QQ, t.dimension)/inner.output_squared
    x = vector(ZZ, range(t.dimension))
    assert inner.precision_correction(x.list()) == x.dot_product(correction*x)
    assert t.frobenius_squared_bound == root.frobenius_squared_bound


def test_Algorithm4_keeps_every_column_of_a_full_H_block(root):
    extra = extension(root, root.dimension)
    child = delegate_extension(root, extra,
        rng=DeterministicRandom(b"full-H-block-extension-test-actual-DelTrap"))
    assert child.dimension == 2*root.dimension
    assert child.public.rows == tuple(a+b for a, b in zip(root.public.rows, extra))
    assert child.prefix == 2*root.dimension-root.w
    decoded = tools.StructuredTrapdoor.from_bytes(child.to_bytes())
    leaf_sampler = StructuredLeftSampler(decoded, extra)
    x = leaf_sampler.sample((19, 220), rng=DeterministicRandom(b"full-H-block-leaf-test"))
    assert len(x) == 3*root.dimension
    assert tuple(sum(a*v for a, v in zip(row, x)) % root.q for row in leaf_sampler.public_rows) == (19, 220)


@pytest.mark.parametrize("extra", [None, (), ((1,),), ((True,), (0,)), ((257,), (0,)), ((1, 2), (3,))])
def test_malformed_extensions_fail_before_entropy(root, extra):
    guard = NoEntropy()
    with pytest.raises(ValueError):
        StructuredLeftSampler(root, extra).sample((0, 0), rng=guard)
    with pytest.raises(ValueError):
        delegate_extension(root, extra, rng=guard)
    assert guard.calls == 0


def test_short_tail_large_prefix_and_bad_syndrome_never_draw(root):
    guard = NoEntropy()
    with pytest.raises(ValueError, match="resource"):
        delegate_extension(root, extension(root, root.w-1), rng=guard)
    with pytest.raises(ValueError, match="resource"):
        StructuredLeftSampler(root, extension(root, 513))
    sampler = StructuredLeftSampler(root, extension(root, 4))
    with pytest.raises(ValueError): sampler.sample((True, 0), rng=guard)
    assert guard.calls == 0
