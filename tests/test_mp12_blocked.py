"""Equations, exact precision enclosures and private compact representation."""

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, matrix, vector, identity_matrix

from ibme.core.randomness import DeterministicRandom
from ibme.lattice.matrix_sampling.packed import PackedMatrix, MAGIC
from ibme.lattice.matrix_sampling.mp12_blocked import (
    PackedTrapdoor, generate_root, BlockedPreimageSampler, delegate,
)


def rng(label):
    return DeterministicRandom(b"TEST-ONLY:blocked-3m:"+label)


@pytest.mark.parametrize("signed,bound,rows", [
    (True, 2**90, ((-2**90, 0, 1), (3, 2**90, -1))),
    (False, 2**80, ((0, 2**80, 17), (3, 21, 4))),
])
def test_packing_roundtrip_and_blocked_integer_products(signed, bound, rows):
    p = PackedMatrix.from_rows(rows, bound, signed, block_columns=1, cache_bytes=0)
    loaded = PackedMatrix.from_bytes(p.to_bytes(), block_columns=2, cache_bytes=4096)
    assert loaded.rows() == rows
    assert loaded.to_bytes() == p.to_bytes()
    a = matrix(ZZ, rows)
    assert loaded.multiply((2, -3, 4)) == a*vector(ZZ, (2, -3, 4))
    assert loaded.multiply((3, -5), transpose=True) == a.transpose()*vector(ZZ, (3, -5))
    assert loaded.norm_squared() == sum(x*x for row in rows for x in row)


@pytest.mark.parametrize("mutation", ["truncated", "appended", "dimensions", "flag", "bound"])
def test_compact_parser_rejects_malformed_or_out_of_domain(mutation):
    raw = PackedMatrix.from_rows(((127, -128),), 128, True).to_bytes()
    pos = len(MAGIC)
    if mutation == "truncated": raw = raw[:-1]
    if mutation == "appended": raw += b"!"
    if mutation == "dimensions": raw = raw[:pos]+(2**20).to_bytes(4, "big")+raw[pos+4:]
    if mutation == "flag": raw = raw[:pos+8]+b"\x02"+raw[pos+9:]
    if mutation == "bound": raw = raw[:pos+9]+(1).to_bytes(32, "big")+raw[pos+41:]
    with pytest.raises(ValueError): PackedMatrix.from_bytes(raw)


def test_failed_packing_never_accepts_boolean_or_oversized_allocation():
    with pytest.raises(ValueError): PackedMatrix.from_rows(((True,),), 1, False)
    with pytest.raises(ValueError): PackedMatrix.from_columns(2**20, 2**20, 1, True, ())


@pytest.fixture(scope="module")
def root():
    return generate_root(2, 1099511627689, 16, rng=rng(b"root"))


def exact_correction(t, S, g, p):
    # Independent, deliberately dense public-toy oracle. Live code never
    # constructs this full covariance or its inverse.
    r = matrix(ZZ, t.r.rows())
    j = r.stack(identity_matrix(ZZ, t.w))
    j = j.stack(matrix(ZZ, len(p)-t.dimension, t.w))
    c = S*identity_matrix(ZZ, len(p))-g*j*j.transpose()
    v = vector(QQ, p)
    return v.dot_product(c.change_ring(QQ).inverse()*v)-v.dot_product(v)/S


def test_residual_certificate_encloses_independent_full_covariance_inverse(root):
    e = PackedMatrix.from_rows(((1, 2, 3), (4, 5, 6)), root.q-1, False)
    s = BlockedPreimageSampler(root, e)
    for p in (tuple(range(s.dimension)), tuple((-1)**i*10**8 for i in range(s.dimension))):
        lo, hi = s.correction_interval(p)
        expected = exact_correction(root, s.output_squared, s.gadget_squared, p)
        assert lo <= expected <= hi
        assert hi-lo <= s.scalar.weight_width/16


def test_left_extension_coordinates_are_sampled_and_equation_is_exact(root):
    e = PackedMatrix.from_rows(((1, 2, 3), (4, 5, 6)), root.q-1, False)
    s = BlockedPreimageSampler(root, e)
    x = s.sample((17, 23), rng=rng(b"left"))
    assert len(x) == root.dimension+3
    assert any(x[root.dimension:])
    assert s.public_product(x) == (17, 23)
    assert sum(v*v for v in x) <= s.dimension*s.output_squared


def test_wide_modulus_real_root_and_preimage_have_no_machine_word_conversion():
    q = 604462909807314587353111
    t = generate_root(2, q, 16, rng=rng(b"wide"), block_columns=7)
    s = BlockedPreimageSampler(t)
    x = s.sample((q-1, q-2), rng=rng(b"wide-sample"))
    assert s.public_product(x) == (q-1, q-2)
    assert t.public.width == 10
    assert "private_values_hidden=True" in repr(t)


def test_delegation_retains_full_random_columns_and_parent_can_sample(root):
    h = PackedMatrix.from_rows(tuple(tuple((i+1)*(j+7) % root.q for j in range(root.dimension))
                                    for i in range(root.n)), root.q-1, False)
    parent = delegate(root, h, rng=rng(b"delegate"))
    assert parent.dimension == 2*root.dimension
    assert parent.prefix == 2*root.dimension-root.w
    assert parent.public.rows() == tuple(a+b for a, b in zip(root.public.rows(), h.rows()))
    # Extras are independently perturbed, not identically zero outputs.
    assert any(x for col in parent.r.columns() for x in col[root.dimension:])
    assert not any(value is root for value in vars(parent).values())
    sampler = BlockedPreimageSampler(parent, h)
    x = sampler.sample((3, 5), rng=rng(b"leaf"))
    assert len(x) == 3*root.dimension
    assert sampler.public_product(x) == (3, 5)


def test_declared_norm_and_public_relation_cannot_be_forged(root):
    with pytest.raises(ValueError): PackedTrapdoor(root.n, root.q, root.public, root.r, 0)
    cols = list(root.public.columns())
    cols[-1] = tuple((x+1) % root.q for x in cols[-1])
    public = PackedMatrix.from_columns(root.n, root.dimension, root.q-1, False, cols)
    with pytest.raises(ValueError): PackedTrapdoor(root.n, root.q, public, root.r, root.bound)


def test_delegation_rejects_cross_domain_extension_before_any_private_entropy(root):
    class NoEntropy:
        calls = 0
        def read(self, count):
            self.calls += 1
            pytest.fail("invalid delegation extension consumed private entropy")
    source = NoEntropy()
    for height, bound, signed in ((root.n+1, root.q-1, False),
                                  (root.n, root.q, False),
                                  (root.n, root.q-1, True)):
        bad = PackedMatrix.from_columns(height, root.w, bound, signed,
            ((0,)*height for _ in range(root.w)))
        with pytest.raises(ValueError): delegate(root, bad, rng=source)
    assert source.calls == 0


def test_public_equation_product_cannot_ignore_extra_coordinates(root):
    for extension in (None, PackedMatrix.from_rows(((1, 2), (3, 4)), root.q-1, False)):
        sampler = BlockedPreimageSampler(root, extension)
        for length in (sampler.dimension-1, sampler.dimension+1):
            with pytest.raises(ValueError): sampler.public_product((0,)*length)
