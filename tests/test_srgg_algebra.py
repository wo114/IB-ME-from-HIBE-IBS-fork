"""SRGG public relations without pretending equation fixtures are sampling."""

from itertools import product
import pytest

from experiments.research.candidates.srgg.algebra import (
    Params, PublicRelation, add, build_public, constant, extraction_from_values,
    gadget_digits, matmul, matvec, multiply, reconstruct_vector, recover_commitment,
    response_from_values, scale, signing_matrix, signing_relation, trapdoor_relation,
    zeta, zeta_star,
)


def example(p):
    a = tuple(tuple(tuple((i * 7 + j * 5 + k * 3 + 1) % p.modulus for k in range(p.degree))
                    for j in range(p.rank)) for i in range(p.rank))
    r = tuple(tuple(tuple((i + 2 * j + k) % 3 - 1 for k in range(p.degree))
                    for j in range(p.rank * p.digits)) for i in range(2 * p.rank))
    public = build_public(p, a, r)
    target = tuple(tuple((i * 11 + k * 2 + 3) % p.modulus for k in range(p.degree)) for i in range(p.rank))
    perturbation = tuple(tuple((i + k) % 5 - 2 for k in range(p.degree)) for i in range(p.columns))
    return public, r, target, perturbation


@pytest.mark.parametrize("p", [Params(degree=2), Params(), Params(rank=2), Params(degree=8, digits=1)])
def test_module_trapdoor_and_error_corrected_key_reconstruction(p):
    public, r, target, perturbation = example(p)
    assert trapdoor_relation(public, r)
    trace = extraction_from_values(public, r, target, perturbation)
    actual = matvec(p, public.a, trace.raw_vector, p.modulus)
    expected = tuple(add(h, scale(e, -1), p.modulus) for h, e in zip(target, trace.error))
    assert actual == expected
    restored = reconstruct_vector(public, target, trace.tail)
    assert matvec(p, public.a, restored, p.modulus) == target
    assert restored[p.rank:] == trace.tail
    difference = tuple(add(x, scale(y, -1), p.modulus) for x, y in zip(restored[:p.rank], trace.raw_vector[:p.rank]))
    assert difference == trace.error
    assert all(-(p.modulus // 2) <= x <= p.modulus // 2 for row in restored[:p.rank] for x in row)
    assert signing_relation(public, target, restored)
    assert "redacted" in repr(trace)
    assert p.security_claim == "none" and not p.backend_admitted


@pytest.mark.parametrize("p", [Params(degree=2, digits=1), Params(), Params(rank=2)])
def test_deterministic_gadget_equation_for_every_scalar_residue(p):
    for value in range(p.modulus):
        target = (value,) * p.degree
        digits, error = gadget_digits(p, target)
        result = (0,) * p.degree
        for i, entry in enumerate(digits): result = add(result, scale(entry, p.p * p.base**i), p.modulus)
        assert result == add(target, scale(error, -1), p.modulus)
        assert all(0 <= e < p.p for e in error)
        assert all(0 <= x < p.base for row in digits for x in row)
    # These canonical digits prove an equation, not Algorithm 6's Gaussian law.


@pytest.mark.parametrize("degree,rank", [(2, 1), (4, 1), (4, 2)])
def test_all_binary_challenges_recover_same_commitment(degree, rank):
    p = Params(degree=degree, rank=rank)
    public, r, target, perturb = example(p)
    y = reconstruct_vector(public, target, extraction_from_values(public, r, target, perturb).tail)
    sig_perturb = tuple(tuple((i + k) % 3 - 1 for k in range(degree)) for i in range(p.columns + 1))
    u = tuple(i - 2 for i in range(degree))
    expected = matvec(p, signing_matrix(public, target), sig_perturb, 2 * p.modulus)
    assert multiply(zeta(p), zeta_star(p)) == constant(p, 2)
    for challenge in product((0, 1), repeat=degree):
        z = response_from_values(public, target, y, sig_perturb, u, challenge)
        assert recover_commitment(public, target, z, challenge) == expected


def test_wrong_identity_statement_changes_signing_relation():
    p = Params()
    public, r, target, perturb = example(p)
    y = reconstruct_vector(public, target, extraction_from_values(public, r, target, perturb).tail)
    changed = ((target[0][0] + 1) % p.modulus,) + target[0][1:]
    assert not signing_relation(public, (changed,), y)
    with pytest.raises(ValueError): response_from_values(public, (changed,), y, (constant(p, 0),) * (p.columns + 1), constant(p, 0), constant(p, 0))


def test_public_equation_alone_does_not_certify_a_user_secret_distribution():
    p = Params()
    public, _, target, _ = example(p)
    # Anyone can fill the HNF first block if long arbitrary integer vectors
    # are allowed. This is a deliberate equation-only negative control.
    tail = (constant(p, 0),) * ((1 + p.digits) * p.rank)
    y = reconstruct_vector(public, target, tail)
    assert signing_relation(public, target, y)


@pytest.mark.parametrize("changes", [{"degree":3}, {"degree":16}, {"rank":3}, {"p":4}, {"base":2}, {"digits":0}, {"p":True}])
def test_parameter_shape_and_resource_limits(changes):
    with pytest.raises(ValueError): Params(**changes)


@pytest.mark.parametrize("kind", ["public-range", "public-shape", "r-support", "r-shape", "tail-shape", "target-boolean", "challenge-not-bit", "response-shape"])
def test_input_boundaries(kind):
    p = Params()
    public, r, target, perturb = example(p)
    trace = extraction_from_values(public, r, target, perturb)
    y = reconstruct_vector(public, target, trace.tail)
    with pytest.raises(ValueError):
        if kind == "public-range": PublicRelation(p, (((p.modulus,) * p.degree,),), public.b)
        elif kind == "public-shape": PublicRelation(p, (), public.b)
        elif kind == "r-support": build_public(p, public.a_hat, (((2,) * p.degree,) * p.digits,) * 2)
        elif kind == "r-shape": trapdoor_relation(public, r[:-1])
        elif kind == "tail-shape": reconstruct_vector(public, target, trace.tail[:-1])
        elif kind == "target-boolean": reconstruct_vector(public, ((True,) * p.degree,), trace.tail)
        elif kind == "challenge-not-bit": response_from_values(public, target, y, (constant(p, 0),) * (p.columns + 1), constant(p, 0), constant(p, 2))
        else: recover_commitment(public, target, (), constant(p, 0))


def test_algebra_inputs_not_modified():
    p = Params()
    public, r, target, perturb = example(p)
    before = public.a, r, target, perturb
    trace = extraction_from_values(public, r, target, perturb)
    reconstruct_vector(public, target, trace.tail)
    assert before == (public.a, r, target, perturb)


def test_primitive_addition_and_product_do_not_silently_truncate():
    p = Params()
    with pytest.raises(ValueError): add((1, 2), (1,))
    value = constant(p, 1)
    with pytest.raises(ValueError): matmul(p, ((value, value), (value,)), ((value,), (value,)))
