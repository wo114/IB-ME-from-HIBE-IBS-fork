"""Differential algebra tests independent of Sage/trapdoor sampling."""
from itertools import product

import pytest

from experiments.research.candidates.yu.circuits import Circuit
from experiments.research.candidates.yu import evaluation as e
from experiments.research.candidates.yu import homomorphic_reference as old


def fixture(p, count):
    a = tuple(tuple((2*i+3*j+1) % p.q for j in range(p.m)) for i in range(p.n))
    r = tuple(tuple(tuple(1 if (k+i+j) % 2 else -1 for j in range(p.w))
                    for i in range(p.m)) for k in range(count))
    return a, r


@pytest.mark.parametrize("q", [3, 17, 81, 257])
def test_both_evaluators_agree_with_independent_reference(q):
    p = e.EvalParams(2, 4, q)
    gates, outputs = ((0, 1), (3, 2), (4, 4), (5, 3)), (6, 3, 0)
    c = Circuit(3, gates, outputs)
    oc = old.NandCircuit(3, gates, outputs)
    op = old.Params(p.n, p.m, q)
    a, r = fixture(p, 3)
    for values in product((0, 1), repeat=3):
        inputs = e.encode_inputs(p, a, values, r)
        public = e.eval_public(p, c, a, inputs)
        private = e.eval_private(p, c, a, values, r)
        reference_private = old.eval_private(op, oc, a, values, r)
        assert e.join(public) == old.eval_public(op, oc, a, inputs)
        assert e.join(private.witnesses) == reference_private.matrix
        assert private.output_bits == c.evaluate(values)
        assert e.homomorphism_holds(p, a, public, private)


def test_literal_constants_duplicate_outputs_and_dead_wires():
    p = e.EvalParams(1, 3, 17)
    c = Circuit(2, ((0, -2), (1, -1), (2, 3), (0, 1)), (-1, -2, 4, 4, 1))
    a, r = fixture(p, 2)
    for values in product((0, 1), repeat=2):
        public = e.eval_public(p, c, a, e.encode_inputs(p, a, values, r))
        private = e.eval_private(p, c, a, values, r)
        assert private.output_bits == (0, 1, values[0], values[0], values[1])
        assert private.output_bits == c.evaluate(values)
        assert e.homomorphism_holds(p, a, public, private)
        assert public[0] == ((0,) * p.w,)
        assert public[1] == e.gadget(p)


def test_constant_only_circuit_has_zero_witness():
    p, c, a = e.EvalParams(1, 2, 3), Circuit(0, (), (-1, -2)), ((1, 2),)
    public = e.eval_public(p, c, a, ())
    private = e.eval_private(p, c, a, (), ())
    assert private.output_bits == (0, 1)
    assert all(x == 0 for block in private.witnesses for row in block for x in row)
    assert e.homomorphism_holds(p, a, public, private)


@pytest.mark.parametrize("length", [1, 2, 3, 5])
def test_composed_equality_exhaustively(length):
    p = e.EvalParams(1, 3, 17)
    a, r = fixture(p, length)
    pattern = tuple(i % 2 for i in range(length))
    c = e.equality_circuit(pattern)
    for values in product((0, 1), repeat=length):
        private = e.eval_private(p, c, a, values, r)
        assert c.evaluate(values) == (int(values == pattern),)
        assert e.homomorphism_holds(p, a,
            e.eval_public(p, c, a, e.encode_inputs(p, a, values, r)), private)


def test_changed_public_output_is_detected():
    p, c = e.EvalParams(1, 3, 17), Circuit(2, ((0, 1),), (2,))
    a, r = fixture(p, 2)
    public = e.eval_public(p, c, a, e.encode_inputs(p, a, (1, 0), r))
    private = e.eval_private(p, c, a, (1, 0), r)
    bad = ((((public[0][0][0]+1) % p.q,) + public[0][0][1:],),)
    assert not e.homomorphism_holds(p, a, bad, private)


def test_public_evaluation_has_no_secret_input():
    p, c = e.EvalParams(1, 2, 17), Circuit(2, ((0, 1),), (2,))
    a = ((1, 0),)
    r1 = (((1,) * p.w, (1,) * p.w),) * 2
    r2 = (((1,) * p.w, (-1,) * p.w),) * 2
    x = (0, 1)
    inputs = e.encode_inputs(p, a, x, r1)
    assert inputs == e.encode_inputs(p, a, x, r2)
    public = e.eval_public(p, c, a, inputs)
    one, two = (e.eval_private(p, c, a, x, r) for r in (r1, r2))
    assert one.witnesses != two.witnesses
    assert all(e.homomorphism_holds(p, a, public, private) for private in (one, two))


@pytest.mark.parametrize("bad", [((17, 0, 0, 0, 0),), ((-1, 0, 0, 0, 0),),
                                  ((True, 0, 0, 0, 0),), ((0,),)])
def test_noncanonical_or_malformed_public_matrix_rejected(bad):
    p, c = e.EvalParams(1, 2, 17), Circuit(1, (), (0,))
    with pytest.raises(ValueError):
        e.eval_public(p, c, ((1, 2),), (bad,))


def test_integer_witness_limit_aborts_without_modular_reduction():
    p, c = e.EvalParams(1, 2, 3), Circuit(1, (), (0,))
    with pytest.raises(ValueError):
        e.eval_private(p, c, ((1, 2),), (0,), ((((1 << e.MAX_WITNESS_BITS), 0), (0, 0)),))


@pytest.mark.parametrize("values", [(), (True,), (2,), (-1,), "1"])
def test_invalid_equality_bits_rejected(values):
    with pytest.raises(ValueError):
        e.equality_circuit(values)
