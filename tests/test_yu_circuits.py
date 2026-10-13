"""Independent Boolean/arithmetic and input/resource checks for finite NANDs."""

from dataclasses import FrozenInstanceError
from itertools import product
import random

import pytest

from experiments.research.candidates.yu.circuits import (
    Builder, Circuit, CircuitBudgetExceeded, MAX_DEPTH, MAX_GATES, ONE, ZERO,
)


def bits(value, width):
    return tuple((value >> i) & 1 for i in range(width))


def number(word):
    return sum(bit << i for i, bit in enumerate(word))


def test_constants_and_nand_truth_table():
    assert Circuit(0, (), (ZERO, ONE)).evaluate(()) == (0, 1)
    c = Circuit(2, ((0, 1),), (2, ZERO, ONE))
    for a, b in product((0, 1), repeat=2):
        assert c.evaluate((a, b)) == (1 - a * b, 0, 1)
    assert c.depth == 1


def test_boolean_builder_folding_and_shared_gates():
    b = Builder(2)
    wires = (ZERO, ONE, 0, 1)
    outputs = tuple(b.nand(x, y) for x in wires for y in wires)
    gates_before = len(b.gates)
    for x in wires:
        for y in wires:
            b.nand(y, x)
    assert len(b.gates) == gates_before
    c = b.finish(outputs)
    for value in product((0, 1), repeat=2):
        lookup = {ZERO: 0, ONE: 1, 0: value[0], 1: value[1]}
        assert c.evaluate(value) == tuple(1 - lookup[x] * lookup[y] for x in wires for y in wires)


@pytest.mark.parametrize("width", [1, 2, 3, 4])
def test_exhaustive_modular_add_and_multiply(width):
    b = Builder(2 * width)
    a, c = tuple(range(width)), tuple(range(width, 2 * width))
    compiled = b.finish(b.add(a, c) + b.multiply(a, c))
    for x in range(1 << width):
        for y in range(1 << width):
            out = compiled.evaluate(bits(x, width) + bits(y, width))
            assert number(out[:width]) == (x + y) % (1 << width)
            assert number(out[width:]) == (x * y) % (1 << width)


def test_comparison_exhausts_every_ticket_and_threshold():
    b = Builder(5)
    c = b.finish(tuple(b.ge_constant(tuple(range(5)), t) for t in range(33)))
    for x in range(32):
        assert c.evaluate(bits(x, 5)) == tuple(int(x >= t) for t in range(33))


def test_constant_arithmetic_and_balanced_or():
    b = Builder(0)
    a, c = b.constant(13, 4), b.constant(7, 4)
    compiled = b.finish(b.add(a, c) + b.multiply(a, c) + (b.any_(()), b.any_((ZERO, ONE))))
    assert compiled.evaluate(()) == bits(4, 4) + bits(11, 4) + (0, 1)
    assert compiled.depth == 0 and compiled.gates == ()


def test_random_dag_against_independent_boolean_interpreter():
    rng = random.Random(804)
    gates = tuple((rng.randrange(-2, 6 + i), rng.randrange(-2, 6 + i)) for i in range(100))
    c = Circuit(6, gates, tuple(range(100, 106)))
    for x in product((0, 1), repeat=6):
        values = {-1: False, -2: True, **dict(enumerate(map(bool, x)))}
        for i, (l, r) in enumerate(gates, 6):
            values[i] = not (values[l] and values[r])
        assert c.evaluate(x) == tuple(int(values[i]) for i in c.outputs)


@pytest.mark.parametrize("args", [
    (-1, (), (ZERO,)), (True, (), (ZERO,)), (8193, (), (ZERO,)),
    (1, [], (0,)), (1, (), [0]), (1, ((0,),), (0,)),
    (1, ([0, 0],), (0,)), (1, ((True, 0),), (0,)),
    (1, ((0, 1),), (0,)), (1, ((0, -3),), (0,)),
    (1, ((0, 0),), (2,)), (1, (), (True,)), (1, (), ()),
    (1, (), (0,) * 65), (1, (), (0.0,)),
])
def test_invalid_circuit_types_dimensions_and_topology(args):
    with pytest.raises(ValueError):
        Circuit(*args)


@pytest.mark.parametrize("x", [None, (), (1, 0), (True,), (0.0,), (2,), "0", iter((0,))])
def test_invalid_input_bits(x):
    with pytest.raises(ValueError):
        Circuit(1, (), (0,)).evaluate(x)


def test_frozen_and_deeply_immutable():
    c = Circuit(1, ((0, 0),), (1,))
    with pytest.raises(FrozenInstanceError):
        c.outputs = (0,)
    with pytest.raises(TypeError):
        c.gates[0][0] = 1


def test_circuit_resource_caps_and_depth_are_enforced():
    with pytest.raises(CircuitBudgetExceeded, match="gate"):
        Circuit(0, ((ZERO, ONE),) * (MAX_GATES + 1), (ZERO,))
    chain = tuple((i, i) for i in range(MAX_DEPTH))
    assert Circuit(1, chain, (MAX_DEPTH,)).depth == MAX_DEPTH
    with pytest.raises(CircuitBudgetExceeded, match="depth"):
        Circuit(1, chain + ((MAX_DEPTH, MAX_DEPTH),), (0,))


def test_builder_caps_fail_before_adding_a_gate():
    b = Builder(1, max_gates=1)
    first = b.invert(0)
    with pytest.raises(CircuitBudgetExceeded):
        b.invert(first)
    assert len(b.gates) == 1
    d = Builder(1, max_depth=1)
    with pytest.raises(CircuitBudgetExceeded):
        d.invert(d.invert(0))


def test_builder_rejects_invalid_words_and_public_constants():
    b = Builder(3)
    for call in (lambda: b.add((0,), (1, 2)), lambda: b.multiply((), (0,)),
                 lambda: b.constant(-1, 3), lambda: b.constant(8, 3),
                 lambda: b.ge_constant((0,), 3), lambda: b.ge_constant((0,), True),
                 lambda: b.ge_constant((3,), 0), lambda: b.any_([0]),
                 lambda: b.xor(True, 0), lambda: b.nand(3, 0)):
        with pytest.raises(ValueError):
            call()
