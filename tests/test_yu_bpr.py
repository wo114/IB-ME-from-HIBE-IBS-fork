"""Real Sage CDT checks plus independent BPR arithmetic/circuit comparisons.

Run in ~/miniconda3/envs/sage/bin/python. Missing Sage is an error, not a skip.
These are finite functional/distribution checks, not PRF or Yu security proofs.
"""

from collections import Counter
from dataclasses import FrozenInstanceError, replace
from fractions import Fraction
from itertools import product
import random

import pytest
from sage.all import RealField, ZZ, matrix

from experiments.research.candidates.yu import bpr
from experiments.research.candidates.yu.bpr import (
    BPRSpec, Params, compile_key_circuit, evaluate, make_spec,
)
from experiments.research.candidates.yu.circuits import Builder, CircuitBudgetExceeded
from experiments.research.gaussian_reference import build_gaussian_table


def bits(value, width):
    return tuple((value >> i) & 1 for i in range(width))


def sage_expected(spec, key, x):
    """Separate MSB string decoding, linear CDF scan, and Sage matrix arithmetic."""
    p = spec.params
    a_end = p.dimension * p.columns * p.modulus_bits
    a_values = [int("".join(map(str, reversed(key[i:i + p.modulus_bits]))), 2)
                for i in range(0, a_end, p.modulus_bits)]
    a = matrix(ZZ, p.dimension, p.columns, a_values)
    result = a.transpose()
    offset = a_end
    for selected in x:
        entries = []
        for _ in range(p.dimension**2):
            ticket = int("".join(map(str, reversed(key[offset:offset + p.ticket_bits]))), 2)
            offset += p.ticket_bits
            entries.append(next(v for v, end in zip(spec.support, spec.cdf) if ticket < end))
        if selected:
            result = result * matrix(ZZ, p.dimension, p.dimension, entries)
    return tuple(int((int(v) % p.modulus) >= p.modulus // 2) for v in result.list())


def encode_known_matrices(spec, a, matrices):
    p = spec.params
    key = tuple(bit for row in a for v in row for bit in bits(v, p.modulus_bits))
    for s in matrices:
        for row in s:
            for value in row:
                index = spec.support.index(value)
                ticket = spec.cdf[index - 1] if index else 0
                assert ticket < spec.cdf[index]
                key += bits(ticket, p.ticket_bits)
    return key


@pytest.mark.parametrize("ticket_bits", [1, 2, 5, 10, 32, 40])
def test_dyadic_cdf_and_certificate_exact(ticket_bits):
    spec = make_spec(Params(2, ticket_bits=ticket_bits))
    table = build_gaussian_table(2, tail_bits=40, mass_bits=80, precision_bits=160)
    size = 1 << ticket_bits
    assert spec.cdf == tuple(size * int(v) // int(table.total_mass) for v in table.cumulative)
    assert spec.cdf[-1] == size
    counts = [hi - lo for lo, hi in zip((0,) + spec.cdf[:-1], spec.cdf)]
    assert sum(counts) == size and min(counts) >= 0
    exact_tv = sum(abs(Fraction(c, size) - Fraction(int(m), int(table.total_mass)))
                   for c, m in zip(counts, table.masses)) / 2
    assert exact_tv <= spec.dyadic_tv_upper
    assert spec.dyadic_tv_upper == Fraction(len(spec.support) - 1, size)
    assert spec.coefficient_tv_upper == min(1, spec.tail_tv_upper + spec.quantization_tv_upper
                                          + spec.dyadic_tv_upper)
    assert spec.key_distribution_tv_upper == min(1, 8 * spec.coefficient_tv_upper)
    assert spec.certificate()["rejection_abort_used"] is False
    if ticket_bits <= 10:
        observed = Counter(spec.coefficient(t) for t in range(size))
        assert tuple(observed[v] for v in spec.support) == tuple(counts)


def test_finite_gaussian_against_independent_high_precision_pmf():
    spec = make_spec(Params(2))
    real = RealField(320)
    weights = {z: (-real.pi() * z**2 / 4).exp() for z in range(-40, 41)}
    total = sum(weights.values())
    counts = dict(zip(spec.support, (hi - lo for lo, hi in zip((0,) + spec.cdf[:-1], spec.cdf))))
    tv = sum(abs(real(counts.get(z, 0)) / (1 << 32) - w / total) for z, w in weights.items()) / 2
    assert tv <= real(spec.coefficient_tv_upper.numerator) / spec.coefficient_tv_upper.denominator
    assert counts[0] > 10 * counts[2]  # Gaussian mass, not uniform support.


def test_no_rejection_sampling_or_abort_is_used(monkeypatch):
    from experiments.research import gaussian_reference as gaussian

    def forbidden(*args, **kwargs):
        raise AssertionError("CDF construction/evaluation must not use rejection sampling")

    monkeypatch.setattr(gaussian.GaussianTable, "sample", forbidden)
    monkeypatch.setattr(gaussian, "draw_uniform_integer", forbidden)
    spec = make_spec(Params(1, gaussian_width=Fraction(3, 2), ticket_bits=5))
    c = compile_key_circuit(spec, (1,))
    key = (0,) * spec.params.key_bits
    assert c.evaluate(key) == evaluate(spec, key, (1,))


def test_exhaustive_small_keys_and_public_inputs():
    p = Params(2, dimension=1, columns=1, modulus_bits=3, ticket_bits=3)
    spec = make_spec(p)
    for x in product((0, 1), repeat=2):
        circuit = compile_key_circuit(spec, x)
        for key in product((0, 1), repeat=p.key_bits):
            expected = sage_expected(spec, key, x)
            assert evaluate(spec, key, x) == expected
            assert circuit.evaluate(key) == expected


@pytest.mark.parametrize("p", [
    Params(2), Params(8), Params(3, dimension=1, columns=3, ticket_bits=40),
    Params(3, dimension=3, columns=1, modulus_bits=4, ticket_bits=8),
    Params(5, dimension=2, columns=3, modulus_bits=6, ticket_bits=12),
    Params(2, modulus_bits=1, ticket_bits=4),
])
def test_random_keys_against_independent_sage_and_nand(p):
    spec, rng = make_spec(p), random.Random(7751)
    inputs = {(0,) * p.input_bits, (1,) * p.input_bits,
              tuple(int(i % 2 == 0) for i in range(p.input_bits))}
    for x in sorted(inputs):
        circuit = compile_key_circuit(spec, x)
        assert circuit.input_count == p.key_bits and len(circuit.outputs) == p.output_bits
        for _ in range(12):
            key = tuple(rng.getrandbits(1) for _ in range(p.key_bits))
            expected = sage_expected(spec, key, x)
            assert evaluate(spec, key, x) == expected
            assert circuit.evaluate(key) == expected


def test_matrix_order_is_not_commuted_and_A_is_transposed():
    spec = make_spec(Params(2, modulus_bits=3))
    a = ((0, 0), (0, 2))
    s1, s2 = ((1, 1), (0, 1)), ((1, 0), (1, 1))
    key = encode_known_matrices(spec, a, (s1, s2))
    swapped = encode_known_matrices(spec, a, (s2, s1))
    circuit = compile_key_circuit(spec, (1, 1))
    assert circuit.evaluate(key) == evaluate(spec, key, (1, 1)) == (0, 0, 0, 0)
    assert circuit.evaluate(swapped) == evaluate(spec, swapped, (1, 1)) == (0, 0, 0, 1)


def test_all_residue_rounding_boundaries_and_lsb_A_layout():
    p = Params(1, dimension=2, columns=3, modulus_bits=5, ticket_bits=3)
    spec = make_spec(p)
    circuit = compile_key_circuit(spec, (0,))
    assert circuit.gates == () and circuit.depth == 0
    for base in range(p.modulus):
        a = [[(base + 3 * i + j) % p.modulus for j in range(p.columns)] for i in range(p.dimension)]
        key = tuple(bit for row in a for value in row for bit in bits(value, p.modulus_bits))
        key += (1,) * (p.key_bits - len(key))
        expected = tuple(int(a[i][j] >= 16) for j in range(p.columns) for i in range(p.dimension))
        assert circuit.evaluate(key) == evaluate(spec, key, (0,)) == expected


def test_negative_gaussian_and_modular_wrap():
    spec = make_spec(Params(1, dimension=1, columns=1, modulus_bits=5))
    key = encode_known_matrices(spec, ((1,),), (((-1,),),))
    assert evaluate(spec, key, (1,)) == (1,)
    assert compile_key_circuit(spec, (1,)).evaluate(key) == (1,)


def test_compiled_CDF_every_interval_boundary():
    spec = make_spec(Params(1, dimension=1, columns=1))
    builder = Builder(spec.params.ticket_bits)
    word = bpr._compile_coefficient(builder, spec, tuple(range(spec.params.ticket_bits)))
    circuit = builder.finish(word)
    tickets = {0, (1 << spec.params.ticket_bits) - 1}
    for end in spec.cdf:
        tickets.update(t for t in (end - 1, end) if 0 <= t < 1 << spec.params.ticket_bits)
    for t in tickets:
        got = sum(bit << i for i, bit in enumerate(circuit.evaluate(bits(t, spec.params.ticket_bits))))
        assert got == spec.coefficient(t) % spec.params.modulus


def test_compiler_does_not_call_numeric_evaluate(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Do not compile a truth table or call numeric evaluation")
    monkeypatch.setattr(bpr, "evaluate", forbidden)
    spec = make_spec(Params(1))
    c = compile_key_circuit(spec, (1,))
    key = (0,) * spec.params.key_bits
    assert c.evaluate(key) == sage_expected(spec, key, (1,))


@pytest.mark.parametrize("kwargs", [
    {"input_bits": True}, {"input_bits": 0}, {"input_bits": 65},
    {"dimension": 0}, {"dimension": 9}, {"dimension": 2.0},
    {"columns": 0}, {"modulus_bits": 0}, {"modulus_bits": 17},
    {"ticket_bits": 0}, {"ticket_bits": 65}, {"gaussian_width": 2.0},
    {"gaussian_width": True}, {"gaussian_width": 0}, {"gaussian_width": 9},
    {"input_bits": 64, "dimension": 8},
])
def test_invalid_params(kwargs):
    with pytest.raises(ValueError):
        Params(**{"input_bits": 2, **kwargs})


def test_specs_are_immutable_and_only_canonical_CDF_is_admitted():
    spec = make_spec(Params(2))
    with pytest.raises(FrozenInstanceError):
        spec.cdf = (1,)
    with pytest.raises(FrozenInstanceError):
        spec.params.input_bits = 5
    for kwargs in ({"cdf": spec.cdf[:-1] + (spec.cdf[-1] - 1,)},
                   {"cdf": spec.cdf[:6] + (spec.cdf[6] + 1,) + spec.cdf[7:]},
                   {"cdf": list(spec.cdf)}, {"support": spec.support[::-1]},
                   {"support": (False,) + spec.support[1:]},
                   {"cdf": (False,) + spec.cdf[1:]},
                   {"params": replace(spec.params, gaussian_width=3)}):
        with pytest.raises(ValueError):
            replace(spec, **kwargs)
    with pytest.raises(ValueError):
        make_spec({"input_bits": 2})
    with pytest.raises(ValueError):
        BPRSpec(spec.params, (0,), (1 << 32,))


def test_wrong_keys_inputs_tickets_and_spec_are_rejected():
    spec = make_spec(Params(2))
    key = (0,) * spec.params.key_bits
    for x in ((0,), (0, 0, 0), (True, 0), (0.0, 1), (2, 0), "00", None):
        with pytest.raises(ValueError):
            evaluate(spec, key, x)
        with pytest.raises(ValueError):
            compile_key_circuit(spec, x)
    for bad_key in (key[:-1], key + (0,), (True,) + key[1:], (0.0,) + key[1:], None):
        with pytest.raises(ValueError):
            evaluate(spec, bad_key, (0, 0))
    for ticket in (-1, 1 << 32, True, 0.0):
        with pytest.raises(ValueError):
            spec.coefficient(ticket)
    with pytest.raises(ValueError):
        evaluate(None, key, (0, 0))
    with pytest.raises(ValueError):
        compile_key_circuit(None, (0, 0))


def test_compiler_propagates_resource_failure_without_partial_circuit(monkeypatch):
    spec = make_spec(Params(1))
    monkeypatch.setattr(bpr, "Builder", lambda count: Builder(count, max_gates=20))
    with pytest.raises(CircuitBudgetExceeded):
        compile_key_circuit(spec, (1,))


def test_default_eight_input_budget_and_determinism():
    spec = make_spec(Params(8))
    circuit = compile_key_circuit(spec, (1,) * 8)
    assert spec.params.key_bits == 1044 and spec.params.output_bits == 4
    assert len(circuit.gates) < 50_000 and circuit.depth < 256
    assert circuit == compile_key_circuit(spec, (1,) * 8)
