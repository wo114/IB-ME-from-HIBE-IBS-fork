"""NAND relation, matching truth tables, exact witness and input budgets."""

from dataclasses import replace
from itertools import product
import json

import pytest

from experiments.research.candidates.yu.homomorphic_reference import (
    Params, NandCircuit, ReferenceBudgetExceeded, PrivateEvaluation,
    MAX_GATES, MAX_DEPTH, MAX_WITNESS_BITS, MAX_CIRCUIT_BYTES,
    encode_inputs, eval_public, eval_private, gadget, gadget_inverse,
    homomorphism_holds, matching_circuit,
)


def fixture_inputs(p, count):
    master = tuple(tuple((3 * i + 5 * j + 1) % p.q for j in range(p.m)) for i in range(p.n))
    witnesses = tuple(tuple(tuple(1 if (i * 3 + j + k) % 3 else -1 for j in range(p.w))
                             for i in range(p.m)) for k in range(count))
    return master, witnesses


def multiply_mod(a, b, q):
    return tuple(tuple(sum(a[i][h] * b[h][j] for h in range(len(b))) % q for j in range(len(b[0])))
                 for i in range(len(a)))


@pytest.mark.parametrize("q", [3, 17, 81, 257, 65537])
def test_gadget_layout_and_every_scalar_residue(q):
    p = Params(n=2, m=3, q=q)
    # Exhaust smaller moduli; the large example tests every bit and endpoints.
    values = tuple(range(q)) if q <= 257 else (0, 1, q - 1, *(1 << k for k in range(p.digit_bits)))
    target = (values, tuple((q - 1 - x) % q for x in values))
    # The inverse's public column resource limit is exercised in small chunks.
    for start in range(0, len(values), 32):
        block = tuple(row[start:start + 32] for row in target)
        inverse = gadget_inverse(p, block)
        assert len(inverse) == p.w and all(x in (0, 1) for row in inverse for x in row)
        assert multiply_mod(gadget(p), inverse, q) == block


@pytest.mark.parametrize("values", list(product((0, 1), repeat=2)))
@pytest.mark.parametrize("q", [17, 81, 257])
def test_all_nand_truth_values_and_integer_witnesses(q, values):
    p, circuit = Params(q=q), NandCircuit(2, ((0, 1),), (2,))
    a, r = fixture_inputs(p, 2)
    inputs = encode_inputs(p, a, values, r)
    public = eval_public(p, circuit, a, inputs)
    private = eval_private(p, circuit, a, values, r)
    assert private.output_bits == (1 - values[0] * values[1],)
    assert homomorphism_holds(p, a, public, private)
    assert private.input_pm1 and private.coefficient_bound == p.w + 1
    assert "unverified" in private.norm_profile and "redacted" in repr(private)


@pytest.mark.parametrize("pattern", [(0,), (1,), (1, 0, 1), (1, 0, 1, 0), (0, 0, 0, 0)])
def test_matching_circuit_against_independent_equality(pattern):
    p, circuit = Params(n=1, m=3, q=17), matching_circuit(pattern)
    a, r = fixture_inputs(p, len(pattern))
    for values in product((0, 1), repeat=len(pattern)):
        assert circuit.evaluate(values) == (int(values == pattern),)
        public = eval_public(p, circuit, a, encode_inputs(p, a, values, r))
        private = eval_private(p, circuit, a, values, r)
        assert private.output_bits == (int(values == pattern),)
        assert homomorphism_holds(p, a, public, private)


def test_multiple_outputs_shared_wires_order_and_composition():
    p = Params()
    first = NandCircuit(3, ((0, 1), (3, 2)), (4, 3, 0))
    a, r = fixture_inputs(p, 3)
    for values in product((0, 1), repeat=3):
        public = eval_public(p, first, a, encode_inputs(p, a, values, r))
        private = eval_private(p, first, a, values, r)
        assert first.evaluate(values) == (1 - (1 - values[0] * values[1]) * values[2], 1 - values[0] * values[1], values[0])
        assert homomorphism_holds(p, a, public, private)
        blocks = tuple(tuple(row[i * p.w:(i + 1) * p.w] for row in public) for i in range(3))
        witnesses = tuple(tuple(row[i * p.w:(i + 1) * p.w] for row in private.matrix) for i in range(3))
        second = matching_circuit((1, 0, 1))
        next_public = eval_public(p, second, a, blocks)
        next_private = eval_private(p, second, a, private.output_bits, witnesses)
        assert homomorphism_holds(p, a, next_public, next_private)
        assert next_private.output_bits == (int(private.output_bits == (1, 0, 1)),)
        assert not next_private.input_pm1  # Algebra composes; original +/-1 scope does not automatically carry over.


def test_public_output_is_independent_of_private_witness_choice():
    p, circuit = Params(n=1, m=2, q=17), NandCircuit(2, ((0, 1),), (2,))
    a = ((1, 0),)
    values = (0, 1)
    first = (((1,) * p.w, (1,) * p.w),) * 2
    second = (((1,) * p.w, (-1,) * p.w),) * 2
    public_inputs = encode_inputs(p, a, values, first)
    assert public_inputs == encode_inputs(p, a, values, second)
    public = eval_public(p, circuit, a, public_inputs)
    one, two = eval_private(p, circuit, a, values, first), eval_private(p, circuit, a, values, second)
    assert one.matrix != two.matrix
    assert homomorphism_holds(p, a, public, one) and homomorphism_holds(p, a, public, two)


def test_mod_reduction_preserves_equation_but_changes_integer_witness():
    p, circuit = Params(n=1, m=3, q=17), NandCircuit(2, ((0, 1),), (2,))
    a, r = ((1, 2, 3),), (((1,) * p.w,) * p.m,) * 2
    inputs = encode_inputs(p, a, (0, 0), r)
    public = eval_public(p, circuit, a, inputs)
    private = eval_private(p, circuit, a, (0, 0), r)
    assert any(x < 0 for row in private.matrix for x in row)
    reduced = replace(private, matrix=tuple(tuple(x % p.q for x in row) for row in private.matrix))
    assert reduced.matrix != private.matrix and homomorphism_holds(p, a, public, reduced)
    assert max(abs(x) for row in reduced.matrix for x in row) > private.coefficient_bound
    # Equation-only checks cannot certify the intended norm or distribution.


def test_modified_public_matrix_fails_relation():
    p, circuit = Params(), matching_circuit((1, 0))
    a, r = fixture_inputs(p, 2)
    public = eval_public(p, circuit, a, encode_inputs(p, a, (1, 0), r))
    private = eval_private(p, circuit, a, (1, 0), r)
    changed = ((public[0][0] + 1) % p.q,) + public[0][1:]
    assert not homomorphism_holds(p, a, (changed, *public[1:]), private)


def test_wrong_private_input_fails_even_when_nand_truth_value_matches():
    p, c = Params(n=1, m=3, q=17), NandCircuit(2, ((0, 1),), (2,))
    a, r = ((1, 2, 3),), (((1,) * p.w,) * p.m,) * 2
    public = eval_public(p, c, a, encode_inputs(p, a, (0, 0), r))
    honest = eval_private(p, c, a, (0, 0), r)
    changed = eval_private(p, c, a, (1, 0), r)
    assert honest.output_bits == changed.output_bits == (1,)
    assert homomorphism_holds(p, a, public, honest)
    assert not homomorphism_holds(p, a, public, changed)


@pytest.mark.parametrize("circuit", [NandCircuit(1, (), (0,)), NandCircuit(2, ((0, 1),), (2, 0)), matching_circuit((1, 0, 1))])
def test_canonical_circuit_roundtrip(circuit):
    assert NandCircuit.from_bytes(circuit.to_bytes()) == circuit
    with pytest.raises(ValueError): NandCircuit.from_bytes(circuit.to_bytes() + b"\0")
    value = json.loads(circuit.to_bytes())
    with pytest.raises(ValueError): NandCircuit.from_bytes(json.dumps(value).encode())  # alternate whitespace encoding


@pytest.mark.parametrize("gates,outputs", [(((0, 2),), (2,)), (((-1, 1),), (2,)), (((True, 1),), (2,)), (((0,),), (2,)), ((), (2,))])
def test_invalid_wires_and_gate_shapes_rejected(gates, outputs):
    with pytest.raises(ValueError): NandCircuit(2, gates, outputs)


def test_static_and_integer_growth_budgets_fail_without_partial_outputs():
    with pytest.raises(ReferenceBudgetExceeded): NandCircuit(2, ((0, 1),) * (MAX_GATES + 1), (0,))
    chain = tuple((1 + i, 1 + i) for i in range(MAX_DEPTH + 1))
    with pytest.raises(ReferenceBudgetExceeded): NandCircuit(2, chain, (0,))
    with pytest.raises(ValueError): NandCircuit.from_bytes(b"x" * (MAX_CIRCUIT_BYTES + 1))
    p, circuit = Params(n=1, m=1, q=17), NandCircuit(1, ((0, 0),), (1,))
    huge = (1 << MAX_WITNESS_BITS) - 1
    with pytest.raises(ReferenceBudgetExceeded): eval_private(p, circuit, ((1,),), (1,), (((huge,) * p.w,),))


@pytest.mark.parametrize("kind", ["master-shape", "public-shape", "negative-public", "boolean-coefficient", "wrong-bits", "wrong-witness-count"])
def test_input_type_dimension_and_canonical_range_checks(kind):
    p, circuit = Params(), NandCircuit(2, ((0, 1),), (2,))
    a, r = fixture_inputs(p, 2)
    inputs = encode_inputs(p, a, (0, 1), r)
    with pytest.raises(ValueError):
        if kind == "master-shape": eval_public(p, circuit, ((0,),), inputs)
        elif kind == "public-shape": eval_public(p, circuit, a, (inputs[0],))
        elif kind == "negative-public": gadget_inverse(p, ((-1,), (0,)))
        elif kind == "boolean-coefficient": gadget_inverse(p, ((True,), (0,)))
        elif kind == "wrong-bits": eval_private(p, circuit, a, (True, 1), r)
        else: eval_private(p, circuit, a, (0, 1), r[:-1])


def test_objects_inputs_remain_unchanged_and_no_security_promotion():
    p, circuit = Params(), matching_circuit((1, 0))
    a, r = fixture_inputs(p, 2)
    before = a, r, circuit.to_bytes()
    private = eval_private(p, circuit, a, (1, 0), r)
    assert before == (a, r, circuit.to_bytes())
    assert p.security_claim == "none" and not p.backend_admitted
    assert PrivateEvaluation.norm_profile.endswith("unverified")


def test_circuit_duplicate_fields_and_unknown_version_rejected():
    raw = NandCircuit(2, ((0, 1),), (2,)).to_bytes()
    with pytest.raises(ValueError, match="duplicate"): NandCircuit.from_bytes(raw[:-1] + b',"input_count":2}')
    with pytest.raises(ValueError): NandCircuit.from_bytes(raw.replace(b"NAND-REFERENCE/1", b"NAND-REFERENCE/2"))


@pytest.mark.parametrize("output_bits", [(), (True,), (2,)])
def test_equation_checker_rejects_malformed_output_bits(output_bits):
    p, c = Params(n=1, m=1, q=17), NandCircuit(1, (), (0,))
    a, r = ((1,),), (((1,) * p.w,),)
    public = eval_public(p, c, a, encode_inputs(p, a, (0,), r))
    private = replace(eval_private(p, c, a, (0,), r), output_bits=output_bits)
    with pytest.raises(ValueError): homomorphism_holds(p, a, public, private)
