"""Bounded exact NAND evaluation for Yu Figure 5, including literal constants.

The public evaluator receives no PRF key or witness.  The optional private
evaluator checks the algebra over ZZ, not the paper's sharper spectral bound.
The original small homomorphic_reference stays unchanged as an independent
regression oracle.  All resource limits here are research execution limits.
"""

from dataclasses import dataclass
from typing import ClassVar

from .circuits import Circuit

MAX_WITNESS_BITS = 8192


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


def bits(values, count):
    if not isinstance(values, (tuple, list)) or len(values) != count:
        raise ValueError("bit-vector length mismatch")
    return tuple(integer(x, 0, 1, "bit") for x in values)


@dataclass(frozen=True)
class EvalParams:
    n: int
    m: int
    q: int
    security_claim: ClassVar[str] = "none"

    def __post_init__(self):
        integer(self.n, 1, 4, "rows")
        integer(self.m, self.n, 192, "master columns")
        integer(self.q, 3, 65537, "modulus")
        if self.q % 2 == 0 or self.w > 64:
            raise ValueError("require odd modulus and at most 64 gadget columns")

    @property
    def digit_bits(self):
        return (self.q - 1).bit_length()

    @property
    def w(self):
        return self.n * self.digit_bits


def matrix(values, rows, columns, q=None):
    if not isinstance(values, (tuple, list)) or len(values) != rows:
        raise ValueError("matrix row count mismatch")
    result = []
    for row in values:
        if not isinstance(row, (tuple, list)) or len(row) != columns:
            raise ValueError("matrix column count mismatch")
        checked = []
        for x in row:
            if type(x) is not int or abs(x).bit_length() > MAX_WITNESS_BITS:
                raise ValueError("integer coefficient outside execution budget")
            if q is not None and not 0 <= x < q:
                raise ValueError("noncanonical public coefficient")
            checked.append(x)
        result.append(tuple(checked))
    return tuple(result)


def join(blocks):
    return tuple(tuple(x for block in blocks for x in block[i])
                 for i in range(len(blocks[0])))


def multiply(left, right, q=None):
    columns = tuple(zip(*right))
    result = tuple(tuple(sum(x*y for x, y in zip(row, col)) for col in columns)
                   for row in left)
    if q is None:
        return result
    return tuple(tuple(x % q for x in row) for row in result)


def gadget(params):
    if not isinstance(params, EvalParams):
        raise ValueError("EvalParams required")
    return tuple(tuple((1 << (j % params.digit_bits)) % params.q
                       if j // params.digit_bits == i else 0
                       for j in range(params.w)) for i in range(params.n))


def inverse(params, block):
    block = matrix(block, params.n, params.w, params.q)
    return tuple(tuple((block[i][j] >> bit) & 1 for j in range(params.w))
                 for i in range(params.n) for bit in range(params.digit_bits))


def public_gate(params, left, right):
    product = multiply(left, inverse(params, right), params.q)
    return tuple(tuple((g-x) % params.q for g, x in zip(grow, row))
                 for grow, row in zip(gadget(params), product))


def _check(params, circuit, master, inputs, private=False):
    if not isinstance(params, EvalParams) or not isinstance(circuit, Circuit):
        raise ValueError("EvalParams and Circuit required")
    master = matrix(master, params.n, params.m, params.q)
    if not isinstance(inputs, (tuple, list)) or len(inputs) != circuit.input_count:
        raise ValueError("input block count mismatch")
    return master, tuple(matrix(block, params.m if private else params.n,
                                params.w, None if private else params.q)
                         for block in inputs)


def _uses(circuit):
    counts = [0] * (circuit.input_count + len(circuit.gates))
    for pair in circuit.gates:
        for wire in pair:
            if wire >= 0:
                counts[wire] += 1
    for wire in circuit.outputs:
        if wire >= 0:
            counts[wire] += 1
    return counts


def _read(wires, wire, constants):
    return constants[-wire-1] if wire < 0 else wires[wire]


def _release(wires, counts, pair):
    for wire in pair:
        if wire >= 0:
            counts[wire] -= 1
            if counts[wire] == 0:
                wires[wire] = None


def eval_public(params, circuit, master, inputs):
    """Return one n-by-w block per output, with dead gate matrices released."""
    _, checked = _check(params, circuit, master, inputs)
    zero = tuple((0,) * params.w for _ in range(params.n))
    constants = (zero, gadget(params))
    wires, counts = list(checked), _uses(circuit)
    for left, right in circuit.gates:
        wires.append(public_gate(params, _read(wires, left, constants),
                                 _read(wires, right, constants)))
        _release(wires, counts, (left, right))
    return tuple(_read(wires, i, constants) for i in circuit.outputs)


def encode_inputs(params, master, values, witnesses):
    values = bits(values, len(witnesses))
    master = matrix(master, params.n, params.m, params.q)
    g = gadget(params)
    result = []
    for bit, witness in zip(values, witnesses):
        witness = matrix(witness, params.m, params.w)
        product = multiply(master, witness, params.q)
        result.append(tuple(tuple((x+bit*y) % params.q for x, y in zip(row, grow))
                            for row, grow in zip(product, g)))
    return tuple(result)


@dataclass(frozen=True, repr=False)
class PrivateEvaluation:
    witnesses: tuple
    output_bits: tuple
    coefficient_bound: int
    norm_profile: ClassVar[str] = "coarse-infinity-only; Yu-Lemma7-spectral-bound-unverified"

    def __repr__(self):
        return "PrivateEvaluation(witnesses=<redacted>, security_claim='none')"


def eval_private(params, circuit, master, values, witnesses):
    master, witnesses = _check(params, circuit, master, witnesses, private=True)
    values = bits(values, circuit.input_count)
    pub = encode_inputs(params, master, values, witnesses)
    zero_r = tuple((0,) * params.w for _ in range(params.m))
    zero_p = tuple((0,) * params.w for _ in range(params.n))
    constants = ((zero_p, zero_r, 0), (gadget(params), zero_r, 1))
    wires = list(zip(pub, witnesses, values))
    initial = max(1, max((abs(x) for block in witnesses for row in block for x in row), default=0))
    counts = _uses(circuit)
    for left, right in circuit.gates:
        lp, lr, lb = _read(wires, left, constants)
        rp, rr, rb = _read(wires, right, constants)
        product = multiply(lr, inverse(params, rp))
        witness = matrix(tuple(tuple(-x-lb*y for x, y in zip(row, rrow))
                               for row, rrow in zip(product, rr)), params.m, params.w)
        wires.append((public_gate(params, lp, rp), witness, 1-lb*rb))
        _release(wires, counts, (left, right))
    outputs = tuple(_read(wires, i, constants) for i in circuit.outputs)
    bound = initial * (params.w + 1)**circuit.depth
    if any(abs(x) > bound for _, block, _ in outputs for row in block for x in row):
        raise RuntimeError("coarse coefficient bound violated")
    return PrivateEvaluation(tuple(x[1] for x in outputs), tuple(x[2] for x in outputs), bound)


def homomorphism_holds(params, master, public, private):
    if not isinstance(private, PrivateEvaluation):
        raise ValueError("private evaluation required")
    expected = encode_inputs(params, master, private.output_bits, private.witnesses)
    checked = tuple(matrix(block, params.n, params.w, params.q) for block in public)
    return checked == expected


def equality_circuit(pattern):
    if not isinstance(pattern, (tuple, list)) or not 1 <= len(pattern) <= 64:
        raise ValueError("bounded nonempty equality pattern required")
    pattern, gates = bits(pattern, len(pattern)), []

    def nand(a, b):
        gates.append((a, b))
        return len(pattern) + len(gates) - 1

    terms = [i if b else nand(i, i) for i, b in enumerate(pattern)]
    while len(terms) > 1:
        nxt = []
        for i in range(0, len(terms)-1, 2):
            t = nand(terms[i], terms[i+1])
            nxt.append(nand(t, t))
        if len(terms) % 2:
            nxt.append(terms[-1])
        terms = nxt
    return Circuit(len(pattern), tuple(gates), (terms[0],))
