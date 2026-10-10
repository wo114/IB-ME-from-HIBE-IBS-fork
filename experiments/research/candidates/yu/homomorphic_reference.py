"""Yu 2026 §2.2 Lemma 7: binary-gadget NAND algebra reference.

Implements the homomorphism identity, not the lemma's O(4^d*m^1.5)
singular-value guarantee. Exact integer witnesses are never reduced mod q.
No PRF, TrapGen, Gaussian, IBS backend, or security claim is provided here.
"""

from dataclasses import dataclass
import json
from typing import ClassVar

MAX_INPUTS, MAX_GATES, MAX_OUTPUTS, MAX_DEPTH = 32, 256, 16, 16
MAX_WITNESS_BITS, MAX_CIRCUIT_BYTES = 512, 65536
CIRCUIT_FORMAT = "IBME/YU2026/NAND-REFERENCE/1"


class ReferenceBudgetExceeded(ValueError):
    """Public research budget exceeded; no partial output is returned."""


def integer(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


def bits(values, count):
    if not isinstance(values, (tuple, list)) or len(values) != count:
        raise ValueError("bit-vector length mismatch")
    return tuple(integer(value, 0, 1, "bit") for value in values)


@dataclass(frozen=True)
class Params:
    n: int = 2
    m: int = 4
    q: int = 257
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        integer(self.n, 1, 4, "rows")
        integer(self.m, 1, 16, "master columns")
        integer(self.q, 3, 65537, "research modulus")
        if self.q % 2 == 0: raise ValueError("odd research modulus required")

    @property
    def digit_bits(self): return (self.q - 1).bit_length()

    @property
    def w(self): return self.n * self.digit_bits


@dataclass(frozen=True)
class NandCircuit:
    input_count: int
    gates: tuple
    outputs: tuple

    def __post_init__(self):
        integer(self.input_count, 1, MAX_INPUTS, "input count")
        if not isinstance(self.gates, (tuple, list)) or len(self.gates) > MAX_GATES:
            raise ReferenceBudgetExceeded("NAND gate count exceeds budget")
        gates, depths = [], [0] * self.input_count
        for index, gate in enumerate(self.gates):
            if not isinstance(gate, (tuple, list)) or len(gate) != 2: raise ValueError("two gate inputs required")
            left, right = (integer(wire, 0, self.input_count + index - 1, "topological wire") for wire in gate)
            depth = 1 + max(depths[left], depths[right])
            if depth > MAX_DEPTH: raise ReferenceBudgetExceeded("NAND depth exceeds budget")
            depths.append(depth)
            gates.append((left, right))
        if not isinstance(self.outputs, (tuple, list)) or not 1 <= len(self.outputs) <= MAX_OUTPUTS:
            raise ValueError("output count outside budget")
        outputs = tuple(integer(wire, 0, len(depths) - 1, "output wire") for wire in self.outputs)
        object.__setattr__(self, "gates", tuple(gates))
        object.__setattr__(self, "outputs", outputs)

    @property
    def wire_depths(self):
        values = [0] * self.input_count
        for left, right in self.gates: values.append(1 + max(values[left], values[right]))
        return tuple(values)

    @property
    def depth(self): return max(self.wire_depths[i] for i in self.outputs)

    def evaluate(self, values):
        wires = list(bits(values, self.input_count))
        for left, right in self.gates: wires.append(1 - wires[left] * wires[right])
        return tuple(wires[i] for i in self.outputs)

    def to_bytes(self):
        return json.dumps(dict(format=CIRCUIT_FORMAT, input_count=self.input_count, gates=self.gates, outputs=self.outputs),
                          sort_keys=True, separators=(",", ":")).encode("ascii")

    @classmethod
    def from_bytes(cls, data):
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_CIRCUIT_BYTES:
            raise ValueError("bounded circuit bytes required")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError("duplicate circuit field")
                result[key] = value
            return result
        try:
            value = json.loads(data, object_pairs_hook=unique)
        except (UnicodeError, RecursionError) as exc:
            raise ValueError("invalid circuit encoding") from exc
        if not isinstance(value, dict) or set(value) != {"format", "input_count", "gates", "outputs"} or value["format"] != CIRCUIT_FORMAT:
            raise ValueError("unknown circuit version/fields")
        result = cls(value["input_count"], value["gates"], value["outputs"])
        if result.to_bytes() != bytes(data): raise ValueError("noncanonical circuit encoding")
        return result


def matching_circuit(pattern):
    """Eq.(3.2)'s public equality function, compiled to a balanced NAND DAG."""
    if not isinstance(pattern, (tuple, list)) or not 1 <= len(pattern) <= MAX_INPUTS:
        raise ValueError("bounded nonempty pattern required")
    pattern, gates = bits(pattern, len(pattern)), []
    def nand(left, right):
        gates.append((left, right))
        return len(pattern) + len(gates) - 1
    terms = [i if value else nand(i, i) for i, value in enumerate(pattern)]
    while len(terms) > 1:
        combined = []
        for i in range(0, len(terms) - 1, 2):
            node = nand(terms[i], terms[i + 1])
            combined.append(nand(node, node))
        if len(terms) % 2: combined.append(terms[-1])
        terms = combined
    return NandCircuit(len(pattern), tuple(gates), (terms[0],))


def _matrix(values, rows, columns, q=None):
    if not isinstance(values, (tuple, list)) or len(values) != rows: raise ValueError("matrix rows mismatch")
    result = []
    for row in values:
        if not isinstance(row, (tuple, list)) or len(row) != columns: raise ValueError("matrix columns mismatch")
        checked = []
        for value in row:
            if isinstance(value, bool) or not isinstance(value, int): raise ValueError("integer coefficient required")
            if q is not None and not 0 <= value < q: raise ValueError("public coefficient is not canonical")
            if abs(value).bit_length() > MAX_WITNESS_BITS: raise ReferenceBudgetExceeded("integer coefficient budget exceeded")
            checked.append(value)
        result.append(tuple(checked))
    return tuple(result)


def _multiply(left, right, q=None):
    transposed = tuple(zip(*right))
    values = tuple(tuple(sum(a * b for a, b in zip(row, column)) for column in transposed) for row in left)
    return values if q is None else tuple(tuple(x % q for x in row) for row in values)


def _join(blocks): return tuple(tuple(x for block in blocks for x in block[i]) for i in range(len(blocks[0])))


def gadget(params):
    if not isinstance(params, Params): raise TypeError("Params required")
    return tuple(tuple((1 << (j % params.digit_bits)) % params.q if j // params.digit_bits == i else 0
                       for j in range(params.w)) for i in range(params.n))


def gadget_inverse(params, public):
    """Canonical least-significant-digit-first bit preimage; not a sampler."""
    if not isinstance(params, Params): raise TypeError("Params required")
    if not isinstance(public, (tuple, list)) or not public or not isinstance(public[0], (tuple, list)):
        raise ValueError("matrix input required")
    columns = len(public[0])
    integer(columns, 1, MAX_OUTPUTS * params.w, "gadget input columns")
    public = _matrix(public, params.n, columns, params.q)
    return tuple(tuple((public[i][j] >> bit) & 1 for j in range(columns))
                 for i in range(params.n) for bit in range(params.digit_bits))


def _inputs(params, circuit, master, inputs, *, private=False):
    if not isinstance(params, Params) or not isinstance(circuit, NandCircuit): raise TypeError("Params/NandCircuit required")
    master = _matrix(master, params.n, params.m, params.q)
    if not isinstance(inputs, (tuple, list)) or len(inputs) != circuit.input_count: raise ValueError("input-block count mismatch")
    rows, modulus = (params.m, None) if private else (params.n, params.q)
    return master, tuple(_matrix(block, rows, params.w, modulus) for block in inputs)


def _public_gate(params, left, right):
    product, g = _multiply(left, gadget_inverse(params, right), params.q), gadget(params)
    return tuple(tuple((a - b) % params.q for a, b in zip(grow, prow)) for grow, prow in zip(g, product))


def encode_inputs(params, master, values, witnesses):
    """Teaching relation Ai=A*Ri+xi*G, no public-distribution claim."""
    if not isinstance(values, (tuple, list)): raise ValueError("bit inputs required")
    circuit = NandCircuit(len(values), (), (0,))
    master, witnesses = _inputs(params, circuit, master, witnesses, private=True)
    values, g = bits(values, len(values)), gadget(params)
    return tuple(tuple(tuple((a + bit * b) % params.q for a, b in zip(arow, grow))
                       for arow, grow in zip(_multiply(master, r, params.q), g)) for bit, r in zip(values, witnesses))


def eval_public(params, circuit, master, inputs):
    """Uses only C, A and Ai; receives no xi or Ri."""
    _, inputs = _inputs(params, circuit, master, inputs)
    wires = list(inputs)
    for left, right in circuit.gates: wires.append(_public_gate(params, wires[left], wires[right]))
    return _join(tuple(wires[i] for i in circuit.outputs))


@dataclass(frozen=True, repr=False)
class PrivateEvaluation:
    matrix: tuple
    output_bits: tuple
    input_pm1: bool
    max_intermediate_abs: int
    coefficient_bound: int
    norm_profile: ClassVar[str] = "coarse-infinity-reference; paper-Lemma7-spectral-bound-unverified"

    def __repr__(self): return "PrivateEvaluation(witness=<redacted>, security_claim='none')"


def eval_private(params, circuit, master, values, witnesses):
    master, witnesses = _inputs(params, circuit, master, witnesses, private=True)
    values = bits(values, circuit.input_count)
    pub = list(encode_inputs(params, master, values, witnesses))
    prv, wire_bits = list(witnesses), list(values)
    initial = max(abs(x) for block in witnesses for row in block for x in row)
    maximum = initial
    for left, right in circuit.gates:
        product = _multiply(prv[left], gadget_inverse(params, pub[right]))
        raw = tuple(tuple(-a - wire_bits[left] * b for a, b in zip(arow, brow)) for arow, brow in zip(product, prv[right]))
        raw = _matrix(raw, params.m, params.w)
        maximum = max(maximum, max(abs(x) for row in raw for x in row))
        prv.append(raw)
        pub.append(_public_gate(params, pub[left], pub[right]))
        wire_bits.append(1 - wire_bits[left] * wire_bits[right])
    result = _join(tuple(prv[i] for i in circuit.outputs))
    bound = initial * (params.w + 1)**circuit.depth
    if max(abs(x) for row in result for x in row) > bound: raise RuntimeError("coarse witness coefficient bound failed")
    return PrivateEvaluation(result, tuple(wire_bits[i] for i in circuit.outputs),
                             all(x in (-1, 1) for block in witnesses for row in block for x in row), maximum, bound)


def homomorphism_holds(params, master, public_output, private):
    if not isinstance(params, Params) or not isinstance(private, PrivateEvaluation): raise TypeError("Params/PrivateEvaluation required")
    output_count = len(private.output_bits)
    integer(output_count, 1, MAX_OUTPUTS, "output count")
    output_bits = bits(private.output_bits, output_count)
    master = _matrix(master, params.n, params.m, params.q)
    public = _matrix(public_output, params.n, output_count * params.w, params.q)
    witness = _matrix(private.matrix, params.m, output_count * params.w)
    masks = _join(tuple(tuple(tuple(bit * x for x in row) for row in gadget(params)) for bit in output_bits))
    product = _multiply(master, witness, params.q)
    expected = tuple(tuple((a + b) % params.q for a, b in zip(row, grow)) for row, grow in zip(product, masks))
    return public == expected
