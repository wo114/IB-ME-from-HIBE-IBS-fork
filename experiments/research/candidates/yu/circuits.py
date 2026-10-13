"""Bounded, immutable NAND circuits for the Yu research implementation.

Only Python's standard library is used. Wire -1 is zero, -2 is one; inputs
precede gates. Gates are NAND only. The finite compiler's measured depth is not
an NC1 theorem or a certificate for homomorphic evaluation's spectral bounds.
"""

from dataclasses import dataclass, field

ZERO, ONE = -1, -2
MAX_INPUTS = 8192
MAX_GATES = 500_000
MAX_OUTPUTS = 64
MAX_DEPTH = 4096


class CircuitBudgetExceeded(ValueError):
    """The requested circuit exceeds an explicit research resource bound."""


def _integer(value, name, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def check_bits(bits, count, name="bits"):
    """Accept bounded concrete sequences, never coerce floats/bools to bits."""
    if type(bits) not in (tuple, list) or len(bits) != count:
        raise ValueError(f"{name} must contain exactly {count} bits")
    if any(type(bit) is not int or bit not in (0, 1) for bit in bits):
        raise ValueError(f"{name} must contain integer zero/one bits")
    return tuple(bits)


def _wire(wire, available):
    if type(wire) is not int or not -2 <= wire < available:
        raise ValueError("Wire must be a constant, input, or earlier gate")
    return wire


@dataclass(frozen=True)
class Circuit:
    input_count: int
    gates: tuple[tuple[int, int], ...]
    outputs: tuple[int, ...]
    _depth: int = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        _integer(self.input_count, "input_count", 0, MAX_INPUTS)
        if type(self.gates) is not tuple or type(self.outputs) is not tuple:
            raise ValueError("Circuit gates and outputs must be immutable tuples")
        if len(self.gates) > MAX_GATES:
            raise CircuitBudgetExceeded("NAND gate budget exceeded")
        if not 1 <= len(self.outputs) <= MAX_OUTPUTS:
            raise ValueError("Circuit requires 1..64 outputs")
        depths = [0] * self.input_count
        maximum = 0
        for gate in self.gates:
            if type(gate) is not tuple or len(gate) != 2:
                raise ValueError("A NAND gate must be a pair of wires")
            left, right = (_wire(w, len(depths)) for w in gate)
            depth = 1 + max(depths[left] if left >= 0 else 0,
                            depths[right] if right >= 0 else 0)
            if depth > MAX_DEPTH:
                raise CircuitBudgetExceeded("NAND depth budget exceeded")
            depths.append(depth)
            maximum = max(maximum, depth)
        for wire in self.outputs:
            _wire(wire, len(depths))
        # Include dead gates too: evaluate() executes every stored gate.
        object.__setattr__(self, "_depth", maximum)

    @property
    def depth(self):
        return self._depth

    def evaluate(self, bits):
        values = list(check_bits(bits, self.input_count, "circuit inputs"))

        def read(wire):
            return values[wire] if wire >= 0 else int(wire == ONE)

        for left, right in self.gates:
            values.append(1 - read(left) * read(right))
        return tuple(read(wire) for wire in self.outputs)


class Builder:
    """Polynomial-size bit arithmetic; hash-consed NANDs, no truth tables.

    Constant folding and common-subexpression sharing preserve the Boolean
    function. Neither operation establishes homomorphic witness norm bounds.
    """

    def __init__(self, input_count, *, max_gates=MAX_GATES, max_depth=MAX_DEPTH):
        self.input_count = _integer(input_count, "input_count", 0, MAX_INPUTS)
        self.max_gates = _integer(max_gates, "max_gates", 0, MAX_GATES)
        self.max_depth = _integer(max_depth, "max_depth", 0, MAX_DEPTH)
        self.gates = []
        self._depths = [0] * input_count
        self._memo = {}

    def nand(self, left, right):
        left, right = _wire(left, len(self._depths)), _wire(right, len(self._depths))
        if left == ZERO or right == ZERO:
            return ONE
        if left == ONE and right == ONE:
            return ZERO
        if left == ONE:
            left = right
        if right == ONE:
            right = left
        pair = tuple(sorted((left, right)))
        if pair in self._memo:
            return self._memo[pair]
        depth = 1 + max(self._depths[left], self._depths[right])
        if len(self.gates) >= self.max_gates or depth > self.max_depth:
            raise CircuitBudgetExceeded("NAND builder gate/depth budget exceeded")
        result = self.input_count + len(self.gates)
        self.gates.append(pair)
        self._depths.append(depth)
        self._memo[pair] = result
        return result

    def invert(self, wire):
        return self.nand(wire, wire)

    def and_(self, left, right):
        return self.invert(self.nand(left, right))

    def or_(self, left, right):
        return self.nand(self.invert(left), self.invert(right))

    def xor(self, left, right):
        _wire(left, len(self._depths))
        _wire(right, len(self._depths))
        if left == right:
            return ZERO
        if left == ZERO:
            return right
        if right == ZERO:
            return left
        if left == ONE:
            return self.invert(right)
        if right == ONE:
            return self.invert(left)
        both = self.nand(left, right)
        return self.nand(self.nand(left, both), self.nand(right, both))

    def _word(self, word):
        if type(word) is not tuple or not 1 <= len(word) <= 64:
            raise ValueError("An LSB word must be an immutable tuple of 1..64 wires")
        for wire in word:
            _wire(wire, len(self._depths))
        return word

    @staticmethod
    def constant(value, width):
        _integer(width, "word width", 1, 64)
        _integer(value, "unsigned word value", 0, (1 << width) - 1)
        return tuple(ONE if (value >> i) & 1 else ZERO for i in range(width))

    def add(self, left, right):
        """Unsigned LSB words, addition modulo 2**width."""
        self._word(left)
        self._word(right)
        if len(left) != len(right):
            raise ValueError("Word widths differ")
        carry, out = ZERO, []
        for i, (a, b) in enumerate(zip(left, right)):
            different = self.xor(a, b)
            out.append(self.xor(different, carry))
            if i + 1 < len(left):
                carry = self.nand(self.nand(a, b), self.nand(different, carry))
        return tuple(out)

    def multiply(self, left, right):
        """Schoolbook truncated multiplication; no exponential enumeration."""
        self._word(left)
        self._word(right)
        if len(left) != len(right):
            raise ValueError("Word widths differ")
        width = len(left)
        rows = [(ZERO,) * i + tuple(self.and_(left[j], right[i])
                                   for j in range(width - i)) for i in range(width)]
        while len(rows) > 1:
            rows = [self.add(rows[i], rows[i + 1]) if i + 1 < len(rows) else rows[i]
                    for i in range(0, len(rows), 2)]
        return rows[0]

    def ge_constant(self, word, threshold):
        """Unsigned comparison with a public constant, including 2**width."""
        self._word(word)
        _integer(threshold, "threshold", 0, 1 << len(word))
        if threshold == 1 << len(word):
            return ZERO
        ge = ONE
        for i, wire in enumerate(word):
            ge = self.and_(wire, ge) if (threshold >> i) & 1 else self.or_(wire, ge)
        return ge

    def any_(self, wires):
        if type(wires) is not tuple or len(wires) > MAX_GATES:
            raise ValueError("OR inputs must be a bounded tuple")
        for wire in wires:
            _wire(wire, len(self._depths))
        current = list(dict.fromkeys(wires))
        while len(current) > 1:
            current = [self.or_(current[i], current[i + 1]) if i + 1 < len(current)
                       else current[i] for i in range(0, len(current), 2)]
        return current[0] if current else ZERO

    def finish(self, outputs):
        return Circuit(self.input_count, tuple(self.gates), outputs)
