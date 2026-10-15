"""Finite matrix BPR PRF and NAND compiler for Yu's key-input circuits.

Source: Banerjee--Peikert--Rosen, author version 2011-09-29, Definition 5.1
(5.1); floor rounding is explicitly allowed after (2.1). We implement
floor((2/q) * (A.T * S_1**x_1 * ... * S_k**x_k mod q)), q=2**b, p=2.
A is n by m, S_i is n by n. Products preserve the input order.

The uniform bit key encodes row-major A (b LSB-first bits per coefficient),
then row-major S_1,...,S_k sampling tickets (B LSB-first bits per coefficient).
Tickets map through a fixed dyadic approximation to D_(Z,r), with explicit
tail, interval/quantization and dyadic TV bounds. No rejection step is used.
The finite PRF is total for every valid key. There is no hash or RNG in evaluate.

This is a variable-time research implementation, security_claim='none'. Toy
parameters do not satisfy an asserted BPR security theorem. The finite circuit
does not prove NC1, a spectral norm bound, or security of the Yu composition.
Only public CDF construction requires Sage; evaluation/compilation use stdlib.
"""

from bisect import bisect_right
from dataclasses import dataclass, field
from fractions import Fraction
from functools import lru_cache

from .circuits import Builder, Circuit, MAX_INPUTS, MAX_OUTPUTS, check_bits, _integer


@dataclass(frozen=True)
class Params:
    input_bits: int
    dimension: int = 2
    columns: int = 2
    modulus_bits: int = 5
    ticket_bits: int = 32
    gaussian_width: object = 2

    def __post_init__(self):
        _integer(self.input_bits, "input_bits", 1, 128)
        _integer(self.dimension, "dimension", 1, 8)
        _integer(self.columns, "columns", 1, 8)
        _integer(self.modulus_bits, "modulus_bits", 1, 16)
        _integer(self.ticket_bits, "ticket_bits", 1, 64)
        if type(self.gaussian_width) not in (int, Fraction):
            raise ValueError("gaussian_width must be an exact int or Fraction")
        width = Fraction(self.gaussian_width)
        if not Fraction(1, 64) <= width <= 8:
            raise ValueError("Research gaussian_width must lie in [1/64, 8]")
        object.__setattr__(self, "gaussian_width", width)
        if self.key_bits > MAX_INPUTS or self.output_bits > MAX_OUTPUTS:
            raise ValueError("PRF key/output exceeds circuit resource bounds")

    @property
    def key_bits(self):
        return (self.dimension * self.columns * self.modulus_bits
                + self.input_bits * self.dimension**2 * self.ticket_bits)

    @property
    def output_bits(self):
        return self.columns * self.dimension

    @property
    def modulus(self):
        return 1 << self.modulus_bits


@lru_cache(maxsize=32)
def _canonical_cdt(width, ticket_bits):
    # Deliberately reuse table construction, NOT table.sample()/abort_upper.
    from experiments.research.gaussian_reference import build_gaussian_table

    table = build_gaussian_table(s=width, tail_bits=40, mass_bits=80, precision_bits=160)
    size = 1 << ticket_bits
    cdf = tuple(size * int(c) // int(table.total_mass) for c in table.cumulative)
    # Convert Sage rationals to immutable standard-library exact rationals.
    exact = lambda x: Fraction(int(x.numerator()), int(x.denominator()))
    return (tuple(int(v) for v in table.support), cdf,
            exact(table.tail_tv_upper), exact(table.quantization_tv_upper))


@dataclass(frozen=True)
class BPRSpec:
    """Public canonical CDT. Hand-supplied/tampered distributions are rejected.

    Construct with make_spec(). Direct construction checks against the same
    interval-derived canonical table, not merely monotonicity. Repeated CDF
    endpoints are allowed: they denote zero-probability support values.
    """

    params: Params
    support: tuple[int, ...]
    cdf: tuple[int, ...]
    tail_tv_upper: Fraction = field(init=False)
    quantization_tv_upper: Fraction = field(init=False)

    def __post_init__(self):
        if type(self.params) is not Params:
            raise ValueError("params must be validated Params")
        if (type(self.support) is not tuple or type(self.cdf) is not tuple
                or not 1 <= len(self.support) <= 1025 or len(self.support) != len(self.cdf)):
            raise ValueError("CDF/support must be equal-length bounded immutable tuples")
        size = 1 << self.params.ticket_bits
        if (any(type(v) is not int or not -512 <= v <= 512 for v in self.support)
                or any(type(c) is not int or not 0 <= c <= size for c in self.cdf)):
            raise ValueError("CDF/support contains out-of-range or noninteger entries")
        support, cdf, tail, quant = _canonical_cdt(self.params.gaussian_width,
                                                 self.params.ticket_bits)
        if self.support != support or self.cdf != cdf:
            raise ValueError("CDF/support differs from the canonical certified Gaussian table")
        object.__setattr__(self, "tail_tv_upper", tail)
        object.__setattr__(self, "quantization_tv_upper", quant)

    @property
    def dyadic_tv_upper(self):
        return Fraction(len(self.support) - 1, 1 << self.params.ticket_bits)

    @property
    def coefficient_tv_upper(self):
        return min(Fraction(1), self.tail_tv_upper + self.quantization_tv_upper
                   + self.dyadic_tv_upper)

    @property
    def key_distribution_tv_upper(self):
        """Product-law bound assuming independent uniform input key bits."""
        return min(Fraction(1), self.params.input_bits * self.params.dimension**2
                   * self.coefficient_tv_upper)

    def coefficient(self, ticket):
        _integer(ticket, "Gaussian ticket", 0, (1 << self.params.ticket_bits) - 1)
        return self.support[bisect_right(self.cdf, ticket)]

    def certificate(self):
        return {"support_count": len(self.support), "ticket_bits": self.params.ticket_bits,
                "tail_tv_upper": str(self.tail_tv_upper),
                "quantization_tv_upper": str(self.quantization_tv_upper),
                "dyadic_tv_upper": str(self.dyadic_tv_upper),
                "coefficient_tv_upper": str(self.coefficient_tv_upper),
                "key_distribution_tv_upper": str(self.key_distribution_tv_upper),
                "rejection_abort_used": False, "total_function": True,
                "security_claim": "none", "constant_time": False}


def make_spec(params):
    if type(params) is not Params:
        raise ValueError("params must be validated Params")
    support, cdf, _, _ = _canonical_cdt(params.gaussian_width, params.ticket_bits)
    return BPRSpec(params, support, cdf)


def _spec(spec):
    if type(spec) is not BPRSpec:
        raise ValueError("spec must be validated BPRSpec")
    return spec.params


def evaluate(spec, key_bits, input_bits):
    """Independent integer evaluation. Output m by n bits, row-major."""
    p = _spec(spec)
    key = check_bits(key_bits, p.key_bits, "PRF key")
    x = check_bits(input_bits, p.input_bits, "PRF input")
    offset = 0

    def integer(width):
        nonlocal offset
        value = sum(key[offset + i] << i for i in range(width))
        offset += width
        return value

    a = [[integer(p.modulus_bits) for _ in range(p.columns)] for _ in range(p.dimension)]
    result = [[a[j][i] for j in range(p.dimension)] for i in range(p.columns)]
    # Left fold from A.T, distinct from the compiler's balanced S product.
    for enabled in x:
        s = [[spec.coefficient(integer(p.ticket_bits)) for _ in range(p.dimension)]
             for _ in range(p.dimension)]
        if enabled:
            result = [[sum(result[i][h] * s[h][j] for h in range(p.dimension)) % p.modulus
                       for j in range(p.dimension)] for i in range(p.columns)]
    return tuple((2 * value) // p.modulus for row in result for value in row)


def _compile_coefficient(builder, spec, word):
    """Fixed public inverse CDF as comparisons and one-hot interval selection."""
    active, low = [], 0
    for value, high in zip(spec.support, spec.cdf):
        if high > low:
            selected = builder.and_(builder.ge_constant(word, low),
                                    builder.invert(builder.ge_constant(word, high)))
            active.append((value % spec.params.modulus, selected))
        low = high
    return tuple(builder.any_(tuple(w for value, w in active if (value >> i) & 1))
                 for i in range(spec.params.modulus_bits))


def _matrix_multiply(builder, left, right):
    """Bit-level matrix arithmetic, with balanced additions per dot product."""
    rows = []
    for row in left:
        out = []
        for j in range(len(right[0])):
            terms = [builder.multiply(row[h], right[h][j]) for h in range(len(right))]
            while len(terms) > 1:
                terms = [builder.add(terms[i], terms[i + 1]) if i + 1 < len(terms)
                         else terms[i] for i in range(0, len(terms), 2)]
            out.append(terms[0])
        rows.append(tuple(out))
    return tuple(rows)


def compile_key_circuit(spec, input_bits) -> Circuit:
    """Compile the PRF as a function of key bits for one fixed public input.

    Unselected S tickets are still present in the input schema but need no
    gates. Selected matrices are multiplied in a balanced order-preserving
    tree, followed by A.T. The p=2 floor rounding is exactly the top residue bit.
    """
    p = _spec(spec)
    x = check_bits(input_bits, p.input_bits, "PRF input")
    builder = Builder(p.key_bits)
    offset = 0

    def word(width):
        nonlocal offset
        result = tuple(range(offset, offset + width))
        offset += width
        return result

    a = tuple(tuple(word(p.modulus_bits) for _ in range(p.columns)) for _ in range(p.dimension))
    selected = []
    for enabled in x:
        if not enabled:
            offset += p.dimension**2 * p.ticket_bits
            continue
        selected.append(tuple(tuple(_compile_coefficient(builder, spec, word(p.ticket_bits))
                                    for _ in range(p.dimension)) for _ in range(p.dimension)))
    while len(selected) > 1:
        selected = [_matrix_multiply(builder, selected[i], selected[i + 1])
                    if i + 1 < len(selected) else selected[i]
                    for i in range(0, len(selected), 2)]
    result = tuple(tuple(a[j][i] for j in range(p.dimension)) for i in range(p.columns))
    if selected:
        result = _matrix_multiply(builder, result, selected[0])
    return builder.finish(tuple(value[-1] for row in result for value in row))
