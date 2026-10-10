"""Exact rational coefficient-space geometry for SRGG perturbation shapes.

No Gaussian output/distribution is implemented. Ring transpose means the
coefficient operator's transpose (conjugate transpose in the ring), not a
bare module-index swap. Positivity is checked with exact LDL pivots.
"""

from dataclasses import dataclass
from fractions import Fraction
import re

from .algebra import Params, constant, identity, matrix, vector, multiply

MAX_DIMENSION, MAX_RATIONAL_BITS = 128, 8192


def rational(value):
    if isinstance(value, bool) or not isinstance(value, (int, str, Fraction)): raise ValueError("exact rational required")
    if isinstance(value, str) and (len(value) > MAX_RATIONAL_BITS or not re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+|\.[0-9]+)?", value)):
        raise ValueError("bounded plain rational/decimal string required")
    try: result = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc: raise ValueError("invalid exact rational") from exc
    if max(abs(result.numerator).bit_length(), result.denominator.bit_length()) > MAX_RATIONAL_BITS:
        raise ValueError("rational budget exceeded")
    return result


def checked(values):
    if not isinstance(values, (tuple, list)) or not 1 <= len(values) <= MAX_DIMENSION: raise ValueError("bounded matrix rows required")
    cols = len(values[0]) if isinstance(values[0], (tuple, list)) else 0
    if not 1 <= cols <= MAX_DIMENSION: raise ValueError("bounded matrix columns required")
    if any(not isinstance(row, (tuple, list)) or len(row) != cols for row in values): raise ValueError("rectangular matrix required")
    return tuple(tuple(rational(value) for value in row) for row in values)


def transpose(a): return tuple(tuple(row) for row in zip(*a))


def product(a, b):
    if len(a[0]) != len(b): raise ValueError("matrix product mismatch")
    bt = transpose(b)
    return checked(tuple(tuple(sum(x * y for x, y in zip(row, col)) for col in bt) for row in a))


def diagonal(entries):
    entries = tuple(rational(value) for value in entries)
    return tuple(tuple(entries[i] if i == j else Fraction(0) for j in range(len(entries))) for i in range(len(entries)))


def combine(a, b, factor):
    if len(a) != len(b) or len(a[0]) != len(b[0]): raise ValueError("matrix combination mismatch")
    factor = rational(factor)
    return checked(tuple(tuple(x + factor * y for x, y in zip(arow, brow)) for arow, brow in zip(a, b)))


def positive_pivots(values):
    a = checked(values)
    if len(a) != len(a[0]) or a != transpose(a): raise ValueError("symmetric square matrix required")
    work, pivots = [list(row) for row in a], []
    for i in range(len(a)):
        pivot = work[i][i]
        if pivot <= 0: raise ValueError("shape is not strictly positive definite")
        pivots.append(pivot)
        for j in range(i + 1, len(a)):
            for k in range(j, len(a)):
                update = rational(work[j][k] - work[j][i] * work[i][k] / pivot)
                work[j][k] = work[k][j] = update
    return tuple(pivots)


def polynomial_operator(params, polynomial):
    polynomial = vector(params, (polynomial,), 1)[0]
    columns = [multiply(polynomial, tuple(int(i == j) for i in range(params.degree))) for j in range(params.degree)]
    return tuple(tuple(col[i] for col in columns) for i in range(params.degree))


def module_operator(params, values):
    if not isinstance(values, (tuple, list)) or not values or not isinstance(values[0], (tuple, list)) or not values[0]:
        raise ValueError("module matrix required")
    rows, cols = len(values), len(values[0])
    if max(rows, cols) * params.degree > MAX_DIMENSION: raise ValueError("coefficient operator budget exceeded")
    values = matrix(params, values, rows, cols)
    blocks = tuple(tuple(polynomial_operator(params, entry) for entry in row) for row in values)
    return checked(tuple(tuple(x for block in row for x in block[i]) for row in blocks for i in range(params.degree)))


@dataclass(frozen=True)
class Widths:
    first_squared: Fraction
    second_squared: Fraction
    r_squared: Fraction

    def __post_init__(self):
        for name in ("first_squared", "second_squared", "r_squared"):
            value = rational(getattr(self, name))
            if value <= 0: raise ValueError("positive squared shape parameter required")
            object.__setattr__(self, name, value)


@dataclass(frozen=True, repr=False)
class Geometry:
    target: tuple
    perturbation: tuple
    noise_squared: Fraction
    floor_squared: Fraction
    lower_scalar: Fraction
    center_operator: tuple
    conditional_shape: tuple
    shifted_schur: tuple
    shifted_pivots: tuple
    schur_pivots: tuple

    def __repr__(self): return "Geometry(private_shape=<redacted>, sampler_implemented=False)"

    def conditioned_center(self, lower_vector):
        if not isinstance(lower_vector, (tuple, list)) or len(lower_vector) != len(self.center_operator[0]):
            raise ValueError("lower coefficient vector dimension mismatch")
        values = tuple(rational(value) for value in lower_vector)
        return tuple(sum(x * y for x, y in zip(row, values)) for row in self.center_operator)


def _geometry(target, top_witness, noise_squared, floor_squared):
    t = checked(top_witness)
    noise, floor = rational(noise_squared), rational(floor_squared)
    upper, lower = len(t), len(t[0])
    target = checked(target)
    if len(target) != upper + lower or len(target[0]) != upper + lower:
        raise ValueError("target/witness shape mismatch")
    if noise <= 0 or floor <= 0: raise ValueError("positive noise/floor required")
    stacked = t + diagonal((1,) * lower)
    full = combine(target, product(stacked, transpose(stacked)), -noise)
    shifted = combine(full, diagonal((1,) * len(full)), -floor)
    pivots = positive_pivots(shifted)
    d = full[upper][upper]
    if any(full[upper + i][upper + j] != (d if i == j else 0) for i in range(lower) for j in range(lower)):
        raise ValueError("scalar lower block required")
    if d <= floor: raise ValueError("lower smoothing margin is not positive")
    a = tuple(tuple(row[:upper]) for row in full[:upper])
    b = tuple(tuple(row[upper:]) for row in full[:upper])
    bb = product(b, transpose(b))
    conditional = combine(a, bb, -1 / d)
    center = checked(tuple(tuple(x / d for x in row) for row in b))
    a_shifted = combine(a, diagonal((1,) * upper), -floor)
    schur = combine(a_shifted, bb, -1 / (d - floor))
    schur_pivots = positive_pivots(schur)
    return Geometry(target, full, noise, floor, d, center, conditional, schur, pivots, schur_pivots)


def master_geometry(params, r, widths):
    if not isinstance(params, Params) or not isinstance(widths, Widths): raise TypeError("Params/Widths required")
    r = matrix(params, r, 2 * params.rank, params.rank * params.digits)
    if any(x not in (-1, 0, 1) for row in r for entry in row for x in entry): raise ValueError("CBD1 coefficient support required")
    top = module_operator(params, r)
    target = diagonal((widths.first_squared,) * len(top) + (widths.second_squared,) * len(top[0]))
    return _geometry(target, top, params.base**2 * widths.r_squared, widths.r_squared)


def signature_geometry(params, user_vector, widths, *, noise_factor=1):
    if not isinstance(params, Params) or not isinstance(widths, Widths): raise TypeError("Params/Widths required")
    if type(noise_factor) is not int or noise_factor not in (1, 2): raise ValueError("declared integer noise factor 1 or 2 required")
    y = vector(params, user_vector, params.columns)
    top = module_operator(params, tuple((entry,) for entry in y))
    first = 2 * params.rank * params.degree
    remaining = (params.rank * params.digits + 1) * params.degree
    target = diagonal((widths.first_squared,) * first + (widths.second_squared,) * remaining)
    return _geometry(target, top, noise_factor * widths.r_squared, widths.r_squared)
