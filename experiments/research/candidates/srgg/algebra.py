"""SRGG Algorithms 1/2/7/8 public relations, not a sampler or IBS backend.

Pure exact negacyclic integer arithmetic. Caller-provided perturbations and
responses have no Gaussian claim; deterministic gadget digits are equation
fixtures only, not Algorithm 6's randomized Gaussian output.
"""

from dataclasses import dataclass
from typing import ClassVar

from ibme.ibs.luo_module_math import negacyclic_schoolbook

MAX_COEFFICIENT_BITS = 128


def integer(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class Params:
    degree: int = 4
    rank: int = 1
    p: int = 5
    base: int = 3
    digits: int = 2
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        integer(self.degree, 2, 8, "degree")
        if self.degree & (self.degree - 1): raise ValueError("power-of-two degree required")
        integer(self.rank, 1, 2, "module rank")
        integer(self.p, 3, 257, "p")
        integer(self.base, 3, 31, "base")
        integer(self.digits, 1, 4, "gadget digits")
        if self.p % 2 == 0 or self.base % 2 == 0: raise ValueError("odd p and gadget base required")

    @property
    def gadget_modulus(self): return self.base**self.digits

    @property
    def modulus(self): return self.p * self.gadget_modulus

    @property
    def columns(self): return (2 + self.digits) * self.rank


def poly(params, values, modulus=None):
    if not isinstance(params, Params): raise TypeError("SRGG research Params required")
    if not isinstance(values, (tuple, list)) or len(values) != params.degree: raise ValueError("polynomial degree mismatch")
    result = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int): raise ValueError("integer coefficient required")
        if abs(value).bit_length() > MAX_COEFFICIENT_BITS: raise ValueError("coefficient budget exceeded")
        if modulus is not None and not 0 <= value < modulus: raise ValueError("noncanonical public coefficient")
        result.append(value)
    return tuple(result)


def vector(params, values, count, modulus=None):
    if not isinstance(values, (tuple, list)) or len(values) != count: raise ValueError("module vector dimension mismatch")
    return tuple(poly(params, value, modulus) for value in values)


def matrix(params, values, rows, cols, modulus=None):
    if not isinstance(values, (tuple, list)) or len(values) != rows: raise ValueError("module matrix row mismatch")
    return tuple(vector(params, row, cols, modulus) for row in values)


def constant(params, value): return (value,) + (0,) * (params.degree - 1)


def add(a, b, modulus=None):
    if not isinstance(a, (tuple, list)) or not isinstance(b, (tuple, list)) or not a or len(a) != len(b):
        raise ValueError("polynomial addition dimension mismatch")
    out = tuple(x + y for x, y in zip(a, b))
    return out if modulus is None else tuple(x % modulus for x in out)


def scale(a, value, modulus=None):
    out = tuple(value * x for x in a)
    return out if modulus is None else tuple(x % modulus for x in out)


def multiply(a, b, modulus=None):
    out = negacyclic_schoolbook(a, b)
    return out if modulus is None else tuple(x % modulus for x in out)


def identity(params, size):
    return tuple(tuple(constant(params, int(i == j)) for j in range(size)) for i in range(size))


def matmul(params, left, right, modulus=None):
    if not left or not right or len(left[0]) != len(right): raise ValueError("module product dimension mismatch")
    if any(len(row) != len(left[0]) for row in left) or any(len(row) != len(right[0]) for row in right):
        raise ValueError("rectangular module matrices required")
    result = []
    for row in left:
        result_row = []
        for j in range(len(right[0])):
            value = constant(params, 0)
            for h, entry in enumerate(row): value = add(value, multiply(entry, right[h][j], modulus), modulus)
            result_row.append(value)
        result.append(tuple(result_row))
    return tuple(result)


def matvec(params, public, values, modulus=None):
    return tuple(row[0] for row in matmul(params, public, tuple((value,) for value in values), modulus))


def gadget(params):
    return tuple(tuple(constant(params, params.p * params.base**(j % params.digits) if j // params.digits == i else 0)
                       for j in range(params.rank * params.digits)) for i in range(params.rank))


@dataclass(frozen=True)
class PublicRelation:
    params: Params
    a_hat: tuple
    b: tuple

    def __post_init__(self):
        if not isinstance(self.params, Params): raise TypeError("Params required")
        p = self.params
        object.__setattr__(self, "a_hat", matrix(p, self.a_hat, p.rank, p.rank, p.modulus))
        object.__setattr__(self, "b", matrix(p, self.b, p.rank, p.rank * p.digits, p.modulus))

    @property
    def a(self):
        i = identity(self.params, self.params.rank)
        return tuple(x + y + z for x, y, z in zip(i, self.a_hat, self.b))


def build_public(params, a_hat, r):
    a_hat = matrix(params, a_hat, params.rank, params.rank, params.modulus)
    r = matrix(params, r, 2 * params.rank, params.rank * params.digits)
    if any(x not in (-1, 0, 1) for row in r for entry in row for x in entry): raise ValueError("master chi=CBD1 support required")
    left = tuple(x + y for x, y in zip(identity(params, params.rank), a_hat))
    product, f = matmul(params, left, r, params.modulus), gadget(params)
    b = tuple(tuple(add(x, scale(y, -1), params.modulus) for x, y in zip(row_f, row_p)) for row_f, row_p in zip(f, product))
    return PublicRelation(params, a_hat, b)


def trapdoor_relation(public, r):
    p = public.params
    r = matrix(p, r, 2 * p.rank, p.rank * p.digits)
    stacked = r + identity(p, p.rank * p.digits)
    return matmul(p, public.a, stacked, p.modulus) == gadget(p)


def gadget_digits(params, target):
    """One deterministic approximate preimage with canonical remainder e."""
    target = poly(params, target, params.modulus)
    entries = [[] for _ in range(params.digits)]
    error = []
    for value in target:
        e, quotient = value % params.p, value // params.p
        error.append(e)
        for i in range(params.digits):
            entries[i].append(quotient % params.base)
            quotient //= params.base
        if quotient: raise RuntimeError("gadget digit capacity failed")
    return tuple(tuple(row) for row in entries), tuple(error)


@dataclass(frozen=True, repr=False)
class ExtractionTrace:
    raw_vector: tuple
    tail: tuple
    error: tuple

    def __repr__(self): return "ExtractionTrace(vectors=<redacted>, sampler_implemented=False)"


def extraction_from_values(public, r, target, perturbation):
    p = public.params
    r = matrix(p, r, 2 * p.rank, p.rank * p.digits)
    if not trapdoor_relation(public, r): raise ValueError("master relation mismatch")
    target = vector(p, target, p.rank, p.modulus)
    perturbation = vector(p, perturbation, p.columns)
    residual = tuple(add(t, scale(v, -1), p.modulus) for t, v in zip(target, matvec(p, public.a, perturbation, p.modulus)))
    blocks, errors = zip(*(gadget_digits(p, value) for value in residual))
    x = tuple(entry for block in blocks for entry in block)
    stacked = r + identity(p, p.rank * p.digits)
    raw = vector(p, tuple(add(a, b) for a, b in zip(perturbation, matvec(p, stacked, x))), p.columns)
    expected = tuple(add(t, scale(e, -1), p.modulus) for t, e in zip(target, errors))
    if matvec(p, public.a, raw, p.modulus) != expected: raise RuntimeError("approximate extraction equation failed")
    return ExtractionTrace(raw, raw[p.rank:], tuple(errors))


def reconstruct_vector(public, target, tail):
    p = public.params
    target = vector(p, target, p.rank, p.modulus)
    tail = vector(p, tail, (1 + p.digits) * p.rank)
    remainder = matvec(p, tuple(a + b for a, b in zip(public.a_hat, public.b)), tail, p.modulus)
    first = tuple(tuple((x - y + p.modulus // 2) % p.modulus - p.modulus // 2 for x, y in zip(t, s)) for t, s in zip(target, remainder))
    full = first + tail
    if matvec(p, public.a, full, p.modulus) != target: raise RuntimeError("HNF exact reconstruction failed")
    return full


def zeta(params):
    return tuple(int(i in (0, params.degree // 2)) for i in range(params.degree))


def zeta_star(params):
    return tuple(1 if i == 0 else -1 if i == params.degree // 2 else 0 for i in range(params.degree))


def signing_matrix(public, target):
    p = public.params
    target = vector(p, target, p.rank, p.modulus)
    j = (zeta_star(p),) + (constant(p, 0),) * (p.rank - 1)
    last = tuple(add(scale(j_i, p.modulus), scale(h, -2), 2 * p.modulus) for j_i, h in zip(j, target))
    return tuple(tuple(scale(entry, 2, 2 * p.modulus) for entry in row) + (b,) for row, b in zip(public.a, last))


def signing_relation(public, target, user_vector):
    p = public.params
    user_vector = vector(p, user_vector, p.columns)
    product = matvec(p, signing_matrix(public, target), user_vector + (constant(p, 1),), 2 * p.modulus)
    j = (zeta_star(p),) + (constant(p, 0),) * (p.rank - 1)
    return product == tuple(scale(entry, p.modulus, 2 * p.modulus) for entry in j)


def response_from_values(public, target, user_vector, perturbation, u, challenge):
    p = public.params
    user_vector = vector(p, user_vector, p.columns)
    if not signing_relation(public, target, user_vector): raise ValueError("user signing relation mismatch")
    perturbation = vector(p, perturbation, p.columns + 1)
    u, challenge = poly(p, u), poly(p, challenge)
    if any(x not in (0, 1) for x in challenge): raise ValueError("binary polynomial challenge required")
    shift = add(multiply(zeta(p), u), challenge)
    witness = user_vector + (constant(p, 1),)
    return vector(p, tuple(add(y, multiply(x, shift)) for y, x in zip(perturbation, witness)), p.columns + 1)


def recover_commitment(public, target, response, challenge):
    p = public.params
    response, challenge = vector(p, response, p.columns + 1), poly(p, challenge)
    if any(x not in (0, 1) for x in challenge): raise ValueError("binary polynomial challenge required")
    product = matvec(p, signing_matrix(public, target), response, 2 * p.modulus)
    qjc = scale(multiply(zeta_star(p), challenge), p.modulus, 2 * p.modulus)
    return (add(product[0], scale(qjc, -1), 2 * p.modulus),) + product[1:]
