"""Exact composite-modulus algebra for the two Sageloli routes.

This module contains the protocol's private matrix/ring arithmetic.  It keeps
the two routes separate while delegating Gaussian operations to the full-dimensional sampling module.
No field inversion is used: the public modulus is the composite ``3^k``.
"""

from __future__ import annotations

from ibme.ibs.luo_module_math import negacyclic_schoolbook


def _mod(value, q):
    return int(value) if q is None else int(value) % q


def matrix(rows, cols, values, q=None):
    if not isinstance(values, (tuple, list)) or len(values) != rows:
        raise ValueError("matrix row dimension mismatch")
    result = []
    for row in values:
        if not isinstance(row, (tuple, list)) or len(row) != cols:
            raise ValueError("matrix column dimension mismatch")
        result.append(tuple(_mod(x, q) if q else int(x) for x in row))
    return tuple(result)


def zeros(rows, cols):
    return tuple(tuple(0 for _ in range(cols)) for _ in range(rows))


def identity(size):
    return tuple(tuple(int(i == j) for j in range(size)) for i in range(size))


def matmul(left, right, q=None):
    if not left or not right or len(left[0]) != len(right):
        raise ValueError("matrix product dimension mismatch")
    rows, inner, cols = len(left), len(right), len(right[0])
    if any(len(row) != inner for row in left) or any(len(row) != cols for row in right):
        raise ValueError("rectangular matrices required")
    return tuple(
        tuple(_mod(sum(left[i][h] * right[h][j] for h in range(inner)), q)
               for j in range(cols))
        for i in range(rows)
    )


def matvec(left, vector, q=None):
    return tuple(row[0] for row in matmul(left, tuple((x,) for x in vector), q))


def hstack(left, right):
    if len(left) != len(right):
        raise ValueError("horizontal stack row mismatch")
    return tuple(tuple(a) + tuple(b) for a, b in zip(left, right))


def vstack(top, bottom):
    return tuple(top) + tuple(bottom)


def sub_mod(left, right, q):
    if len(left) != len(right) or any(len(a) != len(b) for a, b in zip(left, right)):
        raise ValueError("matrix subtraction dimension mismatch")
    return tuple(tuple((x - y) % q for x, y in zip(a, b)) for a, b in zip(left, right))


def gadget_matrix(n, k):
    return tuple(
        tuple(3 ** (j // n) if i == j % n else 0 for j in range(n * k))
        for i in range(n)
    )


def centered(value, q):
    value = int(value) % q
    return value - q if value > q // 2 else value


def centered_poly(poly, q):
    return tuple(centered(v, q) for v in poly)


def matrix_public(abar, root, n, k, m, q):
    width = n * k
    abar = matrix(n, m - width, abar, q)
    root = matrix(m - width, width, root)
    g = gadget_matrix(n, k)
    return abar, hstack(abar, sub_mod(g, matmul(abar, root, q), q))


def poly_add(a, b, q=None):
    if len(a) != len(b):
        raise ValueError("polynomial degree mismatch")
    result = tuple(int(x) + int(y) for x, y in zip(a, b))
    return tuple(x % q for x in result) if q else result


def poly_sub(a, b, q=None):
    return poly_add(a, tuple(-x for x in b), q)


def poly_scale(a, scalar, q=None):
    result = tuple(int(scalar) * int(x) for x in a)
    return tuple(x % q for x in result) if q else result


def poly_mul(a, b, q=None):
    result = tuple(int(x) for x in negacyclic_schoolbook(tuple(a), tuple(b)))
    return tuple(x % q for x in result) if q else result


def ring_matmul(left, right, d, q=None):
    if not left or not right or len(left[0]) != len(right):
        raise ValueError("ring matrix product dimension mismatch")
    if any(len(row) != len(left[0]) for row in left) or any(len(row) != len(right[0]) for row in right):
        raise ValueError("rectangular ring matrices required")
    result = []
    for row in left:
        result_row = []
        for j in range(len(right[0])):
            value = (0,) * d
            for h in range(len(right)):
                value = poly_add(value, poly_mul(row[h], right[h][j], q), q)
            result_row.append(value)
        result.append(tuple(result_row))
    return tuple(result)


def ring_matvec(left, vector, d, q=None):
    return tuple(row[0] for row in ring_matmul(left, tuple((x,) for x in vector), d, q))


def ring_gadget(k, d):
    return tuple(tuple((3**j,) + (0,) * (d - 1) for _ in [0]) for j in range(k))


def ring_public(abar, root, d, k, l, q):
    root_cols = l - k
    abar = tuple(tuple(tuple(int(x) % q for x in poly) for poly in row) for row in abar)
    root = tuple(tuple(tuple(int(x) for x in poly) for poly in row) for row in root)
    g = tuple((3**j,) + (0,) * (d - 1) for j in range(k))
    product = ring_matmul(abar, root, d, q)
    right = tuple(tuple(poly_sub(g[j], product[0][j], q) for j in range(k)) for _ in [0])
    return abar, tuple(abar[0]) + tuple(right[0])


def ring_norm_squared(values, q=None):
    return sum(int(x) ** 2 for poly in values for x in (centered_poly(poly, q) if q else poly))


__all__ = [
    "matrix", "matmul", "matvec", "hstack", "vstack", "gadget_matrix",
    "matrix_public", "poly_add", "poly_sub", "poly_mul", "poly_scale",
    "ring_matmul", "ring_matvec", "ring_public", "ring_norm_squared", "centered",
]
