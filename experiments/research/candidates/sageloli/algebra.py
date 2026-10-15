"""Exact composite-modulus algebra and finite Gaussian gadget fibers.

This module contains the protocol's private matrix/ring arithmetic.  It keeps
the two routes separate while sharing only the scalar ternary gadget sampler.
No field inversion is used: the public modulus is the composite ``3^k``.
"""

from __future__ import annotations

from ibme.lattice.gaussian import sample_integer_gaussian
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


def sample_coset_scalar(target, k, q, sigma, rng):
    """Sample a finite discrete Gaussian in a ``3^k`` gadget fiber.

    At each recurrence step ``x = residue + 3w`` uses the exact integer
    Gaussian primitive conditioned on that residue class.  The final carry is
    retained, so the returned digits satisfy the modular gadget equation even
    for the composite modulus.
    """
    state = int(target) % q
    result = []
    for _ in range(k - 1):
        residue = state % 3
        w = sample_integer_gaussian(float(sigma) / 3.0, center=-residue / 3.0, rng=rng)
        digit = residue + 3 * int(w)
        result.append(digit)
        state = (state - digit) // 3
    result.append(state)
    if (sum((3**i) * value for i, value in enumerate(result)) - int(target)) % q:
        raise RuntimeError("gadget coset equation failed")
    return tuple(result)


def sample_gadget_vector(target, k, q, sigma, rng):
    return sample_coset_scalar(target, k, q, sigma, rng)


def matrix_public(abar, root, n, k, m, q):
    width = n * k
    abar = matrix(n, m - width, abar, q)
    root = matrix(m - width, width, root)
    g = gadget_matrix(n, k)
    return abar, hstack(abar, sub_mod(g, matmul(abar, root, q), q))


def matrix_delegate(abar, root, target, n, k, m, q, sigma, rng):
    """Return T with A*T=target (columns are independently sampled fibers)."""
    abar, a = matrix_public(abar, root, n, k, m, q)
    root = matrix(m - n * k, n * k, root)
    target = matrix(n, n * k, target, q)
    columns = []
    for j in range(n * k):
        y = _sample_matrix_syndrome([target[i][j] for i in range(n)], n, k, q, sigma, rng)
        top = matvec(root, y, None)
        columns.append(tuple(top) + tuple(y))
    t = tuple(tuple(columns[j][i] for j in range(n * k)) for i in range(m))
    if matmul(a, t, q) != target:
        raise RuntimeError("matrix delegation equation failed")
    return t


def matrix_sign(a, h, trapdoor, target, n, k, m, q, sigma, rng):
    x = tuple(sample_integer_gaussian(float(sigma), rng=rng) for _ in range(m))
    residual = tuple((int(target[i]) - matvec(a, x, q)[i]) % q for i in range(n))
    y = sample_gadget_vector(residual[0], k, q, sigma, rng) if n == 1 else _sample_matrix_syndrome(
        residual, n, k, q, sigma, rng)
    top = tuple(x[i] - matvec(trapdoor, y, None)[i] for i in range(m))
    z = top + tuple(y)
    f = hstack(a, h)
    if any((value - target[i]) % q for i, value in enumerate(matvec(f, z, q))):
        raise RuntimeError("matrix signing equation failed")
    return z


def _sample_matrix_syndrome(target, n, k, q, sigma, rng):
    rows = [sample_gadget_vector(value, k, q, sigma, rng) for value in target]
    # G is digit-major: [I, 3I, ..., 3^(k-1)I].
    return tuple(rows[row][digit] for digit in range(k) for row in range(n))


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


def sample_ring_gadget(target, k, d, q, sigma, rng):
    columns = [sample_coset_scalar(target[h], k, q, sigma, rng) for h in range(d)]
    return tuple(tuple(columns[h][j] for h in range(d)) for j in range(k))


def ring_delegate(abar, root, target, d, k, l, q, sigma, rng):
    abar, a = ring_public(abar, root, d, k, l, q)
    root_cols = l - k
    target = tuple(tuple(int(x) % q for x in poly) for poly in target)
    y_columns = [sample_ring_gadget(target[j], k, d, q, sigma, rng) for j in range(k)]
    y = tuple(tuple(y_columns[j][i] for j in range(k)) for i in range(k))
    top = ring_matmul(root, y, d, None)
    t = tuple(tuple(top[i][j] for j in range(k)) for i in range(root_cols)) + y
    if ring_matmul((a,), t, d, q) != (tuple(target),):
        raise RuntimeError("ring delegation equation failed")
    return t


def ring_sign(a, h, trapdoor, target, d, k, l, q, sigma, rng):
    x = tuple(tuple(sample_integer_gaussian(float(sigma), rng=rng) for _ in range(d)) for _ in range(l))
    product = ring_matvec(a, x, d, q)
    residual = tuple((int(target[h]) - product[0][h]) % q for h in range(d))
    y = sample_ring_gadget(residual, k, d, q, sigma, rng)
    correction = ring_matvec(trapdoor, y, d, None)
    top = tuple(poly_sub(x[i], correction[i]) for i in range(l))
    z = top + y
    f = (tuple(a[0]) + tuple(h),)
    if ring_matvec(f, z, d, q) != (tuple(target),):
        raise RuntimeError("ring signing equation failed")
    return z


def ring_norm_squared(values, q=None):
    return sum(int(x) ** 2 for poly in values for x in (centered_poly(poly, q) if q else poly))


__all__ = [
    "matrix", "matmul", "matvec", "hstack", "vstack", "gadget_matrix",
    "matrix_public", "matrix_delegate", "matrix_sign", "sample_coset_scalar",
    "poly_add", "poly_sub", "poly_mul", "poly_scale", "ring_matmul", "ring_matvec",
    "ring_public", "ring_delegate", "ring_sign", "ring_norm_squared", "centered",
]
