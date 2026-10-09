"""Exact negacyclic arithmetic and Luo §4.1 rounding/hint algorithms.

The NTT is a conventional twist/cyclic-DFT/untwist realization. It uses Python
integers, supports the selected >uint32 q, and is not constant-time code.
"""

from dataclasses import dataclass, field


def _integer(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("integer coefficient required")
    return value


def _poly(values, degree):
    if not isinstance(values, (tuple, list)) or len(values) != degree:
        raise ValueError("polynomial dimension mismatch")
    return tuple(_integer(value) for value in values)


def negacyclic_schoolbook(a, b):
    """Integer product in Z[X]/(X^N+1), without modular reduction."""
    n = len(a)
    a, b = _poly(a, n), _poly(b, n)
    if n < 1:
        raise ValueError("empty polynomial")
    result = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            index = i + j
            result[index % n] += x * y * (1 if index < n else -1)
    return tuple(result)


def sparse_product(a, challenge):
    """Exact signed product; challenge coefficients must be -1/0/1."""
    n = len(a)
    a, c = _poly(a, n), _poly(challenge, n)
    if n < 1 or any(value not in (-1, 0, 1) for value in c):
        raise ValueError("invalid sparse polynomial")
    result = [0] * n
    for j, sign in enumerate(c):
        if sign:
            for i, value in enumerate(a):
                index = i + j
                result[index % n] += sign * value * (1 if index < n else -1)
    return tuple(result)


@dataclass(frozen=True)
class NegacyclicRing:
    degree: int
    q: int
    root: int
    _twist: tuple = field(init=False, repr=False, compare=False)
    _untwist: tuple = field(init=False, repr=False, compare=False)
    _forward_steps: tuple = field(init=False, repr=False, compare=False)
    _inverse_steps: tuple = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        n, q, root = (_integer(x) for x in (self.degree, self.q, self.root))
        if not 2 <= n <= 256 or n & (n - 1) or q < 3 or q % 2 == 0 or not 0 < root < q:
            raise ValueError("invalid ring/NTT dimensions")
        if pow(root, n, q) != q - 1 or pow(root, 2 * n, q) != 1:
            raise ValueError("root must be a principal 2N-th root for this power-of-two ring")
        inverse_root = pow(root, -1, q)
        omega, inverse_omega = root * root % q, inverse_root * inverse_root % q
        object.__setattr__(self, "_twist", tuple(pow(root, i, q) for i in range(n)))
        object.__setattr__(self, "_untwist", tuple(pow(inverse_root, i, q) for i in range(n)))
        lengths = tuple(2**i for i in range(1, n.bit_length()))
        object.__setattr__(self, "_forward_steps", tuple(pow(omega, n // length, q) for length in lengths))
        object.__setattr__(self, "_inverse_steps", tuple(pow(inverse_omega, n // length, q) for length in lengths))

    def _cyclic(self, coefficients, steps):
        a = list(_poly(coefficients, self.degree))
        n, q = self.degree, self.q
        index = 0
        for i in range(1, n):
            bit = n >> 1
            while index & bit:
                index ^= bit
                bit >>= 1
            index ^= bit
            if i < index:
                a[i], a[index] = a[index], a[i]
        length = 2
        for step in steps:
            half = length // 2
            for start in range(0, n, length):
                factor = 1
                for j in range(start, start + half):
                    u, v = a[j], a[j + half] * factor % q
                    a[j], a[j + half] = (u + v) % q, (u - v) % q
                    factor = factor * step % q
            length *= 2
        return tuple(a)

    def ntt(self, coefficients):
        a = _poly(coefficients, self.degree)
        return self._cyclic(tuple(x * twist % self.q for x, twist in zip(a, self._twist)), self._forward_steps)

    def inverse_ntt(self, transformed):
        a = self._cyclic(transformed, self._inverse_steps)
        inverse_n = pow(self.degree, -1, self.q)
        return tuple(x * inverse_n * untwist % self.q for x, untwist in zip(a, self._untwist))

    def multiply(self, a, b):
        ah, bh = self.ntt(a), self.ntt(b)
        return self.inverse_ntt(tuple(x * y % self.q for x, y in zip(ah, bh)))

    def prepare_matrix(self, rows):
        if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows):
            raise ValueError("matrix dimensions mismatch")
        return tuple(tuple(self.ntt(poly) for poly in row) for row in rows)

    def matvec(self, prepared, vector):
        if not prepared or len(vector) != len(prepared[0]):
            raise ValueError("matrix/vector dimensions mismatch")
        hats = tuple(self.ntt(poly) for poly in vector)
        output = []
        for row in prepared:
            if len(row) != len(hats):
                raise ValueError("matrix row dimension mismatch")
            product = tuple(sum(row[j][i] * hats[j][i] for j in range(len(hats))) % self.q
                            for i in range(self.degree))
            output.append(self.inverse_ntt(product))
        return tuple(output)


@dataclass(frozen=True)
class Rounding:
    q: int
    alpha: int
    dropped_bits: int

    def __post_init__(self):
        q, alpha, dropped = (_integer(x) for x in (self.q, self.alpha, self.dropped_bits))
        if q < 3 or q % 2 == 0 or alpha < 2 or alpha % 2 or (q - 1) % alpha or q <= 2 * alpha:
            raise ValueError("require even alpha|(q-1), odd q>2alpha")
        if not 1 <= dropped <= 62:
            raise ValueError("invalid dropped bits")

    @staticmethod
    def balanced(value, modulus):
        _integer(value)
        _integer(modulus)
        if modulus < 1:
            raise ValueError("positive modulus required")
        residue = value % modulus
        return residue - modulus if residue > modulus // 2 else residue

    def power2round_pair(self, value):
        r = _integer(value) % self.q
        modulus = 2**self.dropped_bits
        low = self.balanced(r, modulus)
        return (r - low) // modulus, low

    def power2round(self, value):
        return self.power2round_pair(value)[0]

    def decompose(self, value):
        r = _integer(value) % self.q
        low = self.balanced(r, self.alpha)
        if r - low == self.q - 1:
            return 0, low - 1
        return (r - low) // self.alpha, low

    def high_bits(self, value):
        return self.decompose(value)[0]

    def low_bits(self, value):
        return self.decompose(value)[1]

    def make_hint(self, shift, value):
        return int(self.high_bits(value + _integer(shift)) != self.high_bits(value))

    def use_hint(self, hint, value):
        if isinstance(hint, bool):
            hint = int(hint)
        if _integer(hint) not in (0, 1):
            raise ValueError("hint must be a bit")
        high, low = self.decompose(value)
        if not hint:
            return high
        return (high + (1 if low > 0 else -1)) % ((self.q - 1) // self.alpha)
