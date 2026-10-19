"""Sage arithmetic engine for the Lai A-point HIBE.

The engine owns ring arithmetic, the Klein/GPV gadget sampler, ring delegation
and Babai inversion.  Objects cross the boundary as integer coefficient tuples
so the registry/codec never need Sage.  This is a research backend: no security
claim and no perturbation-level sampler proof.
"""
from __future__ import annotations

import hashlib
import math
import secrets

from sage.all import GF, PolynomialRing, QuotientRing, ZZ

from ibme.core.errors import IBMEError, InvalidParameterError, SerializationError
from .objects import (
    LaiCiphertext,
    LaiLevel1SecretKey,
    LaiLevel2SecretKey,
    LaiMasterSecret,
    LaiPublicKey,
)
from .params import LaiParams


class LaiDecryptError(IBMEError):
    """Internal decryption failure; the public API maps it to BOTTOM (None)."""


class _Random:
    """Buffered random-byte stream; production source is the OS CSPRNG.

    ``None`` supplies :class:`SecureRandom`; buffering avoids one syscall per
    coefficient.  An explicit deterministic source is test-only.  No Mersenne
    Twister or other non-cryptographic PRNG is used.
    """

    _BLOCK = 64 * 1024

    def __init__(self, source=None) -> None:
        if source is None:
            try:
                from ibme.core.randomness import SecureRandom

                source = SecureRandom()
            except Exception:  # pragma: no cover
                class _SystemSource:
                    def read(self, n: int) -> bytes:
                        return secrets.token_bytes(n)

                source = _SystemSource()
        self._source = source
        self._buffer = bytearray()

    def _read(self, n: int) -> bytes:
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise InvalidParameterError("random byte count must be a non-negative int")
        if n == 0:
            return b""
        while len(self._buffer) < n:
            chunk = self._source.read(self._BLOCK)
            if not isinstance(chunk, (bytes, bytearray, memoryview)) or not chunk:
                raise InvalidParameterError("random source returned no bytes")
            self._buffer.extend(chunk)
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out

    def _randbelow(self, bound: int) -> int:
        if not isinstance(bound, int) or isinstance(bound, bool) or bound <= 0:
            raise ValueError("bound must be a positive integer")
        k = (bound - 1).bit_length()
        nbytes = (k + 7) // 8
        while True:
            value = int.from_bytes(self._read(nbytes), "big")
            if k:
                value >>= 8 * nbytes - k
            if value < bound:
                return value

    def randrange(self, bound: int) -> int:
        return self._randbelow(bound)

    def random(self) -> float:
        return (int.from_bytes(self._read(7), "big") >> 3) * (2.0 ** -53)

    def gaussian(self, sigma: float, center: float = 0.0) -> int:
        if not (sigma > 0 and math.isfinite(sigma)):
            raise InvalidParameterError("gaussian width must be finite and > 0")
        lo = int(math.floor(center - 8.0 * sigma))
        hi = int(math.ceil(center + 8.0 * sigma))
        weights = [math.exp(-((x - center) ** 2) / (2.0 * sigma * sigma))
                   for x in range(lo, hi + 1)]
        r = self.random() * sum(weights)
        acc = 0.0
        for x, weight in zip(range(lo, hi + 1), weights):
            acc += weight
            if r <= acc:
                return x
        return hi


def _as_random(rng):
    if rng is None:
        return _Random()
    if hasattr(rng, "gaussian") and hasattr(rng, "randrange"):
        return rng
    return _Random(rng)


class _Ring:
    def __init__(self, params: LaiParams) -> None:
        self.params = params
        polynomial = PolynomialRing(GF(params.q), "x")
        self.x = polynomial.gen()
        self.Rq = QuotientRing(polynomial, self.x ** params.n + 1)
        self.zero = self.Rq(0)
        self.one = self.Rq(1)
        self.g = tuple(self.Rq(2 ** i) for i in range(params.k))

    def elem(self, values) -> object:
        return self.Rq(list(values))

    def coeffs(self, value) -> tuple[int, ...]:
        values = [int(c) for c in value.lift().list()]
        return tuple((values + [0] * self.params.n)[:self.params.n])

    def random(self, rng: _Random):
        return self.elem(rng.randrange(self.params.q) for _ in range(self.params.n))

    def gaussian(self, rng: _Random, sigma: float):
        return self.elem(rng.gaussian(sigma) for _ in range(self.params.n))

    def unit(self, rng: _Random):
        for _ in range(4096):
            value = self.random(rng)
            if value.is_unit():
                return value
        raise InvalidParameterError("Lai unit sampling budget exhausted")

    def width(self, value) -> int:
        q = self.params.q
        return max(abs(c if c <= q // 2 else c - q) for c in self.coeffs(value))


class _GadgetSampler:
    def __init__(self, params: LaiParams) -> None:
        self.params = params
        q, k = params.q, params.k
        basis = [[0] * k for _ in range(k)]
        for j in range(k - 1):
            basis[j][j] = 2
            basis[j + 1][j] = -1
        for i in range(k):
            basis[i][k - 1] = (q >> i) & 1
        self.basis = basis
        self.columns = [[basis[i][j] for i in range(k)] for j in range(k)]
        self.orth, _, self.norm = self._gram_schmidt(self.columns)

        from sage.all import QQ, matrix

        smat = matrix(QQ, k, k, basis)
        dual = q * smat.inverse().transpose()
        self.vcols = [[float(dual[i, j]) for i in range(k)] for j in range(k)]
        self.vfirst = [int(dual[0, j]) % q for j in range(k)]
        self.orth_v, _, self.norm_v = self._gram_schmidt(self.vcols)
        self.tolerance = math.sqrt(min(self.norm_v)) / 2.0

    @staticmethod
    def _gram_schmidt(vectors):
        n = len(vectors)
        orth, mu, norm = [], [[0.0] * n for _ in range(n)], []
        for i in range(n):
            current = [float(x) for x in vectors[i]]
            for j in range(i):
                mu[i][j] = (sum(vectors[i][t] * orth[j][t] for t in range(n))
                            / norm[j])
                current = [current[t] - mu[i][j] * orth[j][t] for t in range(n)]
            orth.append(current)
            norm.append(sum(x * x for x in current))
        return orth, mu, norm

    def _particular(self, u: int) -> list[int]:
        q = self.params.q
        v = u % q
        out = []
        for _ in range(self.params.k - 1):
            bit = v & 1
            out.append(bit)
            v = (v - bit) // 2 % q
        out.append(v if v <= q // 2 else v - q)
        return out

    def _klein(self, target, sigma: float, rng: _Random) -> list[int]:
        k = self.params.k
        t = [float(x) for x in target]
        coeff = [0] * k
        for i in range(k - 1, -1, -1):
            c = sum(t[j] * self.orth[i][j] for j in range(k)) / self.norm[i]
            step = sigma / math.sqrt(self.norm[i])
            z = rng.gaussian(step, c)
            coeff[i] = z
            t = [t[j] - z * self.columns[i][j] for j in range(k)]
        return [sum(coeff[j] * self.columns[j][i] for j in range(k))
                for i in range(k)]

    def sample_coset(self, u: int, sigma: float, rng: _Random) -> list[int]:
        particular = self._particular(u)
        shift = self._klein([-x for x in particular], sigma, rng)
        return [particular[i] + shift[i] for i in range(self.params.k)]

    def ring_sample_d(self, ring: _Ring, u, sigma: float, rng: _Random):
        per_coeff = [self.sample_coset(c, sigma, rng) for c in ring.coeffs(u)]
        return tuple(ring.elem(per_coeff[c][i] for c in range(self.params.n))
                     for i in range(self.params.k))

    def ring_del_trap(self, ring: _Ring, base, trap, old_tag, new_tag,
                      new_block, sigma: float, rng: _Random):
        k = self.params.k
        m = len(base)
        if len(trap) != m - k:
            raise InvalidParameterError("parent trapdoor has the wrong row count")
        columns = []
        for j in range(k):
            target = (new_tag * ring.g[j] - new_block[j]) / old_tag
            z = self.ring_sample_d(ring, target, sigma, rng)
            top = [sum((trap[i][t] * z[t] for t in range(k)), ring.zero)
                   for i in range(m - k)]
            column = top + list(z)
            if sum((base[i] * column[i] for i in range(m)), ring.zero) \
                    != new_tag * ring.g[j] - new_block[j]:
                raise InvalidParameterError("delegation relation failed")
            columns.append(column)
        return tuple(tuple(columns[j][i] for j in range(k)) for i in range(m))

    def _babai_coeff(self, y) -> int:
        k = self.params.k
        t = [float(x) for x in y]
        coeff = [0] * k
        for j in range(k - 1, -1, -1):
            c = sum(t[i] * self.orth_v[j][i] for i in range(k)) / self.norm_v[j]
            r = int(round(c))
            coeff[j] = r
            t = [t[i] - r * self.vcols[j][i] for i in range(k)]
        return sum(coeff[j] * self.vfirst[j] for j in range(k)) % self.params.q

    def babai_invert(self, ring: _Ring, y, target, g_ring):
        if not target.is_unit():
            raise LaiDecryptError("tag is not invertible")
        z = ring.elem(self._babai_coeff([int(y[j].lift()[c])
                                         for j in range(self.params.k)])
                      for c in range(self.params.n))
        residual = [y[j] - g_ring[j] * z for j in range(self.params.k)]
        norm = math.sqrt(sum(
            (c if c <= self.params.q // 2 else c - self.params.q) ** 2
            for e in residual for c in ring.coeffs(e)))
        if norm > self.tolerance:
            raise LaiDecryptError(
                f"gadget inversion exceeded the Babai tolerance: {norm:.0f}")
        return z / target


class LaiEngine:
    def __init__(self, params: LaiParams) -> None:
        if type(params) is not LaiParams:
            raise InvalidParameterError("LaiEngine requires LaiParams")
        self.params = params
        self.ring = _Ring(params)
        self.sampler = _GadgetSampler(params)

    # -- tuple helpers ----------------------------------------------------
    def _t(self, value):
        return self.ring.coeffs(value)

    def _tt(self, values):
        return tuple(self._t(value) for value in values)

    def _tv(self, vectors):
        return tuple(self._tt(vector) for vector in vectors)

    def _e(self, value):
        return self.ring.elem(value)

    def _vec(self, values):
        return tuple(self._e(value) for value in values)

    def _mat(self, rows):
        return tuple(tuple(self._e(value) for value in row) for row in rows)

    def _mat_t(self, rows):
        return tuple(tuple(self._t(value) for value in row) for row in rows)

    def _hash_identity(self, level: int, data: bytes):
        domain = b"LAI-A-ID-L1" if level == 1 else b"LAI-A-ID-L2"
        digest = hashlib.shake_256(
            domain + len(data).to_bytes(4, "big") + data).digest(self.params.n)
        bits = [(digest[i // 8] >> (7 - (i % 8))) & 1
                for i in range(self.params.n)]
        return self.ring.elem(bits)

    def identity_tuple(self, level: int, data: bytes):
        return self._t(self._hash_identity(level, data))

    def _public_chain(self, pk: LaiPublicKey, parent_id: bytes, child_id: bytes):
        left = self._e(self.identity_tuple(1, parent_id))
        right = self._e(self.identity_tuple(2, child_id))
        ids = (left, right)
        u0, u1, u2 = (self._vec(vector) for vector in pk.u)
        a_id1 = [u0[j] + left * u1[j] for j in range(self.params.k)]
        a_id = [a_id1[j] + right * u2[j] for j in range(self.params.k)]
        base = list(self._vec(pk.a)) + a_id1
        return base, a_id, ids

    # -- setup / delegation -------------------------------------------------
    def setup(self, rng) -> tuple[LaiPublicKey, LaiMasterSecret]:
        rng = _as_random(rng)
        ring = self.ring
        a0 = [ring.random(rng) for _ in range(self.params.l)]
        trapdoor = [[ring.gaussian(rng, self.params.sigma_r)
                     for _ in range(self.params.k)]
                    for _ in range(self.params.l)]
        a1 = [ring.g[j] - sum((a0[i] * trapdoor[i][j]
                               for i in range(self.params.l)), ring.zero)
              for j in range(self.params.k)]
        if any(sum((a0[i] * trapdoor[i][j]
                    for i in range(self.params.l)), ring.zero) + a1[j] != ring.g[j]
               for j in range(self.params.k)):
            raise InvalidParameterError("Lai trapgen relation failed")
        a = tuple(a0 + a1)
        u = tuple(tuple(ring.random(rng) for _ in range(self.params.k))
                  for _ in range(3))
        pk = LaiPublicKey(self.params, self._tt(a), self._tv(u))
        msk = LaiMasterSecret(pk, self._mat_t(trapdoor))
        return pk, msk

    def extract(self, msk: LaiMasterSecret, parent_id: bytes, rng) -> LaiLevel1SecretKey:
        rng = _as_random(rng)
        ring = self.ring
        pk = msk.public_key
        u0, u1, _ = (self._vec(vector) for vector in pk.u)
        left = self._e(self.identity_tuple(1, parent_id))
        a_id = [u0[j] + left * u1[j] for j in range(self.params.k)]
        tag = ring.unit(rng)
        trapdoor = self.sampler.ring_del_trap(
            ring, self._vec(pk.a), self._mat(msk.trapdoor), ring.one, tag,
            a_id, self.params.sigma, rng)
        return LaiLevel1SecretKey(
            pk, parent_id, self._t(tag), pk.a, self._tt(a_id),
            self._mat_t(trapdoor))

    def derive(self, sk_parent: LaiLevel1SecretKey, child_id: bytes,
               rng) -> LaiLevel2SecretKey:
        rng = _as_random(rng)
        ring = self.ring
        pk = sk_parent.public_key
        _, _, u2 = (self._vec(vector) for vector in pk.u)
        right = self._e(self.identity_tuple(2, child_id))
        base = list(self._vec(sk_parent.base)) + list(self._vec(sk_parent.a_id))
        a_id = [self._e(sk_parent.a_id[j]) + right * u2[j]
                for j in range(self.params.k)]
        tag = ring.unit(rng)
        trapdoor = self.sampler.ring_del_trap(
            ring, base, self._mat(sk_parent.trapdoor), self._e(sk_parent.tag),
            tag, a_id, self.params.sigma, rng)
        return LaiLevel2SecretKey(
            pk, sk_parent.identity, child_id, self._t(tag), self._tt(base),
            self._tt(a_id), self._mat_t(trapdoor))

    # -- message encoding --------------------------------------------------
    def encode_message(self, payload: bytes):
        capacity = self.params.k * self.params.n
        if len(payload) > 255 or 8 + 8 * len(payload) > capacity:
            raise InvalidParameterError("Lai payload exceeds the ring message")
        bits = [0] * capacity
        length = len(payload)
        for i in range(8):
            bits[i] = (length >> (7 - i)) & 1
        for i, byte in enumerate(payload):
            for j in range(8):
                bits[8 + 8 * i + j] = (byte >> (7 - j)) & 1
        return [self.ring.elem(bits[j * self.params.n:(j + 1) * self.params.n])
                for j in range(self.params.k)]

    def decode_message(self, vector) -> bytes:
        bits = []
        q = self.params.q
        for element in vector:
            for c in self.ring.coeffs(element):
                bits.append((c if c <= q // 2 else c - q) % 2)
        length = 0
        for i in range(8):
            length = (length << 1) | (bits[i] & 1)
        if 8 + 8 * length > len(bits):
            raise LaiDecryptError("message length exceeds the payload")
        out = bytearray()
        for i in range(length):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | (bits[8 + 8 * i + j] & 1)
            out.append(byte)
        if any(bits[8 + 8 * length:]):
            raise LaiDecryptError("non-zero message padding")
        return bytes(out)

    # -- encrypt / decrypt --------------------------------------------------
    def encrypt(self, pk: LaiPublicKey, parent_id: bytes, child_id: bytes,
                payload: bytes, rng) -> LaiCiphertext:
        rng = _as_random(rng)
        ring = self.ring
        base, a_id, ids = self._public_chain(pk, parent_id, child_id)
        level = 2
        hprime = ring.unit(rng)
        s = ring.gaussian(rng, self.params.sigma)
        e0 = [ring.gaussian(rng, self.params.sigma) for _ in range(len(base))]
        masks = [[[ring.gaussian(rng, self.params.sigma)
                   for _ in range(self.params.k)] for _ in range(len(base))]
                 for _ in range(level + 1)]
        combined = [list(row) for row in masks[0]]
        for i in range(level):
            for row in range(len(base)):
                for column in range(self.params.k):
                    combined[row][column] += ids[i] * masks[i + 1][row][column]
        e1 = [-sum((e0[i] * combined[i][j] for i in range(len(base))), ring.zero)
              for j in range(self.params.k)]
        u = [base[i] * s + self.params.p * e0[i] for i in range(len(base))]
        target = [a_id[j] + hprime * ring.g[j] for j in range(self.params.k)]
        message = self.encode_message(payload)
        v = [target[j] * s + self.params.p * e1[j] + message[j]
             for j in range(self.params.k)]
        return LaiCiphertext(self.params, level, self._t(hprime), self._tt(u),
                             self._tt(v))

    def decrypt(self, sk_child: LaiLevel2SecretKey, ct: LaiCiphertext) -> bytes:
        ring = self.ring
        if ct.params != self.params or sk_child.params != self.params:
            raise LaiDecryptError("parameter mismatch")
        if ct.level != 2:
            raise LaiDecryptError("Lai API ciphertext must be level 2")
        if len(ct.u) != len(sk_child.base) or len(ct.v) != self.params.k:
            raise LaiDecryptError("ciphertext dimensions do not match the key")
        target = self._e(sk_child.tag) + self._e(ct.hprime)
        if not target.is_unit():
            raise LaiDecryptError("h_id + h' is not a unit")
        y = [sum((self._e(ct.u[i]) * self._e(sk_child.trapdoor[i][j])
                  for i in range(len(ct.u))), ring.zero) + self._e(ct.v[j])
             for j in range(self.params.k)]
        s = self.sampler.babai_invert(ring, y, target, ring.g)
        f = list(self._vec(sk_child.base)) + [
            self._e(sk_child.a_id[j]) + self._e(ct.hprime) * ring.g[j]
            for j in range(self.params.k)]
        b = list(self._vec(ct.u)) + list(self._vec(ct.v))
        error = [b[i] - f[i] * s for i in range(len(f))]
        q = self.params.q
        for i in range(len(sk_child.base)):
            if any((c if c <= q // 2 else c - q) % self.params.p
                   for c in ring.coeffs(error[i])):
                raise LaiDecryptError("left half of e is not zero mod p")
        payload = self.decode_message(error[len(sk_child.base):])
        if max(ring.width(value) for value in error) >= q // 4:
            raise LaiDecryptError("plaintext error is too wide")
        return payload
