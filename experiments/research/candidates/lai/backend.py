"""Lai 2015 ideal-lattice IBE / two-level HIBE research backend (P1).

This is a *research* backend with teaching parameters.  It does not admit a
security level: ``security_claim=none``, ``backend_admitted=False`` and
``parameters_are_formal=False``.  The construction follows the documented
interpretation of Lai-Cheung-Chow, Inscrypt 2014 / LNCS 8957:

* R_q = F_q[x]/(x^n+1), n a power of two, q prime with q = 1 (mod 2n);
* MP12-style ring G-trapdoor with gadget g = (1, 2, 4, ..., 2^{k-1});
* level 1 Extract and level 2 Derive both use ringDelTrap with an appended
  identity block; the parent base vector grows by k ring elements per level;
* encryption samples fresh short R_i and sets e_1 = -e_0^T R;
* decryption uses the dual basis V = q S^{-T} and Babai nearest plane to
  recover s, then checks e mod p.

Only SageMath is supported.  Run under the prescribed WSL environment::

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest \
        tests/test_lai_p1.py -q

The module is deliberately not registered in ``ibme.assembly.registry``.
"""

from __future__ import annotations

import hashlib
import math
import random as _random
import secrets
from dataclasses import dataclass
from typing import Iterable, Sequence

from sage.all import GF, PolynomialRing, QuotientRing, ZZ

__all__ = [
    "LaiError",
    "ParameterError",
    "SamplingError",
    "DecryptError",
    "SerializationError",
    "Params",
    "PublicParams",
    "MasterKey",
    "SecretKey",
    "Ciphertext",
    "LaiScheme",
    "TEACHING_PARAMS",
    "A_POINT_PARAMS",
]


class LaiError(Exception):
    """Base class for this research backend."""


class ParameterError(LaiError):
    pass


class SamplingError(LaiError):
    pass


class DecryptError(LaiError):
    pass


class SerializationError(LaiError):
    pass


def _is_power_of_two(value: int) -> bool:
    return type(value) is int and value > 0 and value & (value - 1) == 0


@dataclass(frozen=True)
class Params:
    """Teaching parameter set; never a formal security parameter."""

    q: int
    n: int
    k: int
    l: int
    p: int = 2
    sigma: float = 3.0
    sigma_r: float = 1.0
    depth: int = 2

    def __post_init__(self) -> None:
        if type(self.q) is not int or self.q < 3 or not ZZ(self.q).is_prime():
            raise ParameterError("q must be an odd prime")
        if not _is_power_of_two(self.n) or self.n < 2:
            raise ParameterError("n must be a power of two >= 2")
        if self.q % (2 * self.n) != 1:
            raise ParameterError("q must satisfy q = 1 (mod 2n)")
        if type(self.k) is not int or self.k < 1:
            raise ParameterError("k must be a positive integer")
        if not (2 ** (self.k - 1) < self.q < 2 ** self.k):
            raise ParameterError("k must equal ceil(log2 q)")
        if type(self.l) is not int or self.l < 1:
            raise ParameterError("l must be a positive integer")
        if self.p != 2:
            raise ParameterError("this prototype packs messages with p=2 only")
        if self.q >= 2 ** 32:
            raise ParameterError("4-byte serialization requires q < 2^32")
        if not (0 < self.sigma and math.isfinite(self.sigma)):
            raise ParameterError("sigma must be finite and > 0")
        if not (0 < self.sigma_r and math.isfinite(self.sigma_r)):
            raise ParameterError("sigma_r must be finite and > 0")
        if self.depth not in (1, 2):
            raise ParameterError("this prototype supports depth 1 or 2")

    @property
    def coefficient_bytes(self) -> int:
        return 3 if self.q < 2 ** 24 else 4


TEACHING_PARAMS = Params(q=1048609, n=8, k=21, l=2, p=2, sigma=2.0,
                         sigma_r=1.0, depth=2)

# A point: one 256-bit identity element per level, 4-byte coefficients.
# Research parameter only; q=2^31+513, q = 1 (mod 512), sigma=2.
A_POINT_PARAMS = Params(q=2147484161, n=256, k=32, l=2, p=2, sigma=2.0,
                        sigma_r=1.0, depth=2)


class _Random:
    """Seedable stream for tests; production seeds from SecureRandom."""

    def __init__(self, source=None) -> None:
        if source is None:
            try:
                from ibme.core.randomness import SecureRandom

                source = SecureRandom()
            except Exception:  # pragma: no cover - standalone use
                class _SystemSource:
                    def read(self, n: int) -> bytes:
                        return secrets.token_bytes(n)

                source = _SystemSource()
        self._source = source
        seed = source.read(32)
        self._rng = _random.Random(int.from_bytes(seed, "big"))

    def randrange(self, bound: int) -> int:
        return self._rng.randrange(bound)

    def random(self) -> float:
        return self._rng.random()

    def gaussian(self, sigma: float, center: float = 0.0) -> int:
        if not (sigma > 0 and math.isfinite(sigma)):
            raise ParameterError("gaussian width must be finite and > 0")
        lo = int(math.floor(center - 8.0 * sigma))
        hi = int(math.ceil(center + 8.0 * sigma))
        weights = [math.exp(-((x - center) ** 2) / (2.0 * sigma * sigma))
                   for x in range(lo, hi + 1)]
        total = sum(weights)
        r = self._rng.random() * total
        acc = 0.0
        for x, w in zip(range(lo, hi + 1), weights):
            acc += w
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
    def __init__(self, params: Params) -> None:
        self.params = params
        polynomial = PolynomialRing(GF(params.q), "x")
        self.x = polynomial.gen()
        self.Rq = QuotientRing(polynomial, self.x ** params.n + 1)
        self.zero = self.Rq(0)
        self.one = self.Rq(1)
        self.g = tuple(self.Rq(2 ** i) for i in range(params.k))

    def elem(self, values: Iterable[int]):
        return self.Rq(list(values))

    def coeffs(self, value) -> list[int]:
        values = [int(c) for c in value.lift().list()]
        return (values + [0] * self.params.n)[:self.params.n]

    def random(self, rng: _Random):
        return self.elem(rng.randrange(self.params.q) for _ in range(self.params.n))

    def gaussian(self, rng: _Random, sigma: float):
        return self.elem(rng.gaussian(sigma) for _ in range(self.params.n))

    def unit(self, rng: _Random):
        for _ in range(4096):
            value = self.random(rng)
            if value.is_unit():
                return value
        raise SamplingError("no unit found in the sampling budget")

    def width(self, value) -> int:
        q = self.params.q
        return max(abs(c if c <= q // 2 else c - q) for c in self.coeffs(value))


class _GadgetSampler:
    """Klein/GPV sampler over the gadget coset and Babai inversion."""

    def __init__(self, params: Params) -> None:
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

    def _klein(self, target: Sequence[float], sigma: float,
               rng: _Random) -> list[int]:
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
            raise ParameterError("parent trapdoor has the wrong row count")
        columns = []
        for j in range(k):
            target = (new_tag * ring.g[j] - new_block[j]) / old_tag
            z = self.ring_sample_d(ring, target, sigma, rng)
            top = [sum((trap[i][t] * z[t] for t in range(k)), ring.zero)
                   for i in range(m - k)]
            column = top + list(z)
            if sum((base[i] * column[i] for i in range(m)), ring.zero) \
                    != new_tag * ring.g[j] - new_block[j]:
                raise SamplingError("delegation relation failed")
            columns.append(column)
        return tuple(tuple(columns[j][i] for j in range(k)) for i in range(m))

    def _babai_coeff(self, y: Sequence[int]) -> int:
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
            raise DecryptError("tag is not invertible")
        z = ring.elem(self._babai_coeff([int(y[j].lift()[c])
                                         for j in range(self.params.k)])
                      for c in range(self.params.n))
        residual = [y[j] - g_ring[j] * z for j in range(self.params.k)]
        norm = math.sqrt(sum(
            (c if c <= self.params.q // 2 else c - self.params.q) ** 2
            for e in residual for c in ring.coeffs(e)))
        if norm > self.tolerance:
            raise DecryptError(f"gadget inversion exceeded the Babai tolerance: {norm:.0f} > {self.tolerance:.0f}")
        return z / target


@dataclass(frozen=True)
class PublicParams:
    params: Params
    a: tuple
    u: tuple


@dataclass(frozen=True)
class MasterKey:
    trapdoor: tuple


@dataclass(frozen=True)
class SecretKey:
    level: int
    identity: tuple
    tag: object
    base: tuple
    a_id: tuple
    trapdoor: tuple


@dataclass(frozen=True)
class Ciphertext:
    level: int
    hprime: object
    u: tuple
    v: tuple


class LaiScheme:
    """Two-level Lai research backend; no registry or security admission."""

    def __init__(self, params: Params = TEACHING_PARAMS) -> None:
        self.params = params
        self.ring = _Ring(params)
        self.sampler = _GadgetSampler(params)

    # -- helpers ---------------------------------------------------------
    def _vec_dot(self, left, right):
        return sum((left[i] * right[i] for i in range(len(left))), self.ring.zero)

    def _matvec(self, matrix, vector):
        k = self.params.k
        return [sum((matrix[i][j] * vector[i] for i in range(len(vector))),
                    self.ring.zero) for j in range(k)]

    def _add(self, left, right):
        return [left[i] + right[i] for i in range(len(left))]

    def _hash_to_ring(self, domain: bytes, data: bytes):
        digest = hashlib.shake_256(domain + len(data).to_bytes(4, "big") + data)
        raw = digest.digest(4 * self.params.n)
        return self.ring.elem(
            int.from_bytes(raw[4 * i:4 * i + 4], "big") % self.params.q
            for i in range(self.params.n))

    def _identity(self, level: int, data: bytes):
        # The paper does not print an identity encoding.  P1 fixes a
        # binary encoding so that id_i * R_i stays short; this is an
        # explicit research choice, not a paper quotation.
        domain = b"LAI-P1-ID-L1" if level == 1 else b"LAI-P1-ID-L2"
        digest = hashlib.shake_256(
            domain + len(data).to_bytes(4, "big") + data
        ).digest(self.params.n)
        bits = [(digest[i // 8] >> (7 - (i % 8))) & 1
                for i in range(self.params.n)]
        return self.ring.elem(bits)

    def _public_chain(self, pp: PublicParams, identity: Sequence[bytes]):
        level = len(identity)
        if level not in (1, 2) or level > self.params.depth:
            raise ParameterError("identity depth is not supported")
        ids = [self._identity(i + 1, data) for i, data in enumerate(identity)]
        a_id1 = [pp.u[0][j] + ids[0] * pp.u[1][j]
                 for j in range(self.params.k)]
        if level == 1:
            return pp.a, a_id1, ids
        a_id = [a_id1[j] + ids[1] * pp.u[2][j]
                for j in range(self.params.k)]
        base = tuple(list(pp.a) + list(a_id1))
        return base, a_id, ids

    # -- key generation and delegation -----------------------------------
    def setup(self, rng: _Random | None = None):
        rng = _as_random(rng)
        ring = self.ring
        a0 = [ring.random(rng) for _ in range(self.params.l)]
        trapdoor = [[ring.gaussian(rng, self.params.sigma_r)
                     for _ in range(self.params.k)]
                    for _ in range(self.params.l)]
        a1 = [ring.g[j] - sum((a0[i] * trapdoor[i][j]
                               for i in range(self.params.l)), ring.zero)
              for j in range(self.params.k)]
        a = tuple(a0 + a1)
        if any(self._vec_dot(a0, [trapdoor[i][j] for i in range(self.params.l)])
               + a1[j] != ring.g[j] for j in range(self.params.k)):
            raise SamplingError("trapgen relation failed")
        u = tuple(tuple(ring.random(rng) for _ in range(self.params.k))
                  for _ in range(self.params.depth + 1))
        return PublicParams(self.params, a, u), MasterKey(
            tuple(tuple(row) for row in trapdoor))

    def extract(self, pp: PublicParams, mk: MasterKey, identity: bytes,
                rng: _Random | None = None) -> SecretKey:
        rng = _as_random(rng)
        ring = self.ring
        a_id = [pp.u[0][j] + self._identity(1, identity) * pp.u[1][j]
                for j in range(self.params.k)]
        tag = ring.unit(rng)
        trapdoor = self.sampler.ring_del_trap(
            ring, pp.a, mk.trapdoor, ring.one, tag, a_id,
            self.params.sigma, rng)
        return SecretKey(1, (self._identity(1, identity),), tag, pp.a,
                         tuple(a_id), trapdoor)

    def derive(self, pp: PublicParams, sk: SecretKey, identity: bytes,
               rng: _Random | None = None) -> SecretKey:
        rng = _as_random(rng)
        if sk.level != 1 or self.params.depth < 2:
            raise ParameterError("derive requires a level-1 key and depth 2")
        ring = self.ring
        child = self._identity(2, identity)
        a_id = [sk.a_id[j] + child * pp.u[2][j] for j in range(self.params.k)]
        base = tuple(list(sk.base) + list(sk.a_id))
        tag = ring.unit(rng)
        trapdoor = self.sampler.ring_del_trap(
            ring, base, sk.trapdoor, sk.tag, tag, a_id,
            self.params.sigma, rng)
        return SecretKey(2, sk.identity + (child,), tag, tuple(base),
                         tuple(a_id), trapdoor)

    # -- encryption / decryption ----------------------------------------
    def encode_message(self, message: bytes):
        capacity = self.params.k * self.params.n
        if len(message) > 255 or 8 + 8 * len(message) > capacity:
            raise ParameterError("message does not fit the teaching vector")
        bits = [0] * capacity
        length = len(message)
        for i in range(8):
            bits[i] = (length >> (7 - i)) & 1
        for i, byte in enumerate(message):
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
            raise DecryptError("message length exceeds the payload")
        out = bytearray()
        for i in range(length):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | (bits[8 + 8 * i + j] & 1)
            out.append(byte)
        if any(bits[8 + 8 * length:]):
            raise DecryptError("non-zero message padding")
        return bytes(out)

    def encrypt(self, pp: PublicParams, identity: Sequence[bytes],
                message: bytes, rng: _Random | None = None) -> Ciphertext:
        rng = _as_random(rng)
        ring = self.ring
        base, a_id, ids = self._public_chain(pp, identity)
        level = len(identity)
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
        e1 = [-sum((e0[i] * combined[i][j]
                    for i in range(len(base))), ring.zero)
              for j in range(self.params.k)]
        u = [base[i] * s + self.params.p * e0[i] for i in range(len(base))]
        target = [a_id[j] + hprime * ring.g[j] for j in range(self.params.k)]
        v = [target[j] * s + self.params.p * e1[j]
             for j in range(self.params.k)]
        m = self.encode_message(message)
        v = [v[j] + m[j] for j in range(self.params.k)]
        return Ciphertext(level, hprime, tuple(u), tuple(v))

    def decrypt(self, pp: PublicParams, sk: SecretKey,
                ct: Ciphertext) -> bytes:
        ring = self.ring
        if ct.level != sk.level:
            raise DecryptError("ciphertext and key levels differ")
        if len(ct.u) != len(sk.base) or len(ct.v) != self.params.k:
            raise DecryptError("ciphertext dimensions do not match the key")
        target = sk.tag + ct.hprime
        if not target.is_unit():
            raise DecryptError("h_id + h' is not a unit")
        y = self._add(self._matvec(sk.trapdoor, ct.u), ct.v)
        s = self.sampler.babai_invert(ring, y, target, ring.g)
        f = list(sk.base) + [sk.a_id[j] + ct.hprime * ring.g[j]
                             for j in range(self.params.k)]
        b = list(ct.u) + list(ct.v)
        error = [b[i] - f[i] * s for i in range(len(f))]
        q = self.params.q
        for i in range(len(sk.base)):
            if any((c if c <= q // 2 else c - q) % self.params.p
                   for c in ring.coeffs(error[i])):
                raise DecryptError("left half of e is not zero mod p")
        message = self.decode_message(error[len(sk.base):])
        if max(ring.width(value) for value in error) >= q // 4:
            raise DecryptError("plaintext error is too wide")
        return message

    # -- canonical ciphertext serialization ------------------------------
    def _encode_ring(self, value) -> bytes:
        width = self.params.coefficient_bytes
        return b"".join(c.to_bytes(width, "big")
                        for c in self.ring.coeffs(value))

    def _decode_ring(self, data: bytes, offset: int):
        width = self.params.coefficient_bytes
        need = width * self.params.n
        if offset + need > len(data):
            raise SerializationError("truncated ring element")
        values = [int.from_bytes(
            data[offset + width * i:offset + width * (i + 1)], "big")
            for i in range(self.params.n)]
        if any(value >= self.params.q for value in values):
            raise SerializationError("ring coefficient out of range")
        return self.ring.elem(values), offset + need

    def encode_ciphertext(self, ct: Ciphertext) -> bytes:
        body = bytearray([ct.level])
        body.extend(self._encode_ring(ct.hprime))
        body.extend(len(ct.u).to_bytes(2, "big"))
        for value in ct.u:
            body.extend(self._encode_ring(value))
        body.extend(len(ct.v).to_bytes(2, "big"))
        for value in ct.v:
            body.extend(self._encode_ring(value))
        return b"LAI1" + len(body).to_bytes(4, "big") + bytes(body)

    def decode_ciphertext(self, data: bytes) -> Ciphertext:
        if len(data) < 9 or data[:4] != b"LAI1":
            raise SerializationError("bad magic or truncated header")
        body_len = int.from_bytes(data[4:8], "big")
        if len(data) != 8 + body_len:
            raise SerializationError("body length does not match the buffer")
        body = data[8:]
        level = body[0]
        if level not in (1, 2):
            raise SerializationError("unsupported level")
        offset = 1
        hprime, offset = self._decode_ring(body, offset)
        if offset + 2 > len(body):
            raise SerializationError("truncated u count")
        count_u = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        expected = self.params.l + level * self.params.k
        if count_u != expected:
            raise SerializationError("unexpected u dimension")
        u = []
        for _ in range(count_u):
            value, offset = self._decode_ring(body, offset)
            u.append(value)
        if offset + 2 > len(body):
            raise SerializationError("truncated v count")
        count_v = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        if count_v != self.params.k:
            raise SerializationError("unexpected v dimension")
        v = []
        for _ in range(count_v):
            value, offset = self._decode_ring(body, offset)
            v.append(value)
        if offset != len(body):
            raise SerializationError("trailing ciphertext bytes")
        return Ciphertext(level, hprime, tuple(u), tuple(v))
