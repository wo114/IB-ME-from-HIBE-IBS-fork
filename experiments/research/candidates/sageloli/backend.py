"""Complete adaptive Sageloli SIS and Ring-SIS research IBS backends.

The two classes implement the same five-method IBS surface while keeping
matrix and ring arithmetic private to their route.  Key extraction uses the
adaptive salts from Figures 6/8 (``r`` for an identity, ``s`` per message),
and every state transition is fail-closed.  These are teaching profiles with
real finite Gaussian gadget fibers; they carry no security or parameter
admission claim.
"""

from __future__ import annotations

from hashlib import sha256
from math import sqrt
from threading import RLock

from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from ibme.ibs.api import IBSError

from . import algebra
from .hashing import sis_h1, sis_h2, rsis_h1, rsis_h2
from .objects import (
    SisParams, RsisParams, SisPublicKey, RsisPublicKey,
    SisMasterSecret, RsisMasterSecret, SisSigningKey, RsisSigningKey,
    SisSignature, RsisSignature, Signature,
)


class SamplingAbort(RuntimeError):
    """Finite sampler/resource failure; callers must not silently reroll."""


def _checked_rng(rng):
    if rng is None:
        return SecureRandom()
    if not callable(getattr(rng, "read", None)):
        raise TypeError("rng must provide read(n) -> bytes")
    return rng


def _read(rng, size):
    try:
        raw = rng.read(size)
    except Exception as exc:
        raise SamplingAbort("randomness source failed") from exc
    if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
        raise SamplingAbort("randomness source returned an invalid length")
    return bytes(raw)


def _identity(params, value):
    try:
        result = validate_identity(value, max_bytes=params.identity_max_bytes)
    except Exception as exc:
        raise EncodingError("invalid or oversized Sageloli identity") from exc
    return result


def _message(params, value):
    try:
        result = validate_bytes(value, name="message")
    except Exception as exc:
        raise EncodingError("message must be bytes-like") from exc
    if len(result) > params.message_max_bytes:
        raise EncodingError("Sageloli message capacity exceeded")
    return result


def _salt(rng, params):
    return _read(rng, params.salt_bytes)


def _cbd(rng):
    value = _read(rng, 1)[0] & 3
    return -1 if value == 0 else 1 if value == 3 else 0


def _uniform(rng, q):
    width = max(1, (q.bit_length() + 7) // 8)
    return int.from_bytes(_read(rng, width), "big") % q


def _matrix_norm(values, q):
    return sum(algebra.centered(v, q) ** 2 for row in values for v in row)


def _expand_poly(poly, d):
    result = [[0 for _ in range(d)] for _ in range(d)]
    for column in range(d):
        basis = tuple(int(column == h) for h in range(d))
        product = algebra.poly_mul(poly, basis)
        for row, value in enumerate(product):
            result[row][column] = value
    return tuple(tuple(row) for row in result)


def _expand_ring_matrix(values, d, modulus=None):
    rows, cols = len(values), len(values[0])
    out = [[0 for _ in range(cols * d)] for _ in range(rows * d)]
    for i, row in enumerate(values):
        for j, poly in enumerate(row):
            block = _expand_poly(poly, d)
            for r in range(d):
                for c in range(d):
                    value = block[r][c]
                    out[i * d + r][j * d + c] = value if modulus is None else value % modulus
    return tuple(tuple(row) for row in out)


def _collapse_ring_matrix(values, d, rows, cols):
    if len(values) != rows * d or len(values[0]) != cols * d:
        raise ValueError("expanded ring matrix dimension mismatch")
    return tuple(
        tuple(tuple(values[i * d + h][j * d] for h in range(d)) for j in range(cols))
        for i in range(rows)
    )


def _ring_from_public(pk):
    p = pk.params
    return tuple(tuple(tuple(pk.a[h][j * p.d] for h in range(p.d)) for j in range(p.l)) for _ in [0])


def _ring_target(h, k, d, q):
    g = tuple((3**j,) + (0,) * (d - 1) for j in range(k))
    return tuple(algebra.poly_sub(h[j], g[j], q) for j in range(k))


def _flat(values):
    if values and isinstance(values[0], (tuple, list)):
        return tuple(v for item in values for v in item)
    return tuple(values)


def _split_ok(z, first, second, bound, q, *, canonical=True):
    z = _flat(z)
    if not z or not any(int(v) for v in z):
        return False
    if canonical and any(int(v) != algebra.centered(v, q) for v in z):
        return False
    return _split_norm_ok(z, first, second, bound, q)


def _split_norm_ok(z, first, second, bound, q):
    """Check the two coefficient blocks without requiring a nonzero vector."""
    z = _flat(z)
    if not z or len(z) != first + second:
        return False
    a = sum(algebra.centered(v, q) ** 2 for v in z[:first])
    b = sum(algebra.centered(v, q) ** 2 for v in z[first:first + second])
    return a <= 2 * first * bound and b <= 2 * second * bound


def _matrix_trapdoor_ok(trapdoor, first, second, bound, q):
    """Check the delegated matrix in its two sampler blocks."""
    if len(trapdoor) != first + second or not trapdoor:
        return False
    columns = len(trapdoor[0])
    if columns < 1 or any(len(row) != columns for row in trapdoor):
        return False
    values = tuple(value for row in trapdoor for value in row)
    return _split_norm_ok(values, first * columns, second * columns, bound, q)


def _ring_trapdoor_ok(trapdoor, d, first, second, bound, q):
    """Check the expanded ring sampler blocks (l-k) and k polynomials."""
    if len(trapdoor) != first + second or not trapdoor:
        return False
    columns = len(trapdoor[0])
    if columns < 1 or any(len(row) != columns for row in trapdoor):
        return False
    values = tuple(value for row in trapdoor for poly in row for value in poly)
    return _split_norm_ok(values, d * first * columns, d * second * columns, bound, q)


class SISBackend:
    route = "sis"
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __init__(self, rng=None):
        self.rng = _checked_rng(rng)

    def setup(self, params):
        if not isinstance(params, SisParams):
            raise TypeError("Sageloli SisParams required")
        width = params.nk
        abar = tuple(tuple(_uniform(self.rng, params.q) for _ in range(params.m - width)) for _ in range(params.n))
        root = tuple(tuple(_cbd(self.rng) for _ in range(width)) for _ in range(params.m - width))
        _, public = algebra.matrix_public(abar, root, params.n, params.k, params.m, params.q)
        pk = SisPublicKey(params, public)
        msk = SisMasterSecret(pk, root, {})
        return pk, msk

    def key_extract(self, msk, identity):
        if not isinstance(msk, SisMasterSecret):
            raise TypeError("Sageloli SIS master secret required")
        params, pk = msk.public_key.params, msk.public_key
        identity = _identity(params, identity)
        with msk._cache_lock:
            current = msk.states.get(identity)
            if current is not None:
                cached = current[1]
                if (current[0] == "issued" and isinstance(cached, SisSigningKey)
                        and cached.identity == identity
                        and cached.public_key.context == pk.context):
                    return cached
                if current[0] == "issued":
                    msk.states[identity] = ("failed", None)
                    raise SamplingAbort("cached SIS signing key binding is invalid")
                raise SamplingAbort("identity pending/failed; automatic reissue is blocked")
            if len(msk.states) >= params.max_users:
                raise SamplingAbort("identity issuance capacity exhausted")
            msk.states[identity] = ("pending", None)
            try:
                r = _salt(self.rng, params)
                h = sis_h1(pk.context, r, identity, params.n, params.k, params.q)
                g = algebra.gadget_matrix(params.n, params.k)
                target = tuple(tuple((h[i][j] - g[i][j]) % params.q for j in range(params.nk)) for i in range(params.n))
                abar = tuple(tuple(pk.a[i][j] for j in range(params.m - params.nk)) for i in range(params.n))
                trap = None
                for _ in range(params.max_extract_attempts):
                    candidate = algebra.matrix_delegate(
                        abar, msk.trapdoor, target, params.n, params.k,
                        params.m, params.q, params.trapdoor_sigma, self.rng)
                    if algebra.matmul(pk.a, candidate, params.q) != target:
                        raise IBSError("SIS delegated trapdoor equation failed")
                    if _matrix_trapdoor_ok(
                            candidate, params.m - params.nk, params.nk,
                            params.s_id_squared, params.q):
                        trap = candidate
                        break
                if trap is None:
                    raise SamplingAbort("SIS identity trapdoor norm rejection budget exhausted")
                key = SisSigningKey(pk, identity, r, trap)
                msk.states[identity] = ("issued", key)
                return key
            except BaseException:
                msk.states[identity] = ("failed", None)
                raise

    def sign(self, sk, message):
        if not isinstance(sk, SisSigningKey):
            raise TypeError("Sageloli SIS signing key required")
        params, pk = sk.public_key.params, sk.public_key
        message = _message(params, message)
        for _ in range(params.max_sign_attempts):
            s = _salt(self.rng, params)
            h = sis_h1(pk.context, sk.identity_salt, sk.identity, params.n, params.k, params.q)
            u = sis_h2(pk.context, sk.identity_salt, s, sk.identity, message, params.n, params.q)
            z = algebra.matrix_sign(pk.a, h, sk.trapdoor, u, params.n, params.k, params.m,
                                    params.q, params.signing_sigma, self.rng)
            z = tuple(algebra.centered(value, params.q) for value in z)
            if not _split_ok(z, params.m, params.nk, params.s_sign_squared, params.q):
                continue
            sig = SisSignature(pk.context, sk.identity_salt, s, z)
            if not self.verify(pk, sk.identity, message, sig):
                raise IBSError("SIS honest signature failed public verification")
            return sig
        raise SamplingAbort("SIS signature norm rejection budget exhausted")

    def verify(self, pk, identity, message, signature):
        try:
            if not isinstance(pk, SisPublicKey) or not isinstance(signature, Signature):
                return False
            params = pk.params
            identity = _identity(params, identity); message = _message(params, message)
            if signature.context != pk.context or len(signature.identity_salt) != params.salt_bytes or len(signature.message_salt) != params.salt_bytes:
                return False
            if len(signature.z) != params.signature_dimension:
                return False
            h = sis_h1(pk.context, signature.identity_salt, identity, params.n, params.k, params.q)
            u = sis_h2(pk.context, signature.identity_salt, signature.message_salt, identity, message, params.n, params.q)
            f = algebra.hstack(pk.a, h)
            if tuple(x % params.q for x in algebra.matvec(f, signature.z, params.q)) != tuple(u):
                return False
            return _split_ok(signature.z, params.m, params.nk, params.s_sign_squared, params.q)
        except (EncodingError, SerializationError, TypeError, ValueError, AttributeError, OverflowError):
            return False

    def load_signature(self, pk, data):
        if not isinstance(pk, SisPublicKey):
            raise TypeError("Sageloli SIS public key required")
        result = Signature.from_bytes(data, pk)
        if len(result.z) != pk.params.signature_dimension:
            raise SerializationError("SIS signature dimension mismatch")
        if not _split_ok(result.z, pk.params.m, pk.params.nk,
                         pk.params.s_sign_squared, pk.params.q):
            raise SerializationError("SIS signature is noncanonical or out of bounds")
        return result


class RSISBackend:
    route = "rsis"
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __init__(self, rng=None):
        self.rng = _checked_rng(rng)

    def setup(self, params):
        if not isinstance(params, RsisParams):
            raise TypeError("Sageloli RsisParams required")
        p = params
        abar = (tuple(tuple(_uniform(self.rng, p.q) for _ in range(p.d)) for _ in range(p.l - p.k)),)
        root = tuple(tuple(tuple(_cbd(self.rng) for _ in range(p.d)) for _ in range(p.k)) for _ in range(p.l - p.k))
        _, ring_a = algebra.ring_public(abar, root, p.d, p.k, p.l, p.q)
        pk = RsisPublicKey(p, _expand_ring_matrix((ring_a,), p.d, p.q))
        msk = RsisMasterSecret(pk, _expand_ring_matrix(root, p.d), {})
        return pk, msk

    def key_extract(self, msk, identity):
        if not isinstance(msk, RsisMasterSecret):
            raise TypeError("Sageloli RSIS master secret required")
        p, pk = msk.public_key.params, msk.public_key
        identity = _identity(p, identity)
        with msk._cache_lock:
            current = msk.states.get(identity)
            if current is not None:
                cached = current[1]
                if (current[0] == "issued" and isinstance(cached, RsisSigningKey)
                        and cached.identity == identity
                        and cached.public_key.context == pk.context):
                    return cached
                if current[0] == "issued":
                    msk.states[identity] = ("failed", None)
                    raise SamplingAbort("cached RSIS signing key binding is invalid")
                raise SamplingAbort("identity pending/failed; automatic reissue is blocked")
            if len(msk.states) >= p.max_users:
                raise SamplingAbort("identity issuance capacity exhausted")
            msk.states[identity] = ("pending", None)
            try:
                r = _salt(self.rng, p)
                h = rsis_h1(pk.context, r, identity, p.k, p.d, p.q)
                target = _ring_target(h, p.k, p.d, p.q)
                abar = (_ring_from_public(pk)[0][:p.l - p.k],)
                root = _collapse_ring_matrix(msk.trapdoor, p.d, p.l - p.k, p.k)
                trap_ring = None
                for _ in range(p.max_extract_attempts):
                    candidate = algebra.ring_delegate(
                        abar, root, target, p.d, p.k, p.l, p.q,
                        p.trapdoor_sigma, self.rng)
                    if algebra.ring_matmul(_ring_from_public(pk), candidate,
                                           p.d, p.q) != (tuple(target),):
                        raise IBSError("RSIS delegated trapdoor equation failed")
                    if _ring_trapdoor_ok(
                            candidate, p.d, p.l - p.k, p.k,
                            p.s_id_squared, p.q):
                        trap_ring = candidate
                        break
                if trap_ring is None:
                    raise SamplingAbort("RSIS identity trapdoor norm rejection budget exhausted")
                trap = _expand_ring_matrix(trap_ring, p.d)
                key = RsisSigningKey(pk, identity, r, trap)
                msk.states[identity] = ("issued", key)
                return key
            except BaseException:
                msk.states[identity] = ("failed", None)
                raise

    def sign(self, sk, message):
        if not isinstance(sk, RsisSigningKey):
            raise TypeError("Sageloli RSIS signing key required")
        p, pk = sk.public_key.params, sk.public_key
        message = _message(p, message)
        for _ in range(p.max_sign_attempts):
            s = _salt(self.rng, p)
            h = rsis_h1(pk.context, sk.identity_salt, sk.identity, p.k, p.d, p.q)
            u = rsis_h2(pk.context, sk.identity_salt, s, sk.identity, message, p.d, p.q)
            a = _ring_from_public(pk)
            ring_h = h
            trap_ring = _collapse_ring_matrix(sk.trapdoor, p.d, p.l, p.k)
            z_polys = algebra.ring_sign(
                a, ring_h, trap_ring, u, p.d, p.k, p.l, p.q,
                p.signing_sigma, self.rng)
            z = tuple(algebra.centered(value, p.q) for poly in z_polys for value in poly)
            if not _split_ok(z, p.first_dimension, p.second_dimension, p.s_sign_squared, p.q):
                continue
            sig = RsisSignature(pk.context, sk.identity_salt, s, z)
            if not self.verify(pk, sk.identity, message, sig):
                raise IBSError("RSIS honest signature failed public verification")
            return sig
        raise SamplingAbort("RSIS signature norm rejection budget exhausted")

    def verify(self, pk, identity, message, signature):
        try:
            if not isinstance(pk, RsisPublicKey) or not isinstance(signature, Signature):
                return False
            p = pk.params; identity = _identity(p, identity); message = _message(p, message)
            if signature.context != pk.context or len(signature.identity_salt) != p.salt_bytes or len(signature.message_salt) != p.salt_bytes:
                return False
            if len(signature.z) != p.signature_dimension:
                return False
            h = rsis_h1(pk.context, signature.identity_salt, identity, p.k, p.d, p.q)
            u = rsis_h2(pk.context, signature.identity_salt, signature.message_salt, identity, message, p.d, p.q)
            z_polys = tuple(tuple(signature.z[i * p.d + h_] for h_ in range(p.d)) for i in range(p.l + p.k))
            a = _ring_from_public(pk)[0]
            f = tuple(a) + tuple(h)
            if algebra.ring_matvec((f,), z_polys, p.d, p.q) != (tuple(u),):
                return False
            return _split_ok(signature.z, p.first_dimension, p.second_dimension, p.s_sign_squared, p.q)
        except (EncodingError, SerializationError, TypeError, ValueError, AttributeError, OverflowError):
            return False

    def load_signature(self, pk, data):
        if not isinstance(pk, RsisPublicKey):
            raise TypeError("Sageloli RSIS public key required")
        result = Signature.from_bytes(data, pk)
        if len(result.z) != pk.params.signature_dimension:
            raise SerializationError("RSIS signature dimension mismatch")
        if not _split_ok(result.z, pk.params.first_dimension, pk.params.second_dimension,
                         pk.params.s_sign_squared, pk.params.q):
            raise SerializationError("RSIS signature is noncanonical or out of bounds")
        return result


class Backend(SISBackend):
    """Default alias used by the generic FixedIssuer (matrix SIS route)."""


__all__ = ["SamplingAbort", "SISBackend", "RSISBackend", "Backend"]
