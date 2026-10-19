"""Public HIBE API adapter for the Lai A-point research backend."""
from __future__ import annotations

from ibme.core.errors import (
    EncodingError,
    IBMEError,
    InvalidParameterError,
    SerializationError,
)
from ibme.core.types import validate_bytes, validate_identity
from .engine import LaiDecryptError, LaiEngine, _as_random
from .objects import (
    LaiCiphertext,
    LaiLevel1SecretKey,
    LaiLevel2SecretKey,
    LaiMasterSecret,
    LaiPublicKey,
)
from .params import LaiParams


class LaiHIBE:
    """Two-level Lai HIBE; research parameters, no security admission.

    Identity order is frozen as ``(parent_id, child_id) = (rcv, phi)``.
    Decryption failures return ``None``; malformed inputs raise project errors.
    """

    def setup(self, params, *, rng=None):
        if type(params) is not LaiParams:
            raise InvalidParameterError(
                f"setup expects LaiParams, got {type(params).__name__}")
        return LaiEngine(params).setup(rng)

    def extract(self, msk, parent_id: bytes, *, rng=None):
        if not isinstance(msk, LaiMasterSecret):
            raise TypeError("extract expects a LaiMasterSecret")
        ident = validate_identity(
            parent_id, name="parent_id", max_bytes=msk.params.identity_bytes)
        return LaiEngine(msk.params).extract(msk, ident, rng)

    def derive(self, sk_parent, child_id: bytes, *, rng=None):
        if not isinstance(sk_parent, LaiLevel1SecretKey):
            raise TypeError("derive expects a LaiLevel1SecretKey")
        ident = validate_identity(
            child_id, name="child_id", max_bytes=sk_parent.params.identity_bytes)
        return LaiEngine(sk_parent.params).derive(sk_parent, ident, rng)

    def encrypt(self, pk, parent_id: bytes, child_id: bytes, payload: bytes,
                *, rng=None):
        if not isinstance(pk, LaiPublicKey):
            raise TypeError("encrypt expects a LaiPublicKey")
        left = validate_identity(
            parent_id, name="parent_id", max_bytes=pk.params.identity_bytes)
        right = validate_identity(
            child_id, name="child_id", max_bytes=pk.params.identity_bytes)
        message = validate_bytes(payload, name="payload")
        if len(message) > pk.params.max_message_bytes:
            raise InvalidParameterError(
                f"payload of {len(message)} bytes exceeds "
                f"max_message_bytes={pk.params.max_message_bytes}")
        return LaiEngine(pk.params).encrypt(pk, left, right, message, rng)

    def decrypt(self, sk_child, ct, *, rng=None):
        if not isinstance(sk_child, LaiLevel2SecretKey):
            raise TypeError("decrypt expects a LaiLevel2SecretKey")
        if not isinstance(ct, LaiCiphertext):
            raise TypeError("decrypt expects a LaiCiphertext")
        if sk_child.params != ct.params:
            return None
        try:
            return LaiEngine(sk_child.params).decrypt(sk_child, ct)
        except (LaiDecryptError, InvalidParameterError, SerializationError,
                IBMEError, ValueError, ZeroDivisionError):
            return None

    def load_ciphertext(self, data: bytes) -> LaiCiphertext:
        return LaiCiphertext.from_bytes(data)

    def validate_key_binding(self, public_key, secret_key) -> bool:
        """Check public/root/identity equations without sampling or entropy."""
        if not isinstance(public_key, LaiPublicKey):
            return False
        if not isinstance(secret_key, (LaiMasterSecret, LaiLevel1SecretKey,
                                       LaiLevel2SecretKey)):
            return False
        if secret_key.params != public_key.params:
            return False
        try:
            engine = LaiEngine(public_key.params)
            ring = engine.ring
            p = public_key.params
            a = engine._vec(public_key.a)
            g = ring.g
            if isinstance(secret_key, LaiMasterSecret):
                a0, a1 = a[:p.l], a[p.l:]
                trap = engine._mat(secret_key.trapdoor)
                return all(
                    sum((a0[i] * trap[i][j] for i in range(p.l)), ring.zero)
                    + a1[j] == g[j] for j in range(p.k))
            u0, u1, u2 = (engine._vec(vector) for vector in public_key.u)
            left = engine._e(engine.identity_tuple(1, secret_key.identity)) \
                if isinstance(secret_key, LaiLevel1SecretKey) else \
                engine._e(engine.identity_tuple(1, secret_key.parent_identity))
            a_id1 = [u0[j] + left * u1[j] for j in range(p.k)]
            if isinstance(secret_key, LaiLevel1SecretKey):
                if engine._vec(secret_key.base) != a or \
                        engine._vec(secret_key.a_id) != tuple(a_id1):
                    return False
                base = a
                a_id = a_id1
            else:
                right = engine._e(engine.identity_tuple(
                    2, secret_key.child_identity))
                expected = [a_id1[j] + right * u2[j] for j in range(p.k)]
                expected_base = tuple(a) + tuple(a_id1)
                if engine._vec(secret_key.base) != expected_base or \
                        engine._vec(secret_key.a_id) != tuple(expected):
                    return False
                base = engine._vec(secret_key.base)
                a_id = expected
            tag = engine._e(secret_key.tag)
            trap = engine._mat(secret_key.trapdoor)
            return all(
                sum((base[i] * trap[i][j] for i in range(len(base))), ring.zero)
                + a_id[j] == tag * g[j] for j in range(p.k))
        except (IBMEError, TypeError, ValueError, ZeroDivisionError):
            return False
