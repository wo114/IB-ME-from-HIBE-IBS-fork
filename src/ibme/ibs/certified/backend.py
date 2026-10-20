"""BNN certification conversion; independent of HIBE and the Wang protocol."""
import threading
from collections import OrderedDict

from ibme.core.errors import EncodingError, RandomnessError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from .objects import (CertifiedPublicKey, CertifiedMasterSecret, CertifiedSigningKey,
                      CertifiedSignature, certificate_message, application_message)
from .ordinary import ordinary
from .params import CertifiedIBSParams


class IssuancePending(RuntimeError):
    """A failed or uncertain issuance must not generate another identity key."""


class CertifiedIBS:
    def __init__(self, rng=None, *, certificate_cache_entries=64):
        self.rng = SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng, "read", None)):
            raise RandomnessError("certified IBS requires read(n) randomness")
        self._rng_lock = threading.Lock()
        self._certificate_lock = threading.Lock()
        self.configure_certificate_cache(certificate_cache_entries)

    def configure_certificate_cache(self, capacity):
        """Bound process-local public verification results; zero disables reuse."""
        if type(capacity) is not int or not 0 <= capacity <= 256:
            raise ValueError("certificate cache capacity must be in 0..256")
        with self._certificate_lock:
            self._certificate_capacity = capacity
            self._certificates = OrderedDict()
            self._certificate_hits = self._certificate_misses = 0

    def clear_certificate_cache(self):
        with self._certificate_lock:
            self._certificates.clear()

    def certificate_cache_info(self):
        with self._certificate_lock:
            return dict(capacity=self._certificate_capacity, entries=len(self._certificates),
                        hits=self._certificate_hits, misses=self._certificate_misses)

    def _certificate_valid(self, engine, pk, identity, signature):
        # Cache the complete *public verification statement*, never a message
        # signature or a result keyed only by an identity/context digest.
        statement = (pk.params.base_algorithm, pk.authority_public,
                     certificate_message(pk, identity, signature.user_public), signature.certificate)
        with self._certificate_lock:
            if statement in self._certificates:
                self._certificate_hits += 1
                self._certificates.move_to_end(statement)
                return True
            self._certificate_misses += 1
            valid = engine.verify(*statement[1:]) is True
            if valid and self._certificate_capacity:
                self._certificates[statement] = None
                while len(self._certificates) > self._certificate_capacity:
                    self._certificates.popitem(last=False)
            return valid

    def _seed(self):
        with self._rng_lock:
            result = self.rng.read(32)
        if type(result) is not bytes or len(result) != 32:
            raise RandomnessError("certified IBS entropy source must return exactly 32 immutable bytes")
        return result

    def setup(self, params):
        if type(params) is not CertifiedIBSParams:
            raise TypeError("expected explicit CertifiedIBSParams")
        engine = ordinary(params)
        public, secret = engine.keypair(self._seed())
        pk = CertifiedPublicKey(params, public)
        return pk, CertifiedMasterSecret(pk, secret)

    def key_extract(self, msk, identity):
        if type(msk) is not CertifiedMasterSecret:
            raise TypeError("expected CertifiedMasterSecret")
        identity = validate_identity(identity, max_bytes=msk.params.identity_bytes)
        with msk._lock:
            if identity in msk._cache:
                key = msk._cache[identity]
                if key is None:
                    raise IssuancePending("certified IBS identity is pending; automatic reissue forbidden")
                return key
            if len(msk._cache) >= msk.params.max_identities:
                raise EncodingError("certified IBS identity capacity exhausted")
            # Check the runtime before reserving the identity or consuming entropy.
            engine = ordinary(msk.params)
            msk._cache[identity] = None
            try:
                if msk.persist_callback:
                    msk.persist_callback(msk)
                public, secret = engine.keypair(self._seed())
                cert = engine.sign(msk._authority_secret,
                                   certificate_message(msk.public_key, identity, public), self._seed())
                key = CertifiedSigningKey(msk.public_key, identity, public, cert, secret)
                msk._cache[identity] = key
                if msk.persist_callback:
                    msk.persist_callback(msk)
                return key
            except BaseException:
                msk._cache[identity] = None
                raise

    def sign(self, sk, message):
        if type(sk) is not CertifiedSigningKey:
            raise TypeError("expected CertifiedSigningKey")
        message = validate_bytes(message, name="message")
        if len(message) > sk.params.message_max_bytes:
            raise EncodingError("certified IBS message capacity exceeded")
        engine = ordinary(sk.params)
        signature = engine.sign(sk.user_secret, application_message(
            sk.public_key, sk.identity, sk.user_public, sk.certificate, message), self._seed())
        return CertifiedSignature(sk.params.base_algorithm, sk.public_key.context,
                                  sk.user_public, sk.certificate, signature)

    def verify(self, pk, identity, message, signature):
        if type(pk) is not CertifiedPublicKey or type(signature) is not CertifiedSignature:
            return False
        try:
            identity = validate_identity(identity, max_bytes=pk.params.identity_bytes)
            message = validate_bytes(message, name="message")
        except EncodingError:
            return False
        if (len(message) > pk.params.message_max_bytes or signature.algorithm != pk.params.base_algorithm
                or signature.context != pk.context):
            return False
        engine = ordinary(pk.params)
        return bool(self._certificate_valid(engine, pk, identity, signature)
                    and engine.verify(signature.user_public, application_message(
                        pk, identity, signature.user_public, signature.certificate, message), signature.message_signature))

    def load_signature(self, pk, data):
        if type(pk) is not CertifiedPublicKey:
            raise TypeError("expected CertifiedPublicKey")
        result = CertifiedSignature.from_bytes(data)
        if result.algorithm != pk.params.base_algorithm or result.context != pk.context:
            raise SerializationError("certified IBS signature public context mismatch")
        engine = ordinary(pk.params)
        if not engine.canonical_signature(result.certificate) or not engine.canonical_signature(result.message_signature):
            raise SerializationError("noncanonical certified IBS signature coefficients/hints")
        return result
