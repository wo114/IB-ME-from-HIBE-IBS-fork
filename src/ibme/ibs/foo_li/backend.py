"""Five-method adapter over the existing Figure 2 finite sampling algorithms."""
import threading

from ibme.core.errors import EncodingError, RandomnessError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from ibme.ibs.api import IBSError
from experiments.research.foo_li_runtime_reference import (
    DOMAINS, ResearchSession, ShakeOracleCandidate, checked_read,
)
from experiments.research.gaussian_reference import SamplingAbort
from .params import FooLiParams, preflight
from .objects import PublicKey, Signature, signature_shape
from .keys import MasterSecret, SigningKey


class FooLiSamplingAbort(SamplingAbort):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Foo-Li operation aborted: {status}; no automatic retry")


class IssuancePending(RuntimeError):
    """An identity is pending/failed; automatic reselection is forbidden."""


class _CheckedRandom:
    def __init__(self, rng):
        if not callable(getattr(rng, "read", None)):
            raise RandomnessError("Foo-Li requires read(n) randomness")
        self.rng, self.lock = rng, threading.Lock()

    def read(self, count):
        with self.lock:
            result = self.rng.read(count)
        if not isinstance(result, (bytes, bytearray, memoryview)):
            raise RandomnessError("Foo-Li entropy source returned non-bytes")
        try:
            with memoryview(result) as view:
                if view.nbytes != count:
                    raise RandomnessError("Foo-Li entropy source returned wrong byte count")
                return view.tobytes()
        except ValueError as exc:
            raise RandomnessError("Foo-Li entropy source returned invalid buffer") from exc


class FooLiIBS:
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __init__(self, rng=None, *, epoch=None):
        self.rng = _CheckedRandom(SecureRandom() if rng is None else rng)
        self.epoch = None if epoch is None else validate_identity(epoch, max_bytes=256)

    def setup(self, params):
        if type(params) is not FooLiParams:
            raise TypeError("expected FooLiParams")
        preflight(params)
        epoch = self.rng.read(32) if self.epoch is None else self.epoch
        outcome = ResearchSession.setup(params.research_config(), epoch, rng=self.rng)
        if outcome.status != "ok":
            raise FooLiSamplingAbort(outcome.status)
        msk = MasterSecret(params, outcome.value)
        return msk.public_key, msk

    def key_extract(self, msk, identity):
        if type(msk) is not MasterSecret:
            raise TypeError("expected Foo-Li MasterSecret")
        identity = validate_identity(identity, max_bytes=msk.params.identity_max_bytes)
        with msk._lock:
            status = msk._states.get(identity)
            if status == "issued":
                return msk._issued_key(identity)
            if status is not None:
                raise IssuancePending("Foo-Li identity pending/failed; automatic reissue forbidden")
            if len(msk._states) >= msk.params.max_users:
                raise EncodingError("Foo-Li identity issuance capacity exhausted")
            if msk.persist_callback is not None and not callable(msk.persist_callback):
                raise TypeError("persist_callback must be callable")
            msk._states[identity] = "pending"
            try:
                if msk.persist_callback is not None:
                    msk.persist_callback(msk)
                outcome = msk._session.extract(identity, seed_rng=self.rng)
                if outcome.status != "ok":
                    raise FooLiSamplingAbort(outcome.status)
                key = msk._issued_key(identity)
                msk._states[identity] = "issued"
                if msk.persist_callback is not None:
                    msk.persist_callback(msk)
                return key
            except BaseException:
                msk._states[identity] = "failed"
                msk._session.users.pop(identity, None)
                msk._keys.pop(identity, None)
                # The already persisted pending record blocks recovery after a
                # crash. Do not call a failed I/O callback again and mask errors.
                raise

    def sign(self, sk, message):
        if type(sk) is not SigningKey:
            raise TypeError("expected Foo-Li SigningKey")
        message = validate_bytes(message, name="message")
        if len(message) > sk.params.message_max_bytes:
            raise EncodingError("Foo-Li message capacity exceeded")
        verifier = sk.public_key._verifier
        try:
            target = verifier.syndrome(sk.identity, message)
            length = sk._sampler.random_tape_bytes
            stream = ShakeOracleCandidate().stream(DOMAINS[4], verifier.context,
                                                   (sk.seed, sk.identity, message), length)
            output = sk._sampler.sample_from_tape(target, checked_read(stream, length))
        except SamplingAbort as exc:
            raise FooLiSamplingAbort("signature_sampling_or_hash_abort") from exc
        signature = Signature(sk.public_key.context, output, sk.bit)
        if not signature_shape(sk.public_key, signature):
            raise FooLiSamplingAbort("signature_norm_rejected")
        if not verifier.verify(sk.identity, message, signature.raw):
            raise IBSError("Foo-Li sampler violated its public signature equation")
        return signature

    def verify(self, pk, identity, message, signature):
        if type(pk) is not PublicKey or not signature_shape(pk, signature):
            return False
        try:
            return bool(pk._verifier.verify(identity, message, signature.raw))
        except (EncodingError, ValueError, TypeError):
            return False

    def load_signature(self, pk, data):
        if type(pk) is not PublicKey:
            raise TypeError("expected Foo-Li PublicKey")
        result = Signature.from_bytes(data)
        if not signature_shape(pk, result):
            raise SerializationError("Foo-Li signature context/dimension/norm mismatch")
        return result
