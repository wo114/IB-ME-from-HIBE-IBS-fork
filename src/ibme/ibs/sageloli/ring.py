"""Common IBS boundary for unchanged v3 sampling, equations and binary wire."""
from dataclasses import dataclass, field

from ibme.core.errors import SerializationError
from ibme.core.hashing import hash_identity
from ibme.ibs.api import IBSBackend, IBSSigningKey


class _NoEntropy:
    def read(self, count):
        raise AssertionError("Sageloli object recovery must not draw entropy")


def _native_backend(rng):
    from .ring_registration import environment
    environment()
    from experiments.research.candidates.sageloli.ring.backend import RingBackend
    return RingBackend(rng=rng)


@dataclass(frozen=True, eq=False, repr=False)
class SigningKey(IBSSigningKey):
    """Add the public identity digest without changing the native key bytes."""
    _key: object = field(repr=False)

    def __post_init__(self):
        from experiments.research.candidates.sageloli.ring.objects import SigningKey as NativeKey
        if type(self._key) is not NativeKey:
            raise TypeError("native ring v3 signing key required")

    @property
    def identity(self): return self._key.identity

    @property
    def identity_digest(self): return hash_identity(self.identity, 32)

    @property
    def public_key(self): return self._key.public_key

    def to_bytes(self): return self._key.to_bytes()

    @classmethod
    def from_bytes(cls, raw): return decode_object("sk", raw)

    def __repr__(self): return "SageloliRingSigningKey(v3, private=<redacted>)"


def decode_object(kind, raw):
    try:
        if kind == "ipk":
            from experiments.research.candidates.sageloli.ring.objects import PublicKey
            return PublicKey.from_bytes(raw)
        backend = _native_backend(_NoEntropy())
        if kind == "imsk":
            return backend.load_master(raw)
        if kind == "sk":
            return SigningKey(backend.load_signing_key(raw))
        raise ValueError("unknown ring v3 object kind")
    except (ValueError, TypeError, OverflowError, UnicodeError) as exc:
        raise SerializationError("invalid Sageloli ring v3 object") from exc


class Backend(IBSBackend):
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False
    nist_security_category = None
    signature_format = "reference"

    def __init__(self, *, rng=None):
        self._backend = _native_backend(rng)
        self.rng = self._backend.rng

    def setup(self, params): return self._backend.setup(params)

    def key_extract(self, master, identity):
        return SigningKey(self._backend.key_extract(master, identity))

    def sign(self, key, message):
        if type(key) is not SigningKey:
            raise TypeError("public Sageloli ring v3 signing key required")
        return self._backend.sign(key._key, message)

    def verify(self, public, identity, message, signature):
        return self._backend.verify(public, identity, message, signature)

    def load_signature(self, public, raw):
        try:
            return self._backend.load_signature(public, raw)
        except (ValueError, TypeError, OverflowError, UnicodeError) as exc:
            raise SerializationError("invalid Sageloli ring v3 signature") from exc

    def execution_metadata(self):
        return self._backend.library.metadata()
