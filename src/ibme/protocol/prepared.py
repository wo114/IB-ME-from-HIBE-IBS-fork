"""Explicit process-local receiver preparation around the original protocol.

The HIBE primitive remains stateless. A session performs Derive once and holds
one opaque, validated leaf key until close. All ciphertext parsing, HIBE/DEM,
IBS and BYTEAUTH checks still execute on every decrypt. Sessions are neither
serialized nor installed as a default protocol/CLI behavior.
"""
from threading import RLock

from ibme.core.errors import InvalidParameterError
from ibme.core.types import validate_identity
from .baseline import BaselineIBME, PublicKey, ReceiverKey
from .byteauth import ByteAuthenticatedIBME


class _PinnedDerivation:
    def __init__(self, backend, parent, sender, leaf):
        self.backend, self.parent, self.sender, self.leaf = backend, parent, sender, leaf

    def __getattr__(self, name):
        return getattr(self.backend, name)

    def derive(self, parent, sender, *, rng=None):
        if parent is not self.parent or sender != self.sender or self.leaf is None:
            raise InvalidParameterError("prepared receiver path mismatch")
        return self.leaf

    def clear(self):
        self.backend = self.parent = self.sender = self.leaf = None


class PreparedReceiver:
    """One public root, receiver and claimed sender; call close after use.

    Retains secret material in ordinary Python memory. close releases references,
    but cannot promise physical zeroization by the Python/Sage runtime.
    """

    def __init__(self, protocol, public, receiver, sender, pinned, leaf_bytes):
        self._lock = RLock()
        self._protocol, self._public, self._receiver = protocol, public, receiver
        self._sender, self._pinned = sender, pinned
        self._leaf_bytes, self._decryptions, self._closed = leaf_bytes, 0, False

    def decrypt(self, ciphertext, *, rng=None):
        with self._lock:
            if self._closed:
                raise RuntimeError("prepared receiver is closed")
            self._decryptions += 1
            return self._protocol.decrypt(self._public, self._receiver, self._sender, ciphertext, rng=rng)

    def info(self):
        with self._lock:
            return dict(scope="one-root-one-receiver-one-sender-process-local",
                        leaf_key_bytes=self._leaf_bytes, decryptions=self._decryptions,
                        closed=self._closed)

    def close(self):
        with self._lock:
            self._pinned.clear()
            self._protocol = self._public = self._receiver = self._sender = None
            self._closed = True

    def __enter__(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("prepared receiver is closed")
            return self

    def __exit__(self, *_exc):
        self.close()

    def __reduce__(self):
        raise TypeError("prepared receivers cannot be persisted")

    def __repr__(self):
        return "PreparedReceiver(secrets=<redacted>, closed=%r)" % self._closed


def prepare_receiver(protocol, public, receiver, sender_id, *, rng=None):
    """Run and validate a real Derive before constructing an explicit session.

    Only the known plain and Suite-bound protocol classes are supported, so subclass-specific
    authentication checks cannot be silently dropped by cloning the protocol.
    """
    from ibme.assembly import _Baseline, _Byteauth

    if type(protocol) not in (BaselineIBME, ByteAuthenticatedIBME, _Baseline, _Byteauth):
        raise TypeError("prepared receiver requires an exact supported protocol class")
    if type(public) is not PublicKey or type(receiver) is not ReceiverKey:
        raise TypeError("IBME public and receiver keys required")
    sender = validate_identity(sender_id, name="sender_id")
    backend = protocol.hibe_backend
    binding = getattr(backend, "validate_key_binding", None)
    if not callable(binding) or binding(public.hpk, receiver.level1_key) is not True:
        raise InvalidParameterError("prepared receiver public/root binding failed")
    leaf = backend.derive(receiver.level1_key, sender, rng=rng)
    if (getattr(leaf, "parent_identity", None) != receiver.identity
            or getattr(leaf, "child_identity", None) != sender):
        raise InvalidParameterError("prepared receiver derived path mismatch")
    if binding(public.hpk, leaf) is not True:
        raise InvalidParameterError("prepared receiver leaf public/root binding failed")
    leaf_bytes = len(leaf.to_bytes())
    pinned = _PinnedDerivation(backend, receiver.level1_key, sender, leaf)
    clone = type(protocol)(pinned, protocol.ibs_backend)
    if type(protocol) in (_Baseline, _Byteauth):
        clone._bind(protocol._runtime)  # Keep every existing Suite input/profile guard.
    return PreparedReceiver(clone, public, receiver, sender, pinned, leaf_bytes)
