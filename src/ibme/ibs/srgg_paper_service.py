"""Persistent fixed issuance for the separate literal SRGG paper baseline.

Uses the existing local lock, pending marker, fsync and atomic replacement.
Snapshots are trusted plaintext for cooperating local writers; there is no
rollback or malicious-storage protection. No security level is established.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from math import isfinite
import os
import stat
from time import monotonic

from ibme.cli_state import StateBusyError
from ibme.core.types import validate_identity
from ibme.ibs import srgg_service as storage
from experiments.research.candidates.srgg import paper_objects as objects
from experiments.research.candidates.srgg.paper_parameters import PaperParams

IssuerStateError = storage.IssuerStateError
IssuerPendingError = storage.IssuerPendingError
IssuerCapacityError = storage.IssuerCapacityError
MAX_STATE_BYTES = storage.MAX_STATE_BYTES


def _preflight(params, max_users):
    """Bound every admitted 256-bit coordinate before entropy or path mutation.

    This is an encoding bound, not a sampled key or a probabilistic norm bound.
    Count repeated cache entries arithmetically to avoid allocating a whole
    impossible snapshot. Nested public/master hex expansion is counted twice.
    """
    if type(params) is not PaperParams:
        raise TypeError("complete published PaperParams required")
    if type(max_users) is not int or not 1 <= max_users <= objects.MAX_USERS:
        raise ValueError("paper issuer capacity must be an integer in 1..64")
    p = params
    try:
        public = objects._encode(objects._record("public", params=p.record(),
            seed=bytes(32).hex(),
            b=(((p.modulus-1,)*p.degree,)*(p.rank*p.digits),)*p.rank))
        tail = ((-(2**256-1),)*p.degree,)*((1+p.digits)*p.rank)
        entry = objects._encode([(b"x"*4096).hex(), "issued", tail])
        master = objects._encode(objects._record("master", public=public.hex(),
            witness=(((-1,)*p.degree,)*(p.rank*p.digits),)*(2*p.rank), entries=[]))
        master_length = len(master)+max_users*len(entry)+max_users-1
        outer = objects._encode(objects._record("issuer", status="failed",
            max_users=max_users, master=""))
        envelope_length = len(outer)+2*master_length
    except Exception as error:
        raise IssuerCapacityError("paper issuer byte envelope exceeds capacity") from error
    if master_length > objects.MAX_WIRE or envelope_length > MAX_STATE_BYTES:
        raise IssuerCapacityError("paper issuer byte envelope exceeds capacity")
    return envelope_length


@dataclass(repr=False)
class _Snapshot:
    master: objects.MasterSecret
    max_users: int
    status: str = "ready"

    def to_bytes(self):
        if type(self.max_users) is not int or not 1 <= self.max_users <= objects.MAX_USERS:
            raise IssuerStateError("invalid paper issuer capacity")
        if type(self.status) is not str or self.status not in ("ready", "failed"):
            raise IssuerStateError("invalid paper issuer status")
        if len(self.master.states) > self.max_users:
            raise IssuerCapacityError("paper issuer cache exceeds capacity")
        return objects._encode(objects._record("issuer", status=self.status,
            max_users=self.max_users, master=self.master.to_bytes().hex()))

    @classmethod
    def from_bytes(cls, data):
        try:
            record = objects._envelope(data, "issuer", ("status", "max_users", "master"))
            if record["status"] != "ready":
                raise IssuerPendingError("paper issuer failed; automatic retry blocked")
            count = record["max_users"]
            if type(count) is not int or not 1 <= count <= objects.MAX_USERS:
                raise ValueError("invalid issuer capacity")
            master = objects.MasterSecret.from_bytes(objects._hex(record["master"]))
            _preflight(master.public_key.params, count)
            if len(master.states) > count:
                raise ValueError("cache exceeds capacity")
            if any(status != "issued" for status, _key in master.states.values()):
                raise IssuerPendingError("paper issuer unfinished; automatic retry blocked")
            result = cls(master, count)
            if result.to_bytes() != data:
                raise ValueError("issuer snapshot changed")
            return result
        except IssuerPendingError:
            raise
        except Exception:
            raise IssuerStateError("invalid paper SRGG issuer snapshot") from None


class FixedIssuer(storage.FixedIssuer):
    """One persisted key per identity under the literal paper object namespace."""

    def __init__(self, path, backend=None, *, expected_public=None, expected_params=None,
                 lock_timeout=300):
        if expected_public is not None and type(expected_public) is not objects.PublicKey:
            raise TypeError("expected paper PublicKey required")
        if expected_params is not None and type(expected_params) is not PaperParams:
            raise TypeError("expected complete paper parameters required")
        if (type(lock_timeout) not in (int, float) or not isfinite(lock_timeout)
                or not 0 <= lock_timeout <= 3600):
            raise ValueError("paper lock timeout must be finite and in 0..3600 seconds")
        if backend is None:
            from experiments.research.candidates.srgg.paper_schur_backend import SourceSchurBackend
            backend = SourceSchurBackend()
        super().__init__(path, backend=backend)
        self.expected_public, self.expected_params = expected_public, expected_params
        self.lock_timeout = lock_timeout

    @contextmanager
    def _locked(self):
        """Extend acquisition waiting only; a locked transaction is never retried.

        The unchanged storage lock allows at most 30 seconds per acquisition.
        Its busy timeout chains the OS locking error; reentry has no OS cause
        and is propagated immediately. No private lock state is inspected.
        """
        self._directory()
        if os.path.lexists(self.path/storage.LOCK_FILE):
            storage._plain_file(self.path/storage.LOCK_FILE)
        deadline = monotonic()+self.lock_timeout
        with ExitStack() as held:
            while True:
                try:
                    held.enter_context(storage.key_issuance_lock(self.path,
                        timeout=min(30, max(0, deadline-monotonic()))))
                    break
                except StateBusyError as error:
                    if not isinstance(error.__cause__, OSError) or monotonic() >= deadline:
                        raise
            yield

    def _check_expected(self, public):
        if self.expected_public is not None and public.to_bytes() != self.expected_public.to_bytes():
            raise IssuerStateError("paper issuer differs from expected public key")
        if self.expected_params is not None and public.params != self.expected_params:
            raise IssuerStateError("paper issuer differs from expected parameters")

    def _load(self):
        self._check_pending()
        path = self.path/storage.STATE_FILE
        info = storage._plain_file(path)
        if not 0 < info.st_size <= MAX_STATE_BYTES:
            raise IssuerStateError("paper issuer snapshot size out of bounds")
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(os.open(path, flags), "rb") as handle:
            actual = os.fstat(handle.fileno())
            if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or actual.st_size != info.st_size:
                raise IssuerStateError("paper issuer snapshot changed during open")
            data = handle.read(info.st_size+1)
        if len(data) != info.st_size:
            raise IssuerStateError("paper issuer snapshot changed during read")
        snapshot = _Snapshot.from_bytes(data)
        self._check_expected(snapshot.master.public_key)
        return snapshot

    def initialize(self, params, *, max_users=1):
        _preflight(params, max_users)
        if self.expected_params is not None and params != self.expected_params:
            raise IssuerStateError("paper initialization parameters mismatch")
        if self.expected_public is not None:
            raise IssuerStateError("expected public is for reopening, not a new root")
        self._directory(create=True)
        self._check_empty()
        with self._locked():
            self._check_empty()
            snapshot = None
            try:
                self._begin()
                public, master = self.backend.setup(params)
                if (type(public) is not objects.PublicKey or type(master) is not objects.MasterSecret
                        or public.params != params or master.public_key != public or master.states):
                    raise IssuerStateError("inconsistent paper setup objects")
                snapshot = _Snapshot(objects.MasterSecret.from_bytes(master.to_bytes()), max_users)
                self._atomic_write(snapshot.to_bytes())
                self._finish()
                return public
            except BaseException:
                self._block(snapshot)
                raise

    def key_extract(self, identity):
        identity = validate_identity(identity, max_bytes=4096)
        self._existing()
        with self._locked():
            snapshot = self._load()
            public = snapshot.master.public_key
            cached = snapshot.master.states.get(identity)
            if cached is not None:
                status, key = cached
                if status == "issued":
                    return key
                raise IssuerPendingError("paper identity unfinished; automatic retry blocked")
            if len(snapshot.master.states) >= snapshot.max_users:
                raise IssuerCapacityError("paper issuer identity capacity exhausted")
            self._begin()
            snapshot.master.states[identity] = ("pending", None)
            try:
                self._atomic_write(snapshot.to_bytes())
                issued = {value: entry for value, entry in snapshot.master.states.items()
                          if entry[0] == "issued"}
                working = objects.MasterSecret(public, snapshot.master.witness, issued)
                key = self.backend.key_extract(working, identity)
                if (type(key) is not objects.SigningKey or key.identity != identity
                        or key.public_key != public):
                    raise IssuerStateError("inconsistent paper issued key")
                key = objects.SigningKey.from_bytes(key.to_bytes())
                snapshot.master.states[identity] = ("issued", key)
                self._atomic_write(snapshot.to_bytes())
                self._finish()
                return key
            except BaseException:
                snapshot.master.states[identity] = ("failed", None)
                self._block(snapshot)
                raise


__all__ = ["FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerCapacityError", "StateBusyError"]
