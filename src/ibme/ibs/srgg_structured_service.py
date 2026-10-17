"""Fail-closed fixed issuance for the opt-in structured SRGG backend.

Reuses the audited local lock/pending/fsync/replace machinery of the legacy
SRGG issuer. Its schema and crypto objects are separate. Cooperating local
writers and trusted plaintext snapshots only; no rollback protection.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from math import isqrt
import os
import stat

from ibme.core.types import validate_identity
from ibme.ibs import srgg_service as storage
from experiments.research.candidates.srgg import structured_backend as api
from experiments.research.candidates.srgg.structured_execution import ExecutionParams, SCHEMA as PUBLIC_SCHEMA


IssuerStateError = storage.IssuerStateError
IssuerPendingError = storage.IssuerPendingError
IssuerCapacityError = storage.IssuerCapacityError
MAX_STATE_BYTES = storage.MAX_STATE_BYTES


def _preflight(params, max_users):
    """Conservative byte envelope, before entropy or directory mutation."""
    if type(params) is not ExecutionParams:
        raise TypeError("complete structured ExecutionParams required")
    if type(max_users) is not int or not 1 <= max_users <= api.MAX_USERS:
        raise ValueError("structured issuer capacity must be in 1..64")
    p = params
    try:
        worst_public = api._encode({"schema": PUBLIC_SCHEMA, "params": asdict(p),
            "seed": bytes(32).hex(),
            "b": (((p.modulus-1,)*p.degree,)*(p.rank*p.digits),)*p.rank})
        worst_tail = ((-isqrt(p.user_norm_cap),)*p.degree,)*((1+p.digits)*p.rank)
        entries = [[(bytes([i])+b"x"*4095).hex(), "issued", worst_tail] for i in range(max_users)]
        master = api._encode(api._record("master", public=worst_public.hex(),
            witness=(((-1,)*p.degree,)*(p.rank*p.digits),)*(2*p.rank), entries=entries))
        envelope = api._encode(api._record("issuer", status="ready", max_users=max_users,
                                            master=master.hex()))
    except Exception as exc:
        raise IssuerCapacityError("structured issuer byte envelope exceeds capacity") from exc
    if len(envelope) > MAX_STATE_BYTES:
        raise IssuerCapacityError("structured issuer byte envelope exceeds capacity")
    return len(envelope)


@dataclass(repr=False)
class _Snapshot:
    master: api.MasterSecret
    max_users: int
    status: str = "ready"

    def to_bytes(self):
        if type(self.max_users) is not int or not 1 <= self.max_users <= api.MAX_USERS:
            raise IssuerStateError("invalid structured issuer capacity")
        if type(self.status) is not str or self.status not in ("ready", "failed"):
            raise IssuerStateError("invalid structured issuer status")
        if len(self.master.states) > self.max_users:
            raise IssuerCapacityError("structured issuer cache exceeds capacity")
        return api._encode(api._record("issuer", status=self.status,
            max_users=self.max_users, master=self.master.to_bytes().hex()))

    @classmethod
    def from_bytes(cls, data):
        try:
            record = api._envelope(data, "issuer", ("status", "max_users", "master"))
            if record["status"] != "ready":
                raise IssuerPendingError("structured issuer failed; automatic retry blocked")
            capacity = record["max_users"]
            if type(capacity) is not int or not 1 <= capacity <= api.MAX_USERS:
                raise ValueError("invalid issuer capacity")
            master = api.MasterSecret.from_bytes(api._hex(record["master"]))
            _preflight(master.public_key.params, capacity)
            if len(master.states) > capacity:
                raise ValueError("cache exceeds capacity")
            if any(status != "issued" for status, _key in master.states.values()):
                raise IssuerPendingError("structured issuer unfinished; automatic retry blocked")
            result = cls(master, capacity)
            if result.to_bytes() != data:
                raise ValueError("issuer snapshot changed")
            return result
        except IssuerPendingError:
            raise
        except Exception:
            raise IssuerStateError("invalid structured SRGG issuer snapshot") from None


class FixedIssuer(storage.FixedIssuer):
    """Same local transaction discipline, opt-in structured object schema."""

    def __init__(self, path, backend=None, *, expected_public=None, expected_params=None):
        if expected_public is not None and type(expected_public) is not api.PublicKey:
            raise TypeError("expected structured PublicKey required")
        if expected_params is not None and type(expected_params) is not ExecutionParams:
            raise TypeError("expected complete structured parameters required")
        super().__init__(path, backend=api.Backend() if backend is None else backend)
        self.expected_public, self.expected_params = expected_public, expected_params

    def _check_expected(self, public):
        if self.expected_public is not None and public.to_bytes() != self.expected_public.to_bytes():
            raise IssuerStateError("structured issuer differs from expected public key")
        if self.expected_params is not None and public.params != self.expected_params:
            raise IssuerStateError("structured issuer differs from expected parameters")

    def _load(self):
        self._check_pending()
        path = self.path/storage.STATE_FILE
        info = storage._plain_file(path)
        if not 0 < info.st_size <= MAX_STATE_BYTES:
            raise IssuerStateError("structured issuer snapshot size out of bounds")
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(os.open(path, flags), "rb") as handle:
            actual = os.fstat(handle.fileno())
            if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or actual.st_size != info.st_size:
                raise IssuerStateError("structured issuer snapshot changed during open")
            data = handle.read(info.st_size+1)
        if len(data) != info.st_size:
            raise IssuerStateError("structured issuer snapshot changed during read")
        snapshot = _Snapshot.from_bytes(data)
        self._check_expected(snapshot.master.public_key)
        return snapshot

    def initialize(self, params, *, max_users=2):
        _preflight(params, max_users)
        if self.expected_params is not None and params != self.expected_params:
            raise IssuerStateError("structured initialization parameters mismatch")
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
                if (type(public) is not api.PublicKey or type(master) is not api.MasterSecret
                        or public.params != params or master.public_key != public or master.states):
                    raise IssuerStateError("inconsistent structured setup objects")
                snapshot = _Snapshot(api.MasterSecret.from_bytes(master.to_bytes()), max_users)
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
                raise IssuerPendingError("structured identity unfinished; automatic retry blocked")
            if len(snapshot.master.states) >= snapshot.max_users:
                raise IssuerCapacityError("structured issuer identity capacity exhausted")
            self._begin()
            snapshot.master.states[identity] = ("pending", None)
            try:
                self._atomic_write(snapshot.to_bytes())
                issued = {value: entry for value, entry in snapshot.master.states.items()
                          if entry[0] == "issued"}
                working = api.MasterSecret(public, snapshot.master.witness, issued)
                key = self.backend.key_extract(working, identity)
                if type(key) is not api.SigningKey or key.identity != identity or key.public_key != public:
                    raise IssuerStateError("inconsistent structured issued key")
                key = api.SigningKey.from_bytes(key.to_bytes())
                snapshot.master.states[identity] = ("issued", key)
                self._atomic_write(snapshot.to_bytes())
                self._finish()
                return key
            except BaseException:
                snapshot.master.states[identity] = ("failed", None)
                self._block(snapshot)
                raise


__all__ = ["FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerCapacityError"]
