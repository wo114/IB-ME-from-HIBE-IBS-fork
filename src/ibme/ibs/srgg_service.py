"""Persistent fixed issuance for the existing SRGG research backend.

``FixedIssuer`` adds a bounded, local ledger around the unchanged SRGG
``Backend.key_extract``.  A successful identity is reused after process
restart.  A pending or failed transaction blocks the issuer instead of
silently sampling another key.  The snapshot is trusted plaintext and this
module establishes no security reduction or security level.

The raw SRGG backend keeps its in-memory cache semantics.  The service writes
the pending state first, then invokes the raw extractor on a working master
copy that contains only already-issued identities; this is necessary because
the raw backend deliberately refuses to extract an identity already marked
pending.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import stat
import tempfile

from ibme.cli_state import LOCK_FILE, key_issuance_lock
from ibme.core.errors import IBMEError
from ibme.core.types import validate_identity
from experiments.research.candidates.srgg.backend import Backend
from experiments.research.candidates.srgg.config import Config
from experiments.research.candidates.srgg.objects import (
    MAX_WIRE,
    MasterSecret,
    PublicKey,
    SigningKey,
    decode,
    encode,
    unhex,
)


STATE_FILE = "master.bin"
PENDING_FILE = "master.bin.pending"
MAX_STATE_BYTES = MAX_WIRE
MAX_USERS = 64
_PENDING_CONTENT = b"IBME:SRGG:ISSUER-PENDING:v1\n"
_FIELDS = ("version", "status", "context", "max_users", "master", "entries")


class IssuerStateError(IBMEError):
    """The private SRGG issuer directory or snapshot is invalid."""


class IssuerPendingError(IBMEError):
    """An unconfirmed transaction blocks automatic retry or reissuance."""


class IssuerCapacityError(IssuerStateError):
    """The bounded SRGG issuer ledger has no remaining capacity."""


def _zero_poly(degree: int) -> tuple[int, ...]:
    return (0,) * degree


def _zero_matrix(rows: int, cols: int, degree: int) -> tuple:
    poly = _zero_poly(degree)
    return tuple(tuple(poly for _ in range(cols)) for _ in range(rows))


def _zero_vector(count: int, degree: int) -> tuple:
    poly = _zero_poly(degree)
    return tuple(poly for _ in range(count))


def _preflight(params: Config, max_users: int) -> int:
    """Bound the whole canonical snapshot before filesystem or entropy use."""

    if type(params) is not Config:
        raise TypeError("exact SRGG Config required")
    if type(max_users) is not int or not 1 <= max_users <= MAX_USERS:
        raise ValueError("max_users must be an integer in 1..64")
    if max_users > params.max_users:
        raise ValueError("issuer capacity cannot exceed the SRGG backend identity capacity")

    p = params.algebra
    zero_b = _zero_matrix(p.rank, p.rank * p.digits, p.degree)
    public_raw = PublicKey(params, b"\0" * 32, zero_b).to_bytes()
    zero_r = _zero_matrix(2 * p.rank, p.rank * p.digits, p.degree)
    zero_tail = _zero_vector((1 + p.digits) * p.rank, p.degree)

    # Use distinct maximum-length identities so the estimate covers the
    # canonical map and every issued key without constructing a secret key.
    identities = {
        (bytes((index,)) + b"x" * (params.identity_max_bytes - 1)).hex(): {
            "status": "issued",
            "key": encode("SK", {
                "pk": public_raw.hex(),
                "identity": (bytes((index,)) + b"x" * (params.identity_max_bytes - 1)).hex(),
                "tail": zero_tail,
            }).hex(),
        }
        for index in range(max_users)
    }
    master_raw = encode("MSK", {"pk": public_raw.hex(), "r": zero_r, "states": identities})
    entries = [
        {"identity": identity, "status": "issued", "key": row["key"]}
        for identity, row in sorted(identities.items())
    ]
    try:
        raw = encode("ISSUER", {
            "version": 1,
            "status": "ready",
            "context": sha256(public_raw).hexdigest(),
            "max_users": max_users,
            "master": master_raw.hex(),
            "entries": entries,
        })
    except ValueError as error:
        raise IssuerCapacityError(
            "advertised SRGG issuer capacity exceeds the bounded snapshot"
        ) from error
    if len(raw) > MAX_STATE_BYTES:
        raise IssuerCapacityError("advertised SRGG issuer capacity exceeds the bounded snapshot")
    return len(raw)


@dataclass(repr=False)
class _Snapshot:
    master: MasterSecret
    max_users: int
    status: str = "ready"

    def to_bytes(self) -> bytes:
        entries = []
        for identity, (status, key) in sorted(self.master.states.items()):
            entries.append({
                "identity": identity.hex(),
                "status": status,
                "key": key.to_bytes().hex() if key is not None else None,
            })
        return encode("ISSUER", {
            "version": 1,
            "status": self.status,
            "context": self.master.public_key.context.hex(),
            "max_users": self.max_users,
            "master": self.master.to_bytes().hex(),
            "entries": entries,
        })

    @classmethod
    def from_bytes(cls, raw: bytes) -> "_Snapshot":
        record = decode("ISSUER", raw, _FIELDS)
        try:
            if type(record["version"]) is not int or record["version"] != 1:
                raise ValueError("unsupported issuer state version")
            if type(record["status"]) is not str or record["status"] not in ("ready", "failed"):
                raise ValueError("invalid issuer transaction status")
            count = record["max_users"]
            if type(count) is not int or not 1 <= count <= MAX_USERS:
                raise ValueError("invalid issuer capacity")
            context = unhex(record["context"])
            if len(context) != 32:
                raise ValueError("invalid public context")
            rows = record["entries"]
            if type(rows) is not list or len(rows) > count:
                raise ValueError("issuer ledger exceeds capacity")

            previous = None
            decoded_rows = []
            for row in rows:
                if type(row) is not dict or set(row) != {"identity", "status", "key"}:
                    raise ValueError("invalid ledger fields")
                identity = validate_identity(unhex(row["identity"]), max_bytes=4096)
                if previous is not None and identity <= previous:
                    raise ValueError("duplicate or unsorted ledger identity")
                previous = identity
                status = row["status"]
                if type(status) is not str or status not in ("pending", "failed", "issued"):
                    raise ValueError("invalid ledger status")
                if status == "issued":
                    key_raw = unhex(row["key"])
                    if not key_raw:
                        raise ValueError("issued key required")
                elif row["key"] is not None:
                    raise ValueError("unissued entries cannot contain a key")
                else:
                    key_raw = None
                decoded_rows.append((identity, status, key_raw))

            if record["status"] != "ready" or any(status != "issued" for _, status, _ in decoded_rows):
                raise IssuerPendingError("SRGG issuer ledger is unfinished; automatic retry is blocked")

            master_raw = unhex(record["master"])
            master_record = decode("MSK", master_raw, ("pk", "r", "states"))
            public_raw = unhex(master_record["pk"])
            public_record = decode("PK", public_raw, ("config", "seed", "b"))
            params = Config.from_record(public_record["config"])
            _preflight(params, count)
            if sha256(public_raw).digest() != context:
                raise ValueError("issuer public context mismatch")
            for identity, _, key_raw in decoded_rows:
                validate_identity(identity, max_bytes=params.identity_max_bytes)
                key_record = decode("SK", key_raw, ("pk", "identity", "tail"))
                if key_record["pk"] != master_record["pk"] or unhex(key_record["identity"]) != identity:
                    raise ValueError("issued key identity or public context mismatch")

            # The master wire repeats the issuer cache.  Check its public
            # schema and exact key bytes before reconstructing private
            # matrices, so a cheap ledger mismatch cannot force a costly
            # private decode.
            master_states = master_record["states"]
            row_ids = {identity.hex() for identity, _, _ in decoded_rows}
            if type(master_states) is not dict or set(master_states) != row_ids:
                raise ValueError("master/ledger identity schema mismatch")
            row_map = {identity.hex(): (status, key_raw) for identity, status, key_raw in decoded_rows}
            for identity_hex, entry in master_states.items():
                if type(entry) is not dict or set(entry) != {"status", "key"}:
                    raise ValueError("master state schema mismatch")
                status, key_raw = row_map[identity_hex]
                if entry["status"] != status or entry["key"] != key_raw.hex():
                    raise ValueError("master/ledger key state mismatch")

            # Only after cheap schema, capacity, and public-context checks do
            # we reconstruct the private root and issued keys.
            master = MasterSecret.from_bytes(master_raw)
            if master.public_key.to_bytes() != public_raw:
                raise ValueError("master/public mismatch")
            expected = {identity: (status, None) for identity, status, _ in decoded_rows}
            for identity, status, key_raw in decoded_rows:
                key = SigningKey.from_bytes(key_raw)
                if key.identity != identity or key.public_key.to_bytes() != public_raw:
                    raise ValueError("issued key binding mismatch")
                expected[identity] = (status, key)
            if set(master.states) != set(expected):
                raise ValueError("master/ledger identity mismatch")
            if any(master.states[identity][0] != status for identity, (status, _) in expected.items()):
                raise ValueError("master/ledger status mismatch")
            if any(master.states[identity][1] is None for identity in expected):
                raise ValueError("issued key missing from master state")
            result = cls(master, count, record["status"])
            if result.to_bytes() != bytes(raw):
                raise ValueError("noncanonical issuer snapshot")
            return result
        except IssuerPendingError:
            raise
        except Exception:
            # Do not expose parser details or private state in public errors.
            raise IssuerStateError("invalid SRGG issuer snapshot") from None


def _plain_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
        raise IssuerStateError("issuer files must be ordinary files with one link")
    return info


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FixedIssuer:
    """A local cooperating-writer SRGG issuer with fail-closed recovery."""

    def __init__(self, path, backend: Backend | None = None):
        raw = os.fspath(path)
        if type(raw) is not str or not raw.strip():
            raise ValueError("issuer path must be a nonempty directory path")
        self.path = Path(os.path.abspath(raw))
        if self.path == self.path.parent:
            raise ValueError("a filesystem root cannot be an issuer directory")
        self.backend = Backend() if backend is None else backend

    def _directory(self, *, create=False):
        if create:
            if not os.path.lexists(self.path):
                self.path.mkdir(mode=0o700, parents=False, exist_ok=False)
        info = self.path.lstat()
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise IssuerStateError("issuer path must be an ordinary directory")

    def _check_pending(self):
        if os.path.lexists(self.path / PENDING_FILE):
            raise IssuerPendingError("SRGG issuer pending; automatic retry is blocked; private review required")

    def _check_empty(self):
        self._check_pending()
        if any(entry.name != LOCK_FILE for entry in self.path.iterdir()):
            raise FileExistsError("issuer initialization requires an empty directory")

    @contextmanager
    def _locked(self):
        self._directory()
        if os.path.lexists(self.path / LOCK_FILE):
            _plain_file(self.path / LOCK_FILE)
        with key_issuance_lock(self.path):
            yield

    def _begin(self):
        self._check_pending()
        descriptor = os.open(self.path / PENDING_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_PENDING_CONTENT)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(self.path)

    def _finish(self):
        try:
            (self.path / PENDING_FILE).unlink()
            _sync_directory(self.path)
        except BaseException:
            try:
                if not os.path.lexists(self.path / PENDING_FILE):
                    self._begin()
            except BaseException:
                pass
            raise

    def _block(self, snapshot=None):
        try:
            if not os.path.lexists(self.path / PENDING_FILE):
                self._begin()
        except BaseException:
            pass
        if snapshot is not None:
            snapshot.status = "failed"
            try:
                self._atomic_write(snapshot.to_bytes())
            except BaseException:
                pass

    def _atomic_write(self, raw: bytes):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_STATE_BYTES:
            raise IssuerStateError("issuer snapshot exceeds the bounded byte format")
        target = self.path / STATE_FILE
        if os.path.lexists(target):
            _plain_file(target)
        descriptor, name = tempfile.mkstemp(dir=self.path, prefix=".srgg-", suffix=".tmp")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            _sync_directory(self.path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _load(self) -> _Snapshot:
        self._check_pending()
        path = self.path / STATE_FILE
        info = _plain_file(path)
        if not 0 < info.st_size <= MAX_STATE_BYTES:
            raise IssuerStateError("issuer snapshot is empty or exceeds the size limit")
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not 0 < info.st_size <= MAX_STATE_BYTES):
                raise IssuerStateError("issuer snapshot is not a bounded ordinary file")
            raw = handle.read(info.st_size + 1)
        if len(raw) != info.st_size:
            raise IssuerStateError("issuer snapshot size changed during the bounded read")
        try:
            return _Snapshot.from_bytes(raw)
        except IssuerPendingError:
            raise
        except Exception:
            raise IssuerStateError("issuer snapshot is invalid") from None

    def _existing(self):
        self._directory()
        if not os.path.lexists(self.path / STATE_FILE):
            self._check_pending()
            raise IssuerStateError("issuer has not been initialized")

    def initialize(self, params: Config, *, max_users: int = 16) -> PublicKey:
        _preflight(params, max_users)
        self._directory(create=True)
        self._check_empty()
        with self._locked():
            self._check_empty()
            snapshot = None
            try:
                self._begin()
                public, master = self.backend.setup(params)
                if (not isinstance(public, PublicKey) or not isinstance(master, MasterSecret)
                        or public.config != params or public.to_bytes() != master.public_key.to_bytes()
                        or master.states):
                    raise IssuerStateError("setup returned inconsistent SRGG objects")
                snapshot = _Snapshot(MasterSecret.from_bytes(master.to_bytes()), max_users)
                self._atomic_write(snapshot.to_bytes())
                self._finish()
                return public
            except BaseException:
                self._block(snapshot)
                raise

    def public_key(self) -> PublicKey:
        self._existing()
        with self._locked():
            return self._load().master.public_key

    def key_extract(self, identity: bytes) -> SigningKey:
        identity = validate_identity(identity, max_bytes=4096)
        self._existing()
        with self._locked():
            snapshot = self._load()
            public = snapshot.master.public_key
            identity = validate_identity(identity, max_bytes=public.config.identity_max_bytes)
            cached = snapshot.master.states.get(identity)
            if cached is not None:
                status, key = cached
                if status == "issued":
                    return key
                raise IssuerPendingError("SRGG identity issuance is unfinished; automatic retry is blocked")
            if len(snapshot.master.states) >= snapshot.max_users:
                raise IssuerCapacityError("fixed issuer identity capacity exhausted")

            self._begin()
            snapshot.master.states[identity] = ("pending", None)
            try:
                self._atomic_write(snapshot.to_bytes())
                # The raw backend sees its own in-memory cache.  Exclude only
                # this pending identity so it can perform one genuine extract;
                # already-issued identities still count toward max_users.
                issued = {
                    value: entry for value, entry in snapshot.master.states.items()
                    if entry[0] == "issued"
                }
                working = MasterSecret(snapshot.master.public_key, snapshot.master.r, issued)
                key = self.backend.key_extract(working, identity)
                if (not isinstance(key, SigningKey) or key.identity != identity
                        or key.public_key.to_bytes() != public.to_bytes()):
                    raise IssuerStateError("extraction returned an inconsistent SRGG key")
                key = SigningKey.from_bytes(key.to_bytes())
                snapshot.master.states[identity] = ("issued", key)
                self._atomic_write(snapshot.to_bytes())
                self._finish()
                return key
            except BaseException:
                snapshot.master.states[identity] = ("failed", None)
                self._block(snapshot)
                raise


__all__ = ["FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerCapacityError"]
