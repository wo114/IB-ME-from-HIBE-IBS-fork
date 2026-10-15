"""Persistent fixed issuance for the existing Wang--Pan--Wagner backend.

``FixedIssuer`` adds a bounded ledger around the *unchanged* raw KeyExt. A
successful identity keeps its original key and salt across process restarts.
New issuance reserves a pending marker AND ledger entry before raw sampling.
Uncertain completion blocks the issuer; there is no automatic resampling or
marker removal. Signatures still use the backend's fresh message randomness.

Private snapshots are PLAINTEXT. Use a dedicated private local directory,
outside Git, evidence packages and synchronized/shared storage. The permanent
same-OS lock and fsync requests cover local cooperating processes, not malicious
rollback/admin changes, pathname races, NFS, Windows/WSL mixed writers or a
hard-power-loss theorem. Windows directory fsync has no portable counterpart.
This module establishes no fixed-service security reduction or security level.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from math import isqrt
import os
from pathlib import Path
import stat
import tempfile

from ibme.cli_state import LOCK_FILE, key_issuance_lock
from ibme.core.errors import IBMEError
from ibme.core.types import validate_identity
from experiments.research.candidates.wang_pw.backend import Backend
from experiments.research.candidates.wang_pw.codec import (
    MAX_WIRE_BYTES, canonical, decode, encode, unhex,
)
from experiments.research.candidates.wang_pw.objects import (
    MasterSecret, PublicKey, SigningKey,
)
from experiments.research.candidates.wang_pw.params import Params


STATE_FILE = "master.bin"
PENDING_FILE = "master.bin.pending"
MAX_STATE_BYTES = MAX_WIRE_BYTES
MAX_USERS = 64
_PENDING_CONTENT = b"IBME:WangPW:ISSUER-PENDING:v1\n"
_FIELDS = ("version", "status", "context", "max_users", "master", "entries")


class IssuerStateError(IBMEError):
    """The private directory or bounded issuer snapshot is invalid."""


class IssuerPendingError(IBMEError):
    """Unconfirmed completion forbids automatic issuance or reissuance."""


class IssuerCapacityError(IssuerStateError):
    """The fixed public storage or identity capacity has been exhausted."""


def _matrix_size(rows: int, cols: int, digits: int) -> int:
    return 2 + rows * (2 + cols * digits + cols - 1) + rows - 1


def _preflight(params: Params, max_users: int) -> int:
    """Bound the WHOLE advertised ledger before filesystem changes or entropy.

    Only byte lengths are computed: no large hypothetical matrices/keys are
    allocated. Trapdoor coefficient magnitudes follow the existing norm gates.
    JSON hex nesting is included, not merely the raw integer payload.
    """
    if type(params) is not Params:
        raise TypeError("exact WangPW Params required")
    if type(max_users) is not int or not 1 <= max_users <= MAX_USERS:
        raise ValueError("max_users must be an integer in 1..64")
    pk_size = len(encode("PK", {"params": params.record(), "a": []})) - 2
    pk_size += _matrix_size(params.n, params.m, len(str(params.q - 1)))
    master_size = len(encode("MSK", {"pk": "", "trapdoor": []})) - 2
    master_size += 2 * pk_size + _matrix_size(
        params.m_bar, params.w, len(str(isqrt(params.master_quality))) + 1,
    )
    key_size = len(encode("SK", {"pk": "", "identity": "", "identity_salt": "", "trapdoor": []})) - 2
    key_size += 2 * pk_size + 2 * (params.identity_max_bytes + params.salt_bytes)
    key_size += _matrix_size(params.m, params.w, len(str(isqrt(params.user_quality))) + 1)
    entry_size = len(canonical({"identity": "", "status": "issued", "key": ""}))
    entry_size += 2 * (params.identity_max_bytes + key_size)
    base_size = len(encode("ISSUER", {"version": 1, "status": "failed", "context": "0" * 64,
        "max_users": max_users, "master": "", "entries": []}))
    total = base_size + 2 * master_size + max_users * entry_size + max_users - 1
    if total > MAX_STATE_BYTES:
        raise IssuerCapacityError("advertised issuer capacity exceeds the bounded snapshot format")
    return total


@dataclass(repr=False)
class _Snapshot:
    master: MasterSecret = field(repr=False)
    max_users: int
    entries: dict = field(default_factory=dict, repr=False)
    status: str = "ready"

    def to_bytes(self) -> bytes:
        return encode("ISSUER", {"version": 1, "status": self.status, "context": self.master.public_key.context.hex(),
            "max_users": self.max_users, "master": self.master.to_bytes().hex(),
            "entries": [{"identity": identity.hex(), "status": status,
                "key": key.to_bytes().hex() if key is not None else None}
                for identity, (status, key) in sorted(self.entries.items())]})

    @classmethod
    def from_bytes(cls, raw):
        record = decode("ISSUER", raw, _FIELDS)
        try:
            if type(record["version"]) is not int or record["version"] != 1:
                raise ValueError("unsupported issuer state version")
            if type(record["status"]) is not str or record["status"] not in ("ready", "failed"):
                raise ValueError("invalid issuer transaction status")
            count = record["max_users"]
            if type(count) is not int or not 1 <= count <= MAX_USERS:
                raise ValueError("invalid issuer capacity")
            rows = record["entries"]
            if type(rows) is not list or len(rows) > count:
                raise ValueError("issuer ledger exceeds capacity")
            context = unhex(record["context"])
            if len(context) != 32:
                raise ValueError("invalid public context")
            # Validate cheap ledger structure before parsing trapdoors.
            previous, decoded = None, []
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
                else:
                    if row["key"] is not None:
                        raise ValueError("unissued entries cannot contain a key")
                    key_raw = None
                decoded.append((identity, status, key_raw))
            if record["status"] != "ready" or any(status != "issued" for _, status, _ in decoded):
                raise IssuerPendingError("WangPW issuer ledger is unfinished; automatic retry is blocked")
            master_raw = unhex(record["master"])
            master_record = decode("MSK", master_raw, ("pk", "trapdoor"))
            public_raw = unhex(master_record["pk"])
            public_record = decode("PK", public_raw, ("params", "a"))
            params = Params.from_record(public_record["params"])
            _preflight(params, count)
            if sha256(public_raw).digest() != context:
                raise ValueError("issuer public context mismatch")
            for identity, _, key_raw in decoded:
                validate_identity(identity, max_bytes=params.identity_max_bytes)
                key_record = decode("SK", key_raw, ("pk", "identity", "identity_salt", "trapdoor"))
                if key_record["pk"] != master_record["pk"] or unhex(key_record["identity"]) != identity:
                    raise ValueError("issued key identity or full public context mismatch")
            # All inexpensive state/context/capacity checks precede private
            # trapdoor reconstruction, including checks on every issued entry.
            master = MasterSecret.from_bytes(master_raw)
            public = master.public_key
            result = cls(master, count)
            for identity, status, key_raw in decoded:
                validate_identity(identity, max_bytes=public.params.identity_max_bytes)
                key = SigningKey.from_bytes(key_raw) if key_raw is not None else None
                if key is not None and (key.identity != identity or key.public_key.to_bytes() != public.to_bytes()):
                    raise ValueError("issued key identity or full public context mismatch")
                result.entries[identity] = (status, key)
            if result.to_bytes() != bytes(raw):
                raise ValueError("noncanonical issuer snapshot")
            return result
        except IssuerPendingError:
            raise
        except Exception:
            # Never forward parser messages that could contain private state.
            raise IssuerStateError("invalid WangPW issuer snapshot") from None


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
    """One private local directory and a permanent cooperating-writer lock.

    The directory's parent must exist. Initialization accepts an empty final
    directory or creates it; existing state/unrelated files are not overwritten.
    A pending marker or ledger tombstone blocks all reads/issuance. Backup and
    rollback protection are outside this interface. The supplied backend is a
    trusted dependency, whose outputs are still checked before publication.
    """

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
            try:
                self.path.mkdir(mode=0o700)
            except FileExistsError:
                pass
        info = self.path.lstat()
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise IssuerStateError("issuer path must be an ordinary directory")

    def _check_pending(self):
        if os.path.lexists(self.path / PENDING_FILE):
            raise IssuerPendingError("WangPW issuer pending; automatic retry is blocked; private review required")

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
                pass  # The outer transaction independently saves FAILED state.
            raise

    def _block(self, snapshot=None):
        # Try both persistence channels independently: inability to create a
        # marker must not skip a still-writable FAILED ledger, or vice versa.
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
        descriptor, name = tempfile.mkstemp(dir=self.path, prefix=".wang-pw-", suffix=".tmp")
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
            result = _Snapshot.from_bytes(raw)
        except IssuerPendingError:
            raise
        except Exception:
            raise IssuerStateError("issuer snapshot is invalid") from None
        return result

    def _existing(self):
        self._directory()
        if not os.path.lexists(self.path / STATE_FILE):
            self._check_pending()
            raise IssuerStateError("issuer has not been initialized")

    def initialize(self, params: Params, *, max_users: int = 16) -> PublicKey:
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
                        or public.params != params or public.to_bytes() != master.public_key.to_bytes()):
                    raise IssuerStateError("setup returned inconsistent public keys or parameters")
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
            identity = validate_identity(identity, max_bytes=public.params.identity_max_bytes)
            if identity in snapshot.entries:
                return snapshot.entries[identity][1]
            if len(snapshot.entries) >= snapshot.max_users:
                raise IssuerCapacityError("fixed issuer identity capacity exhausted")
            self._begin()
            snapshot.entries[identity] = ("pending", None)
            try:
                self._atomic_write(snapshot.to_bytes())
                key = self.backend.key_extract(snapshot.master, identity)
                if (not isinstance(key, SigningKey) or key.identity != identity
                        or key.public_key.to_bytes() != public.to_bytes()):
                    raise IssuerStateError("extraction returned an inconsistent key")
                key = SigningKey.from_bytes(key.to_bytes())
                snapshot.entries[identity] = ("issued", key)
                self._atomic_write(snapshot.to_bytes())
                self._finish()
                return key
            except BaseException:
                snapshot.entries[identity] = ("failed", None)
                self._block(snapshot)
                raise


__all__ = ["FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerCapacityError"]
