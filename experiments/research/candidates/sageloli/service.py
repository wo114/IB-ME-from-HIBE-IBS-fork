"""Persistent fixed identity issuance for the Sageloli research backends.

The matrix SIS and ring RSIS implementations share the five method surface but
keep their private algebra in separate backend/object modules.  ``FixedIssuer``
only persists the backend's ``MasterSecret`` object and therefore does not
inspect either representation.  State files are deliberately plaintext local
research state; keep the directory private and outside Git.

Issuance is fail-closed.  A permanent local lock serialises cooperating
writers, ``master.bin.pending`` records an in-flight transaction, and a failed
or uncertain transaction leaves the issuer blocked until an operator reviews
the private state.  This is crash/restart hygiene, not rollback protection or a
cryptographic security claim.  The implementation makes no parameter,
distribution, or SIS/RSIS security assertion.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from ibme.cli_state import LOCK_FILE, key_issuance_lock
from ibme.core.errors import IBMEError
from ibme.core.types import validate_identity


STATE_FILE = "master.bin"
PENDING_FILE = "master.bin.pending"
_PENDING_CONTENT = b"IBME:Sageloli:ISSUER-PENDING:v1\n"
_DEFAULT_MAX_STATE_BYTES = 32 * 1024 * 1024
try:
    from .codec import MAX_WIRE_BYTES as MAX_STATE_BYTES
except Exception:  # pragma: no cover - codec import is stdlib-only in normal use
    MAX_STATE_BYTES = _DEFAULT_MAX_STATE_BYTES


class IssuerStateError(IBMEError):
    """The private issuer directory or serialized master is invalid."""


class IssuerPendingError(IBMEError):
    """An uncertain transaction blocks automatic retry or reissuance."""


def _object_classes():
    """Load classes lazily so importing the service needs no Sage runtime."""
    from . import objects

    master = tuple(item for item in (
        getattr(objects, "SisMasterSecret", None),
        getattr(objects, "RsisMasterSecret", None),
        getattr(objects, "MasterSecret", None),
    ) if item is not None)
    public = tuple(item for item in (
        getattr(objects, "SisPublicKey", None),
        getattr(objects, "RsisPublicKey", None),
        getattr(objects, "PublicKey", None),
    ) if item is not None)
    signing = tuple(item for item in (
        getattr(objects, "SisSigningKey", None),
        getattr(objects, "RsisSigningKey", None),
        getattr(objects, "SigningKey", None),
    ) if item is not None)
    if not master or not public or not signing or any(
            not callable(getattr(item, "from_bytes", None))
            and not callable(getattr(item, "_from", None))
            for group in (master, public, signing) for item in group):
        raise IssuerStateError("Sageloli object codecs are unavailable")
    return master, public, signing


def _decode_master(raw: bytes):
    """Decode either route without exposing private parser diagnostics."""
    try:
        from . import objects
    except Exception:
        objects = None
    # The generic decoder dispatches the serialized kind to the concrete
    # ``SisMasterSecret``/``RsisMasterSecret`` subclass.  Prefer it whenever
    # present: calling a route-specific inherited classmethod directly would
    # otherwise reconstruct an RSIS snapshot as a SIS instance and the RSIS
    # backend would reject the recovered master on restart.
    generic = getattr(objects, "MasterSecret", None) if objects is not None else None
    parser = getattr(generic, "from_bytes", None)
    if callable(parser):
        try:
            return parser(raw)
        except Exception:
            pass
    master_classes, _, _ = _object_classes()
    for cls in master_classes:
        parser = getattr(cls, "from_bytes", None)
        if callable(parser):
            try:
                result = parser(raw)
                # Route-aware service recovery must never hand a concrete
                # backend the other route's master object.
                route = getattr(getattr(result, "public_key", None), "route", None)
                name = cls.__name__.lower()
                if "sis" in name and "rsis" not in name and route != "sis":
                    continue
                if "rsis" in name and route != "rsis":
                    continue
                return result
            except Exception:
                continue
        parser = getattr(cls, "_from", None)
        if not callable(parser) or objects is None:
            continue
        public_name = "SisPublicKey" if "Sis" in cls.__name__ else "RsisPublicKey"
        public_cls = getattr(objects, public_name, None)
        if public_cls is None:
            continue
        try:
            return parser(raw, public_cls)
        except Exception:
            continue
    raise IssuerStateError("issuer snapshot is invalid") from None


def _max_state_bytes() -> int:
    try:
        from . import objects

        value = getattr(objects, "MAX_WIRE", None)
        if value is None:
            value = MAX_STATE_BYTES
    except Exception:
        value = _DEFAULT_MAX_STATE_BYTES
    return value if type(value) is int and 0 < value <= _DEFAULT_MAX_STATE_BYTES else _DEFAULT_MAX_STATE_BYTES


def _public_of(master: Any):
    for name in ("public_key", "public"):
        value = getattr(master, name, None)
        if value is not None:
            return value
    raise IssuerStateError("master secret has no public key")


def _raw_bytes(value: Any) -> bytes:
    try:
        raw = value.to_bytes()
    except Exception:
        raise IssuerStateError("issuer object has no canonical byte encoding") from None
    if type(raw) is not bytes or not raw:
        raise IssuerStateError("issuer object encoding is empty or noncanonical")
    return raw


def _identity_limit(master: Any) -> int:
    public = _public_of(master)
    candidates = (
        getattr(getattr(public, "config", None), "identity_max_bytes", None),
        getattr(getattr(public, "params", None), "identity_max_bytes", None),
        getattr(getattr(master, "config", None), "identity_max_bytes", None),
        getattr(getattr(master, "params", None), "identity_max_bytes", None),
    )
    for value in candidates:
        if type(value) is int and value > 0:
            return value
    return 4096


def _identity(value: Any, master: Any | None = None) -> bytes:
    # Preserve the project's public EncodingError/TypeError contract.  The
    # validator never includes private state in its diagnostics.
    return validate_identity(value, max_bytes=_identity_limit(master) if master is not None else 4096)


def _state_map(master: Any):
    """Return the first conventional issuer ledger exposed by a master.

    Sageloli's two backends use ``states``.  The aliases make this service
    usable with the existing Foo--Li/Yu style adapters while keeping the
    service independent of a private matrix or ring representation.
    """
    for name in ("states", "_states", "_ledger"):
        value = getattr(master, name, None)
        if isinstance(value, dict):
            return value
    return None


def _entry(master: Any, identity: bytes):
    states = _state_map(master)
    if states is None or identity not in states:
        return None
    raw = states[identity]
    if isinstance(raw, tuple) and len(raw) == 2:
        return raw[0], raw[1]
    if isinstance(raw, dict) and set(raw) == {"status", "key"}:
        return raw["status"], raw["key"]
    if isinstance(raw, str):
        keys = getattr(master, "_keys", {})
        return raw, keys.get(identity) if isinstance(keys, dict) else None
    raise IssuerStateError("invalid Sageloli issuer ledger entry")


def _set_entry(master: Any, identity: bytes, status: str, key: Any = None) -> None:
    states = _state_map(master)
    if states is None:
        raise IssuerStateError("master secret has no issuer ledger")
    if status not in ("pending", "failed", "issued"):
        raise IssuerStateError("invalid Sageloli issuer ledger status")
    # The native Sageloli/SRGG shape is {identity: (status, key)}.  Preserve
    # existing dict/string layouts when an adapter chooses one of them.
    old = states.get(identity)
    if isinstance(old, dict) and set(old) == {"status", "key"}:
        states[identity] = {"status": status, "key": key}
    elif isinstance(old, str) or (old is None and hasattr(master, "_ledger")):
        states[identity] = status
        keys = getattr(master, "_keys", None)
        if not isinstance(keys, dict):
            keys = {}
            setattr(master, "_keys", keys)
        if key is None:
            keys.pop(identity, None)
        else:
            keys[identity] = key
    else:
        states[identity] = (status, key)


def _state_status(master: Any, identity: bytes):
    current = _entry(master, identity)
    return None if current is None else current[0]


def _public_equal(left: Any, right: Any) -> bool:
    try:
        return _raw_bytes(left) == _raw_bytes(right)
    except IssuerStateError:
        return left == right


def _plain_file(path: Path) -> os.stat_result:
    info = path.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & reparse):
        raise IssuerStateError("issuer files must be ordinary files with one link")
    return info


def _sync_directory(path: Path) -> None:
    # Windows has no portable directory-fsync API.  File fsync is still used.
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FixedIssuer:
    """Persistent fixed-key service shared by the matrix and ring backends."""

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __init__(self, path, backend=None):
        raw = os.fspath(path)
        if type(raw) is not str or not raw.strip():
            raise ValueError("issuer path must be a nonempty directory path")
        self.path = Path(os.path.abspath(raw))
        if self.path == self.path.parent:
            raise ValueError("a filesystem root cannot be an issuer directory")
        if backend is None:
            from .backend import Backend

            backend = Backend()
        if not all(callable(getattr(backend, name, None)) for name in
                   ("setup", "key_extract", "sign", "verify", "load_signature")):
            raise TypeError("Sageloli backend must implement the five methods")
        self.backend = backend

    def _directory(self, *, create=False) -> None:
        if create:
            try:
                self.path.mkdir(mode=0o700)
            except FileExistsError:
                pass
        info = self.path.lstat()
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if (not stat.S_ISDIR(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & reparse):
            raise IssuerStateError("issuer path must be an ordinary directory")

    def _check_pending(self) -> None:
        if os.path.lexists(self.path / PENDING_FILE):
            raise IssuerPendingError(
                "Sageloli issuer pending; automatic retry is blocked; private review required"
            )

    def _check_empty(self) -> None:
        self._check_pending()
        if any(entry.name != LOCK_FILE for entry in self.path.iterdir()):
            raise FileExistsError("issuer initialization requires an empty directory")

    @contextmanager
    def _locked(self):
        self._directory()
        lock = self.path / LOCK_FILE
        if os.path.lexists(lock):
            _plain_file(lock)
        with key_issuance_lock(self.path):
            yield

    def _begin(self) -> None:
        self._check_pending()
        descriptor = os.open(self.path / PENDING_FILE,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_PENDING_CONTENT)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(self.path)

    def _finish(self) -> None:
        try:
            (self.path / PENDING_FILE).unlink()
            _sync_directory(self.path)
        except BaseException:
            # If unlink happened before fsync reported failure, re-arm the
            # marker while the lock is still held.
            if not os.path.lexists(self.path / PENDING_FILE):
                try:
                    self._begin()
                except BaseException:
                    pass
            raise

    def _atomic_write(self, raw: bytes) -> None:
        limit = _max_state_bytes()
        if type(raw) is not bytes or not 0 < len(raw) <= limit:
            raise IssuerStateError("issuer snapshot exceeds the bounded byte format")
        target = self.path / STATE_FILE
        if os.path.lexists(target):
            _plain_file(target)
        descriptor, name = tempfile.mkstemp(dir=self.path, prefix=".sageloli-", suffix=".tmp")
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

    def _load(self):
        self._check_pending()
        path = self.path / STATE_FILE
        info = _plain_file(path)
        limit = _max_state_bytes()
        if not 0 < info.st_size <= limit:
            raise IssuerStateError("issuer snapshot is empty or exceeds the size limit")
        flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not 0 < info.st_size <= limit):
                raise IssuerStateError("issuer snapshot is not a bounded ordinary file")
            raw = handle.read(info.st_size + 1)
        if len(raw) != info.st_size:
            raise IssuerStateError("issuer snapshot size changed during the bounded read")
        master = _decode_master(raw)
        backend_route = getattr(self.backend, "route", None)
        master_route = getattr(_public_of(master), "route", None)
        if backend_route in ("sis", "rsis") and master_route in ("sis", "rsis"):
            if backend_route != master_route:
                raise IssuerStateError("issuer snapshot route does not match backend")
        return master, raw

    def _existing(self) -> None:
        self._directory()
        if not os.path.lexists(self.path / STATE_FILE):
            self._check_pending()
            raise IssuerStateError("issuer has not been initialized")

    def _persist(self, master, saved: bytes) -> bytes:
        raw = _raw_bytes(master)
        if raw != saved:
            self._atomic_write(raw)
            return raw
        return saved

    def initialize(self, params):
        if params is None or not (
                callable(getattr(params, "record", None))
                or callable(getattr(params, "to_bytes", None))):
            raise TypeError("Sageloli parameters are required")
        # Force the public parameter object to validate before creating the
        # issuer directory or consuming setup entropy.  ``record`` is used by
        # the current config classes; older route objects expose to_bytes.
        try:
            if callable(getattr(params, "record", None)):
                record = params.record()
                if not isinstance(record, dict):
                    raise TypeError("Sageloli parameter record is invalid")
            else:
                raw_params = params.to_bytes()
                if type(raw_params) is not bytes or not raw_params:
                    raise TypeError("Sageloli parameter encoding is invalid")
        except Exception as exc:
            if isinstance(exc, (TypeError, ValueError)):
                raise
            raise TypeError("Sageloli parameters are invalid") from exc
        # Reject an obvious route/backend mismatch before creating a pending
        # marker.  A failed setup from a real sampler remains fail-closed, but
        # a caller typo must not poison an otherwise empty issuer directory.
        backend_route = getattr(self.backend, "route", None)
        if backend_route in ("sis", "rsis"):
            try:
                from .config import SISParams, RSISParams
                expected = SISParams if backend_route == "sis" else RSISParams
                if not isinstance(params, expected):
                    raise TypeError("Sageloli parameter route does not match backend")
            except ImportError:
                pass
        self._directory(create=True)
        self._check_empty()
        with self._locked():
            self._check_empty()
            self._begin()
            try:
                public, master = self.backend.setup(params)
                master_public = _public_of(master)
                if master_public is not public and not _public_equal(master_public, public):
                    raise IssuerStateError("setup returned inconsistent public keys")
                # A setup adapter must persist the exact public parameter
                # profile requested by the caller.  This prevents a route or
                # teaching-profile mix-up from becoming a recoverable state
                # file that only fails much later during extraction.
                public_params = getattr(public, "params", None)
                master_params = getattr(master_public, "params", None)
                if public_params is not None and public_params != params:
                    raise IssuerStateError("setup returned mismatched public parameters")
                if master_params is not None and master_params != params:
                    raise IssuerStateError("master/public parameter mismatch")
                raw = _raw_bytes(master)
                self._atomic_write(raw)
                self._finish()
                return public
            except BaseException:
                # Setup has no recoverable prior master.  Keep the marker even
                # if a partial snapshot was published; retry is manual.
                if not os.path.lexists(self.path / PENDING_FILE):
                    try:
                        self._begin()
                    except BaseException:
                        pass
                raise

    def public_key(self):
        self._existing()
        with self._locked():
            master, _ = self._load()
            return _public_of(master)

    def key_extract(self, identity):
        self._existing()
        with self._locked():
            master, saved = self._load()
            identity = _identity(identity, master)
            current = _entry(master, identity)
            if current is not None:
                status, key = current
                if status == "issued" and key is not None:
                    return key
                raise IssuerPendingError(
                    "Sageloli identity pending/failed; automatic reissue is blocked"
                )
            # Native backends enforce the same capacity, but the service must
            # check it before reserving a new ledger entry.  Otherwise a full
            # ledger would temporarily grow to max_users + 1, the backend
            # would reject the request, and the failed marker could leave an
            # unreadable snapshot on disk.
            states = _state_map(master)
            limit = getattr(getattr(_public_of(master), "params", None),
                            "max_users", None)
            if (states is not None and type(limit) is int
                    and len(states) >= limit):
                raise IssuerStateError("identity issuance capacity exhausted")
            self._begin()

            # Backends may opt into callbacks (Foo--Li/Yu pattern).  The
            # callback accepts either callback() or callback(master) styles.
            def persist(current=None):
                nonlocal saved
                if current is not None and current is not master:
                    raise IssuerStateError("unexpected master in persistence callback")
                saved = self._persist(master, saved)

            had_callback = hasattr(master, "persist_callback")
            old_callback = getattr(master, "persist_callback", None)
            if had_callback:
                try:
                    master.persist_callback = persist
                except Exception:
                    had_callback = False
            try:
                # Durably publish the reservation before entering the real
                # sampler.  The native backends also create their own pending
                # entry and reject an already-present identity, so remove the
                # in-memory reservation immediately after the snapshot write;
                # the on-disk marker/ledger still blocks crash recovery.
                if states is not None:
                    _set_entry(master, identity, "pending", None)
                    persist(master)
                    states.pop(identity, None)
                key = self.backend.key_extract(master, identity)
                # Publish any backend-updated issued ledger, then validate the
                # returned key's identity/public binding before removing marker.
                entry = _entry(master, identity)
                if entry is None or entry[0] != "issued":
                    _set_entry(master, identity, "issued", key)
                else:
                    key = entry[1]
                signing_classes = _object_classes()[2]
                if not isinstance(key, signing_classes):
                    raise IssuerStateError("extraction returned an invalid signing key")
                if getattr(key, "identity", None) != identity:
                    raise IssuerStateError("extraction returned a key for another identity")
                if not _public_equal(getattr(key, "public_key", None), _public_of(master)):
                    raise IssuerStateError("extraction returned a key for another public context")
                persist(master)
                self._finish()
                return key
            except BaseException:
                # Preserve a failed ledger when possible.  Marker remains even
                # if persistence itself fails or the process exits abruptly.
                try:
                    _set_entry(master, identity, "failed", None)
                    persist(master)
                except BaseException:
                    pass
                raise
            finally:
                if had_callback:
                    try:
                        master.persist_callback = old_callback
                    except BaseException:
                        pass

    def sign(self, signing_key, message):
        return self.backend.sign(signing_key, message)

    def verify(self, public_key, identity, message, signature):
        return self.backend.verify(public_key, identity, message, signature)

    def load_signature(self, public_key, data):
        return self.backend.load_signature(public_key, data)


__all__ = ["FixedIssuer", "IssuerStateError", "IssuerPendingError",
           "STATE_FILE", "PENDING_FILE", "MAX_STATE_BYTES"]
