"""Local, fixed-issuance storage for the Yu research backend.

Only this dedicated directory is used: a permanent OS lock, ``master.bin``,
``master.bin.pending`` and transient files for atomic replacement. The master
snapshot is PLAINTEXT, including private keys/trapdoor bases; keep it private
and outside Git, public evidence and synchronized/shared storage. POSIX modes
are best effort; Windows ACLs remain the operator's responsibility.

Operations must run on the process main thread: the real Sage/PARI HNF path
can crash in background threads. A thread guard rejects BEFORE state or entropy
changes; use separate processes for concurrency, not thread-pool dispatch.
All operations hold the existing same-OS local-filesystem issuance lock. Each
extraction reloads the master, durably reserves the directory before invoking
the backend, saves its pending/issued callbacks, and returns only after commit.
Any interrupted/failed transaction blocks the WHOLE issuer, including cached
identities, until an operator reviews it. No automatic recovery or marker
deletion is provided. Never delete or replace the permanent lock to unlock it.

File fsync and, on POSIX, directory fsync are requested; unsupported operations
fail closed. Native Windows has no portable directory-fsync implementation
here. This is not protection against malicious rollback, administrator edits,
concurrent pathname manipulation, distributed/NFS access, Windows/WSL mixed
writers, or a cross-OS hard-power-loss guarantee. Storage cannot make an
unwritable filesystem persist a marker. Yu's research/parameter limits
are unchanged; this service establishes no cryptographic security claim.
"""

# Adapted from ibme.ibs.foo_li.service (Foo--Li delivery 46529e0); copied
# storage mechanics only. No Foo--Li import or deterministic-signature contract.
# Yu signs with fresh randomness independently of this fixed KEY issuer.

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile
import threading
from typing import TYPE_CHECKING

from ibme.cli_state import LOCK_FILE, key_issuance_lock
from ibme.core.errors import IBMEError, SerializationError
from ibme.core.types import validate_identity
from .codec import MAX_OBJECT

if TYPE_CHECKING:
    from . import YuIBS, YuParams, MasterSecret, PublicKey, SigningKey


STATE_FILE = "master.bin"
PENDING_FILE = "master.bin.pending"
MAX_STATE_BYTES = MAX_OBJECT  # The codec's 16 MiB cap applies before disk reads.
_PENDING_CONTENT = b"IBME:Yu:ISSUER-PENDING:v1\n"


class IssuerStateError(SerializationError):
    """The local issuer directory or bounded master snapshot is invalid."""


class IssuerPendingError(IBMEError):
    """Unconfirmed completion forbids automatic issuance/reissuance."""


class IssuerThreadError(IBMEError):
    """Sage/PARI work must stay on a process main thread; use processes."""


def _main_thread() -> None:
    if threading.current_thread() is not threading.main_thread():
        raise IssuerThreadError(
            "Yu issuer requires the process main thread; use separate processes "
            "for concurrent requests (Sage/PARI is not background-thread safe)"
        )


def _plain_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
        raise IssuerStateError("issuer files must be ordinary files with one link")
    return info


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return  # File fsync still applies; see the explicit platform boundary.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class FixedIssuer:
    """One dedicated directory; ``backend`` must honor the pending callbacks.

    ``initialize`` creates only the final directory (its parent must exist), or
    uses an empty directory. An existing instance, unrelated contents or stale
    temporary files are never overwritten. ``public_key`` also refuses pending
    transactions. Errors do not include secret snapshot contents.
    """

    def __init__(self, path, backend: YuIBS | None = None):
        raw = os.fspath(path)
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("issuer path must be a nonempty directory path")
        self.path = Path(os.path.abspath(raw))
        if self.path == self.path.parent:
            raise ValueError("a filesystem root cannot be an issuer directory")
        if backend is None:
            from . import YuIBS
            backend = YuIBS()
        self.backend = backend

    def _directory(self, *, create=False) -> None:
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

    def _check_pending(self) -> None:
        # Even an empty marker or dangling symlink blocks automatic recovery.
        if os.path.lexists(self.path / PENDING_FILE):
            raise IssuerPendingError(
                "Yu issuer pending; automatic retry is blocked; "
                "private state requires operator review"
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
        # Reuse the permanent flock/msvcrt inode and its reentry protection.
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
            # unlink may already have taken effect when it or directory fsync
            # reports failure. Rearm before releasing the writer lock.
            if not os.path.lexists(self.path / PENDING_FILE):
                self._begin()
            raise

    def _atomic_write(self, raw: bytes) -> None:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_STATE_BYTES:
            raise IssuerStateError("issuer snapshot exceeds the bounded byte format")
        target = self.path / STATE_FILE
        if os.path.lexists(target):
            _plain_file(target)
        descriptor, name = tempfile.mkstemp(dir=self.path, prefix=".yu-", suffix=".tmp")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            _sync_directory(self.path)
        finally:
            # Only our own temporary pathname; never remove the pending/lock.
            if temporary.exists():
                temporary.unlink()

    def _load(self) -> tuple[MasterSecret, bytes]:
        from . import MasterSecret

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
            master = MasterSecret.from_bytes(raw)
        except Exception:
            # A malformed secret must not appear in a parser's exception text.
            raise IssuerStateError("issuer snapshot is invalid") from None
        return master, raw

    def initialize(self, params: YuParams) -> PublicKey:
        from .params import preflight

        _main_thread()
        preflight(params)
        self._directory(create=True)
        self._check_empty()
        with self._locked():
            self._check_empty()
            self._begin()
            try:
                public, master = self.backend.setup(params)
                if public.to_bytes() != master.public_key.to_bytes():
                    raise IssuerStateError("setup returned inconsistent public keys")
                self._atomic_write(master.to_bytes())
                self._finish()
                return public
            except BaseException:
                # A completion interruption may occur after marker removal.
                # Never turn uncertain initialization into an automatic retry.
                if not os.path.lexists(self.path / PENDING_FILE):
                    try:
                        self._begin()
                    except BaseException:
                        pass  # No filesystem guarantee if rearming itself fails.
                raise

    def public_key(self) -> PublicKey:
        _main_thread()
        # Do not create a lock in an arbitrary directory without issuer state.
        self._directory()
        if not os.path.lexists(self.path / STATE_FILE):
            self._check_pending()
            raise IssuerStateError("issuer has not been initialized")
        with self._locked():
            master, _ = self._load()
            return master.public_key

    def key_extract(self, identity: bytes) -> SigningKey:
        _main_thread()
        identity = validate_identity(identity)
        self._directory()
        if not os.path.lexists(self.path / STATE_FILE):
            self._check_pending()
            raise IssuerStateError("issuer has not been initialized")
        with self._locked():
            master, saved = self._load()
            identity = validate_identity(identity, max_bytes=master.params.identity_max_bytes)

            def persist(current):
                nonlocal saved
                if current is not master:
                    raise IssuerStateError("unexpected master in persistence callback")
                raw = current.to_bytes()
                if raw != saved:
                    self._atomic_write(raw)
                    saved = raw

            master.persist_callback = persist
            self._begin()
            try:
                key = self.backend.key_extract(master, identity)
                # A cache hit needs no rewrite. A new key must be durable even
                # if a future backend adds a post-callback state transition.
                persist(master)
                self._finish()
                return key
            except BaseException:
                # Preserve a backend FAILED tombstone when storage still works.
                # Even a successfully saved failure never clears the marker.
                try:
                    if not os.path.lexists(self.path / PENDING_FILE):
                        self._begin()
                    persist(master)
                except BaseException:
                    pass
                raise
            finally:
                master.persist_callback = None


__all__ = ["FixedIssuer", "IssuerStateError", "IssuerPendingError", "IssuerThreadError"]
