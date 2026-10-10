"""Local OS locks and fail-closed markers; never store secrets in markers."""

from contextlib import contextmanager
import errno
import math
import os
from pathlib import Path
import time

from ibme.core.errors import IBMEError

LOCK_FILE = ".ibme-issue.lock"


class StateBusyError(IBMEError):
    """An active local writer still owns the state; no unlocked fallback."""


class ReceiverStatePendingError(IBMEError):
    """A receiver operation did not confirm durable completion."""


def receiver_pending_path(key_path: Path) -> Path:
    return Path(str(key_path) + ".pending")


def check_receiver_ready(key_path: Path) -> None:
    # lexists also rejects broken symlinks; a stale or unknown marker is never
    # removed automatically. Caller holds the same state lock as issuance.
    if os.path.lexists(receiver_pending_path(key_path)):
        raise ReceiverStatePendingError(
            "receiver state pending after an incomplete operation; automatic "
            "decrypt/reissuance is blocked until the private state is reviewed"
        )


@contextmanager
def receiver_state_transaction(key_path: Path, original: bytes, snapshot, publish):
    """Reserve before sampling, persist success/failure, then release.

    Caller already holds key_issuance_lock. snapshot is the opaque receiver
    serializer; publish atomically replaces its key file. A hard process exit,
    serialization/publication failure or marker-removal failure leaves this
    receiver blocked. No automatic recovery, rollback or resampling occurs.
    The marker stores only a fixed version string, never a key or identity.
    This is a local-process crash guard, not a filesystem power-loss theorem.
    """
    check_receiver_ready(key_path)
    marker = receiver_pending_path(key_path)
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(b"IBME:RECEIVER-PENDING:v1\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        yield
    finally:
        raw = snapshot()
        if raw != original:
            publish(key_path, raw)
        marker.unlink()


@contextmanager
def key_issuance_lock(state: Path, *, timeout=30):
    """Serialize setup/issuance/decrypt from before reading through publication.

    Windows uses a one-byte msvcrt lock; POSIX uses flock on the same permanent
    file. Never unlink it: a replacement inode could create two concurrent locks.
    OS handle closure, including process termination, releases ownership.
    This is a same-OS, local-filesystem contract, not a distributed/NFS lock.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 <= timeout <= 30:
        raise ValueError("state lock timeout must be finite and between 0 and 30 seconds")
    root = Path(state).resolve()
    if not root.is_dir():
        raise ValueError("key state directory does not exist")
    descriptor = os.open(root / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    acquired = False
    with os.fdopen(descriptor, "r+b", buffering=0) as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"\0")  # Windows byte-range locking needs one byte.
        if os.name == "nt":
            import msvcrt
            def lock():
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            def unlock():
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            def lock(): fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            def unlock(): fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        deadline = time.monotonic() + timeout
        try:
            while True:
                try:
                    lock()
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise StateBusyError("state writer busy; requested operation was not performed") from exc
                    time.sleep(min(0.02, remaining))
            yield
        finally:
            if acquired:
                unlock()
