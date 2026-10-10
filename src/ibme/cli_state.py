"""Local OS locks for CLI state writers; never store secrets in the lock file."""

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


@contextmanager
def key_issuance_lock(state: Path, *, timeout=30):
    """Serialize local setup/issuance from before reading through publication.

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
                        raise StateBusyError("state writer busy; key issuance was not performed") from exc
                    time.sleep(min(0.02, remaining))
            yield
        finally:
            if acquired:
                unlock()
