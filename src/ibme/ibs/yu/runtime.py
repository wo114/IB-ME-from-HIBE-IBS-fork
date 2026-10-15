"""Protect Sage/PARI algebra from unsupported background-thread execution."""
import threading
from ibme.core.errors import IBMEError


class YuThreadError(IBMEError):
    """Use each process's main thread for Sage algebra and private recovery."""


def main_thread():
    if threading.current_thread() is not threading.main_thread():
        raise YuThreadError("Yu Sage algebra requires the process main thread; use separate processes")
