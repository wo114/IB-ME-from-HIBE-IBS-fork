"""Explicit execution policy for the Sage research kernel."""
import threading


class StudyExecutionError(RuntimeError):
    """A fresh Sage operation was requested from an unsupported thread."""


def require_main_thread(operation):
    if threading.current_thread() is not threading.main_thread():
        raise StudyExecutionError(operation+" requires the main thread; cached replay is allowed")
