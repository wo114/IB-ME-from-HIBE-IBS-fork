"""Explicit provider dispatch shared by the certification layer.

Future providers need their own code/codec/profile; no wire-selected imports.
"""
from .mldsa import MLDSA


def ordinary(params):
    return MLDSA(params.base_algorithm, timeout=params.timeout_seconds)
