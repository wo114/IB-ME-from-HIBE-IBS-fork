"""Explicit provider dispatch shared by the certification layer.

Providers have separate code/codec/profile; no wire-selected imports.
"""
from .mldsa import MLDSA, PROFILES as MLDSA_PROFILES
from .falcon import Falcon, PROFILES as FALCON_PROFILES

PROFILES={**MLDSA_PROFILES, **FALCON_PROFILES}


def ordinary(params):
    if params.base_algorithm in MLDSA_PROFILES:
        return MLDSA(params.base_algorithm, timeout=params.timeout_seconds)
    if params.base_algorithm in FALCON_PROFILES:
        return Falcon(params.base_algorithm, timeout=params.timeout_seconds)
    raise ValueError("unsupported certified IBS ordinary signature algorithm")
