"""Compatibility entry point for the M1 Luo matrix research engine.

The sole implementation now lives in the installable ibme.ibs package. Existing
M1 entry points, test vectors and MATRIX-REF/1 encodings remain compatible.
Research parameters only; security_claim: none.
"""

from pathlib import Path
import sys

# Allow standalone checkout research commands without an editable installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ibme.ibs.luo_reference import (
    MAGIC, MAX_IDENTITIES, MAX_WIRE_BYTES, PARAM_FIELDS, VERSION,
    MatrixParams, MasterState, PublicKey, SamplingAbort, Signature, SigningKey,
    hash_h1, hash_h2, key_extract, setup, sign, sign_for_identity, uniform_below, verify,
)

__all__ = [
    "MAGIC", "MAX_IDENTITIES", "MAX_WIRE_BYTES", "PARAM_FIELDS", "VERSION",
    "MatrixParams", "MasterState", "PublicKey", "SamplingAbort", "Signature",
    "SigningKey", "hash_h1", "hash_h2", "key_extract", "setup", "sign",
    "sign_for_identity", "uniform_below", "verify",
]
