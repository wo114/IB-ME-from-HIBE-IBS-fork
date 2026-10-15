"""Public lifecycle receipt for the SRGG persistent fixed issuer.

The receipt records only public sizes, booleans, parameters, and limitations.
It does not export the master secret, user keys, random seeds, or signatures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
from time import perf_counter

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.srgg_service import FixedIssuer
from .backend import Backend
from .config import Config


def audit_report():
    config = Config()
    root = Path(tempfile.mkdtemp(prefix="ibme-srgg-issuer-")) / "issuer"
    started = perf_counter()
    issuer = FixedIssuer(root, Backend(rng=DeterministicRandom(b"srgg-service-audit-root")))
    public = issuer.initialize(config, max_users=2)
    setup_seconds = perf_counter() - started
    first = issuer.key_extract(b"Alice")
    after_first = (root / "master.bin").stat().st_size

    restarted = FixedIssuer(root, Backend(rng=DeterministicRandom(b"srgg-service-audit-restart")))
    cached = restarted.key_extract(b"Alice")
    restored_public = restarted.public_key()
    signer = Backend(rng=DeterministicRandom(b"srgg-service-audit-sign"))
    signature = signer.sign(cached, b"srgg-persistent-service")
    verified = signer.verify(restored_public, b"Alice", b"srgg-persistent-service", signature)

    return {
        "schema": "IBME/SRGG-FIXED-ISSUER-AUDIT/1",
        "parameters": config.record(),
        "public": {
            "public_key_bytes": len(public.to_bytes()),
            "state_bytes_one_issued_identity": after_first,
            "setup_seconds": setup_seconds,
        },
        "checks": {
            "public_key_restored": restored_public.to_bytes() == public.to_bytes(),
            "cached_identity_same_key": cached.to_bytes() == first.to_bytes(),
            "post_restore_signature_verified": verified,
        },
        "test_coverage": [
            "tests/test_srgg_service.py covers pending/failed blocking, atomic-save faults and hard-exit recovery.",
            "tests/test_srgg_service.py covers two-process same-identity serialization under the local lock.",
        ],
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "limitations": [
            "The snapshot is trusted local plaintext and has no malicious rollback or administrator-integrity protection.",
            "The lock and fsync behavior cover cooperating same-OS processes; NFS, mixed Windows/WSL writers and hard-power-loss guarantees are out of scope.",
            "The raw Backend remains available with its in-memory cache semantics; this service is an explicit wrapper and does not change the registry or CLI.",
            "The SRGG research profile has an 8-bit challenge and is publicly forgeable; functional service evidence is not a security proof.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result["checks"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
