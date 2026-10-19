"""Run the three literal Table 4 sets in the required WSL Sage environment.

Only public metadata, timings, sizes and boolean checks are saved. Private
snapshots stay in TemporaryDirectory and are never included in reports.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import tempfile
from time import perf_counter

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom, SecureRandom
from ibme.ibs.srgg_paper_service import FixedIssuer
from .paper_backend import Backend
from .paper_objects import MasterSecret, SigningKey
from .paper_parameters import PaperParams
from .paper_validation import codec_checks, attack_checks


class NoRead:
    def read(self, count):
        raise AssertionError("cached/rejected operation unexpectedly consumed entropy")


def audit(profile_name="PARAM-I", *, interpretation="table-standard-deviation",
          production_random=False, progress=None, backend_class=Backend):
    params = PaperParams(profile_name, interpretation)
    source = Path(params.source.source_pdf)
    if sha256(source.read_bytes()).hexdigest() != params.source.source_sha256:
        raise ValueError("frozen paper checksum mismatch")
    identity, message = b"Alice", b"SRGG paper baseline: 32 bytes!!!"
    if len(message) != 32:
        raise RuntimeError("audit message length drift")
    rng = SecureRandom() if production_random else DeterministicRandom(
        ("paper-baseline-"+profile_name+"-"+interpretation).encode("ascii"))
    backend = backend_class(rng=rng)
    report = {"schema": "IBME/SRGG-PAPER-AUDIT/1", "profile": params.record(),
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "published_inputs": params.source.record(),
              "notation": params.numerical_convention(),
              "numerical_options": {"series": asdict(backend.series_options),
                                    "scalar": asdict(backend.scalar_options)},
              "environment": {"python": platform.python_version(), "sage": sage_version,
                              "platform": platform.platform(), "machine": platform.machine()},
              "randomness": "SecureRandom" if production_random else "DeterministicRandom TEST ONLY",
              "backend_class": backend_class.__module__+"."+backend_class.__name__,
              "identity_bytes": len(identity), "message_bytes": len(message),
              "repetitions": 1, "rom_used": True, "teaching_parameters": False,
              "formal_security_parameters": False, "security_claim": "none",
              "backend_admitted": False, "parameters_are_formal": False,
              "nist_security_category": None, "private_material_exported": False,
              "timings_seconds": {}, "checks": {}, "status": "running"}
    def measured(label, action):
        if progress:
            progress(profile_name+": "+label)
        start = perf_counter()
        value = action()
        report["timings_seconds"][label] = perf_counter()-start
        return value
    with tempfile.TemporaryDirectory(prefix="srgg-paper-private-") as private:
        issuer = FixedIssuer(Path(private)/"issuer", backend)
        public = measured("setup", lambda: issuer.initialize(params))
        key = measured("extract", lambda: issuer.key_extract(identity))
        signature = measured("sign", lambda: backend.sign(key, message))
        report["checks"]["honest_verify"] = measured("verify", lambda:
            backend.verify(public, identity, message, signature))
        # Snapshot remains memory only and checks the complete master cache.
        master = issuer._load().master
        restored_master = MasterSecret.from_bytes(master.to_bytes())
        report["checks"]["master_cached_key_reused_without_entropy"] = (
            backend_class(rng=NoRead()).key_extract(restored_master, identity).to_bytes() == key.to_bytes())
        strict, sizes = measured("codecs", lambda: codec_checks(public, master, key, signature))
        report["checks"].update(strict)
        report["object_sizes_bytes"] = sizes
        reopened = FixedIssuer(issuer.path, backend_class(rng=NoRead()),
                               expected_public=public, expected_params=params)
        report["checks"]["persistent_restart_cached_key_same_without_entropy"] = (
            reopened.key_extract(identity).to_bytes() == key.to_bytes())
        restored_key = SigningKey.from_bytes(key.to_bytes())
        again = measured("sign_after_key_restore", lambda: backend.sign(restored_key, message))
        report["checks"]["restored_key_resigned"] = backend.verify(public, identity, message, again)
        loaded = backend.load_signature(public, signature.to_bytes())
        report["checks"]["public_bound_signature_load"] = loaded.to_bytes() == signature.to_bytes()
        attacks, strong = measured("attacks", lambda:
            attack_checks(backend, public, identity, message, signature))
        report["checks"].update(attacks)
        report["native_strong_probe"] = strong
        report["master_sampler"] = backend.last_master_certificate
        report["signature_sampler"] = backend.last_sign_certificate
        report["signature_attempt_entropy"] = getattr(backend, "last_sign_attempt_certificate", None)
        report["signature_call_entropy"] = getattr(backend, "last_sign_call_certificate", None)
        report["attempts"] = {"setup": backend.setup_attempts, "sign": backend.sign_attempts,
                              "extraction_calls": backend.extract_calls}
    report["functional_checks_passed"] = all(report["checks"].values())
    report["status"] = "functional-pass" if report["functional_checks_passed"] else "functional-fail"
    report["proof_limit"] = "Functional tests and unsuccessful finite attacks are not a security proof."
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II", "PARAM-III"), default="PARAM-I")
    parser.add_argument("--interpretation", choices=("table-standard-deviation", "literal-density-width"),
                        default="table-standard-deviation")
    parser.add_argument("--production-random", action="store_true")
    parser.add_argument("--sampler", choices=("joint", "source-schur"), default="joint")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.sampler == "source-schur":
            from .paper_schur_backend import SourceSchurBackend
            backend_class = SourceSchurBackend
        else:
            backend_class = Backend
        report = audit(args.profile, interpretation=args.interpretation,
                       production_random=args.production_random, progress=lambda value: print(value, flush=True),
                       backend_class=backend_class)
    except Exception as error:
        report = {"schema": "IBME/SRGG-PAPER-AUDIT/1", "status": "execution-failed",
                  "profile": args.profile, "interpretation": args.interpretation,
                  "sampler": args.sampler,
                  "error_type": type(error).__name__,
                  "error": "standalone audit failed; private exception details omitted",
                  "private_material_exported": False, "security_claim": "none"}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
        print(json.dumps({"status": "execution-failed", "output": str(args.output),
                          "private_diagnostics_exported": False}))
        raise SystemExit(1) from None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "output": str(args.output),
                      "strong_counterexample": report["native_strong_probe"]["native_strong_counterexample_found"]}))
    if not report["functional_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
