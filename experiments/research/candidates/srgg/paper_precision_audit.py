"""Compare 160/192-bit numerical profiles on one original-paper SRGG key.

Run with WSL ``~/miniconda3/envs/sage``.  The deterministic seed, five-byte
identity and 32-byte message match ``paper_audit.audit``.  Setup and extraction
run once with the original 160-bit numerical profile.  Both comparison plans
then use that same witness and signing key without reading entropy.  Only
public certificates, source hashes, timings and boolean checks are exported;
private spectral bounds, series lengths, centers and key material stay local.

The 192-bit setting changes a numerical approximation target, not Table 4
widths, gamma, root support or the Backend default.  These functional and
numerical checks do not establish a signature-law bridge or security proof.
The bounded runner uses Unix SIGALRM and is intended for the prescribed WSL
environment; native operations may defer Python signal handling briefly.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import signal
from time import perf_counter

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .paper_backend import Backend
from .paper_parameters import PaperParams


SCHEMA = "IBME/SRGG-FIXED-ROOT-NUMERICAL-PROFILE-COMPARISON/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_FILES = (
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_samplef.py",
    "experiments/research/candidates/srgg/structured_samplef.py",
    "experiments/research/candidates/srgg/sampling_error.py",
)
IDENTITY = b"Alice"
MESSAGE = b"SRGG paper baseline: 32 bytes!!!"


class _CountRandom:
    def __init__(self, seed):
        self.inner = DeterministicRandom(seed)
        self.used = 0

    def read(self, count):
        self.used += count
        return self.inner.read(count)


class _RunDeadline(Exception):
    pass


def _deadline(_signum, _frame):
    raise _RunDeadline("bounded numerical-profile experiment deadline")


def audit(profile_name="PARAM-III", *, deadline_seconds=420, progress=None):
    """Return public evidence; a failed phase ends without a replacement key.

    Source paths in the receipt are repository-relative.  No private snapshot
    is written, including on timeout.  The caller decides where to save the
    returned public report.
    """
    if type(deadline_seconds) is not int or not 10 <= deadline_seconds <= 3600:
        raise ValueError("deadline_seconds must be an integer in [10,3600]")
    if not hasattr(signal, "SIGALRM"):
        raise RuntimeError("this bounded audit requires the prescribed WSL Sage environment")
    if signal.getitimer(signal.ITIMER_REAL)[0] != 0:
        raise RuntimeError("an existing real-time alarm must not be replaced")
    params = PaperParams(profile_name, "table-standard-deviation")
    paper = ROOT / params.source.source_pdf
    paper_hash = sha256(paper.read_bytes()).hexdigest()
    if paper_hash != params.source.source_sha256:
        raise ValueError("frozen paper checksum mismatch")
    if len(IDENTITY) != 5 or len(MESSAGE) != 32:
        raise RuntimeError("paper audit identity/message length drift")

    seed = ("paper-baseline-" + profile_name + "-table-standard-deviation").encode("ascii")
    report = {
        "schema": SCHEMA,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "profile": profile_name,
        "interpretation": params.interpretation,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
        "formal_security_parameters": False,
        "private_material_exported": False,
        "private_rho_terms_centers_and_keys_exported": False,
        "randomness": "DeterministicRandom TEST ONLY",
        "seed_source": "paper_audit.audit profile and interpretation literal seed",
        "deterministic_seed_ascii": seed.decode("ascii"),
        "sage": sage_version,
        "environment": {
            "python": platform.python_version(), "sage": sage_version,
            "platform": platform.platform(), "machine": platform.machine(),
        },
        "identity_bytes": len(IDENTITY), "message_bytes": len(MESSAGE),
        "repetitions": 1, "rom_used": True, "teaching_parameters": False,
        "deadline_seconds": deadline_seconds, "deadline_mechanism": "Unix SIGALRM",
        "timings_seconds": {}, "certificates": {}, "status": "running",
        "module_sha256_at_import": {
            path: sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_FILES
        },
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "paper": {
            "path": paper.relative_to(ROOT).as_posix(), "sha256": paper_hash,
            "frozen_sha256": params.source.source_sha256, "frozen_hash_matches": True,
        },
        "source_inputs": params.source.record(),
        "parameter_record": params.record(),
        "notation": params.numerical_convention(),
        "proof_limit": "Functional and numerical evidence is not a production signature-law bridge or a security proof.",
    }

    def measured(label, action):
        report["current_phase"] = label
        if progress:
            progress(profile_name + ": " + label)
        phase_start = perf_counter()
        try:
            return action()
        finally:
            report["timings_seconds"][label] = perf_counter() - phase_start

    source = _CountRandom(seed)
    baseline = Backend(rng=source)
    baseline.series_options = replace(baseline.series_options, series_error_bits=160)
    refined = Backend(rng=source)
    refined.series_options = replace(baseline.series_options, series_error_bits=192)
    report["numerical_options_160"] = asdict(baseline.series_options)
    report["numerical_options_192"] = asdict(refined.series_options)
    report["backend_default_changed"] = False
    report["fixed_witness_reselected_for_numerical_profile"] = False
    previous_handler = signal.signal(signal.SIGALRM, _deadline)
    start = perf_counter()
    signal.alarm(deadline_seconds)
    try:
        public, master = measured("setup160", lambda: baseline.setup(params))
        report["setup_attempts"] = baseline.setup_attempts
        report["certificates"]["master160_setup"] = baseline.last_master_certificate
        key = measured("extract160_once", lambda: baseline.key_extract(master, IDENTITY))
        report["extraction_calls"] = baseline.extract_calls
        report["certificates"]["master160_extract"] = baseline.last_master_certificate
        report["entropy_after_extract_bytes"] = source.used

        master192 = measured("prepare_master192_same_witness", lambda:
            refined._master_plan(params, master.witness))
        report["certificates"]["master192"] = master192.public_certificate()
        signature160 = measured("prepare_signature160_same_key", lambda: baseline._sign_plan(key))
        report["certificates"]["signature160"] = signature160.public_certificate()
        signature192 = measured("prepare_signature192_same_key", lambda: refined._sign_plan(key))
        report["certificates"]["signature192"] = signature192.public_certificate()
        report["same_fixed_root_and_key_used"] = True
        report["plan_preparation_read_no_entropy"] = source.used == report["entropy_after_extract_bytes"]
        report["table4_inputs_unchanged"] = public.params.source.record() == params.source.record()

        signature = measured("sign192_once_original_norm_retry", lambda: refined.sign(key, MESSAGE))
        report["honest_verify_192"] = refined.verify(public, IDENTITY, MESSAGE, signature)
        report["sign_attempts_192"] = refined.sign_attempts
        report["certificates"]["signature192_after_sign"] = refined.last_sign_certificate
        report["total_entropy_bytes"] = source.used
        report["status"] = "completed" if report["honest_verify_192"] else "functional-fail"
    except _RunDeadline as error:
        report["status"], report["error_type"] = "bounded-deadline", type(error).__name__
    except Exception as error:
        # Exception strings or tracebacks could include private arithmetic.
        report["status"], report["error_type"] = "failed", type(error).__name__
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)
        report["elapsed_seconds"] = perf_counter() - start
        for certificate in report["certificates"].values():
            certificate["public_numerical_at_most_2_minus_96"] = (
                Fraction(certificate["finite_center_numerical_tv_upper"]) <= Fraction(1, 2**96))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II", "PARAM-III"), default="PARAM-III")
    parser.add_argument("--deadline-seconds", type=int, default=420)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists; use a fresh receipt path")
    report = audit(args.profile, deadline_seconds=args.deadline_seconds,
                   progress=lambda phase: print(phase, flush=True))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as receipt:
        receipt.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "status": report["status"], "output": str(args.output),
        "elapsed_seconds": report["elapsed_seconds"],
        "public_numerical_bounds": {
            label: value["finite_center_numerical_tv_upper"]
            for label, value in report["certificates"].items()
        },
        "honest_verify_192": report.get("honest_verify_192"),
    }), flush=True)
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
