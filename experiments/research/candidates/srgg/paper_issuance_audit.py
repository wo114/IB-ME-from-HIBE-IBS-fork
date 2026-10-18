"""Bounded original-parameter, fixed-root issuance-law experiment in WSL Sage.

One Setup and one extraction per requested profile. A failed analysis gate
never redraws a root. Receipts contain public certificates, hashes and checks;
private keys, witnesses, Fourier spectra and private diagnostics stay in RAM.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import signal
from time import perf_counter

from sage.version import version as sage_version

from .paper_backend import Backend
from .paper_algebra import PaperRing, identity_target
from .paper_issuance_bridge import issuance_certificate
from .paper_objects import SigningKey
from .paper_parameters import PaperParams
from .paper_precision_audit import _CountRandom, _RunDeadline, _deadline
from .paper_resource_audit import build_report


SCHEMA = "IBME/SRGG-PAPER-FIXED-ROOT-ISSUANCE-AUDIT/1"
ROOT = Path(__file__).resolve().parents[4]
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
IDENTITY = b"Alice"


def audit(profile_name, *, deadline_seconds=300, progress=None):
    if profile_name not in PROFILES:
        raise ValueError("original Table 4 profile required")
    if type(deadline_seconds) is not int or not 10 <= deadline_seconds <= 3600:
        raise ValueError("bounded integer deadline in [10,3600] required")
    if not hasattr(signal, "SIGALRM") or signal.getitimer(signal.ITIMER_REAL)[0] != 0:
        raise RuntimeError("WSL Unix SIGALRM required and existing alarms must be preserved")
    params = PaperParams(profile_name, "table-standard-deviation")
    paper_hash = sha256((ROOT/params.source.source_pdf).read_bytes()).hexdigest()
    if paper_hash != params.source.source_sha256:
        raise ValueError("frozen source PDF differs")
    seed = ("paper-baseline-"+profile_name+"-table-standard-deviation").encode("ascii")
    source = _CountRandom(seed)
    backend = Backend(rng=source)
    files = sorted((ROOT/"experiments/research/candidates/srgg").glob("*.py"))
    result = {"schema": SCHEMA, "profile": profile_name,
        "parameter_record": params.record(), "source_inputs": params.source.record(),
        "paper_sha256": paper_hash, "notation": params.numerical_convention(),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform(), "machine": platform.machine()},
        "source_sha256": {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest() for p in files},
        "randomness": "DeterministicRandom TEST ONLY", "deterministic_seed_ascii": seed.decode("ascii"),
        "identity_bytes": len(IDENTITY), "message_bytes": None, "repetitions": 1,
        "rom_used": True, "teaching_parameters": False,
        "deadline_seconds": deadline_seconds, "timings_seconds": {}, "checks": {},
        "status": "running", "private_material_exported": False,
        "all_setup_roots_certified": False, "full_signature_law_certified": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
        "proof_limit": "Fixed-root numerical, algebraic and functional evidence is not a full IBS security proof."}
    def measured(label, action):
        result["current_phase"] = label
        if progress:
            progress(profile_name+": "+label)
        start = perf_counter()
        try:
            return action()
        finally:
            result["timings_seconds"][label] = perf_counter()-start
    started = perf_counter()
    previous = signal.signal(signal.SIGALRM, _deadline)
    signal.alarm(deadline_seconds)
    try:
        public, master = measured("setup_once", lambda: backend.setup(params))
        ring = PaperRing(params)
        result["public_context_sha256"] = public.context.hex()
        result["setup_attempts"] = backend.setup_attempts
        result["analysis_gate_root_redraws"] = 0
        result["checks"]["trapdoor_public_relation"] = ring.build_public(public.a_hat, master.witness) == public.b
        result["checks"]["cbd1_support"] = all(x in (-1, 0, 1) for row in master.witness for poly in row for x in poly)
        # Resolve the deterministic identity/hash before defining its fixed h.
        target = identity_target(public, IDENTITY)
        plan = measured("prepare_same_root", lambda: backend._master_plan(params, master.witness))
        before = source.used
        certificate = measured("certify_same_root", lambda: issuance_certificate(params, plan, backend._components(params)[0]))
        result["issuance_law"] = certificate
        result["checks"]["analysis_consumed_no_entropy"] = before == source.used
        resource = measured("public_resource_preflight", build_report)
        row = next(row for row in resource["rows"] if row["label"] == profile_name+"/table-standard-deviation")
        envelope = row["object_coordinate_envelope_conditional_on_prepared_plans"]
        wire = row["wire_envelope"]
        result["public_finite_support_envelope"] = envelope
        result["public_wire_envelope"] = wire
        result["checks"]["finite_raw_coordinate_guards"] = envelope["raw_within_256bit_ring_input_cap"]
        result["checks"]["finite_hnf_coordinate_guards"] = envelope["hnf_full_key_coordinate_abs_upper"].bit_length() <= 256
        result["checks"]["public_and_key_wire_guards"] = wire["public_fits_wire"] and wire["key_class_fits_wire"]
        result["checks"]["fixed_master_empty_capacity"] = not master.states
        result["checks"]["coarse_c_gate"] = certificate["c_gate"]["certified"]
        # Failure is saved; never select another root to pass this analysis.
        if not all(result["checks"].values()):
            result["status"] = "analysis-inconclusive"
            return result
        key = measured("extract_once_same_root", lambda: backend.key_extract(master, IDENTITY))
        result["checks"]["same_plan_certificate_at_extraction"] = backend.last_master_certificate == plan.public_certificate()
        result["checks"]["key_equation"] = ring.matvec(ring.public_a(public), key.full, params.modulus) == target
        result["checks"]["key_roundtrip"] = SigningKey.from_bytes(key.to_bytes()).to_bytes() == key.to_bytes()
        result["checks"]["one_extraction"] = backend.extract_calls == 1
        result["object_sizes_bytes"] = {"public": len(public.to_bytes()), "key": len(key.to_bytes())}
        delta_text = certificate["complete_law_tv_upper_including_abort"]
        delta = None if delta_text is None else Fraction(delta_text)
        result["mathematical_first_issuance_bound_applies_under_iid_byte_and_no_fault_model"] = (
            delta is not None and delta < 1 and all(result["checks"].values()))
        result["issuance_success_lower_under_same_model"] = None if delta is None else str(1-delta)
        result["conditional_success_vector_tv_upper_under_same_model"] = delta_text
        result["byte_model_experiment_limit"] = "TEST deterministic bytes check execution; probability bounds assume fresh iid uniform bytes, not a theorem about this test seed"
        result["status"] = "completed" if all(result["checks"].values()) else "functional-fail"
    except _RunDeadline:
        result["status"], result["error_type"] = "bounded-deadline", "_RunDeadline"
    except Exception as error:
        result["status"], result["error_type"] = "failed", type(error).__name__
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        result["elapsed_seconds"] = perf_counter()-started
        result["total_entropy_bytes"] = source.used
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--deadline-seconds", type=int, default=300)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists; choose a fresh public receipt path")
    result = audit(args.profile, deadline_seconds=args.deadline_seconds,
                   progress=lambda value: print(value, flush=True))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as receipt:
        receipt.write(json.dumps(result, indent=2, sort_keys=True)+"\n")
    print(json.dumps({"profile": args.profile, "status": result["status"],
        "elapsed_seconds": result["elapsed_seconds"], "output": str(args.output)}), flush=True)
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
