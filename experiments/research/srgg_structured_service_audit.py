"""Real standalone structured issuer lifecycle; reports never contain secrets."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from time import perf_counter

from sage.version import version as sage_version

from ibme.core.randomness import SecureRandom
from ibme.ibs.srgg.structured import Backend, FixedIssuer, Parameters, PublicKey, SigningKey, Signature
from ibme.ibs.srgg_structured_service import _preflight
from experiments.research.candidates.srgg.formal_candidates import conditional_candidate
from experiments.research.gaussian_reference import SamplingAbort


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "IBME/SRGG-STRUCTURED-SERVICE-AUDIT/1"
PARENT_ENTROPY_CAP = 512*1024*1024
CHILD_ENTROPY_CAP = 256*1024*1024


class AuditEntropy:
    """Bound the whole lifecycle separately from each individual request.

    The frozen execution counter caps a whole audit at 256 MiB. Two issuances
    and two maximally retried signatures need a larger parent envelope; no
    individual request or production sampler limit is enlarged here.
    """
    def __init__(self, source, maximum):
        if type(maximum) is not int or not 1 <= maximum <= PARENT_ENTROPY_CAP:
            raise ValueError("bounded audit entropy limit required")
        self.source, self.maximum, self.used = source, maximum, 0

    def read(self, size):
        if type(size) is not int or not 0 <= size <= CHILD_ENTROPY_CAP:
            raise ValueError("bounded individual entropy request required")
        if self.used+size > self.maximum:
            raise SamplingAbort("whole service audit entropy cap exhausted")
        data = self.source.read(size)
        if type(data) is not bytes or len(data) != size:
            raise ValueError("invalid audit entropy response")
        self.used += size
        return data


class NoEntropy:
    def read(self, size):
        raise AssertionError("cache/verification must consume no entropy")


class NoIssueBackend(Backend):
    def setup(self, params):
        raise AssertionError("reopened issuer must not setup")

    def key_extract(self, master, identity):
        raise AssertionError("reopened cache must not extract")


def worker(path, identity, key_digest, public_digest):
    """Fresh-process restoration, cache reuse and fresh production signature."""
    issuer = FixedIssuer(path, backend=NoIssueBackend(rng=NoEntropy()))
    public = issuer.public_key()
    key = issuer.key_extract(bytes.fromhex(identity))
    source = AuditEntropy(SecureRandom(), CHILD_ENTROPY_CAP)
    message = b"SRGG restored in a fresh process"
    signature = Backend(rng=source).sign(key, message)
    checks = {
        "public_equal": sha256(public.to_bytes()).hexdigest() == public_digest,
        "key_equal": sha256(key.to_bytes()).hexdigest() == key_digest,
        "restored_sign_verify": Backend(rng=NoEntropy()).verify(public, key.identity, message, signature),
    }
    return {"checks": checks, "completed": all(checks.values()), "entropy_bytes": source.used}


def audit(degree=8):
    rank, digits = (2, 8) if degree == 512 else (1, 3)
    params = Parameters.from_candidate(conditional_candidate(degree=degree, rank=rank, digits=digits))
    source = AuditEntropy(SecureRandom(), PARENT_ENTROPY_CAP)
    backend = Backend(rng=source)
    checks, times, sizes = {}, {}, {}
    result = {"schema": SCHEMA, "parameters": asdict(params), "Q": params.modulus,
        "environment": {"platform": platform.platform(), "python": platform.python_version(), "sage": sage_version},
        "roots_requested": 1, "new_identities_requested": 2, "identity_lengths": [13, 11],
        "message_lengths": [32, 65536, len(b"SRGG restored in a fresh process")], "new_signatures_requested": 3,
        "production_randomness": True, "root_reselection": False, "key_reselection": False,
        "numerical_profile": "query-bounded-deep", "oracle_model": "classical SHAKE research execution",
        "temporary_trusted_plaintext_state": True, "private_payloads_exported": False,
        "snapshot_capacity_users": 2, "snapshot_capacity_bytes": 2*1024*1024,
        "parent_entropy_cap_bytes": source.maximum, "child_entropy_cap_bytes": CHILD_ENTROPY_CAP,
        "extra_audit_abort_probability_certified": False,
        "extra_global_entropy_cap_abort_probability_certified": degree == 512,
        "extra_global_entropy_cap_abort_upper": 0 if degree == 512 else None,
        "global_cap_certificate_scope": "n512 lifecycle only; finite local sampler limits remain",
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "nist_security_category": None, "completed": False,
        "checks": checks, "timings_seconds": times, "wire_bytes": sizes}
    source_names = ["experiments/research/candidates/srgg/"+name for name in (
        "structured_backend.py", "structured_execution.py", "structured_samplef.py", "wide_scalar.py",
        "aggregate_budget.py", "formal_candidates.py")]+[
        "src/ibme/ibs/srgg_structured_service.py", "src/ibme/ibs/srgg_service.py",
        "src/ibme/ibs/srgg/structured.py", "src/ibme/ibs/srgg/structured_registration.py",
        "experiments/research/srgg_structured_service_audit.py"]
    result["source_sha256"] = {name: sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names}
    stage, started = "preflight", perf_counter()
    try:
        sizes["conservative_snapshot_envelope"] = _preflight(params, 2)
        with tempfile.TemporaryDirectory(prefix="ibme-srgg-structured-audit-") as temporary:
            path = Path(temporary)/"issuer"
            issuer = FixedIssuer(path, backend=backend, expected_params=params)
            stage, tick = "setup-persist", perf_counter()
            public = issuer.initialize(params, max_users=2)
            times[stage] = perf_counter()-tick
            checks["public_roundtrip"] = PublicKey.from_bytes(public.to_bytes()) == public
            sizes["public"] = len(public.to_bytes())
            keys = []
            for i, identity in enumerate((b"research-user", b"second-user")):
                stage, tick = "extract-persist-"+str(i), perf_counter()
                key = issuer.key_extract(identity)
                keys.append(key)
                times[stage] = perf_counter()-tick
                sizes["key-"+str(i)] = len(key.to_bytes())
                checks["key_roundtrip_"+str(i)] = SigningKey.from_bytes(key.to_bytes()) == key
                message = bytes(range(32)) if i == 0 else b"m"*65536
                stage, tick = "sign-"+str(i), perf_counter()
                signature = backend.sign(key, message)
                times[stage] = perf_counter()-tick
                sizes["signature-"+str(i)] = len(signature.to_bytes())
                stage, tick = "verify-negative-"+str(i), perf_counter()
                verifier = Backend(rng=NoEntropy())
                checks["honest_"+str(i)] = verifier.verify(public, identity, message, signature)
                checks["signature_roundtrip_"+str(i)] = backend.load_signature(public, signature.to_bytes()) == signature
                checks["wrong_identity_"+str(i)] = not verifier.verify(public, identity+b"!", message, signature)
                changed_message = message[:-1]+b"!"
                checks["wrong_message_"+str(i)] = not verifier.verify(public, identity, changed_message, signature)
                random_bytes = source.read((params.columns+2)*params.degree)
                response = tuple(tuple((x & 1)-((x >> 1) & 1) for x in
                    random_bytes[j*params.degree:(j+1)*params.degree]) for j in range(params.columns+1))
                random_signature = Signature(public.context, response, tuple(x & 1 for x in random_bytes[-params.degree:]))
                checks["random_signature_"+str(i)] = not verifier.verify(public, identity, message, random_signature)
                times[stage] = perf_counter()-tick
            stage, tick = "reopen-cache", perf_counter()
            reopened = FixedIssuer(path, backend=NoIssueBackend(rng=NoEntropy()),
                expected_public=public, expected_params=params)
            checks["reopen_public"] = reopened.public_key() == public
            checks["reopen_cache"] = all(reopened.key_extract(key.identity) == key for key in keys)
            times[stage] = perf_counter()-tick
            sizes["final_snapshot"] = (path/"master.bin").stat().st_size
            checks["snapshot_within_envelope"] = sizes["final_snapshot"] <= sizes["conservative_snapshot_envelope"]
            stage, tick = "fresh-process-restore-sign", perf_counter()
            process = subprocess.run([sys.executable, "-m", "experiments.research.srgg_structured_service_audit",
                "--worker", str(path), keys[0].identity.hex(), sha256(keys[0].to_bytes()).hexdigest(),
                sha256(public.to_bytes()).hexdigest()], cwd=ROOT, capture_output=True, text=True, timeout=120)
            checks["fresh_process_exit"] = process.returncode == 0
            if process.returncode == 0:
                result["fresh_process"] = json.loads(process.stdout)
                checks["fresh_process_lifecycle"] = result["fresh_process"]["completed"]
            times[stage] = perf_counter()-tick
            result["completed"] = all(checks.values())
    except Exception as exc:
        # Never serialize exception text: a backend may include private values.
        result.update(failed_stage=stage, failure_type=type(exc).__name__)
    result["total_seconds"] = perf_counter()-started
    result["actual_main_entropy_bytes"] = source.used
    try:
        import resource
        result["parent_peak_rss_KiB"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result["child_peak_rss_KiB"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    except ImportError:
        result["parent_peak_rss_KiB"] = result["child_peak_rss_KiB"] = None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--degree", type=int, choices=(8, 512), default=8)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", nargs=4, metavar=("PATH", "IDENTITY_HEX", "KEY_DIGEST", "PUBLIC_DIGEST"))
    args = parser.parse_args()
    result = worker(*args.worker) if args.worker else audit(args.degree)
    text = json.dumps(result, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    else:
        print(text, end="")
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
