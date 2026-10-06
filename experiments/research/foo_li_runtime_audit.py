"""Reproducible public evidence for research lifecycle and initialization.

All seeds are explicitly TEST-only. Temporary plaintext snapshots are removed
by TemporaryDirectory; no production secrets are created, printed or archived.
Results retain every preselected setup/extraction/signature attempt.
"""
from dataclasses import asdict
from hashlib import sha256
import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from sage.all import QQ
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from .foo_li_initialization import initialization_budget
from .foo_li_runtime_reference import ResearchConfig, ResearchSession, canonical_json, prepare
from .online_gaussian_reference import OnlineOptions
from .online_mp12_reference import OnlineGaussianGenTrap


def test_config():
    return ResearchConfig(options=OnlineOptions(tail_bits=24, mass_bits=64,
        precision_bits=128, gaussian_abort_bits=24, max_uniform_trials=64))


def certificate_report(config):
    generator, master, user, budget = prepare(config)
    c = config
    eps = QQ(c.epsilon0)
    eps_f = 2*eps+eps*eps
    master_cert, user_cert = master.certificate(), user.certificate()
    eps_del = min(QQ(1), c.w*QQ(master_cert["tv_upper_including_abort"]))
    eps_sp = QQ(user_cert["tv_upper_including_abort"])
    tau_master = QQ(1)/2**c.m*(1+eps)/(1-eps)
    tau_signature = QQ(1)/2**(c.m+c.w)*(1+eps_f)/(1-eps_f)
    hash_abort = QQ(c.n*c.w+c.n)/2**c.options.max_uniform_trials
    total = min(QQ(1), QQ(budget["delta_init_upper"])+eps_del+c.w*tau_master+eps_sp+tau_signature+hash_abort)
    return {
        "config": asdict(config), "initialization": budget,
        "master_public_class_sampled_certificate": master_cert,
        "user_public_class_sampled_certificate": user_cert,
        "public_tape_bytes": {"setup": generator.random_tape_bytes,
            "delegation_column": master.random_tape_bytes,
            "delegation_full": c.w*master.random_tape_bytes, "signature": user.random_tape_bytes},
        "conditional_uniform_byte_ideal_RO_budget": {
            "delta_init": budget["delta_init_upper"], "epsilon_del": str(eps_del),
            "w_tau_m": str(c.w*tau_master), "epsilon_SP": str(eps_sp),
            "tau_signature": str(tau_signature), "public_hash_abort": str(hash_abort),
            "total_upper": str(total), "display_total_upper": float(total),
            "actual_SHAKE_failure_bound": None,
            "note": "requires fresh uniform oracle tapes; software tests do not prove this replacement"},
        "class_certificate_method": "public width/quality classes, not secret-specific narrow widths",
        "security_claim": "none",
    }


def audit_report():
    config = test_config()
    attempts = []
    process_replays = []
    all_replays_equal = True
    with tempfile.TemporaryDirectory(prefix="fooli-research-") as folder:
        for attempt in range(3):
            result = ResearchSession.setup(config, b"audit-epoch",
                rng=DeterministicRandom(f"runtime-audit-master-{attempt}".encode()))
            row = {"attempt": attempt, "setup_status": result.status, "users": []}
            attempts.append(row)
            if result.status != "ok":
                continue
            session = result.value
            row["initial_state"] = session.init_state
            row["public_matrix"] = [[int(x) for x in line] for line in session.generated.public.rows()]
            for identity in (b"Alice", b"Bob", "滕佑".encode()):
                outcome = session.extract(identity,
                    seed_rng=DeterministicRandom(f"runtime-audit-user-{attempt}-".encode()+identity))
                user_row = {"identity_hex": identity.hex(), "extract_status": outcome.status, "signatures": []}
                row["users"].append(user_row)
                if outcome.status != "ok":
                    continue
                for message in (b"", b"first", b"second", b"\x00\xff"):
                    signature = session.sign_raw(identity, message)
                    entry = {"message_hex": message.hex(), "status": signature.status}
                    if signature.status == "ok":
                        entry["verified"] = bool(session.verify(identity, message, signature.value))
                        entry["norm_squared"] = sum(x*x for x in signature.value[0])
                        entry["signature_sha256"] = sha256(canonical_json(signature.value)).hexdigest()
                    # Serialize to disk, discard the live issuer, and reconstruct.
                    path = Path(folder)/"research-only-secret.json"
                    path.write_bytes(session.dump_secret_state())
                    if identity == b"Alice" and message == b"first":
                        command = [sys.executable, "-m", "experiments.research.foo_li_runtime_audit",
                            "--replay-secret", str(path), "--identity-hex", identity.hex(), "--message-hex", message.hex()]
                        worker = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
                        replay = json.loads(worker.stdout) if worker.returncode == 0 else None
                        process_replays.append({"setup_attempt": attempt, "exit_code": worker.returncode,
                            "same_signature": replay == {"status": signature.status,
                                "signature_sha256": entry.get("signature_sha256")}, "stderr": worker.stderr})
                    restored = ResearchSession.restore(path.read_bytes())
                    entry["disk_reload_same_secret_state"] = restored.dump_secret_state() == session.dump_secret_state()
                    entry["replayed_identically"] = restored.sign_raw(identity, message) == signature
                    all_replays_equal &= entry["disk_reload_same_secret_state"] and entry["replayed_identically"]
                    session = restored
                    user_row["signatures"].append(entry)
    signatures = [sig for row in attempts for user in row["users"] for sig in user["signatures"]]
    return {
        "schema_version": 1, "security_claim": "none", "production_backend_registered": False,
        "algorithm_scope": "research Foo-Li raw signing lifecycle using existing online MP12",
        "environment": {"python": sys.version.split()[0], "sage": sage_version, "platform": platform.platform(),
            "machine": platform.machine(), "processor": platform.processor(),
            "hardware_acceleration": "not configured or benchmarked; underlying Sage/GMP/MPFR libraries",
            "threads": "no explicit parallel execution"},
        "parameter_source": "hand-selected q=3 wiring controls; NOT safe cryptographic parameters",
        "rng": "DeterministicRandom for ALL experiment seeds; counter-block SHAKE candidate for five domains",
        "rom": "probability table assumes ideal fresh oracle tapes; experiment uses real SHAKE candidate",
        "identity_lengths": [5, 3, 6], "message_lengths": [0, 5, 6, 2],
        "preselected_setup_attempts": 3, "all_attempts": attempts,
        "counts": {"setups_ok": sum(row["setup_status"] == "ok" for row in attempts),
            "extractions_ok": sum(user["extract_status"] == "ok" for row in attempts for user in row["users"]),
            "raw_signature_attempts": len(signatures), "raw_signatures_ok": sum(x["status"] == "ok" for x in signatures),
            "verified": sum(x.get("verified", False) for x in signatures)},
        "all_disk_replays_equal": all_replays_equal,
        "fresh_process_replays": process_replays,
        "debug_certificate": certificate_report(config),
        "prior_round10_initialization_only": initialization_budget(
            OnlineGaussianGenTrap(2147483659, 1, 1), 64, 4095, "1/65536"),
        "independent_new_trials_from_replays": 0,
        "secret_snapshots_archived": False,
        "limitations": ["New initialization derivation is written mathematics plus Sage arithmetic, not a new Lean theorem",
            "No general Python-to-Lean refinement or SHAKE-to-ideal-RO theorem",
            "No authenticated/encrypted/atomic concurrent keystore, signature wire codec or IBSBackend registration",
            "No near-uniform public-key guarantee, formal parameters, SIS estimate or end-to-end IB-ME acceptance",
            "Not a performance benchmark; all failure attempts retained; repeated inputs are not independent trials"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--replay-secret", type=Path)
    parser.add_argument("--identity-hex")
    parser.add_argument("--message-hex")
    args = parser.parse_args()
    if args.replay_secret is not None:
        if args.output or args.run_tests or args.identity_hex is None or args.message_hex is None:
            parser.error("Replay needs identity/message hex and no report options")
        session = ResearchSession.restore(args.replay_secret.read_bytes())
        outcome = session.sign_raw(bytes.fromhex(args.identity_hex), bytes.fromhex(args.message_hex))
        print(json.dumps({"status": outcome.status, "signature_sha256":
            sha256(canonical_json(outcome.value)).hexdigest() if outcome.status == "ok" else None}))
        return 0
    if args.output is None or args.identity_hex is not None or args.message_hex is not None:
        parser.error("Report mode needs --output and no replay identity/message")
    repo = Path(__file__).resolve().parents[2]
    watched = [
        "experiments/research/foo_li_initialization.py", "experiments/research/foo_li_runtime_reference.py",
        "experiments/research/foo_li_runtime_audit.py", "tests/test_foo_li_runtime_reference.py",
        "experiments/research/online_mp12_reference.py", "experiments/research/online_gaussian_reference.py",
        "experiments/research/general_gadget_reference.py", "experiments/research/gaussian_reference.py",
        "experiments/research/mp12_sampled_reference.py", "experiments/research/mp12_trapdoor_chain.py",
        "src/ibme/core/randomness.py", "src/ibme/core/encoding.py", "src/ibme/core/hashing.py",
        "papers/2011_lattice_trapdoors_micciancio.pdf", "papers/2023_tightly_secure_ibs_foo.pdf",
    ]
    def fingerprints():
        return {name: sha256((repo/name).read_bytes()).hexdigest() for name in watched}
    before = fingerprints()
    value = audit_report()
    value["source_sha256"] = before
    if args.run_tests:
        command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
            "tests/test_foo_li_runtime_reference.py", "tests/test_online_sampling_reference.py",
            "tests/test_encoding.py"]
        test = subprocess.run(command, cwd=repo, capture_output=True, text=True, check=False)
        value["tests"] = {"command": ["~/miniconda3/envs/sage/bin/python", *command[1:]],
            "exit_code": test.returncode, "stdout": test.stdout, "stderr": test.stderr}
    value["sources_unchanged_during_run"] = before == fingerprints()
    counts = value["counts"]
    okay = (counts == {"setups_ok": 3, "extractions_ok": 9, "raw_signature_attempts": 36,
        "raw_signatures_ok": 36, "verified": 36} and value["all_disk_replays_equal"] and
        len(value["fresh_process_replays"]) == 3 and all(x["same_signature"] for x in value["fresh_process_replays"]) and
        value["sources_unchanged_during_run"] and value.get("tests", {}).get("exit_code", 0) == 0)
    value["status"] = "PASS_RESEARCH_CHECKS_WITH_OPEN_SECURITY_GATES" if okay else "RESEARCH_CHECKS_FAILED"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": value["status"], "counts": counts,
        "tests": value.get("tests", {}).get("stdout", "not run"),
        "delta_init_debug": float(QQ(value["debug_certificate"]["initialization"]["delta_init_upper"])),
        "delta_init_prior_round10": float(QQ(value["prior_round10_initialization_only"]["delta_init_upper"])),
        "conditional_total_debug": value["debug_certificate"]["conditional_uniform_byte_ideal_RO_budget"]["display_total_upper"],
        "output": str(args.output)}, ensure_ascii=False, indent=2))
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
