"""Generate a sanitized C2 target receipt from a fresh target CLI state.

The receipt contains hashes, sizes, timings and verdicts only; it never stores
private keys, state file contents, ciphertext bytes, or plaintext.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from time import perf_counter

REPO = Path(__file__).resolve().parents[4]
RECEIVER = "alice"
SENDER = "bob"
WRONG_RECEIVER = "carol"
WRONG_SENDER = "mallory"


def validate_c2_meta(meta: dict) -> dict:
    """Reject another suite before labeling its execution as the C2 recipe."""
    from ibme.assembly import SuiteConfig
    from ibme.hibe.lai.params import LaiParams, TARGET_CANDIDATE_PARAMS
    from ibme.hibe.lai.registration import ASSEMBLY_VERSION
    config = SuiteConfig.from_dict(meta.get("suite"))
    suite = config.to_dict()
    if (suite["hibe"] != "lai-ideal-hibe" or suite["hibe_version"] != ASSEMBLY_VERSION
            or LaiParams(**suite["hibe_params"]) != TARGET_CANDIDATE_PARAMS
            or suite["ibs"] != "luo-module" or suite["transport"] != "hybrid"
            or suite["protocol"] != "byteauth-v1" or meta.get("suite_digest") != config.digest):
        raise ValueError("receipt requires the exact C2 + Luo Hybrid BYTEAUTH suite")
    return suite


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cli_env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = "src:."
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def run_decrypt(name: str, state: Path, ct: Path, receiver: str, sender: str,
                out: Path, log: Path) -> dict:
    start = perf_counter()
    process = subprocess.run(
        [sys.executable, "-m", "ibme.cli", "decrypt",
         "--receiver", receiver, "--sender", sender,
         "--in", str(ct), "--out", str(out), "--state", str(state)],
        cwd=REPO, env=cli_env(), capture_output=True, text=True, timeout=1800)
    text = (process.stdout or "") + (process.stderr or "")
    log.write_text(text, encoding="utf-8")
    output = out if out.exists() else None
    return {"rc": process.returncode,
            "seconds": round(perf_counter() - start, 2),
            "bottom": "BOTTOM" in text.splitlines(),
            "output_bytes": output.stat().st_size if output else 0,
            "output_sha256": sha256_file(output) if output else None}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--ct", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--message", type=Path, default=None)
    parser.add_argument("--setup-log", type=Path, default=None)
    args = parser.parse_args(argv)
    state = args.state.resolve()
    ct = args.ct.resolve()
    message = (args.message or (state / "message.bin")).resolve()
    for name, path in (("state", state), ("ciphertext", ct), ("message", message)):
        if not path.exists():
            raise SystemExit(f"missing {name}: {path}")
    if not (state / "state.json").exists():
        raise SystemExit("state.json missing; run target_state_setup.sh first")
    if not any(state.glob("receiver-*.bin")):
        raise SystemExit("receiver key missing; run target_state_setup.sh first")
    if len(list(state.glob("receiver-*.bin"))) < 2:
        raise SystemExit("two receiver keys required (alice + carol)")
    if not any(state.glob("sender-*.bin")):
        raise SystemExit("sender key missing; run target_state_setup.sh first")

    meta = json.loads((state / "state.json").read_text(encoding="utf-8"))
    suite = validate_c2_meta(meta)
    receipt = {
        "schema": "IBME/LAI/C2-TARGET-RECEIPT/1",
        "date": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "platform": sys.platform,
            "python": sys.version.split()[0],
        },
        "parameters": suite.get("hibe_params"),
        "suite_digest": suite.get("suite_digest") or meta.get("suite_digest"),
        "capacity": meta.get("capacity"),
        "state_bytes": sum(p.stat().st_size for p in state.rglob("*") if p.is_file()),
        "state_file_count": sum(1 for p in state.rglob("*") if p.is_file()),
        "ct_bytes": ct.stat().st_size,
        "ct_sha256": sha256_file(ct),
        "message_bytes": message.stat().st_size,
        "message_sha256": sha256_file(message),
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "target_c2_rerun_this_batch": True,
    }

    if args.setup_log and args.setup_log.exists():
        text = args.setup_log.read_text(encoding="utf-8", errors="replace")
        receipt["setup"] = {
            m.group(1): {"rc": int(m.group(2)), "seconds": int(m.group(3))}
            for m in re.finditer(r"^(\w+) rc=(\d+) sec=(\d+)$", text, re.M)}
    else:
        receipt["setup"] = {}

    with tempfile.TemporaryDirectory(prefix="lai-c2-receipt-") as tmp:
        work = Path(tmp)
        honest_out = work / "honest.out"
        receipt["honest"] = run_decrypt(
            "honest", state, ct, RECEIVER, SENDER, honest_out, work / "honest.log")
        receipt["honest"]["matches"] = (
            receipt["honest"]["rc"] == 0
            and honest_out.exists()
            and sha256_file(honest_out) == receipt["message_sha256"])
        receipt["honest"].pop("output_sha256", None)

        cases = {
            "wrong_receiver": (WRONG_RECEIVER, SENDER),
            "wrong_sender": (RECEIVER, WRONG_SENDER),
            "both_wrong": (WRONG_RECEIVER, WRONG_SENDER),
        }
        copies = {}
        for name in cases:
            copies[name] = work / name
            shutil.copytree(state, copies[name])

        def run_case(item):
            name, (receiver, sender) = item
            out = work / f"{name}.out"
            result = run_decrypt(name, copies[name], ct, receiver, sender,
                                 out, work / f"{name}.log")
            result.pop("output_sha256", None)
            return name, result

        with ThreadPoolExecutor(max_workers=3) as pool:
            receipt["wrong_identity"] = dict(pool.map(run_case, cases.items()))

        tamper_out = work / "byteauth.json"
        process = subprocess.run(
            [sys.executable, "experiments/research/candidates/lai/target_byteauth_negative.py",
             "--state", str(state), "--ct", str(ct), "--output", str(tamper_out)],
            cwd=REPO, env=cli_env(), capture_output=True, text=True, timeout=300)
        if tamper_out.exists():
            tamper = json.loads(tamper_out.read_text(encoding="utf-8"))
            receipt["outer_tamper"] = {
                "rc": process.returncode,
                "all_ok": tamper.get("all_ok"),
                "cases": tamper.get("cases", {}),
            }
        else:
            receipt["outer_tamper"] = {"rc": process.returncode, "all_ok": False,
                                       "error": "tamper subprocess did not produce a receipt"}

    wrong_ok = all(case["bottom"] and case["rc"] == 1 and case["output_bytes"] == 0
                   for case in receipt["wrong_identity"].values())
    receipt["all_ok"] = bool(
        receipt["honest"]["matches"]
        and wrong_ok
        and receipt["outer_tamper"].get("all_ok")
        and receipt["outer_tamper"]["rc"] == 0)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps({"output": str(args.output), "all_ok": receipt["all_ok"],
                      "honest_matches": receipt["honest"]["matches"],
                      "wrong_identity_ok": wrong_ok,
                      "outer_tamper_ok": receipt["outer_tamper"].get("all_ok")}))
    return 0 if receipt["all_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
