"""C2 target-level outer BYTEAUTH tamper/truncation checks.

Uses the persisted target CLI state; outer OTS verification rejects before
the expensive HIBE derive for the cases here. Replay and wrong-identity
behaviour would require separate state/keys and are recorded as not tested.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from time import perf_counter

from ibme.cli import _load_state_meta, _read_state_object, _runtime_for_state
from ibme.protocol.baseline import PublicKey, ReceiverKey, is_bottom

DEFAULT_STATE = Path("/tmp/lai-target-cli")
DEFAULT_CT = Path("/tmp/lai-target-ct.bin")
RECEIVER = "alice"
SENDER = "bob"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--ct", type=Path, default=DEFAULT_CT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/lai-target-byteauth-negative.json"))
    args = parser.parse_args(argv)
    state, ct_path = args.state, args.ct
    meta = _load_state_meta(state)
    proto, classes, _ = _runtime_for_state(meta, False)
    public = PublicKey.from_bytes(
        _read_state_object(state / "mpk.bin", meta, "mpk"),
        classes["hpk"], classes["ipk"])
    # CLI key filenames are digest-derived; use the persisted receiver digest.
    receiver_path = next(state.glob("receiver-*.bin"))
    dk = ReceiverKey.from_bytes(
        _read_state_object(receiver_path, meta, "receiver"), classes["sk1"])
    raw = ct_path.read_bytes()
    ct = proto.load_ciphertext(raw)
    sender = SENDER.encode()
    report = {"state": str(state), "ct_bytes": len(raw), "cases": {},
              "outer_honest": "tested separately by CLI lifecycle",
              "security_claim": "none"}

    def check(name, data):
        t0 = perf_counter()
        try:
            out = proto.decrypt(public, dk, sender, data)
            ok = is_bottom(out)
        except Exception as exc:  # malformed input should normally be BOTTOM
            ok = False
            report["cases"][name] = {"rejected": False,
                                     "error": f"{type(exc).__name__}: {exc}"}
            print(name, "FAIL", type(exc).__name__, exc, flush=True)
            return
        report["cases"][name] = {"rejected": ok,
                                 "seconds": round(perf_counter() - t0, 3)}
        print(name, "rejected" if ok else "ACCEPTED", round(perf_counter() - t0, 3),
              flush=True)

    context = bytearray(ct.context)
    context[0] ^= 1
    check("tampered_context", replace(ct, context=bytes(context)).to_bytes())
    signature = bytearray(ct.signature)
    signature[0] ^= 1
    check("tampered_signature", replace(ct, signature=bytes(signature)).to_bytes())
    inner = bytearray(ct.inner_bytes)
    inner[0] ^= 1
    check("tampered_inner_bytes", replace(ct, inner_bytes=bytes(inner)).to_bytes())
    check("truncated_ct", raw[:-1])
    check("appended_ct", raw + b"\x00")
    report["all_ok"] = all(v["rejected"] for v in report["cases"].values())
    args.output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["all_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
