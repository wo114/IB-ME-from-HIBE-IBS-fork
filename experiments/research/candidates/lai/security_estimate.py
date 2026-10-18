"""Complete attack-set PLWE estimate for the selected Lai C2/C3 candidates.

Run with the prescribed Sage environment and the pinned external estimator.
The GSA shape model is used for the complete attack set because the LGSA
hybrid path hits an estimator math-domain error at C2 q.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from time import perf_counter

ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
CANDIDATES = (
    ("c2-2048-2p38", 2048, 274877976577, 39),
    ("c3-2048-2p39", 2048, 549755904001, 40),
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator-path", type=Path,
                        default=Path.home() / "lattice-estimator")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    sys.path.insert(0, str(args.estimator_path))
    from estimator import LWE, ND
    from estimator.reduction import ADPS16
    from sage.all import log, oo

    commit = subprocess.run(["git", "-C", str(args.estimator_path), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    if commit != ESTIMATOR_COMMIT:
        raise SystemExit(f"unexpected estimator commit: {commit}")
    report = {"schema": "IBME/LAI/PLWE-ATTACKS/1", "estimator_commit": commit,
              "model": "PLWE coefficient LWE, m=(l+k)n, Xs=D(2), Xe=D(4)",
              "target_bits": 128, "candidates": {},
              "security_claim": "none", "backend_admitted": False}
    for name, n, q, k in CANDIDATES:
        entry = {"n": n, "q": str(q), "q_bits": q.bit_length(), "k": k,
                 "m": (2 + k) * n, "shapes": {}}
        for shape in ("gsa", "lgsa"):
            for mode in ("classical", "quantum"):
                t0 = perf_counter()
                params = LWE.Parameters(n=n, m=(2 + k) * n, q=q,
                                        Xs=ND.DiscreteGaussian(2.0),
                                        Xe=ND.DiscreteGaussian(4.0), tag=name)
                try:
                    result = LWE.estimate(
                        params, red_cost_model=ADPS16(mode=mode),
                        red_shape_model=shape,
                        deny_list=("arora-gb", "bkw"),
                        catch_exceptions=False, quiet=True)
                    bits = {attack: round(float(log(value["rop"], 2)), 2)
                            for attack, value in result.items() if value["rop"] != oo}
                    entry["shapes"].setdefault(shape, {})[mode] = {
                        "attacks": bits, "best": min(bits.values()) if bits else None,
                        "seconds": round(perf_counter() - t0, 2)}
                except Exception as exc:
                    entry["shapes"].setdefault(shape, {})[mode] = {
                        "error": f"{type(exc).__name__}: {exc}",
                        "seconds": round(perf_counter() - t0, 2)}
                print(name, shape, mode, entry["shapes"][shape][mode], flush=True)
        report["candidates"][name] = entry
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps({"output": str(args.output), "estimator_commit": commit}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
