"""SIS cost scan for candidate MP12-root-basis Wang-PW parameters."""
from math import log
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "test-results" / "lattice-estimator"))

from estimator import SIS  # noqa: E402
from estimator.reduction import ADPS16  # noqa: E402

Q32 = 4294967291
Q64 = 18446744073709551557

CANDIDATES = [
    ("n256-q32", 256, Q32, 16384, [2**16, 2**17, 2**18]),
    ("n256-q64", 256, Q64, 32768, [2**17, 2**18, 2**19]),
    ("n512-q32", 512, Q32, 32768, [2**17, 2**18, 2**19]),
    ("n512-q64", 512, Q64, 65536, [2**18, 2**19, 2**20]),
]


def main():
    for name, n, q, m, bounds in CANDIDATES:
        for bound in bounds:
            params = SIS.Parameters(n=n, m=m, q=q, length_bound=bound, norm=2, tag=name)
            row = {"name": name, "n": n, "q_bits": q.bit_length(), "m": m,
                   "beta_log2": round(log(bound, 2), 2)}
            for mode in ("classical", "quantum"):
                result = SIS.estimate(params, red_cost_model=ADPS16(mode=mode),
                                      red_shape_model="lgsa", catch_exceptions=False, quiet=True)
                finite = [c["rop"] for c in result.values() if c["rop"] != float("inf")]
                row[mode] = round(float(log(min(finite), 2)), 2) if finite else None
            print(row, flush=True)


if __name__ == "__main__":
    main()
