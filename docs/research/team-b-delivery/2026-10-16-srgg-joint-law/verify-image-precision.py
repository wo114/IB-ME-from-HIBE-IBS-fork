"""Exact arithmetic receipt for the sharper theta/image bound in this batch.

This does not run a sampler or quantum algorithm, estimate hardness, or change
parameters. The original GSO/kernel proof and the new quantum lemma must be
reviewed separately. Output is exclusive; old receipts are never overwritten.
"""
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
import argparse
import json


ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / "docs/research/team-b-delivery/2026-10-16-srgg-bridge/integrated-bridge.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def report():
    data = SOURCE.read_bytes()
    source = json.loads(data)
    profiles = [p for p in source["profiles"] if p["profile"] == "query-bounded-deep"]
    require(len(profiles) == 1, "unique deep source profile required")
    profile = profiles[0]
    reference = profile["full_kernel_reference"]
    dimension = reference["dimension"]
    width_ratio = Fraction(reference["normalized_kernel_width_squared_lower"])
    shape = 157
    require(type(dimension) is int and dimension == 10240, "frozen dimension mismatch")
    require(shape <= width_ratio < shape+1, "frozen normalized width mismatch")
    # pi > 4 log(2): pi > 3 and log(2) < 3/4 by strict trapezoid
    # integration of the convex function 1/t on [1,2].
    a = Fraction(1, 1 << (4*shape))
    theta_tail = 2*a/(1-a**3)
    x = dimension*theta_tail
    require(x < 1, "nontrivial theta product bound required")
    epsilon = x/(1-x)
    image_tv = epsilon/(1-epsilon)
    contamination = 2*epsilon/(1+epsilon)
    require(epsilon < Fraction(1, 1 << 613), "dual mass target failed")
    require(image_tv < Fraction(1, 1 << 613), "image target failed")
    require(contamination < Fraction(1, 1 << 612), "minorization target failed")
    queries = 1 << 40
    advantage_squared = 4*queries**2*contamination
    require(advantage_squared < Fraction(1, 1 << 530), "quantum target failed")
    return {
        "schema": "IBME/SRGG-IDEAL-IMAGE-PRECISION/1",
        "source": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "source_sha256": sha256(data).hexdigest(),
        "profile": profile["profile"],
        "dimension": dimension,
        "normalized_width_squared_lower": str(width_ratio),
        "integer_shape": shape,
        "theta_a_upper": str(a),
        "theta_tail_upper": str(theta_tail),
        "dual_mass_upper": str(epsilon),
        "dual_mass_strictly_below_2exp": -613,
        "image_tv_upper": str(image_tv),
        "image_tv_strictly_below_2exp": -613,
        "contamination_upper": str(contamination),
        "contamination_strictly_below_2exp": -612,
        "row_queries": queries,
        "quantum_comparison_squared_upper": str(advantage_squared),
        "quantum_comparison_strictly_below_2exp": -265,
        "sampler_calls": 0,
        "random_bytes": 0,
        "scope": "ideal independent latent rows only; excludes finite issuance, target programming, collapsing and hardness",
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(report(), indent=2, sort_keys=True)+"\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
