"""Join delivered CHKP gates with the mainline seed contract; never admit.

This is a static integration check, not a new GenBasis implementation, actual
GS measurement, noise experiment or security estimate. The hypothetical
minimum AP09 layout uses the delivered finite implementation's inequalities;
its certificate gives sufficient widths, not an impossibility theorem.
"""

import ast
from dataclasses import asdict
from fractions import Fraction
from hashlib import sha256
import json
from math import isqrt
from pathlib import Path

from .chkp_paper_preflight import PaperCandidate, screen_candidate

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "gpv": "experiments/research/chkp_gpv.py",
    "ap09": "experiments/research/chkp_genbasis.py",
    "cache": "experiments/research/chkp_leaf_cache_types.py",
    "leaf": "experiments/research/chkp_leaf_reference.py",
    "hybrid": "src/ibme/protocol/hybrid_hibe.py",
}


def _source(name):
    return (ROOT / SOURCES[name]).read_text(encoding="utf-8").replace("\r\n", "\n")


def _constant(source, name):
    """Read only literal top-level constants, without importing Sage or exec."""
    for node in ast.parse(_source(source)).body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == name:
                return ast.literal_eval(node.value)
            if isinstance(target, (ast.Tuple, ast.List)):
                for index, item in enumerate(target.elts):
                    if isinstance(item, ast.Name) and item.id == name:
                        return ast.literal_eval(node.value)[index]
    raise ValueError(f"missing literal delivered constant: {source}.{name}")


def minimum_ap09_layout(n, q):
    ell = (q - 1).bit_length()
    d = n * ell + 1
    m1, m2 = d, 2 * n * ell + 2 * d
    remaining = m2 - 2 * n * ell
    w = 1 << (remaining.bit_length() - 1)
    required_scale_squared = Fraction(4 * d * m2, w)
    scale = isqrt(required_scale_squared.numerator // required_scale_squared.denominator)
    if scale * scale < required_scale_squared:
        scale += 1
    return dict(n=n, q=q, random_rows=d, m1=m1, m2=m2, hadamard_scale=scale,
                root_dimension=m1 + m2, level1_dimension=2 * (m1 + m2),
                leaf_dimension=3 * (m1 + m2),
                gs_squared_certificate_upper=max((scale + 3)**2 * d + 5, 8 * n * ell + 2))


def screen_handoff(candidate, *, epsilon_bits=16):
    if not isinstance(candidate, PaperCandidate):
        raise ValueError("need a paper candidate")
    if type(epsilon_bits) is not int or not 2 <= epsilon_bits <= 4096:
        raise ValueError("epsilon_bits must be an exact integer in 2..4096")
    paper = screen_candidate(candidate)
    layout = minimum_ap09_layout(candidate.n, candidate.q)
    cap = _constant("gpv", "MAX_DIMENSION")
    # Hypothetical successful first RandBasis, without optional LLL: use only
    # its published GS upper bound s1^2 * D1, then the GPV C1-exec rule.
    d1, d2 = layout["level1_dimension"], layout["leaf_dimension"]
    factor1 = (2 * d1 * (1 + 2**epsilon_bits) - 1).bit_length()
    factor2 = (2 * d2 * (1 + 2**epsilon_bits) - 1).bit_length()
    s1_squared = 4 * layout["gs_squared_certificate_upper"] * factor1
    s2_squared = 4 * (s1_squared * d1) * factor2
    seed_bytes = _constant("hybrid", "SEED_BYTES")
    cache_bits, batch_bits = _constant("cache", "MAX_CAPACITY"), _constant("leaf", "MAX_LEAF_TARGETS")
    return {
        "scope": "CHKP delivery / mainline static integration gates",
        "candidate": asdict(candidate), "paper_preflight": paper,
        "minimum_finite_ap09_layout": layout,
        "candidate_root_fits_minimum_ap09_layout": candidate.m >= layout["root_dimension"],
        "minimum_ap09_leaf_fits_current_gpv_cap": d2 <= cap,
        "current_gpv_dimension_cap": cap,
        "hypothetical_minimum_layout_sufficient_widths": {
            "epsilon_bits": epsilon_bits, "s1_squared": s1_squared, "s2_squared": s2_squared,
            "same_q_meets_sufficient_leaf_correctness_relation":
                candidate.q**2 >= 16 * s2_squared * (d2 + 1)**2,
            "actual_basis_or_sampling_executed": False,
            "necessary_width_or_impossibility_claim": False,
        },
        "payload_contract": {
            "hybrid_seed_bytes": seed_bytes, "seed_bits_lower_bound": 8 * seed_bytes,
            "current_cache_capacity_bits": cache_bits, "current_leaf_batch_bits": batch_bits,
            "current_single_cache_covers_seed_lower_bound": cache_bits >= 8 * seed_bytes,
            "additional_inner_framing_bits": "not_frozen; can increase requirement",
        },
        "source_lf_sha256": {SOURCES[name]: sha256(_source(name).encode()).hexdigest() for name in SOURCES},
        "backend_admitted": False, "parameters_are_formal": False, "security_claim": "none",
        "unresolved": ["actual GS and public distribution error", "sampling tape/abort and memory",
                       "alpha/noise and actual KEM correctness", "complete H/G and HIBE lifecycle",
                       "256-or-more fixed bit addresses and bounded private wire", "security estimates"],
    }


def main():
    candidates = [PaperCandidate(1, 10, 2, 9064, 15952640),
                  PaperCandidate(2, 64, 65537, 16**2, 64**2)]
    print(json.dumps([screen_handoff(c) for c in candidates], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
