"""Reproduce the SRGG paper's Table 5 concrete-security estimates.

The paper does give the concrete attack model (Section 5.2):

* key recovery: primal attack on the q-ary lattice, dimension d=2m+1,
  short vector (s,e,-1), modulus Q;
* forgery: nearest-colattice approximate-CVP, block size condition
  beta >= min_{k<=d-m} (delta_beta^(d-k) * M^(m/(d-k)) - k),
  where the verification modulus is 2Q;
* Core-SVP cost: 2^(0.292*beta) classical / 2^(0.265*beta) quantum.

This module implements those formulas with explicit dimension mappings and
compares the result with the author-reported Table 5 values.  It is a
reproduction of the *paper's concrete-security model*, not a formal security
proof, not a NIST category, and not a replacement for the Theorem 1
q>2*gamma source audit.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from math import e, pi, sqrt
from pathlib import Path

from .paper_profiles import profiles


SCHEMA = "IBME/SRGG-PAPER-CORE-SVP-REPRODUCTION/1"
TARGET_CLASSICAL_BITS = 128


def delta_beta(beta):
    """BKZ root-Hermite factor from the paper's displayed approximation."""
    if type(beta) is not int or beta <= 50:
        raise ValueError("integer BKZ block size > 50 required")
    return (((pi*beta)**(1/beta))*beta/(2*pi*e))**(1/(2*(beta-1)))


def core_svp_bits(beta):
    """Paper's ADPS16 Core-SVP conversion."""
    return {"classical": round(0.292*beta),
            "quantum": round(0.265*beta),
            "classical_exact": 0.292*beta,
            "quantum_exact": 0.265*beta}


def key_recovery_beta(profile):
    """Smallest beta satisfying the paper's primal key-recovery condition."""
    m = profile.rank * profile.degree
    d = 2*m + 1
    Q = profile.Q
    norm = sqrt(m + 1)  # E||(s,e,-1)|| for CBD1 s,e; public bound, not a secret sample
    for beta in range(51, 4096):
        right = delta_beta(beta)**(2*beta-d-1) * Q**(m/d)
        if norm*sqrt(beta/d) <= right:
            return beta, m, d, Q, norm
    raise ValueError("key-recovery formula produced no block size in range")


def forgery_rhs(beta, d, m, modulus):
    """min_{k<=d-m} delta_beta^(d-k) * modulus^(m/(d-k)) - k."""
    values = [delta_beta(beta)**(d-k) * modulus**(m/(d-k)) - k
              for k in range(0, d-m+1)]
    return min(values)


def forgery_beta(profile):
    """Smallest beta whose approximate-CVP output fits the response bound."""
    columns = (2 + profile.digits) * profile.rank
    d = (columns + 1) * profile.degree
    m = profile.rank * profile.degree
    modulus = 2 * profile.Q  # verification relation uses 2Q
    gamma = float(profile.gamma)
    for beta in range(51, 4096):
        if forgery_rhs(beta, d, m, modulus) <= gamma:
            return beta, m, d, modulus, gamma
    raise ValueError("forgery formula produced no block size in range")


@dataclass(frozen=True)
class ReproductionRow:
    profile: str
    key_author_beta: int
    key_reproduced_beta: int
    key_author_classical: int
    key_author_quantum: int
    key_reproduced_classical: int
    key_reproduced_quantum: int
    forgery_author_beta: int
    forgery_reproduced_beta: int
    forgery_author_classical: int
    forgery_author_quantum: int
    forgery_reproduced_classical: int
    forgery_reproduced_quantum: int
    meets_128_classical_euf_cma: bool


def reproduction_rows():
    rows = []
    for profile in profiles:
        kb, km, kd, kq, knorm = key_recovery_beta(profile)
        fb, fm, fd, fmod, fgamma = forgery_beta(profile)
        kb_bits = core_svp_bits(kb)
        fb_bits = core_svp_bits(fb)
        author = profile.author_report
        rows.append(ReproductionRow(
            profile=profile.name,
            key_author_beta=author.key_recovery_bkz,
            key_reproduced_beta=kb,
            key_author_classical=author.key_recovery_classical_bits,
            key_author_quantum=author.key_recovery_quantum_bits,
            key_reproduced_classical=kb_bits["classical"],
            key_reproduced_quantum=kb_bits["quantum"],
            forgery_author_beta=author.forgery_bkz,
            forgery_reproduced_beta=fb,
            forgery_author_classical=author.forgery_classical_bits,
            forgery_author_quantum=author.forgery_quantum_bits,
            forgery_reproduced_classical=fb_bits["classical"],
            forgery_reproduced_quantum=fb_bits["quantum"],
            meets_128_classical_euf_cma=fb_bits["classical"] >= TARGET_CLASSICAL_BITS,
        ))
    return tuple(rows)


def build_report():
    rows = [asdict(row) for row in reproduction_rows()]
    by_name = {row["profile"]: row for row in rows}
    selected = by_name["PARAM-II"]
    return {
        "schema": SCHEMA,
        "paper_locations": "Section 5.2 pp.9-10; Table 5 p.10",
        "formulas": {
            "delta_beta": "(((pi beta)^(1/beta) beta)/(2 pi e))^(1/(2(beta-1)))",
            "key_recovery": "||(s,e,-1)|| sqrt(beta/d) <= delta_beta^(2 beta-d-1) Q^(m/d), d=2m+1",
            "forgery": "beta >= min_{k<=d-m} (delta_beta^(d-k) M^(m/(d-k)) - k), M=2Q",
            "core_svp": "classical=round(0.292 beta), quantum=round(0.265 beta)",
        },
        "dimension_mapping": {
            "key_recovery": "m=rank*n; d=2m+1; modulus=Q; norm=sqrt(m+1) (E||(s,e,-1)|| for CBD1)",
            "forgery": "m=rank*n; d=((2+w)rank+1)*n; modulus=2Q; target=gamma",
        },
        "rows": rows,
        "selected_profile": "PARAM-II",
        "selected_row": selected,
        "target": {
            "classical_bits": TARGET_CLASSICAL_BITS,
            "claim": "128-bit classical EUF-CMA concrete-security target",
            "selected_meets_target": selected["meets_128_classical_euf_cma"],
            "selected_forgery_classical_bits": selected["forgery_reproduced_classical"],
            "selected_forgery_quantum_bits": selected["forgery_reproduced_quantum"],
        },
        "reproduction_assessment": {
            "key_recovery_matches_within_beta": max(abs(row["key_reproduced_beta"]-row["key_author_beta"]) for row in rows),
            "forgery_matches_within_beta": max(abs(row["forgery_reproduced_beta"]-row["forgery_author_beta"]) for row in rows),
            "author_reported_values_reproduced": "approximate; small beta differences remain",
        },
        "known_gaps": [
            "Theorem 1 q>2*gamma source mapping is not repaired by the concrete estimate",
            "native strong same-message replacement counterexample remains; target is EUF-CMA only",
            "structural ring-HNF/CRT/subfield attack costs are not estimated here",
            "author C/ANS sampler and performance not reproduced",
            "not a NIST category or formal parameter admission",
        ],
        "scope": "paper concrete-security model reproduction and 128-bit PARAM-II decision",
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("output path already exists")
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"output": str(args.output),
                      "selected": report["selected_profile"],
                      "meets_128": report["target"]["selected_meets_target"],
                      "forgery_classical": report["target"]["selected_forgery_classical_bits"]},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
