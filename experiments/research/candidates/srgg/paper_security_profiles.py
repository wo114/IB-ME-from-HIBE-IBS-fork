"""HIBE-independent SRGG security-parameter candidate selection.

The paper's Table 4 rows already carry author-reported target and forgery
bits.  This module turns those rows into an explicit candidate study and
selects a *research security baseline*; it does not change Table 4, claim a
NIST category, or turn author reports into reproduced estimates.

Candidate policy:

* ``PARAM-I``  — 100-bit target, below the 128-bit classical baseline.
* ``PARAM-II`` — 180-bit target / 171-bit reported forgery; selected as the
  smallest implemented Table 4 profile above the 128-bit baseline.
* ``PARAM-III``— 256-bit target / 242-bit reported forgery; retained as the
  high-security option for a >=192-bit baseline.
* New n>512 or p-increase profiles are screened but not selected: the current
  Fourier/Schur implementation gates n<=512, and increasing p alone conflicts
  with the signing-geometry/Q>2*gamma relation.  They are not presented as
  executable security parameters.

All rows keep ``security_claim=none``, ``backend_admitted=false``,
``parameters_are_formal=false`` and ``nist_security_category=null``.  The
selected profile is an author-target research baseline, not a formal
admission: the paper's q/Q/2*gamma mapping, source normalizations and the
native-strong same-message counterexample remain separate open items.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .paper_parameters import PaperParams
from .paper_profiles import profiles


SCHEMA = "IBME/SRGG-PAPER-SECURITY-PROFILES/1"
SELECTED_PROFILE = "PARAM-II"
SELECTED_INTERPRETATION = "table-standard-deviation"
HIGH_SECURITY_PROFILE = "PARAM-III"
BASELINE_CLASSICAL_BITS = 128


@dataclass(frozen=True)
class SecurityCandidate:
    name: str
    implementation_status: str
    author_target_bits: int
    key_recovery_classical_bits: int
    key_recovery_quantum_bits: int
    forgery_classical_bits: int
    forgery_quantum_bits: int
    degree: int
    rank: int
    p: int
    base: int
    digits: int
    Q: int
    gamma: str
    selected: bool
    rationale: str
    caveats: tuple


def _candidate(profile, *, selected=False, rationale="", caveats=(), status="implemented_table4"):
    report = profile.author_report
    return SecurityCandidate(
        name=profile.name,
        implementation_status=status,
        author_target_bits=report.target_bits,
        key_recovery_classical_bits=report.key_recovery_classical_bits,
        key_recovery_quantum_bits=report.key_recovery_quantum_bits,
        forgery_classical_bits=report.forgery_classical_bits,
        forgery_quantum_bits=report.forgery_quantum_bits,
        degree=profile.degree,
        rank=profile.rank,
        p=profile.p,
        base=profile.base,
        digits=profile.digits,
        Q=profile.Q,
        gamma=str(profile.gamma),
        selected=selected,
        rationale=rationale,
        caveats=tuple(caveats),
    )


def candidates():
    """Return implemented candidates followed by non-executable screens."""
    by_name = {profile.name: profile for profile in profiles}
    common = (
        "author-reported bits are not reproduced",
        "q>2*gamma fails under the natural Q mapping",
        "native-strong same-message replacement counterexample remains",
    )
    result = [
        _candidate(by_name["PARAM-I"], rationale=(
            "smallest Table 4 row, but 100-bit target and 103/93-bit reported "
            "forgery are below the 128-bit classical baseline"),
            caveats=common),
        _candidate(by_name["PARAM-II"], selected=True, rationale=(
            "smallest implemented Table 4 row with author-reported forgery "
            "above 128-bit classical (171/155) and key recovery 178/161; "
            "standard-deviation reading has a non-null first-issuance bridge"),
            caveats=common),
        _candidate(by_name["PARAM-III"], rationale=(
            "high-security option for a >=192-bit baseline: 242/219-bit "
            "reported forgery, 255/232-bit key recovery; heavier d=4 profile"),
            caveats=common),
    ]
    result.extend([
        SecurityCandidate(
            name="STATIC-N1024-D4",
            implementation_status="not_executable",
            author_target_bits=0,
            key_recovery_classical_bits=0,
            key_recovery_quantum_bits=0,
            forgery_classical_bits=0,
            forgery_quantum_bits=0,
            degree=1024,
            rank=4,
            p=16383,
            base=31,
            digits=2,
            Q=15744063,
            gamma="not_assigned",
            selected=False,
            rationale=(
                "larger n could raise lattice security, but current "
                "FourierSchurPlan/Schur resource gates require n<=512 and no "
                "reproduced security estimate exists for this construction"),
            caveats=("no executable backend", "no width/gamma allocation",
                     "no security estimate"),
        ),
        SecurityCandidate(
            name="STATIC-P-INCREASE",
            implementation_status="rejected",
            author_target_bits=0,
            key_recovery_classical_bits=0,
            key_recovery_quantum_bits=0,
            forgery_classical_bits=0,
            forgery_quantum_bits=0,
            degree=512,
            rank=4,
            p=262143,
            base=31,
            digits=2,
            Q=262143*961,
            gamma="Table4-PARAM-III",
            selected=False,
            rationale=(
                "increasing p alone can make Q>2*gamma but the HNF head and "
                "signing Schur geometry scale with Q; fixed Table 4 signature "
                "widths no longer cover the user-key class, so this is not a "
                "valid correctness-preserving security profile"),
            caveats=("signing geometry breaks", "widths/gamma would need a "
                     "new allocation", "no security estimate"),
        ),
    ])
    return tuple(result)


def selected_params(interpretation=SELECTED_INTERPRETATION):
    if interpretation not in ("table-standard-deviation", "literal-density-width"):
        raise ValueError("explicit Gaussian interpretation required")
    return PaperParams(SELECTED_PROFILE, interpretation)


def selection_report():
    rows = [asdict(candidate) for candidate in candidates()]
    selected = next(row for row in rows if row["selected"])
    if selected["name"] != SELECTED_PROFILE:
        raise AssertionError("selected candidate and profile constant differ")
    if selected["forgery_classical_bits"] < BASELINE_CLASSICAL_BITS:
        raise AssertionError("selected profile is below the classical baseline")
    return {
        "schema": SCHEMA,
        "selection_policy": {
            "baseline_classical_bits": BASELINE_CLASSICAL_BITS,
            "selected_profile": SELECTED_PROFILE,
            "selected_interpretation": SELECTED_INTERPRETATION,
            "high_security_profile": HIGH_SECURITY_PROFILE,
            "criterion": (
                "smallest implemented Table 4 row whose author-reported "
                "forgery classical bits meet the 128-bit classical baseline; "
                "PARAM-III is retained for a >=192-bit baseline"),
        },
        "candidates": rows,
        "selected": selected,
        "selected_params_record": selected_params().record(),
        "table4_unchanged": {
            "profiles": [profile.name for profile in profiles],
            "degree": 512,
            "p": 16383,
            "base": 31,
            "digits": 2,
            "Q": 15744063,
        },
        "known_gaps": [
            "author target/forgery bits are reports, not reproduced estimates",
            "the paper's q>2*gamma condition is not met by Q under the natural mapping",
            "Q/2Q, zeta factor1/factor2, r/sigma unit and Algorithm 4 d/f ambiguities remain",
            "native-strong has same-message replacement counterexamples",
            "ring-HNF/CRT/subfield attack costs and NIST category are not established",
        ],
        "scope": "research security baseline selection; not a formal admission",
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
    report = selection_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"output": str(args.output),
                      "selected": report["selected"]["name"],
                      "forgery_classical_bits": report["selected"][
                          "forgery_classical_bits"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
