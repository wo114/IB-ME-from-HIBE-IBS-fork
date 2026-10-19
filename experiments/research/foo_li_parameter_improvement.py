"""Systematic parameter-improvement search for the Foo-Li matrix-SIS route.

Three questions beyond the 2026-10-06 hand-picked 36-point audit:

1. Does a selected grid of (q, n, m_bar, generation width) inside the
   delivered backend's gates yield a candidate window? The grid does not
   cover all legal shapes or widths and its float prefilter is not a proof.
   The audit fixed the generation width at 16 and used an automatic m_bar
   family; both levers are explored here within the declared grid.
2. Which points survive the exact standard-LLL exclusion bound?
3. Beyond the gates: which smallest points carry >=128-bit core-SVP SIS
   hardness (Chen-Nguyen root-Hermite delta, 0.292b classical / 0.265b
   quantum), and by how much do they violate each gate?

Method: a float mirror of the exact screen's monotone constraints brackets a
candidate window per (q, n, width); every reported point is then re-verified
by the original MPFI ``screen``.  Hardness numbers are core-SVP
approximations, not estimator runs and not security admissions.  No keys,
matrices or signatures are produced here.
"""

from __future__ import annotations

import argparse
from math import isfinite, log2, pi, sqrt
from pathlib import Path
import platform
import sys

from sage.all import previous_prime

from experiments.research.foo_li_parameter_screen import (
    FIELD, interval_upper, screen)

GAMMA = 5
QUALITY_CAP = 10**12
SIGMA_CAP = 2**40
DIM_CAP = 128
Q_CAP = 2**32


def mp12_r_squared(w, bits):
    """MP12 part of the smoothing width; the exact screen also applies C2."""

    inner = 2**(-(bits + (max(w - 1, 0)).bit_length() + 8))
    need = interval_upper((FIELD(2*w*(1+1/inner))).log()/FIELD.pi())
    return max(1, int(need.ceil()))


def float_window(q, n, g, bits):
    """Heuristic float bracket of selected constraints -> (lo, hi, notes).

    The regularity target includes a four-bit margin, uses binary floats,
    and the cap estimate uses only the MP12 part of the exact width. An empty
    bracket is not a rigorous rejection certificate. The exact screen
    checks retained candidates; discarded points have not been checked.
    """

    k = (q - 1).bit_length()
    w = n * k
    c = min(1.0, 1.0 / q + 1.0 / sqrt(g))
    if c >= 1.0:
        return None
    logc = -log2(c)
    if logc <= 0:
        return None
    # Regularity: log2(w)-1+(n*log2 q + m_bar*log2 c)/2 <= -bits.
    numerator = n * log2(q) + 2 * (bits + 4 + log2(w) - 1)
    lo = max(w, int(numerator / logc))
    if lo > 128 - 2 * w:
        return None
    hi = 128 - 2 * w
    if hi < lo or hi < w:
        return None
    r2 = mp12_r_squared(w, bits)
    # Caps grow with m_bar; find the largest m_bar with all caps holding.
    cap = QUALITY_CAP
    limit = hi
    notes = []
    for m_bar in range(hi, lo - 1, -1):
        m = m_bar + w
        q0 = m_bar * w * g
        s2 = r2 * (GAMMA + 2) * (q0 + 1)
        q1 = m * w * s2
        t2 = r2 * (GAMMA + 2) * (q1 + 1)
        if max(q0, q1) <= cap and max(s2, t2) <= cap and \
                (GAMMA + 2) * (max(q0, q1) + 1) <= SIGMA_CAP:
            limit = m_bar
            break
    else:
        return None
    if limit < lo:
        return None
    return lo, limit, {"r_squared": r2}


def core_svp_delta(b):
    """Chen-Nguyen root-Hermite factor for BKZ block size b."""

    # Reference: lattice-estimator e4333d9, estimator/reduction.py:72.
    return ((pi * b) ** (1.0 / b) * b / (2 * pi * 2.718281828459045)) ** (1.0 / (2 * (b - 1)))


def core_svp_sis(q, n_rows, m_cols, log2_beta, *, quantum=False):
    """Smallest BKZ block size solving SIS; core-SVP bits = 0.292/0.265 * (b-1).

    Standard q-ary attack model: pick d' in (n_rows, m_cols] columns, lattice
    det q^n_rows; BKZ-b reaches norm ~ delta^d' * q^(n_rows/d').  The attack
    wins when that drops to beta=2^log2_beta; the optimal d' minimises it.
    Documented heuristic approximation, matching the project's prior
    cost-model tier; not an estimator run and not a security admission.
    """

    if log2_beta <= 0:
        return 0.0, 0, 0
    logq = log2(q)

    def best_lognorm(b):
        delta = core_svp_delta(b)
        logdelta = log2(delta)
        d_star = max(n_rows + 1, min(m_cols, int(sqrt(n_rows * logq / logdelta)) + 1))
        return min(d_star * logdelta + (n_rows * logq) / d_star,
                   m_cols * logdelta + (n_rows * logq) / m_cols), d_star

    low, high = 53, 1200
    best = None
    while low <= high:
        mid = (low + high) // 2
        lognorm, d_star = best_lognorm(mid)
        if lognorm <= log2_beta:
            best = (mid, d_star)
            high = mid - 1
        else:
            low = mid + 1
    rate = 0.265 if quantum else 0.292
    if best is None:
        # A search limit is not an exact attack cost. The evidence serializer
        # represents this censored result as null and never selects it as a
        # confirmed >=128-bit target of this heuristic model.
        return float('inf'), None, None
    b_attack, d_star = best
    return rate * (b_attack - 1), b_attack, d_star


def exact_case(q, n, g, m_bar, bits):
    """Run the original MPFI screen; map its output to the backend gates."""

    try:
        case = screen(q, n, bits=bits, generation_width_squared=g, m_bar=m_bar)
    except ValueError as exc:
        return {"q": q, "n": n, "g": g, "m_bar": m_bar, "error": str(exc)[:120]}
    p = case["parameters"]
    gates = {
        "q_cap": q <= Q_CAP,
        "n_cap": n <= 128,
        "m_bar_cap": p["m_bar"] <= 128,
        "dimension_cap": p["d"] <= DIM_CAP,
        "quality_caps": max(p["master_quality_squared"], p["user_quality_squared"]) <= QUALITY_CAP,
        "width_caps": max(p["s_squared"], p["t_squared"],
                          p["r_squared"], g) <= QUALITY_CAP,
        "sigma_cap": (GAMMA + 2) * (max(p["master_quality_squared"],
                                        p["user_quality_squared"]) + 1) <= SIGMA_CAP,
        "c3_user_quality": p["user_quality_squared"] >= p["m"] * p["w"] * p["s_squared"],
        "t_ge_s": p["t_squared"] >= p["s_squared"],
    }
    lll = case["standard_LLL_attack_control"]
    beta_squared = int(case["beta_red_squared"])
    log2_beta = log2(beta_squared) / 2
    classical, b_classical, d_classical = core_svp_sis(q, n, p["m"], log2_beta)
    quantum, _, _ = core_svp_sis(q, n, p["m"], log2_beta, quantum=True)
    return {"q": q, "n": n, "k": p["k"], "g": g, "m_bar": p["m_bar"], "w": p["w"],
            "m": p["m"], "d": p["d"], "bits": bits,
            "r_squared": p["r_squared"], "master_quality_squared": p["master_quality_squared"],
            "user_quality_squared": p["user_quality_squared"],
            "s_squared": p["s_squared"], "t_squared": p["t_squared"],
            "beta_red_squared": str(beta_squared),
            "analytic_prescreen_pass": case["analytic_prescreen_pass"],
            "failed_checks": [name for name, ok in case["analytic_checks"].items() if not ok],
            "backend_gates_pass": all(gates.values()),
            "failed_gates": [name for name, ok in gates.items() if not ok],
            "lll_bound_excludes": lll["bound_fits_beta_red"],
            "core_svp_classical_bits": round(classical, 2) if isfinite(classical) else None,
            "core_svp_quantum_bits": round(quantum, 2) if isfinite(quantum) else None,
            "core_svp_cost_status": "bracketed" if isfinite(classical) else "unbracketed_at_1200",
            "core_svp_attack_blocksize": b_classical,
            "core_svp_attack_dimension": d_classical,
            "public_matrix_kib": round(n * p["m"] * p["k"] / 8 / 1024, 1)}


def in_gate_exhaustive(bits=160):
    """Legacy name for a finite-grid probe, not exhaustive backend rejection."""

    widths = [16, 2**6, 2**8, 2**10, 2**12, 2**16, 2**20, 2**24, 2**28]
    results = []
    stats = {"k_n_width_probes": 0, "windows_found": 0, "exact_screens": 0}
    for k in range(3, 33):
        q = int(previous_prime(2**k))
        if (q - 1).bit_length() != k:
            continue
        for n in range(1, min(4, 42 // k) + 1):
            w = n * k
            if 3 * w > 128:
                continue
            for g in widths:
                stats["k_n_width_probes"] += 1
                window = float_window(q, n, g, bits)
                if window is None:
                    continue
                stats["windows_found"] += 1
                lo, hi, _ = window
                # Check retained candidates; wider windows are sampled.
                span = list(range(lo, hi + 1))
                if len(span) > 8:
                    span = [lo, hi] + [lo + (hi - lo) * i // 6 for i in range(1, 6)]
                for m_bar in sorted(set(span)):
                    stats["exact_screens"] += 1
                    results.append(exact_case(q, n, g, m_bar, bits))
    passing = [r for r in results if r.get("analytic_prescreen_pass")]
    return {"stats": stats, "cases": len(results),
            "coverage": {"q_policy": "largest prime below 2**k; k=3..32",
                         "n_max": 4, "generation_width_squared": widths,
                         "m_bar_policy": "retained bracket; at most seven samples if wider than eight",
                         "all_backend_parameters_covered": False,
                         "prefilter_is_rigorous": False},
            "conclusion": ("no_candidate_window_in_declared_grid" if not stats["windows_found"]
                           else "retained_candidates_checked_only"),
            "analytic_pass": len(passing),
            "analytic_and_gates_pass": sum(r.get("backend_gates_pass", False) for r in passing),
            "lll_excluded_among_pass": sum(r.get("lll_bound_excludes", False) for r in passing),
            "best_points": sorted(
                [r for r in passing],
                key=lambda r: (not r.get("backend_gates_pass", False),
                               r.get("lll_bound_excludes", False),
                               -(r.get("core_svp_classical_bits") or 0)))[:8],
            "all_results": results}


def target_search(bits=160):
    """Beyond-gate candidates with full failure attribution per filter.

    Reports every candidate's fate: analytic screen outcome (with failed
    checks), LLL exclusion, and core-SVP bits, so an empty target set is a
    diagnosable table instead of a silent grid.
    """

    out = []
    for q in (2**31 - 1, int(previous_prime(2**32)), 2**61 - 1, 2**89 - 1, 2**127 - 1):
        k = (q - 1).bit_length()
        # The small-n band is where the quality chain's beta growth loses to
        # the sqrt(n)-shaped core-SVP threshold; the large-n band (q at the
        # screen's prime cap) is where hard instances can first exist.
        n_grid = (1, 2, 4, 8, 16, 32, 64, 128) if k < 120 else \
                 (1, 8, 64, 256, 512, 1024, 2048, 4096)
        for n in n_grid:
            for g in (16, 2**8, 2**16):
                # Regularity-driven m_bar (auto family), plus one step tighter.
                try:
                    base = screen(q, n, bits=bits, generation_width_squared=g)
                    m_bar_auto = base["parameters"]["m_bar"]
                except ValueError as exc:
                    out.append({"q": q, "n": n, "g": g, "m_bar": None,
                                "stage": "auto_screen_error", "error": str(exc)[:100]})
                    continue
                for m_bar in {m_bar_auto, m_bar_auto + 16}:
                    case = exact_case(q, n, g, m_bar, bits)
                    if "error" in case:
                        case["stage"] = "exact_error"
                    elif not case["analytic_prescreen_pass"]:
                        case["stage"] = "analytic_fail"
                    elif case["lll_bound_excludes"]:
                        case["stage"] = "lll_excluded"
                    elif case["core_svp_classical_bits"] is None:
                        case["stage"] = "unbracketed_attack_search"
                    elif case["core_svp_classical_bits"] < 128:
                        case["stage"] = "below_128_bits"
                    else:
                        case["stage"] = "target"
                    out.append(case)
    targets = [r for r in out if r.get("stage") == "target"]
    targets.sort(key=lambda r: (r["public_matrix_kib"], r["d"]))
    by_stage = {}
    for r in out:
        by_stage[r["stage"]] = by_stage.get(r["stage"], 0) + 1
    best_hardness = sorted(
        [r for r in out if r.get("core_svp_classical_bits") is not None],
        key=lambda r: -r["core_svp_classical_bits"])[:5]
    return {"candidates": len(out), "by_stage": by_stage,
            "targets_128bit": len(targets), "smallest": targets[:6],
            "highest_core_svp_any_stage": best_hardness,
            "failed_check_histogram": _failed_check_histogram(out),
            "all_cases": out}


def _failed_check_histogram(cases):
    histogram = {}
    for case in cases:
        for name in case.get("failed_checks") or ():
            histogram[name] = histogram.get(name, 0) + 1
    return histogram


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {"schema_version": 2, "security_claim": "none", "backend_admitted": False,
              "parameters_are_formal": False,
              "method": "float-window pre-filter + exact MPFI screen confirmation; "
                        "core-SVP Chen-Nguyen approximation for beyond-gate targets",
              "environment": {"python": sys.version.split()[0],
                              "platform": platform.platform()},
              "core_svp_model": {
                  "delta_exponent": "1/(2*(b-1))",
                  "reference": "https://github.com/malb/lattice-estimator/blob/e4333d9bf9ef42fd8a29651b0c559fba7ce0d834/estimator/reduction.py#L72",
                  "blocksize_search": [53, 1200], "cost_rates_times_b_minus_1": [0.292, 0.265],
                  "unbracketed_cost": "null; excluded from target selection",
                  "estimator_package_executed": False},
              "in_gate_search": in_gate_exhaustive(),
              "target_search": target_search()}
    import json
    value = json.dumps(report, ensure_ascii=False, indent=2, default=str, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(value, encoding="utf-8", newline="\n")
    else:
        print(value, end="")


if __name__ == "__main__":
    main()
