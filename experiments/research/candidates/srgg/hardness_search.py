"""Zero-entropy SRGG arithmetic search and pinned attack-model comparators.

No backend preset is changed. Coefficient LWE/SIS estimates do not model the
module/CRT structure, constitute attack executions, or establish NIST levels.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from math import gcd, isqrt
from pathlib import Path
import platform
import signal
import subprocess
import sys
from time import perf_counter
import warnings

from .formal_candidates import Candidate, geometry_bounds, smoothing_certificate


SCHEMA = "IBME/SRGG-HARDNESS-FINITE-SEARCH/1"
ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
BASES = (3, 7, 15, 31, 63)
DIGITS = tuple(range(2, 33))
POINTS = ((512, 1), (512, 2), (512, 4), (512, 8), (512, 12), (512, 16),
          (1024, 2), (1024, 4), (1024, 6), (1024, 8), (2048, 2), (2048, 3), (2048, 4),
          (4096, 2), (8192, 2))
P_MAX = 2**32-1


def _integer(value, name, low=1, high=2**32):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def build_candidate(*, degree, rank, base, digits, r_squared, p,
                    raw_norm_multiplier=16):
    """Same sufficient all-CBD1 geometry as formal_candidates, generalized p/b/r."""
    _integer(degree, "degree", 2, 2**16)
    if degree & (degree-1):
        raise ValueError("power-of-two degree required")
    for value, name, high in ((rank, "rank", 32), (base, "base", 2**16-1),
            (digits, "digits", 32), (r_squared, "r squared", 4096),
            (p, "p", P_MAX), (raw_norm_multiplier, "raw multiplier", 2**16)):
        _integer(value, name, high=high)
    if p < 3 or base < 3 or p % 2 == 0 or base % 2 == 0 or gcd(p, base) != 1:
        raise ValueError("odd coprime p/base at least three required")
    columns = (2+digits)*rank
    root = 2*rank*rank*digits*degree*degree+1
    master = base*base*r_squared*root+r_squared+1
    raw = raw_norm_multiplier*columns*degree*master
    user = 2*raw+2*rank*degree*(p-1)**2
    signature = 2*r_squared*(degree*user+1)+r_squared+1
    signature_cap = (columns+1)*degree*signature
    return Candidate(f"search-n{degree}-d{rank}-b{base}-w{digits}-r2{r_squared}-p{p}",
        degree, rank, p, base, digits, r_squared, master, master,
        signature, signature, raw, user, signature_cap)


def minimum_p(*, degree, rank, base, digits, r_squared,
              p_max=P_MAX, raw_norm_multiplier=16):
    """Find first allowed p with Q^2>4B, using the exact quadratic.

    Handles convex, linear, and concave cases; returning None means no allowed
    odd p coprime to base in this finite interval, not global impossibility.
    """
    _integer(p_max, "p maximum", 3, P_MAX)
    _integer(base, "base", 3, 2**16-1)
    if base % 2 == 0:
        raise ValueError("odd base required")
    # p=3 may share a factor with b; geometry coefficients themselves do not
    # depend on coprimality. Find a small valid seed solely to derive them.
    seed = 3
    while gcd(seed, base) != 1:
        seed += 2
    c = build_candidate(degree=degree, rank=rank, base=base, digits=digits,
        r_squared=r_squared, p=seed, raw_norm_multiplier=raw_norm_multiplier)
    dimension = (c.columns+1)*degree
    a = dimension*4*r_squared*rank*degree*degree
    constant = dimension*(4*r_squared*degree*c.raw_norm_squared_cap+3*r_squared+1)
    quadratic = base**(2*digits)-4*a

    def gap(p):
        return quadratic*p*p+8*a*p-4*a-4*constant

    # The increasing branch ends at the vertex if the quadratic is concave.
    top = p_max
    if quadratic < 0:
        vertex = (4*a)//(-quadratic)
        choices = {max(3, min(p_max, vertex)), max(3, min(p_max, vertex+1))}
        top = max(choices, key=gap)
    if gap(top) <= 0:
        return None
    low, high = 3, top
    while low < high:
        mid = (low+high)//2
        if gap(mid) > 0:
            high = mid
        else:
            low = mid+1
    p = low if low % 2 else low+1
    while p <= p_max and gap(p) > 0:
        if gcd(p, base) == 1:
            result = build_candidate(degree=degree, rank=rank, base=base,
                digits=digits, r_squared=r_squared, p=p,
                raw_norm_multiplier=raw_norm_multiplier)
            assert result.modulus**2 > 4*result.signature_norm_squared_cap
            return p
        p += 2
    return None


def reduction_requirement(*, degree, rank, digits, target_bits=128,
                          identity_query_bits=40, free_query_bits=40):
    """Exact conditional per-hardness-advantage threshold, NOT cost conversion.

    Ignores simulation distance only to isolate the reduction's algebraic loss.
    A finite work factor cannot be substituted for an advantage bound here.
    """
    for v, name, low, high in ((degree, "degree", 2, 2**16),
            (rank, "rank", 1, 32), (digits, "digits", 1, 32),
            (target_bits, "target bits", 1, 512),
            (identity_query_bits, "identity query bits", 0, 64),
            (free_query_bits, "free query bits", 0, 64)):
        _integer(v, name, low, high)
    if degree % 2:
        raise ValueError("even degree required")
    p = Fraction(1, 2**(target_bits+identity_query_bits))
    t = max(Fraction(0), p-Fraction(1, 2**degree))
    f = max(Fraction(0), t*t/(8*2**free_query_bits)-t/Fraction(2**(degree//2+2)))
    terms = 1+rank*digits
    threshold = f/terms
    bits = None
    if threshold:
        bits = max(0, threshold.denominator.bit_length()-threshold.numerator.bit_length())
        while Fraction(1, 2**bits) > threshold:
            bits += 1
        while bits and Fraction(1, 2**(bits-1)) <= threshold:
            bits -= 1
    return {"target_IBS_advantage_exact": str(Fraction(1, 2**target_bits)),
        "identity_query_bound": 2**identity_query_bits,
        "free_H2_entry_bound": 2**free_query_bits, "hardness_terms": terms,
        "simulation_distance_assumed_only_for_illustration": "0",
        "F_at_target_after_identity_loss_exact": {
            "numerator_hex": hex(f.numerator), "denominator_hex": hex(f.denominator)},
        "each_hardness_advantage_upper_required_exact": {
            "numerator_hex": hex(threshold.numerator), "denominator_hex": hex(threshold.denominator)},
        "sufficient_each_advantage_dyadic_bits": bits,
        "finite_attack_cost_is_not_an_advantage_bound": True,
        "conditional_classical_ROM_only": True}


def candidate_record(candidate):
    gates = geometry_bounds(candidate)
    smoothing = smoothing_certificate((candidate.columns+1)*candidate.degree,
        candidate.r_squared, candidate.smoothing_epsilon_bits)
    q, n, d = candidate.modulus, candidate.degree, candidate.rank
    four_b = 4*candidate.signature_norm_squared_cap
    full_kernel = full_kernel_smoothing(candidate)
    return {"name": candidate.name, "parameters": asdict(candidate), "Q": q,
        "Q_bits": q.bit_length(), "geometry": gates,
        "rounding_Z_smoothing": smoothing, "full_kernel_smoothing": full_kernel,
        "arithmetic_passes": gates["all_arithmetic_gates_pass"] and
            smoothing["sufficient_smoothing_condition_passes"] and full_kernel["passes"],
        "MLWE_single_column_comparator": {"n": d*n, "m": d*n, "q": q,
            "secret": "CenteredBinomial(1)", "error": "CenteredBinomial(1)",
            "shared_Ahat_columns_in_real_setup": d*candidate.digits,
            "samples_not_multiplied_by_shared_columns": True},
        "HNF_MSIS_comparator": {"rows": d*n,
            "columns": (candidate.columns+1)*n, "q": q,
            "norm": 2, "squared_length_bound_exact": four_b,
            "infinity_bound_implied": isqrt(four_b),
            "module_shape": [d, candidate.columns+1]},
        "modeled_component_bytes": {"B_plus_seed":
            (d*d*candidate.digits*n*q.bit_length()+7)//8+32,
            "signature_without_framing":
            (((candidate.columns+1)*n*(2*isqrt(candidate.signature_norm_squared_cap)).bit_length()+7)//8)+(n+7)//8},
        "reduction_scenarios": [reduction_requirement(degree=n, rank=d,
            digits=candidate.digits, identity_query_bits=k, free_query_bits=k)
            for k in (0, 20, 40)], "estimates": {}}


def full_kernel_smoothing(candidate):
    """Existing full-kernel ordered GSO and elementary theta sufficient bound.

    Uses a conservative all-CBD1 Frobenius class, never a measured private R.
    This is not the complete convolution/finite-sampler/error certificate.
    """
    c = candidate
    root = 2*c.rank*c.rank*c.digits*c.degree*c.degree+1
    gso = max(c.p*c.p, root*(c.base*c.base+1))
    floor = c.master_first_squared//gso
    target_bits = 192 if c.r_squared >= 128 else 80
    smoothing = None if floor < 1 else smoothing_certificate(c.columns*c.degree,
        min(4096,floor),target_bits)
    return {"basis_gso_squared_upper": gso,
        "isotropic_master_over_gso_squared_floor": floor,
        "target_relative_error_bits": target_bits,
        "theta_certificate": smoothing,
        "passes": smoothing is not None and smoothing["sufficient_smoothing_condition_passes"],
        "actual_complete_bridge_instantiated": False}


def arithmetic_search(*, points=POINTS, r_squared_values=(64, 128)):
    selected, summaries = [], []
    for n, d in points:
        for r2 in r_squared_values:
            pool, geometric_count = [], 0
            for b in BASES:
                for w in DIGITS:
                    p = minimum_p(degree=n, rank=d, base=b, digits=w, r_squared=r2)
                    if p is not None:
                        geometric_count += 1
                        candidate = build_candidate(degree=n, rank=d, base=b,
                            digits=w, r_squared=r2, p=p)
                        if full_kernel_smoothing(candidate)["passes"]:
                            pool.append(candidate)
            winner = min(pool, key=lambda c:(c.modulus, (c.columns+1)*n)) if pool else None
            summaries.append({"degree": n, "rank": d, "r_squared": r2,
                "shape_trials": len(BASES)*len(DIGITS),
                "geometric_passing_shapes": geometric_count,
                "full_kernel_smoothing_passing_shapes": len(pool),
                "selection_rule": "minimum Q; tie smaller signature dimension",
                "selected_name": None if winner is None else winner.name})
            if winner is not None:
                selected.append(candidate_record(winner))
    # Current research point must remain visible independently of search winners.
    current = build_candidate(degree=512,rank=2,base=31,digits=8,r_squared=64,p=16383)
    return {"schema": SCHEMA, "finite_domain": {"points": [list(p) for p in points],
        "bases": list(BASES), "digits": list(DIGITS), "r_squared": list(r_squared_values),
        "p": "all odd coprime values 3<=p<=2^32-1, minimum exact passing p per shape",
        "raw_norm_multiplier": 16, "CBD1_root_support_preserved": True},
        "selection_summaries": summaries, "current_research_point": candidate_record(current),
        "selected_candidates": selected, "actual_entropy_bytes": 0,
        "backend_preset_modified": False, "crypto_lifecycle_executed": False,
        "module_or_composite_specific_attacks_covered": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def verify_estimator(root):
    root = Path(root).expanduser().resolve()
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-c", "core.autocrlf=true", "-C", str(root),
        "status", "--porcelain"], text=True).strip()
    if revision != ESTIMATOR_COMMIT or dirty:
        raise ValueError("clean pinned estimator required")
    return root


def run_estimators(report, root, *, checkpoint, per_point_seconds=60):
    """Three attack families, two models, at most the public per-point budget."""
    _integer(per_point_seconds, "point seconds", 1, 60)
    if not hasattr(signal, "SIGALRM"):
        raise ValueError("bounded estimator execution requires the specified WSL Sage")
    root = verify_estimator(root)
    sys.path.insert(0, str(root))
    import estimator
    from estimator import LWE, ND, SIS
    from estimator.conf import max_beta
    from estimator.reduction import ADPS16
    from sage.all import Mod, RealField, log, oo, ZZ
    from sage.version import version
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("foreign estimator import")
    report["estimator"] = {"repository": "https://github.com/malb/lattice-estimator",
        "commit": ESTIMATOR_COMMIT, "clean_checkout": True,
        "models": "ADPS16 classical 0.292 / quantum 0.265 Core-SVP",
        "families": ["primal-uSVP LGSA", "plain dual", "Euclidean SIS lattice (shape ignored)"],
        "excluded": ["BDD/hybrid", "BKW", "Arora-GB", "module/subfield/CRT attacks"],
        "per_point_seconds": per_point_seconds,
        "upstream_primal_and_dual_global_beta_limit": max_beta,
        "attack_goals": {"lwe-usvp": "heuristic secret search",
            "lwe-dual": "decisional distinguisher", "sis-lattice": "nonzero short kernel search"},
        "euclidean_bound_numeric_precision_bits": 192}
    report["environment"] = {"python": sys.version, "sage": version,
        "platform": platform.platform(), "machine": platform.machine(),
        "processor": platform.processor()}
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        report["environment"]["cpu_model"] = next((line.partition(":")[2].strip()
            for line in cpuinfo.read_text().splitlines() if line.startswith("model name")), "unknown")
    def expired(signum, frame):
        raise TimeoutError("per-point estimate time budget exhausted")
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        for row in [report["current_research_point"]]+report["selected_candidates"]:
            started = perf_counter()
            p = row["MLWE_single_column_comparator"]
            lwe = LWE.Parameters(n=p["n"],m=p["m"],q=p["q"],
                Xs=ND.CenteredBinomial(1),Xe=ND.CenteredBinomial(1),tag=row["name"])
            s = row["HNF_MSIS_comparator"]
            sis = SIS.Parameters(n=s["rows"],m=s["columns"],q=s["q"],
                length_bound=RealField(192)(s["squared_length_bound_exact"]).sqrt(),norm=2,tag=row["name"])
            row["modulus_factorization"] = [[int(p),int(e)] for p,e in ZZ(row["Q"]).factor()]
            row["cyclotomic_prime_factor_degrees"] = [
                {"prime": int(p), "multiplicity": int(e),
                 "irreducible_degree": int(Mod(p,2*row["parameters"]["degree"]).multiplicative_order()),
                 "interpretation": "factor degree only; projected CBD1 law/attack not estimated"}
                for p,e in ZZ(row["Q"]).factor()]
            deadline = started+per_point_seconds
            for mode in ("classical", "quantum"):
                for name, call in (("lwe-usvp", lambda:LWE.primal_usvp(lwe,red_cost_model=ADPS16(mode=mode),red_shape_model="lgsa")),
                        ("lwe-dual", lambda:LWE.dual(lwe,red_cost_model=ADPS16(mode=mode))),
                        ("sis-lattice", lambda:SIS.lattice(sis,red_cost_model=ADPS16(mode=mode)))):
                    cost_started = perf_counter()
                    record = {"status": "error_no_estimate"}
                    try:
                        remaining = deadline-perf_counter()
                        if remaining <= 0:
                            raise TimeoutError("per-point estimate time budget exhausted")
                        signal.setitimer(signal.ITIMER_REAL, remaining)
                        with warnings.catch_warnings(record=True) as caught:
                            cost = call()
                        record.update(status="finite_heuristic_comparator" if cost["rop"] != oo else "no_finite_estimate",
                            log2_rop=None if cost["rop"] == oo else float(log(cost["rop"],2)),
                            cost_fields={str(k):str(v) for k,v in cost.items() if k != "problem"},
                            warnings=[str(w.message) for w in caught])
                    except Exception as error:
                        record.update(error=type(error).__name__+": "+str(error),log2_rop=None)
                    finally:
                        signal.setitimer(signal.ITIMER_REAL, 0)
                    record["seconds"] = perf_counter()-cost_started
                    row["estimates"].setdefault(mode,{})[name] = record
                    checkpoint(report)
            row["estimate_seconds"] = perf_counter()-started
            print(json.dumps({"name":row["name"],"Q_bits":row["Q_bits"],
                "costs":{mode:{name:cost["log2_rop"] for name,cost in attacks.items()}
                    for mode,attacks in row["estimates"].items()}}),flush=True)
            checkpoint(report)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    verify_estimator(root)
    report["estimator"]["completed"] = True
    statuses = [record["status"] for row in [report["current_research_point"]]+
        report["selected_candidates"] for mode in row["estimates"].values() for record in mode.values()]
    report["estimator"]["task_status_counts"] = {name:statuses.count(name) for name in sorted(set(statuses))}
    report["estimator"]["all_tasks_returned_finite"] = all(status == "finite_heuristic_comparator" for status in statuses)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator-path", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("output already exists; preserve prior evidence")
    report = arithmetic_search()
    paths = [Path(__file__),Path(__file__).with_name("formal_candidates.py")]
    report["source_sha256"] = {str(p.relative_to(Path(__file__).parents[4])):
        hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    def save(data):
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8",newline="\n")
    save(report)
    if args.estimator_path:
        run_estimators(report,args.estimator_path,checkpoint=save)
        save(report)


if __name__ == "__main__":
    main()
