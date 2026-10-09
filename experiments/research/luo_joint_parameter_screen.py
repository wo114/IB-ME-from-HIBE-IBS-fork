"""Bounded joint Luo matrix screening and exact module-modulus checks.

Analysis only: no new IBS backend, private keys or production preset are made.
Run the full audit with the pinned external estimator in the designated Sage
environment. The pure arithmetic helpers are also usable in ordinary Python.
"""

from __future__ import annotations

import argparse
from collections import Counter
from decimal import Decimal, ROUND_CEILING, localcontext
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import platform
import sys

from experiments.research.luo_parameter_screen import (
    ESTIMATOR_COMMIT, ESTIMATOR_URL, PAPER_URL, _rejection_cost, _validate,
    lwe_attack_goal, screening_rows, verify_estimator_checkout,
)


N_VALUES = (256, 512, 1024, 2048)
WIDTH_RATIOS = (4, 8, 16, 32, 64)
Q_GAPS = (24, 32)
TARGET_STAT_BITS = 128
HEURISTIC_COST_FLOOR = 128
PUBLIC_BUDGET = 512 * 2**20
SIGNATURE_BUDGET = 8 * 2**20
MODULE_TABLE = (
    ("table-90", 34, 6, 5, 39, 49920, 4984012800, 26, 6691),
    ("table-136", 36, 8, 7, 39, 69888, 9768665088, 27, 9738),
    ("table-200", 38, 11, 10, 49, 125440, 31470387200, 28, 14680),
)


def plan_masks(m: int, k: int, kappa: int, eta: int) -> tuple[int, int]:
    if any(isinstance(x, bool) or not isinstance(x, int) or x < 1 for x in (m, k, kappa, eta)):
        raise ValueError("positive integer mask-planning inputs required")
    if kappa > k:
        raise ValueError("challenge weight exceeds dimension")
    with localcontext() as context:
        context.prec = 80
        g1 = int((Decimal(m * k * kappa * eta) / Decimal(10).ln()).to_integral_value(ROUND_CEILING))
        g2 = int((Decimal(m * kappa * g1) / Decimal(10).ln()).to_integral_value(ROUND_CEILING))
    return g1, g2


def witness_bounds(p: dict) -> dict:
    _validate(p)
    beta1, beta2 = p["kappa"] * p["eta"], p["kappa"] * p["gamma1"]
    statement = 2 * p["gamma2"] + 2 * p["kappa"] * beta1
    event_e = 2 * p["gamma2"] + 2 * beta2
    return dict(
        theorem_statement=statement, event_E=event_e, event_E_prime=statement,
        screening_bound=max(statement, event_e),
        scope="conservative triangle bound from PDF pages 8/10; does not repair nonzero-witness or forking proof gaps",
    )


def public_uniform_bound_squared(n: int, m: int, k: int, q: int, eta: int) -> Fraction:
    """LHL + a column hybrid: squared TV upper bound, assuming prime q.

    A is uniform and S columns are independent uniform bounded integers; q>2eta
    makes their residue representation injective. This hides the public image
    statistically and does not imply that bounded preimages are hard to find.
    """
    if any(isinstance(x, bool) or not isinstance(x, int) or x < 1 for x in (n, m, k, q, eta)):
        raise ValueError("positive integer entropy inputs required")
    if q < 3 or q <= 2 * eta:
        raise ValueError("q>2eta and prime q are required for this universal-hash model")
    return Fraction(k * k * q**n, 4 * (2 * eta + 1)**m)


def public_uniformity(p: dict, *, target_bits=TARGET_STAT_BITS) -> dict:
    _validate(p)
    if isinstance(target_bits, bool) or not isinstance(target_bits, int) or target_bits < 1:
        raise ValueError("positive statistical target required")
    squared = public_uniform_bound_squared(p["n"], p["m"], p["k"], p["q"], p["eta"])
    support_bits = p["m"] * math.log2(2 * p["eta"] + 1)
    image_bits = p["n"] * math.log2(p["q"])
    return dict(
        target_statistical_distance_bits=target_bits,
        exact_arithmetic_sufficient=squared <= Fraction(1, 2**(2 * target_bits)),
        tv_upper_bound_log2=min(0.0, math.log2(p["k"]) - 1 + (image_bits - support_bits) / 2),
        one_column_support_bits=support_bits, one_column_codomain_bits=image_bits,
        one_column_support_ratio_log2=support_bits - image_bits,
        support_distance_lower_bound=("1-2^(support_ratio_log2)" if support_bits < image_bits else "0"),
        assumptions="prime q>2eta; uniform A; independent uniform columns S; bound averaged over A",
        scope="sufficient public-distribution check, not a key-recovery or IBS security proof",
    )


def resource_projection(p: dict) -> dict:
    _validate(p)
    coefficient_bytes = (p["q"].bit_length() + 7) // 8
    max_z = p["gamma2"] - p["kappa"] * p["gamma1"] - 1
    signed_z_bytes = max(1, (max_z.bit_length() + 1 + 7) // 8)
    public = p["n"] * (p["m"] + p["k"]) * coefficient_bytes
    signature = p["m"] * signed_z_bytes + 8 * p["k"] + p["n"] * p["k"] * coefficient_bytes
    return dict(
        modular_coefficient_bytes=coefficient_bytes, signed_z_coefficient_bytes=signed_z_bytes,
        public_A_T_raw_bytes=public, signature_z_c_W_raw_bytes=signature,
        public_within_512MiB=public <= PUBLIC_BUDGET, signature_within_8MiB=signature <= SIGNATURE_BUDGET,
        z_within_int64=max_z < 2**63,
        setup_AS_scalar_products=p["n"] * p["m"] * p["k"],
        signing_Ay_scalar_products=p["n"] * p["m"],
        current_backend_executable=False,
        scope="future byte-aligned dense representation; int64 c; no framing/seed compression or timing benchmark",
    )


def matrix_frontier(prime_above) -> list[dict]:
    rows = []
    for n in N_VALUES:
        for ratio in WIDTH_RATIOS:
            for gap in Q_GAPS:
                m, k, kappa = n * ratio, 256, 64
                for eta_exponent in range(33):
                    eta = 2**eta_exponent
                    g1, g2 = plan_masks(m, k, kappa, eta)
                    p = dict(n=n, m=m, k=k, kappa=kappa, eta=eta, gamma1=g1, gamma2=g2, q=3)
                    # Only mask bounds are used here; q is assigned before any audit.
                    bound = 2 * g2 + 2 * kappa * g1
                    p["q"] = int(prime_above(2**((bound - 1).bit_length() + gap)))
                    entropy = public_uniformity(p)
                    if entropy["exact_arithmetic_sufficient"]:
                        break
                else:
                    raise RuntimeError("fixed eta search range exhausted; do not return a default row")
                beta1, beta2 = kappa * eta, kappa * g1
                rows.append(dict(
                    name=f"matrix-n{n}-r{ratio}-gap{gap}", parameters=p,
                    first_passing_power_of_two_eta_exponent=eta_exponent, eta_trials=eta_exponent + 1,
                    q_prime=None, q_gap_bits=gap, public_uniformity=entropy,
                    witness_bounds=witness_bounds(p), resources=resource_projection(p),
                    extraction=_rejection_cost(g1, beta1, m * k, strict=False),
                    signing=_rejection_cost(g2, beta2, m, strict=True),
                    euclidean_subattack={}, infinity_attack={},
                    classification="unassessed", security_claim="none", backend_admitted=False,
                ))
    return rows


def select_hint_modulus(alpha: int, stated_bits: int, primality, *, max_ratio=128) -> dict:
    """Conditional bit-length interpretation; q is not an author-supplied q."""
    if any(isinstance(x, bool) or not isinstance(x, int) for x in (alpha, stated_bits, max_ratio)):
        raise ValueError("integer exact Hint-modulus inputs required")
    if alpha < 2 or alpha % 2 or stated_bits < 2 or max_ratio < 3:
        raise ValueError("invalid exact Hint-modulus search")
    lower, upper = 2**(stated_bits - 1), 2**stated_bits
    in_interval, first = [], None
    for ratio in range(3, max_ratio + 1):
        q = ratio * alpha + 1
        if q < lower or not primality(q):
            continue
        if q < upper:
            in_interval.append(dict(ratio=ratio, q=q))
        if first is None:
            first = dict(ratio=ratio, q=q, q_bit_length=q.bit_length())
    if first is None:
        raise RuntimeError("Hint-modulus ratio budget exhausted")
    if (upper - 2) // alpha > max_ratio:
        raise ValueError("search budget does not cover the stated bit interval")
    return dict(
        stated_bit_interval=[lower, upper], primes_within_interval=in_interval,
        first_prime_at_or_above_lower_bound=first, searched_ratios=[3, max_ratio],
        interpretation="conditional: Table 1 log2(q) interpreted as bit length; no exact author modulus available",
    )


def select_flexible_hint_modulus(gamma2: int, stated_bits: int, primality, *, max_trials=10000) -> dict:
    """Keep q's bit interval and choose gamma3 from the algorithm's divisibility.

    The Table 1 relation gamma3=gamma2/2 is relaxed, while alpha=2gamma3,
    alpha|(q-1), q>2alpha and q=1 mod 512 remain explicit. This is a parameter
    variant, not an exact reproduction of the author's unidentified modulus.
    """
    if any(isinstance(x, bool) or not isinstance(x, int) or x < 1
           for x in (gamma2, stated_bits, max_trials)) or stated_bits < 2:
        raise ValueError("positive integer flexible-modulus inputs required")
    lower, upper = 2**(stated_bits - 1), 2**stated_bits
    ratio = max(3, (upper - 1 + gamma2 // 2) // gamma2)
    period = math.lcm(512, 2 * ratio)
    q = 1 + ((upper - 2) // period) * period
    for trial in range(1, max_trials + 1):
        if q < lower:
            break
        if primality(q):
            alpha = (q - 1) // ratio
            return dict(
                selected=dict(q=q, q_bit_length=q.bit_length(), ratio=ratio, alpha=alpha, gamma3=alpha // 2),
                prime_trials=trial, prime_budget=max_trials, progression_period=period,
                stated_bit_interval=[lower, upper],
                parameter_change="gamma3 chosen independently; gamma2 and all algorithm steps preserved",
            )
        q -= period
    raise RuntimeError("flexible exact-modulus search exhausted its public budget")


def _cost_records(results, log, oo, *, lwe=False) -> dict:
    return {attack: dict(
        attack_goal=lwe_attack_goal(attack) if lwe else "nonzero_kernel_search",
        status="no_finite_estimate" if cost["rop"] == oo else "finite_heuristic_estimate",
        rop_log2=None if cost["rop"] == oo else float(log(cost["rop"], 2)),
        cost_fields={key: str(value) for key, value in cost.items() if key != "problem"},
    ) for attack, cost in results.items()}


def _below_floor(records) -> bool:
    return any(record["rop_log2"] is not None and record["rop_log2"] < HEURISTIC_COST_FLOOR
               for record in records.values())


def audit(root: Path) -> dict:
    root, revision = verify_estimator_checkout(root)
    sys.path.insert(0, str(root))
    import estimator
    from estimator import LWE, ND, SIS
    from estimator.reduction import ADPS16
    from sage.all import GF, is_prime, log, next_prime, oo
    from sage.version import version as sage_version
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("imported estimator is outside the pinned checkout")

    rows = matrix_frontier(next_prime)
    for row in rows:
        p, bound = row["parameters"], row["witness_bounds"]["screening_bound"]
        row["q_prime"] = bool(is_prime(p["q"]))
        if not row["q_prime"]:
            raise RuntimeError("selected modulus is not prime")
        try:
            for mode in ("classical", "quantum"):
                params = SIS.Parameters(n=p["n"], m=p["m"], q=p["q"], length_bound=bound, norm=2)
                result = SIS.estimate(params, red_cost_model=ADPS16(mode=mode), catch_exceptions=False, quiet=True)
                row["euclidean_subattack"][mode] = _cost_records(result, log, oo)
            if any(_below_floor(records) for records in row["euclidean_subattack"].values()):
                row["classification"] = "excluded_by_valid_euclidean_subattack"
            elif not (row["resources"]["public_within_512MiB"] and row["resources"]["signature_within_8MiB"]):
                row["classification"] = "excluded_by_research_resource_budget"
            else:
                for mode in ("classical", "quantum"):
                    params = SIS.Parameters(n=p["n"], m=p["m"], q=p["q"], length_bound=bound, norm=oo)
                    result = SIS.estimate(params, red_cost_model=ADPS16(mode=mode), red_shape_model="lgsa",
                                          catch_exceptions=False, quiet=True)
                    row["infinity_attack"][mode] = _cost_records(result, log, oo)
                complete = all(records and all(x["rop_log2"] is not None for x in records.values())
                               for records in row["infinity_attack"].values())
                if not complete:
                    row["classification"] = "model_incomplete_no_admission"
                elif any(_below_floor(records) for records in row["infinity_attack"].values()):
                    row["classification"] = "excluded_by_infinity_attack"
                else:
                    row["classification"] = "heuristic_cost_screen_survivor_only"
        except Exception as exc:
            row["classification"] = "estimator_error_no_admission"
            row["estimator_error"] = dict(type=type(exc).__name__, message=str(exc))
        row["infinity_scope"] = "estimated only after Euclidean cost and dense-resource prefilters"

    modules, lwe_cache = [], {}
    for name, bits, rank, columns, kappa, g1, g2, dropped, paper_size in MODULE_TABLE:
        fixed = select_hint_modulus(g2, bits, is_prime)
        flexible = select_flexible_hint_modulus(g2, bits, is_prime)
        variants = [("fixed-gamma3", fixed, kappa), ("flexible-gamma3", flexible, kappa)]
        if name == "table-200":
            variants.append(("flexible-gamma3-kappa64", flexible, 64))
        for variant, selection, selected_kappa in variants:
            q = (selection["selected"] if "selected" in selection else
                 selection["first_prime_at_or_above_lower_bound"])["q"]
            gamma3 = selection["selected"]["gamma3"] if "selected" in selection else g2 // 2
            alpha = 2 * gamma3
            root_ntt = int(GF(q).multiplicative_generator()**((q - 1) // 512))
            count = math.comb(256, selected_kappa) * 2**selected_kappa
            module = dict(
                name=name + "-" + variant, source="Table 1 dimensions/masks; hand-selected q/gamma3; not an author preset",
                parameters=dict(degree=256, k=rank, l=columns, eta=1, kappa=selected_kappa,
                                gamma1=g1, gamma2=g2, gamma3=gamma3, dropped_bits=dropped, q=q),
                modulus_selection=selection,
                exact_conditions=dict(q_prime=bool(is_prime(q)), alpha_divides_q_minus_one=(q - 1) % alpha == 0,
                                      q_above_twice_alpha=q > 2 * alpha, q_congruent_1_mod512=q % 512 == 1,
                                      root_512=root_ntt, root_order_512=pow(root_ntt, 256, q) == q - 1,
                                      lowbit_challenge_bound_below_gamma3=selected_kappa * 2**(dropped - 1) < gamma3,
                                      beta2_below_gamma3=selected_kappa * g1 < gamma3),
                lwe_comparator_input=dict(secret_dimension=256 * columns, samples=256 * rank, q=q,
                                          secret="Uniform[-1,1]", error="Uniform[-1,1]"),
                lwe_comparator_scope="unstructured coefficient-dimensional lattice comparator; ignores module correlations/algebraic attacks; not an MLWE certificate",
                challenge_bits=math.log2(count), generic_quantum_search_exponent=math.log2(count) / 2,
                paper_reported_signature_bytes=paper_size, actual_signature_size_measured=False,
                estimates={}, security_claim="none", backend_admitted=False, qrom_proof=False,
                extraction_planning=_rejection_cost(g1, selected_kappa, 256 * (rank + columns), strict=False),
            )
            cache_key = (columns, rank, q)
            if cache_key not in lwe_cache:
                estimates = {}
                for mode in ("classical", "quantum"):
                    params = LWE.Parameters(n=256 * columns, m=256 * rank, q=q,
                                            Xs=ND.Uniform(-1, 1), Xe=ND.Uniform(-1, 1))
                    result = LWE.estimate(params, red_cost_model=ADPS16(mode=mode), red_shape_model="lgsa",
                                          deny_list=("arora-gb", "bkw"), catch_exceptions=False, quiet=True)
                    estimates[mode] = _cost_records(result, log, oo, lwe=True)
                lwe_cache[cache_key] = estimates
            module["estimates"] = lwe_cache[cache_key]
            modules.append(module)

    # Reproduce the pinned infinity optimizer issue on a rejected row; do not
    # turn a tool exception into a large attack-cost or safety claim.
    probe_row = next(row for row in rows if row["name"] == "matrix-n512-r4-gap24")
    p = probe_row["parameters"]
    try:
        costs = SIS.estimate(SIS.Parameters(n=p["n"], m=p["m"], q=p["q"],
                            length_bound=probe_row["witness_bounds"]["screening_bound"], norm=oo),
                             red_cost_model=ADPS16(mode="classical"), red_shape_model="lgsa",
                             catch_exceptions=False, quiet=True)
        optimizer_control = dict(status="returned", estimates=_cost_records(costs, log, oo))
    except Exception as exc:
        optimizer_control = dict(status="error_recorded", type=type(exc).__name__, message=str(exc),
                                 interpretation="unknown cost, not security success; the valid Euclidean attack already excludes this row")
    optimizer_control["profile"] = probe_row["name"]

    return dict(
        schema="IBME/LUO2024/JOINT-PARAMETER-SCREEN/1", paper=PAPER_URL,
        provenance=dict(paper_sha256=hashlib.sha256(Path("papers/2024_ibs_without_trapdoors_luo.pdf").read_bytes()).hexdigest(),
                        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        estimator=ESTIMATOR_URL, estimator_commit=revision, clean_checkout=True),
        runtime=dict(python=sys.version.split()[0], sage=sage_version, platform=platform.platform()),
        selection=dict(n_values=N_VALUES, width_ratios=WIDTH_RATIOS, q_gap_bits=Q_GAPS,
                       eta_powers=[0, 32], k=256, kappa=64, statistical_target_bits=TARGET_STAT_BITS,
                       heuristic_cost_floor_log2=HEURISTIC_COST_FLOOR,
                       public_budget_bytes=PUBLIC_BUDGET, signature_budget_bytes=SIGNATURE_BUDGET,
                       mask_planning="about ten trials per stage; central-region lower bounds reported separately"),
        matrix_rows=rows, matrix_classification_counts=dict(Counter(row["classification"] for row in rows)),
        prior_eta1_controls=[dict(name=name, parameters=p, public_uniformity=public_uniformity(p),
                                 witness_bounds=witness_bounds(p)) for name, p, executable in screening_rows() if not executable],
        module_rows=modules, infinity_optimizer_control=optimizer_control,
        cost_model="ADPS16 classical/quantum Core-SVP heuristic; SIS infinity/LWE LGSA",
        euclidean_prefilter="norm2 <= B implies norm_infinity <= B; same B, no sqrt(m) substitution",
        algorithm_instances_added=0, complete_ibme_instances_added=0, private_material_generated=False,
        security_claim="none", backend_admitted=False,
        limitations=[
            "This bounded grid is not an exhaustive impossibility result for matrix IBS.",
            "The public-distribution bound is not a bounded-preimage or key-recovery hardness theorem.",
            "Theorem 1 and event E have different bounds; the larger triangle bound is only a conservative screening input.",
            "No repaired nonzero-witness, fixed-key forking or QROM proof is claimed.",
            "Heuristic cost survivors still require proof/parameter mapping and real implementation/resource checks.",
            "Module q values change Table 1 inputs; no published security number is inherited.",
            "Module estimates ignore structured/algebraic attacks; MSIS forgery/Hint compression remain unimplemented.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.estimator_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(output=str(args.output), matrix_rows=len(result["matrix_rows"]),
                          classifications=result["matrix_classification_counts"],
                          module_rows=len(result["module_rows"]), security_claim="none")))


if __name__ == "__main__":
    main()
