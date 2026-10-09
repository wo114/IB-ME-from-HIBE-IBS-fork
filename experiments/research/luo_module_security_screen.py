"""Luo §4.4 Hint bridge, conditional fork bounds and pinned MSIS screen.

Analysis only. Published public-oracle simulation/cached-key interpretation is
an explicit hypothesis, not re-proved by this finite arithmetic/cost audit.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
import math
from pathlib import Path
import platform
import sys
import warnings

from experiments.research.luo_parameter_screen import (
    ESTIMATOR_COMMIT, ESTIMATOR_URL, PAPER_URL, verify_estimator_checkout,
)
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleParams
from ibme.ibs.luo_module_math import sparse_product

COST_FLOOR = 128
GRID_BETA = (40, 80, 160, 320, 480, 600, 640, 672, 674, 688, 736, 800)
GRID_ZETA = (0, 1, 128, 256, 512, 1024)


def _positive(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"positive integer {name} required")
    return value


def _center(value, q):
    residue = value % q
    return residue - q if 2 * residue > q else residue


def _require(condition, label):
    if not condition:
        raise RuntimeError(label)


def processor_model():
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unavailable"


def public_high_lift(high, p):
    """A canonical full w lifting w1, including the 1024 carry corner."""
    if isinstance(high, bool) or not isinstance(high, int) or not 0 <= high <= p.max_w1:
        raise ValueError("invalid compressed identity high value")
    full = min(high * 2**p.dropped_bits, p.q - 1)
    low = full - high * 2**p.dropped_bits
    if p.rounding().power2round(full) != high or not -2**(p.dropped_bits - 1) < low <= 2**(p.dropped_bits - 1):
        raise ValueError("high value has no valid canonical lift")
    return full, low


def hint_correction(value, hint, p):
    """Centered integer u with alpha*UseHint(h,v) = v+u (mod q)."""
    if (isinstance(value, bool) or not isinstance(value, int) or isinstance(hint, bool)
            or not isinstance(hint, int) or hint not in (0, 1)):
        raise ValueError("integer value and bit hint required")
    high = p.rounding().use_hint(hint, value)
    return _center(2 * p.gamma3 * high - value, p.q)


def compression_bounds(p):
    dropped = p.kappa * 2**(p.dropped_bits - 1)
    hint = 2 * p.gamma3 + 1
    return dict(sign_z=p.gamma2 - p.beta2 - 1, extraction_z=p.gamma1 - p.beta1,
                dropped_low_product=dropped, hint_correction=hint, uncompressed_error=hint + dropped,
                source="PDF page 16, Section 4.4 and Equation (4.1); coefficient infinity norms",
                hash_lift="H1(Power2Round(w),id); does not treat H1 as an independent oracle on every full low-bit lift")


def witness_rows(p):
    """Conditional algebraic fork bounds; uniform maxima relax block bounds."""
    b = compression_bounds(p)
    cases = (
        ("known-identity-tight", p.l + p.k,
         [2 * b["sign_z"] + 2 * p.kappa * b["extraction_z"],
          2 * b["uncompressed_error"] + 2 * p.kappa * b["extraction_z"]],
         "[A|I_k]", "Same cached w1/CID and H2 input; integer witness nonzero uses the conditional cube-guess lemma"),
        ("known-identity-paper-loose", p.l + p.k,
         [2 * p.gamma2 + 2 * p.beta2, 2 * b["uncompressed_error"] + 2 * p.beta2],
         "[A|I_k]", "Conservative paper-style strict-bound relaxation of the known-identity branch"),
        ("fresh-identity-augmented", p.l + p.k + 1,
         [2 * b["sign_z"], 2 * b["uncompressed_error"], 2 * p.kappa],
         "[A|I_k|t]", "After the MLWE t-uniform hybrid; same H2 challenge, distinct H1 challenges; final product block proves nonzero"),
        ("all-branches-relaxed", p.l + p.k + 1,
         [2 * p.gamma2 + 2 * p.beta2, 2 * b["uncompressed_error"] + 2 * p.beta2, 2 * p.kappa],
         "[A|I_k|t]", "Relaxed common box; known-identity witnesses append a zero t block"),
    )
    return [dict(name=name, module_rows=p.k, module_columns=columns,
                 coefficient_rows=p.degree * p.k, coefficient_columns=p.degree * columns,
                 block_infinity_bounds=blocks, uniform_screen_bound=max(blocks), q=p.q,
                 below_q_half=2 * max(blocks) < p.q - 1, normalized_matrix=matrix,
                 interpretation=scope, estimates={}, security_claim="none", backend_admitted=False)
            for name, columns, blocks, matrix, scope in cases]


def conditional_cube_guess_bound(dimensions, radius, label_count, tries=1):
    """Average bound for a uniform cube, a bounded label, injective guesses.

    The adversary may choose each nonzero multiplier and target after seeing
    the label. Multiplication must be injective in the INTEGER ring. Extra
    views must be simulatable from the label and independent randomness.
    """
    _positive(dimensions, "dimensions")
    _positive(radius, "radius")
    _positive(label_count, "label count")
    _positive(tries, "tries")
    if dimensions > 32768:
        raise ValueError("finite cube resource budget exceeded")
    return min(Fraction(1), Fraction(label_count * tries, (2 * radius + 1)**dimensions))


def nonzero_conditions(p):
    b = p.gamma1 - p.beta1
    dimensions, label_dimensions = p.degree * (p.l + p.k), p.degree * p.k
    labels = (p.max_w1 + 1)**label_dimensions
    bound = conditional_cube_guess_bound(dimensions, b, labels, tries=2**20)
    bits = dimensions * math.log2(2 * b + 1) - label_dimensions * math.log2(p.max_w1 + 1) - 20
    return dict(
        fresh_identity=dict(integer_ring="Z[X]/(X^N+1), power-of-two N; integral domain",
                            last_block="c*(CID-CID')", coefficient_bound=2 * p.kappa,
                            bound_below_q=2 * p.kappa < p.q,
                            requires_c_nonzero_and_CID_distinct=True,
                            invertible_mod_q_challenge_not_required=True),
        known_identity=dict(uniform_key_cube_dimensions=dimensions, cube_radius=b,
                            public_label_dimensions=label_dimensions, labels_per_coefficient=p.max_w1 + 1,
                            illustrative_guess_union=2**20, average_bound_log2=min(0.0, -bits),
                            exact_bound_at_most_2pow_minus128=bound <= Fraction(1, 2**128),
                            pointwise_posterior_claim=False,
                            hypothesis="Published Extract/Sign oracle simulation with shared cached identity state; view reveals the uniform key only through w1 and independent public randomness; excludes timings and failed programming events"),
        scope="Finite conditional nonzero bridges, not a replacement for the paper's simulator/forking probabilities or a full QROM theorem")


def finite_budget_checks(p):
    def record(gamma, beta, count, attempts, strict):
        target = 2 * (gamma - beta) + (-1 if strict else 1)
        central = 2 * (gamma - 2 * beta) + (-1 if strict else 1)
        if central <= 0:
            return dict(unconditional_central_region_empty=True)
        log_accept = count * math.log(central / (2 * gamma + 1))
        lower = math.exp(log_accept)
        plan = count * math.log(target / (2 * gamma + 1))
        return dict(coefficient_count=count, attempt_limit=attempts,
                    ideal_new_hash_planning_expected_trials=math.exp(-plan),
                    ideal_planning_abort_upper_log2=attempts * math.log1p(-math.exp(plan)) / math.log(2),
                    unconditional_central_region_acceptance_lower_log2=log_accept / math.log(2),
                    central_region_abort_upper_log2=attempts * math.log1p(-lower) / math.log(2),
                    scope="Mask cube only; planning assumes new ideal hash challenges; excludes uniform/XOF/programming budgets")
    return dict(extraction=record(p.gamma1, p.beta1, p.degree * (p.l + p.k), p.max_extract_attempts, False),
                sign_z_only=record(p.gamma2, p.beta2, p.degree * p.l, p.max_sign_attempts, True),
                signing_remaining_rejections_not_bounded_here=True,
                interpretation="These are availability/model checks, not an observed abort frequency or a security-level claim")


def arithmetic_audit():
    """Independent Sage quotient/evaluation checks and all small Hint inputs."""
    from sage.all import PolynomialRing, ZZ, GF, matrix, vector, identity_matrix, is_prime
    from experiments.research.luo_module_audit import SagePolynomialOracle, use_hint
    p = LuoModuleParams()
    require = _require
    require(bool(is_prime(p.q)), "selected modulus primality")
    require(int(GF(p.q)(p.root).multiplicative_order()) == 2 * p.degree, "selected primitive NTT root")
    require((p.q - 1) % (2 * p.gamma3) == 0 and p.q > 4 * p.gamma3, "selected Hint arithmetic")
    scalar_count, lift_count = 0, 0
    for q in (17, 31, 41, 97):
        for alpha in range(2, q // 2 + 1, 2):
            if (q - 1) % alpha:
                continue
            # These contexts test the rounding bridge without IBS mask bounds.
            from ibme.ibs.luo_module_math import Rounding
            rounding = Rounding(q, alpha, 3)
            for value in range(q):
                for hint in (0, 1):
                    correction = _center(alpha * rounding.use_hint(hint, value) - value, q)
                    expected = _center(alpha * use_hint(hint, value, q, alpha) - value, q)
                    require(correction == expected and abs(correction) <= alpha + 1, "independent small Hint correction")
                    scalar_count += 1
    for high in range(p.max_w1 + 1):
        full, low = public_high_lift(high, p)
        modulus = 2**p.dropped_bits
        residue = full % modulus
        centered = residue - modulus if 2 * residue > modulus else residue
        require((full - centered) // modulus == high and centered == low, "independent high lift")
        lift_count += 1
    require(hint_correction(0, 1, p) == -(2 * p.gamma3 + 1), "tight arbitrary-hint carry corner")
    require(public_high_lift(1024, p) == (p.q - 1, p.q - 1 - 1024 * 2**p.dropped_bits), "1024 high carry lift")
    polynomials = PolynomialRing(ZZ, "x")
    require(bool((polynomials.gen()**p.degree + 1).is_irreducible()), "integer ring is not a domain")
    oracle = SagePolynomialOracle(p.degree, p.q)
    random = DeterministicRandom(b"luo-module-security:bridge")
    full_cases, sparse_cases = 0, 0
    for _ in range(12):
        c = [0] * p.degree
        positions = list(range(p.degree))
        for index in range(p.kappa):
            chosen = index + int.from_bytes(random.read(2), "big") % (p.degree - index)
            positions[index], positions[chosen] = positions[chosen], positions[index]
            c[positions[index]] = 1 if random.read(1)[0] & 1 else -1
        c = tuple(c)  # Fixed audit challenges, not a production distribution sampler.
        full = tuple(int.from_bytes(random.read(5), "big") % p.q for _ in range(p.degree))
        w1 = tuple(p.rounding().power2round(x) for x in full)
        w0 = tuple(x - high * 2**p.dropped_bits for x, high in zip(full, w1))
        v = tuple(int.from_bytes(random.read(5), "big") % p.q for _ in range(p.degree))
        hints = tuple(random.read(1)[0] & 1 for _ in range(p.degree))
        u = tuple(hint_correction(value, hint, p) for value, hint in zip(v, hints))
        dropped = oracle.multiply(w0, c, integer=True)
        require(dropped == sparse_product(w0, c), "Sage dropped-bit product")
        transformed = tuple(a + b for a, b in zip(u, dropped))
        bounds = compression_bounds(p)
        require(max(map(abs, transformed)) <= bounds["uncompressed_error"], "error bridge norm")
        # v = Az-(w1*2^d+t*CID)c. Replacing w1*2^d by w changes
        # v to v-w0*c, so adding u+w0*c gives exactly the same value.
        require(tuple((value - shift + error) % p.q for value, shift, error in zip(v, dropped, transformed))
                == tuple((value + error) % p.q for value, error in zip(v, u)), "Equation 4.1 compression bridge")
        full_cases += 1
    normalization_cases, known_zero_control = 0, False
    for degree, modulus, root in ((2, 17, 4), (4, 17, 2)):
        oracle = SagePolynomialOracle(degree, modulus)
        challenges = [tuple(sign if j == i else 0 for j in range(degree))
                      for i in range(degree) for sign in (-1, 1)]
        for left, right, c in product(challenges, repeat=3):
            if left == right:
                continue
            difference = tuple(x - y for x, y in zip(left, right))
            witness = oracle.multiply(difference, c, integer=True)
            require(any(witness) and max(map(abs, witness)) <= 2 and any(x % modulus for x in witness),
                    "fresh-identity integer/modular nonzero product")
            sparse_cases += 1
        # Left-normalizing an invertible public block preserves the witness,
        # not just its equation. This finite example is not a distribution test.
        field = GF(modulus)
        require(int(field(root).multiplicative_order()) == 2 * degree, "small NTT root order")
        polynomials_q = PolynomialRing(field, "x")
        ring = polynomials_q.quotient(polynomials_q.gen()**degree + 1, "a")
        x = ring.gen()
        block = matrix(ring, [[1, x], [0, 1]])
        inverse = matrix(ring, [[1, -x], [0, 1]])
        require(inverse * block == identity_matrix(ring, 2), "public block inversion")
        a, t = matrix(ring, [[x + 1], [x - 1]]), matrix(ring, [[2 - x], [1 + x]])
        raw = a.augment(block).augment(t)
        normalized = inverse * raw
        normalized_a, normalized_t = inverse * a, inverse * t
        z, c = vector(ring, [x - 1]), x + 1
        errors = -(normalized_a * z) - vector(ring, [row[0] * c for row in normalized_t.rows()])
        witness = vector(ring, [z[0], *errors, c])
        require(not any(raw * witness) and not any(normalized * witness), "normalization preserves exact kernel")
        m = normalized_a.augment(identity_matrix(ring, 2))
        sid, mask = vector(ring, [1, x, -1]), vector(ring, [x + 1, 1, x])
        c, c_prime = ring(1), x
        response, forked_response = mask + c * sid, mask + c_prime * sid
        zero = forked_response - response - (c_prime - c) * sid
        require(c != c_prime and not any(zero) and not any(m * zero), "known-key zero-witness control")
        known_zero_control = True
        normalization_cases += 1
    return dict(scalar_hint_cases=scalar_count, high_lifts_checked=lift_count,
                signed_polynomial_error_cases=full_cases, small_nonzero_product_cases=sparse_cases,
                integer_cyclotomic_irreducible=True, high1024_low=public_high_lift(1024, p)[1],
                tight_hint_correction=-(2 * p.gamma3 + 1), normalization_examples=normalization_cases,
                known_branch_fork_alone_can_give_zero_control=known_zero_control,
                prime=True, selected_root_order=2 * p.degree,
                normalization_bad_block_probability_upper=dict(numerator=p.degree, denominator=p.q - 1,
                    interpretation="For a uniform k-by-k block over the fully split Rq: condition on invertibility, then normalize; reduction success loses a multiplicative factor, not an additive IBS advantage"))


def _record_cost(cost, log, oo):
    return dict(status="no_finite_estimate" if cost["rop"] == oo else "finite_heuristic_estimate",
                rop_log2=None if cost["rop"] == oo else float(log(cost["rop"], 2)),
                fields={key: str(value) for key, value in cost.items() if key != "problem"})


def audit(estimator_path):
    root, revision = verify_estimator_checkout(estimator_path)
    sys.path.insert(0, str(root))
    import estimator
    from estimator import SIS
    from estimator.reduction import ADPS16
    from estimator.sis_lattice import SISLattice
    from sage.all import oo, log
    from sage.env import SAGE_VERSION
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("estimator import does not match requested checkout")
    p, rows, tool_warnings = LuoModuleParams(), witness_rows(LuoModuleParams()), []
    arithmetic = arithmetic_audit()
    for row in rows:
        params = SIS.Parameters(n=row["coefficient_rows"], m=row["coefficient_columns"], q=p.q,
                                length_bound=row["uniform_screen_bound"], norm=oo, tag=row["name"])
        for mode in ("classical", "quantum"):
            try:
                with warnings.catch_warnings(record=True) as caught:
                    result = SIS.estimate(params, red_cost_model=ADPS16(mode=mode), red_shape_model="lgsa",
                                          catch_exceptions=False, quiet=True)
                if not result:
                    raise RuntimeError("SIS estimator returned no attack")
                row["estimates"][mode] = {name: _record_cost(cost, log, oo) for name, cost in result.items()}
                tool_warnings.extend(str(w.message) for w in caught)
            except Exception as exc:
                row["estimates"][mode] = {"error": dict(status="estimator_error_no_admission",
                                                       type=type(exc).__name__, message=str(exc), rop_log2=None)}
    common = rows[-1]
    grid = []
    params = SIS.Parameters(n=common["coefficient_rows"], m=common["coefficient_columns"], q=p.q,
                            length_bound=common["uniform_screen_bound"], norm=oo)
    for mode in ("classical", "quantum"):
        for beta, zeta in product(GRID_BETA, GRID_ZETA):
            try:
                cost = SISLattice.cost_infinity(beta, params, zeta=zeta, red_cost_model=ADPS16(mode=mode), red_shape_model="lgsa")
                grid.append(dict(mode=mode, beta=beta, zeta=zeta, **_record_cost(cost, log, oo)))
            except Exception as exc:
                grid.append(dict(mode=mode, beta=beta, zeta=zeta, status="estimator_error_no_admission",
                                 type=type(exc).__name__, message=str(exc), rop_log2=None))
    finite = [cost["rop_log2"] for row in rows for records in row["estimates"].values()
              for cost in records.values() if cost["rop_log2"] is not None]
    finite.extend(cost["rop_log2"] for cost in grid if cost["rop_log2"] is not None)
    complete = all(cost["rop_log2"] is not None for row in rows for records in row["estimates"].values() for cost in records.values())
    count = math.comb(p.degree, p.kappa) * 2**p.kappa
    challenge_quantum = math.log2(count) / 2
    prior_path = Path("docs/research/2026-10-09-m2b/joint-screen.json")
    prior = json.loads(prior_path.read_text(encoding="utf-8"))
    previous = next(row for row in prior["module_rows"] if row["name"] == "table-200-flexible-gamma3-kappa64")
    if any(previous["parameters"].get(name) != getattr(p, name) for name in previous["parameters"]):
        raise ValueError("prior MLWE comparator does not match current math parameters")
    lwe_costs = [cost["rop_log2"] for records in previous["estimates"].values() for cost in records.values()
                 if cost["rop_log2"] is not None]
    grid_errors = sum(cost["status"] == "estimator_error_no_admission" for cost in grid)
    passed = complete and grid_errors == 0 and bool(finite) and min(finite) >= COST_FLOOR and challenge_quantum >= COST_FLOOR and min(lwe_costs) >= COST_FLOOR
    all_sources = ("experiments/research/luo_module_security_screen.py", "src/ibme/ibs/luo_module.py",
                   "src/ibme/ibs/luo_module_math.py", "papers/2024_ibs_without_trapdoors_luo.pdf")
    control49 = replace(p, kappa=49)
    return dict(schema="IBME/LUO2024/MODULE-SECURITY-SCREEN/1", paper=PAPER_URL,
                params=asdict(p), compression=compression_bounds(p), witnesses=rows,
                nonzero=nonzero_conditions(p), arithmetic=arithmetic, budgets=finite_budget_checks(p),
                comparator_grid=grid, tool_warnings=sorted(set(tool_warnings)),
                provenance=dict(estimator=ESTIMATOR_URL, estimator_commit=revision, clean_checkout=True,
                                prior_mlwe_artifact_sha256=sha256(prior_path.read_bytes()).hexdigest(),
                                source_sha256={name: sha256(Path(name).read_bytes()).hexdigest() for name in all_sources}),
                runtime=dict(python=sys.version, sage=SAGE_VERSION, platform=platform.platform(), processor=processor_model()),
                cost_scope="Unstructured coefficient-dimensional homogeneous infinity-norm SIS comparator, relaxing all block bounds to their maximum; module algebraic attacks and exact IBS advantage excluded",
                model="ADPS16 classical/quantum Core-SVP, LGSA; no hardware run-time estimate",
                prior_mlwe_comparator=previous["estimates"], challenge_space_bits=math.log2(count),
                generic_quantum_challenge_search_exponent=challenge_quantum,
                kappa49_control=dict(params_same_except_kappa=True,
                                     challenge_bits=math.log2(math.comb(p.degree, 49) * 2**49),
                                     generic_quantum_search_exponent=math.log2(math.comb(p.degree, 49) * 2**49) / 2,
                                     meets128_search_floor=(math.comb(p.degree, 49) * 2**49 >= 2**256),
                                     error_bound=compression_bounds(control49)["uncompressed_error"]),
                decision=dict(arithmetic_usable=True, chosen_cost_models_complete=complete,
                              finite_grid_error_count=grid_errors,
                              heuristic128_floor_pass=passed, retain_scheme=True, retain_current_research_parameters=passed,
                              formal_release_admitted=False, security_claim="none",
                              explanation="Keep this parameter variant for engineering if the explicit heuristic floor passes; cite the module-security sketch only with its simulator/normalization/forking hypotheses. No complete QROM theorem or safe HIBE is inferred."),
                private_material_generated=False, new_algorithm_instances=0, admitted_secure_ibme_instances=0,
                security_claim="none", backend_admitted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.estimator_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["decision"], ensure_ascii=False))


if __name__ == "__main__":
    main()
