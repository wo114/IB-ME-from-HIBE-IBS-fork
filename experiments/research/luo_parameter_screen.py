"""Public parameter feasibility and pinned SIS/LWE attack-cost screening.

This is analysis, not a secure preset or an extension of MATRIX-REF/1. The
large rows are not executable by the bounded reference backend. Cost models
are heuristic; quantum lattice costs do not establish a QROM IBS theorem.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, localcontext, ROUND_CEILING
from itertools import product
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

from experiments.research.luo_matrix_reference import (
    MatrixParams, MasterState, PublicKey, VERSION, key_extract, setup, sign, verify,
)
from ibme.core.randomness import DeterministicRandom


ESTIMATOR_COMMIT = "53da5982597709ba0fdf94ea37a84d822310fd84"
ESTIMATOR_URL = "https://github.com/malb/lattice-estimator"
PAPER_URL = "https://icics2024.aegean.gr/wp-content/uploads/2024/08/150570198.pdf"
MATH_FIELDS = ("n", "m", "k", "q", "eta", "kappa", "gamma1", "gamma2")


def _validate(p: dict):
    if set(p) != set(MATH_FIELDS):
        raise ValueError("unexpected matrix screening fields")
    if any(isinstance(p[x], bool) or not isinstance(p[x], int) or p[x] < 1 for x in MATH_FIELDS):
        raise ValueError("screening parameters must be positive integers")
    if not (p["m"] > p["n"] and p["kappa"] <= p["k"] and p["q"] >= 3 and p["q"] % 2 == 1):
        raise ValueError("require m>n, kappa<=k and odd q; primality checked separately")
    if p["gamma1"] <= p["kappa"] * p["eta"] or p["gamma2"] <= p["kappa"] * p["gamma1"]:
        raise ValueError("invalid mask and shift bounds")


def planned_large_row(n: int, m: int, k: int, kappa: int, q: int) -> dict:
    """Hand-selected dimensions, masks planned for about ten trials each."""
    with localcontext() as context:
        context.prec = 60
        gamma1 = int((Decimal(m * k * kappa) / Decimal(10).ln()).to_integral_value(ROUND_CEILING))
        gamma2 = int((Decimal(m * kappa * gamma1) / Decimal(10).ln()).to_integral_value(ROUND_CEILING))
    p = dict(n=n, m=m, k=k, kappa=kappa, q=q, eta=1, gamma1=gamma1, gamma2=gamma2)
    _validate(p)
    return p


def screening_rows():
    tiny = {x: getattr(MatrixParams(), x) for x in MATH_FIELDS}
    wide = {**tiny, "k": 32, "kappa": 8, "q": 2**31 - 1, "gamma1": 4096, "gamma2": 131072}
    return [
        ("r1-tiny", tiny, True),
        ("m2-functional", wide, True),
        ("screen-n128-q61", planned_large_row(128, 256, 128, 32, 2**61 - 1), False),
        ("screen-n256-q61", planned_large_row(256, 512, 128, 32, 2**61 - 1), False),
        ("screen-n512-q61", planned_large_row(512, 1024, 192, 48, 2**61 - 1), False),
        # next_prime(2**76) checked in the required Sage environment. Exact q,
        # not a log2(q) placeholder; still only a cost-screening input.
        ("screen-n512-k256-q77", planned_large_row(
            512, 1024, 256, 64, 75557863725914323419151), False),
    ]


def _rejection_cost(gamma, beta, coefficients, *, strict):
    total = 2 * gamma + 1
    accepted = 2 * (gamma - beta) + (-1 if strict else 1)
    # Constant-shift/ideal-hash planning count, not measured acceptance or a
    # proof of independence when the shift is a hash of the sampled mask.
    log_p = coefficients * math.log1p((accepted - total) / total)
    central = max(0, 2 * (gamma - 2 * beta) + (-1 if strict else 1))
    log_lower = None if central == 0 else coefficients * math.log1p((central - total) / total)
    return dict(
        planning_expected_trials=math.exp(-log_p) if -log_p < 700 else None,
        planning_log2_expected_trials=-log_p / math.log(2),
        unconditional_central_region_log2_acceptance_lower_bound=(
            None if log_lower is None else log_lower / math.log(2)),
        coefficient_count=coefficients,
        scope="planning model plus deterministic central-region bound; excludes uniform-draw/hash budgets",
    )


def screen_row(name: str, p: dict, executable: bool) -> dict:
    _validate(p)
    n, m, k, q, c = (p[x] for x in ("n", "m", "k", "q", "kappa"))
    beta1, beta2 = c * p["eta"], c * p["gamma1"]
    sis_bound = 2 * p["gamma2"] + 2 * c * beta1
    challenge_count = math.comb(k, c) * 2**c
    coef_bytes = ((q - 1).bit_length() + 7) // 8
    current_wire = executable and q < 2**32 and p["gamma2"] < 2**31
    # Exact MATRIX-REF/1 signature formula is only emitted when encodable.
    signature_bytes = 90 + len(VERSION) + 8 * (m + k) + n * k * coef_bytes if current_wire else None
    return dict(
        name=name, source="hand-selected research or screening family, not published safe parameters",
        parameters=p, beta1=beta1, beta2=beta2, q_bit_length=q.bit_length(), q_prime=None,
        reference_executable=executable, current_wire_encodable=current_wire,
        challenge_count=str(challenge_count), challenge_bits=math.log2(challenge_count),
        generic_quantum_challenge_search_exponent=math.log2(challenge_count) / 2,
        challenge_count_at_least_2pow128=challenge_count >= 2**128,
        challenge_count_at_least_2pow256=challenge_count >= 2**256,
        extraction=_rejection_cost(p["gamma1"], beta1, m * k, strict=False),
        signing=_rejection_cost(p["gamma2"], beta2, m, strict=True),
        estimator_input=dict(n=n, m=m, q=q, length_bound=sis_bound, norm="infinity"),
        master_recovery_lwe_input=(None if executable else master_recovery_lwe_input(p)),
        master_recovery_lwe_estimates={},
        sis_bound_below_q=sis_bound < q,
        public_A_T_raw_coefficient_bytes=n * (m + k) * coef_bytes,
        signature_raw_z_c_W_bytes=8 * (m + k) + n * k * coef_bytes,
        raw_size_scope="byte-aligned modular coefficients and int64 z/c; excludes future framing",
        current_signature_wire_bytes=signature_bytes,
        estimates={}, security_claim="none", backend_admitted=False,
    )


def master_recovery_lwe_input(p: dict) -> dict:
    """Return the one-column LWE instance exposed by the public key.

    Split A=[A0|A1] and S=[S0;S1]. When A0 is invertible,
    A0^-1 T = S0 + (A0^-1 A1) S1 (mod q). Each column is a bounded-secret,
    bounded-error LWE instance. This is a screening transform, not by itself a
    reduction proving that recovery of one column forges the full IBS scheme.
    """
    _validate(p)
    n, m = p["n"], p["m"]
    return dict(
        secret_dimension=m - n,
        sample_count=n,
        q=p["q"],
        secret_distribution=f"uniform integers [{-p['eta']},{p['eta']}], inclusive",
        error_distribution=f"uniform integers [{-p['eta']},{p['eta']}], inclusive",
        public_equation="A0^-1*T = S0 + (A0^-1*A1)*S1 (mod q)",
        condition="A0 (the first n columns of A) is invertible over Z_q",
        samples_per_master_column=n,
        independent_master_columns=p["k"],
        scope="heuristic one-column master-key recovery screen; no full-scheme forgery claim",
    )


def recover_small_master(public: PublicKey, *, candidate_limit=100000):
    """Public bounded-secret enumeration; returns an equivalent master or None.

    Only A,T and public bounds are read. There is no victim private state,
    key-extraction query or signing query. Exponential enumeration is explicitly
    confined to tiny research instances.
    """
    p = public.params
    candidate_count = (2 * p.eta + 1)**p.m
    if candidate_count > candidate_limit:
        raise ValueError("bounded-secret negative control exceeds enumeration budget")
    targets = {tuple(public.T[i][j] for i in range(p.n)) for j in range(p.k)}
    matches = {}
    for vector in product(range(-p.eta, p.eta + 1), repeat=p.m):
        image = tuple(sum(public.A[i][j] * vector[j] for j in range(p.m)) % p.q for i in range(p.n))
        if image in targets and image not in matches:
            matches[image] = vector
    if len(matches) != len(targets):
        return None, candidate_count
    columns = [matches[tuple(public.T[i][j] for i in range(p.n))] for j in range(p.k)]
    secret = tuple(tuple(columns[j][i] for j in range(p.k)) for i in range(p.m))
    return MasterState(public, secret), candidate_count


def public_forgery_controls() -> list[dict]:
    output = []
    for name, p, executable in screening_rows():
        if not executable:
            continue
        public, _ = setup(MatrixParams(**p), rng=DeterministicRandom(f"luo-m2:public:{name}".encode()))
        recovered, count = recover_small_master(public)
        if recovered is None:
            raise RuntimeError("public negative control did not reconstruct a valid master")
        attacker_rng = DeterministicRandom(f"luo-m2:attacker:{name}".encode())
        identity, message = b"target", b"public master recovery"
        key = key_extract(recovered, identity, rng=attacker_rng)
        signature = sign(key, message, rng=attacker_rng)
        valid = verify(public, identity, message, signature)
        if not valid:
            raise RuntimeError("publicly reconstructed master failed to produce a valid forgery")
        output.append(dict(
            profile=name, candidate_vectors_checked=count, victim_extract_queries=0,
            victim_sign_queries=0, equivalent_master_recovered=True, forged_signature_accepted=True,
            identity_hex=identity.hex(), message_hex=message.hex(), public_key_hex=public.to_bytes().hex(),
            signature_hex=signature.to_bytes().hex(), private_material_published=False,
            scope="tiny-profile attack; not an attack on legal security-target paper parameters",
        ))
    return output


def run_estimator(rows: list[dict], root: Path, *, public_master_lwe_control=False) -> dict:
    root = root.resolve()
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    # A checkout made by Windows Git can use CRLF. Check Git-normalized
    # content in WSL too, without treating line-ending conversion as edits.
    dirty = subprocess.check_output([
        "git", "-c", "core.autocrlf=true", "-C", str(root), "status", "--porcelain",
    ], text=True).strip()
    if revision != ESTIMATOR_COMMIT or dirty:
        raise ValueError("estimator must be the clean, pinned revision")
    sys.path.insert(0, str(root))
    import estimator
    from estimator import LWE, ND, SIS
    from estimator.reduction import ADPS16
    from sage.all import is_prime, log, oo
    from sage.version import version as sage_version
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("imported estimator is outside the requested checkout")
    for row in rows:
        row["q_prime"] = bool(is_prime(row["parameters"]["q"]))
        if row["reference_executable"]:
            row["estimate_scope"] = "omitted: direct public master recovery is already demonstrated"
            continue
        p = row["estimator_input"]
        params = SIS.Parameters(n=p["n"], m=p["m"], q=p["q"], length_bound=p["length_bound"],
                                norm=oo, tag=row["name"])
        for mode in ("classical", "quantum"):
            result = SIS.estimate(params, red_cost_model=ADPS16(mode=mode), red_shape_model="lgsa",
                                  catch_exceptions=False, quiet=True)
            if not result:
                raise RuntimeError("estimator returned no attack result")
            attacks = {}
            for attack, cost in result.items():
                finite = cost["rop"] != oo
                attacks[attack] = dict(
                    status="finite_heuristic_estimate" if finite else "no_finite_estimate",
                    rop_log2=None if not finite else float(log(cost["rop"], 2)),
                    cost_fields={key: str(value) for key, value in cost.items() if key != "problem"},
                )
            row["estimates"][mode] = attacks
    for row in rows:
        if row["reference_executable"]:
            continue
        model = row["master_recovery_lwe_input"]
        eta = row["parameters"]["eta"]
        params = LWE.Parameters(
            n=model["secret_dimension"], m=model["sample_count"], q=model["q"],
            Xs=ND.Uniform(-eta, eta), Xe=ND.Uniform(-eta, eta), tag=row["name"] + ":master-column",
        )
        for mode in ("classical", "quantum"):
            result = LWE.estimate(
                params, red_cost_model=ADPS16(mode=mode), red_shape_model="lgsa",
                deny_list=("arora-gb", "bkw"), catch_exceptions=False, quiet=True,
            )
            if not result:
                raise RuntimeError("LWE estimator returned no standard lattice attack result")
            attacks = {}
            for attack, cost in result.items():
                finite = cost["rop"] != oo
                attacks[attack] = dict(
                    status="finite_heuristic_estimate" if finite else "no_finite_estimate",
                    rop_log2=None if not finite else float(log(cost["rop"], 2)),
                    cost_fields={key: str(value) for key, value in cost.items() if key != "problem"},
                )
            row["master_recovery_lwe_estimates"][mode] = dict(
                attacks=attacks,
                attack_scope="implemented classical lattice families; BKW and algebraic Arora-GB excluded",
            )
    public_control = None
    if public_master_lwe_control:
        from experiments.research.luo_public_master_lwe_probe import run_control
        public_control = run_control()
    return dict(repository=ESTIMATOR_URL, commit=revision, clean_checkout=True,
                cost_model="ADPS16 classical 0.292 / quantum 0.265, Core-SVP heuristic",
                shape_model="lgsa", problem_norm="infinity", sage_version=sage_version,
                public_master_lwe_control=public_control,
                scope="implemented lattice attack model; not all possible IBS attacks or a security proof")


def audit(estimator_path: Path | None = None, *, public_master_lwe_control=False) -> dict:
    rows = [screen_row(*row) for row in screening_rows()]
    if public_master_lwe_control and estimator_path is None:
        raise ValueError("the public Sage control is run together with the pinned estimator audit")
    tool = None if estimator_path is None else run_estimator(
        rows, estimator_path, public_master_lwe_control=public_master_lwe_control,
    )
    best = max((math.comb(32, c) * 2**c, c) for c in range(1, 33))
    return dict(
        schema="IBME/LUO2024/MATRIX-SCREEN/1", paper=PAPER_URL,
        theorem_mapping="Section 2.1 infinity-norm SIS; Theorem 1 d=2*gamma2+2*kappa*beta1; explicit n,m,q",
        master_recovery_lwe_model=dict(
            equation="A=[A0|A1], S=[S0;S1], U=A0^-1*T=S0+(A0^-1*A1)*S1 (mod q)",
            condition="A0 is invertible over Z_q; for uniform square A0 the probability is product_{i=1}^n(1-q^-i)",
            interpretation="each of the k public master columns gives n samples of an (m-n)-dimensional bounded-secret, bounded-error LWE instance",
            limitation="heuristic implemented-lattice-attack screen and one-column recovery experiment; neither alone proves a full IBS forgery or a theorem-level break",
        ),
        runtime=dict(python=sys.version.split()[0], platform=platform.platform(), processor=platform.processor()),
        research_reference_challenge_cap=dict(k=32, maximizing_kappa=best[1], count=str(best[0]),
                                              log2_count=math.log2(best[0])),
        rows=rows, estimator=tool, public_forgery_controls=public_forgery_controls(),
        reduction_budget_example=dict(
            target_bits=128, assumed_s_plus_h=2**20, illustrative_required_sis_advantage_exponent=296,
            interpretation="128-bit IBS advantage with delta^2/(s+h)^2 requires about 2*128+2*20 SIS advantage exponent; NOT a work-factor conversion or certificate",
            theorem_is_approximate=True, runtime_and_reduction_errors_accounted=False,
            quantum_reduction_available=False,
        ),
        algorithm_instances=1, parameter_profiles_implemented=2, analysis_only_profiles=4,
        complete_ibme_instances=0, security_claim="none", backend_admitted=False,
        limitations=[
            "Parameter families are hand-selected and do not extend the executable reference limits.",
            "Rejection planning counts assume constant shift/ideal fresh hash; the central-region bound is separate.",
            "Core-SVP and LGSA costs are heuristic and version/model dependent.",
            "Quantum SIS and generic search costs do not prove quantum or QROM IBS security.",
            "Raw size projections omit a future big-modulus format and are not timing benchmarks.",
            "No published formal safe parameter set or complete IBME backend is admitted.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator-path", type=Path)
    parser.add_argument("--public-master-lwe-control", action="store_true",
                        help="run the deterministic public-only Sage recovery control")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.estimator_path, public_master_lwe_control=args.public_master_lwe_control)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(output=str(args.output), profiles=len(result["rows"]),
                          public_forgery_controls=len(result["public_forgery_controls"]),
                          estimator_commit=None if result["estimator"] is None else ESTIMATOR_COMMIT,
                          security_claim="none")))


if __name__ == "__main__":
    main()
