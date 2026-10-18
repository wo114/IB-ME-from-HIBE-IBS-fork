"""Abort-preserving adaptive history bounds for the unchanged SRGG paper backend.

This is a fixed accepted-root analysis.  It compares logical operation
transcripts, not wall-clock timing or malicious/external storage faults.  The
source first-issuance law is uniform in a canonical identity target h on this
root; the signature certificate is only for the one frozen Alice signing key.
The two scopes must never be silently composed into a random-key signature law.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from fractions import Fraction
from hashlib import sha256
from io import StringIO
import json
from functools import lru_cache
from pathlib import Path
import platform
import runpy

from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.srgg_paper_service import _preflight, IssuerCapacityError

from .paper_objects import MAX_USERS
from .paper_parameters import PaperParams
from .paper_schur_backend import SourceSchurBackend
from .paper_schur_finite_chain import fixed_root_finite_chain_certificate
from .paper_schur_normalizer import fixed_root_normalizer_certificate
from .paper_schur_numerical import SchurNumericalAudit


SCHEMA = "IBME/SRGG-PAPER-ADAPTIVE-HISTORY-FOLLOWUP/1"
ROOT = Path(__file__).resolve().parents[4]
SOURCE_PACKAGE = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-source-issuance"
FINITE_PACKAGE = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-finite-chain"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")


def probability(value):
    if type(value) not in (int, str, Fraction):
        raise ValueError("exact probability required")
    answer = Fraction(value)
    if not 0 <= answer <= 1:
        raise ValueError("probability outside [0,1]")
    return answer


def union_bound(delta, count):
    """Adaptive kernel coupling: at most count matching-history fresh calls.

    The input delta must bound each conditional kernel uniformly on every
    reachable matching history.  In particular, a single observed fixture
    probability cannot be inserted here merely because it is a small number.
    Abort is an ordinary output symbol; caches and deterministic recovery
    transitions have zero new coupling cost while the histories match.
    """
    delta = probability(delta)
    if type(count) is not int or not 0 <= count <= 1024:
        raise ValueError("bounded nonnegative call count required")
    return min(Fraction(1), count * delta)


def dyadic_upper(value):
    """Readable outward power-of-two upper bound, never rounded inward."""
    value = probability(value)
    if value == 0:
        return "0"
    if value == 1:
        return "1"
    bits = value.denominator.bit_length() - value.numerator.bit_length()
    bits = max(0, bits)
    while bits and value > Fraction(1, 2**bits):
        bits -= 1
    while value <= Fraction(1, 2**(bits + 1)):
        bits += 1
    return "2^-" + str(bits) if bits else "1"


@lru_cache(maxsize=1)
def authenticated_inputs():
    """Reuse the frozen source-issuance verifier, including all dependency hashes."""
    namespace = runpy.run_path(str(SOURCE_PACKAGE / "verify_delivery.py"))
    with redirect_stdout(StringIO()):
        namespace["main"]()
    source_bytes = (SOURCE_PACKAGE / "source-issuance.json").read_bytes()
    finite_bytes = (FINITE_PACKAGE / "finite-fixed-root.json").read_bytes()
    joint_bytes = (FINITE_PACKAGE / "joint-fixed-root.json").read_bytes()
    source, finite, joint = map(json.loads, (source_bytes, finite_bytes, joint_bytes))
    if not (len(source["rows"]) == len(finite["rows"]) == len(joint["rows"])):
        raise ValueError("six-row source chain differs")
    if len(source["rows"]) != 6 or len(finite["rows"]) != 6 or len(joint["rows"]) != 6:
        raise ValueError("six original rows required")
    return source, finite, joint, {
        "source_issuance_sha256": sha256(source_bytes).hexdigest(),
        "finite_sha256": sha256(finite_bytes).hexdigest(),
        "joint_sha256": sha256(joint_bytes).hexdigest(),
        "source_package_manifest_sha256": sha256(
            (SOURCE_PACKAGE / "MANIFEST.json").read_bytes()).hexdigest(),
    }


def _row(report, pair):
    rows = [r for r in report["rows"] if (r["profile"], r["interpretation"]) == pair]
    if len(rows) != 1:
        raise ValueError("original Table 4 row missing or duplicate")
    return rows[0]


def service_capacity(params):
    """Worst-case canonical-state byte envelope for the existing FixedIssuer."""
    admitted = 0
    for users in range(1, MAX_USERS + 1):
        try:
            _preflight(params, users)
        except IssuerCapacityError:
            break
        admitted = users
    return admitted


def certificate(profile, interpretation):
    pair = (profile, interpretation)
    if profile not in PROFILES or interpretation not in INTERPRETATIONS:
        raise ValueError("original profile and explicit Gaussian interpretation required")
    source, finite, joint, binding = authenticated_inputs()
    sr, fr, jr = (_row(report, pair) for report in (source, finite, joint))
    params = PaperParams(*pair)
    if (sr["paper_parameters"] != params.record() or
            fr["paper_parameters"] != params.record() or
            not (sr["seed_sha256"] == fr["seed_sha256"] == jr["seed_sha256"])):
        raise ValueError("source/finite/joint parameter or root mismatch")

    # The source report already replays this root and one issuance, and its
    # verifier authenticates all source/finite/joint receipts.  Replaying the
    # same fixture key here binds the signature plan to that issuance.
    seed = ("paper-baseline-" + profile + "-" + interpretation).encode("ascii")
    backend = SourceSchurBackend(rng=DeterministicRandom(seed))
    public, master = backend.setup(params)
    key = backend.key_extract(master, b"Alice")
    if (backend.setup_attempts != 1 or backend.extract_calls != 1 or
            public.context.hex() != sr["public_context_sha256"] or
            master.states.get(b"Alice") != ("issued", key)):
        raise ValueError("fixture root or signing key differs")
    plan = backend._sign_plan(key)
    audit = SchurNumericalAudit(plan)
    if (audit.public_certificate() != fr["signature"]["numerical_input"] or
            fixed_root_finite_chain_certificate(audit) != fr["signature"]["finite_chain"] or
            fixed_root_normalizer_certificate(audit) != fr["signature"]["ideal_schur_normalizer"]):
        raise ValueError("same-key signature Schur plan differs")
    joint_sign_text = jr["signature"]["finite_vs_joint_integer_gaussian_tv_upper_exact"]
    if (not jr["signature"]["fixed_root_combined_tv_bound_nontrivial"] or
            joint_sign_text is None):
        raise ValueError("fixed-key signature perturbation bound missing")

    _gadget, scalar = backend._components(params)
    # This is the actual new sign source's budget constructor.  It consumes no
    # entropy here; SourceSchurBackend.sign installs it at every attempt.
    attempt = backend._sign_attempt_source(params, plan, scalar)
    if (attempt.used != 0 or
            backend.last_sign_attempt_certificate["cap_installed_by_backend"] is not True):
        raise ValueError("source sign attempt budget not installed")
    budget = backend.last_sign_attempt_certificate
    if (not budget["admitted"] or budget["u_reachable_centers_exact"] !=
            ["-1", "-1/2", "0", "1/2"] or
            budget["extra_abort_term_is_not_charged_twice"] is not True):
        raise ValueError("uniform adaptive u batch premise missing")
    # The batch kernel TV already includes the extra whole-attempt cap event:
    # the perturbation has its own hard cap, so a newly exhausted full source
    # implies that the u segment exceeded its separately charged cap.
    delta_sign = min(Fraction(1), Fraction(joint_sign_text) +
                     Fraction(budget["u_scalar_kernel_tv_including_aggregate_exact"]))
    sign_call = union_bound(delta_sign, backend.sign_max_attempts)

    issue_text = sr["complete_law_tv_upper_including_abort"]
    issue = None if issue_text is None else probability(issue_text)
    if issue is not None and (not issue < 1 or
            not sr["first_issuance_tv_bound_applies_under_iid_bytes_and_no_external_faults"] or
            not sr["same_root_c_gate"]["certified"] or
            not sr["successful_finite_key_object_guard"]["raw_and_key_within_256bit_object_guard"]):
        raise ValueError("uniform fixed-root issuance prerequisites missing")
    capacity = service_capacity(params)
    return {
        "schema": SCHEMA,
        "profile": profile,
        "interpretation": interpretation,
        "paper_parameters": params.record(),
        "root_seed_sha256": sha256(seed).hexdigest(),
        "public_context_sha256": public.context.hex(),
        "authenticated_predecessors": binding,
        "same_fixture_key_signature_plan_replayed": True,
        "same_fixture_key_perturbation_tv_upper": dyadic_upper(Fraction(joint_sign_text)),
        "same_fixture_key_u_batch_tv_including_outer_cap_upper":
            dyadic_upper(Fraction(budget["u_scalar_kernel_tv_including_aggregate_exact"])),
        "same_fixture_key_one_attempt_tv_upper": dyadic_upper(delta_sign),
        "same_fixture_key_one_sign_call_tv_upper": dyadic_upper(sign_call),
        "same_fixture_key_two_adaptive_sign_calls_tv_upper": dyadic_upper(
            union_bound(sign_call, 2)),
        "same_fixture_key_two_adaptive_sign_calls_bound_nontrivial":
            union_bound(sign_call, 2) < 1,
        "sign_attempts_per_call": backend.sign_max_attempts,
        "one_sign_call_hard_entropy_cap_bytes":
            backend.last_sign_call_certificate["one_sign_call_hard_cap_bytes"],
        "sign_reference": "same fixed Alice key; joint integer perturbation plus ideal u kernels; original Algorithm 7 challenge, norm retries, object guards, abort and verification",
        "sign_scope": "all admissible adaptive messages for this one frozen key; not randomly issued keys",
        "sign_norm_exhaustion_probability_upper": None,
        "fixed_service_worst_case_capacity_users": capacity,
        "one_fresh_issuance_tv_upper": None if issue is None else dyadic_upper(issue),
        "issuance_only_history_at_capacity_tv_upper":
            None if issue is None or capacity == 0 else dyadic_upper(union_bound(issue, capacity)),
        "issuance_only_history_at_capacity_bound_nontrivial":
            issue is not None and capacity > 0 and union_bound(issue, capacity) < 1,
        "issuance_uniformity":
            "at this fixed root, the same zero-centered master plan, all-center gadget residue and C normalizer bounds, and 256-bit successful-output envelope do not depend on h; every valid identity's canonical target is h in R_Q^d",
        "issuance_history_scope":
            "at most capacity first-touch identities; adaptive identities, cached repeats, canonical snapshots and restarts as common deterministic logical postprocessing; abort retained",
        "fresh_iid_uniform_bytes_and_stated_mpfr_model_required": True,
        "logical_schedule_shared_and_no_external_storage_faults_required": True,
        "reference_wire_guard_applied_symmetrically_with_abort": True,
        "random_issued_key_then_sign_history_tv": None,
        "uniform_all_reachable_signing_keys_schur_bound": None,
        "bad_issued_key_sign_plan_probability": None,
        "all_accepted_setup_roots_tv": None,
        "faulty_storage_history_tv": None,
        "native_strong_security_proven": False,
        "rom_used": True, "teaching_parameters": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
        "private_material_exported": False,
    }


def build_report():
    rows = [certificate(profile, interpretation)
            for profile in PROFILES for interpretation in INTERPRETATIONS]
    return {
        "schema": SCHEMA + "/REPORT",
        "scope": "six original Table 4 fixed roots; issuance-only adaptive history and one-fixture-key adaptive signing history are separate",
        "paper": {"path": "papers/2025_efficient_ibs_jia.pdf",
                  "sha256": rows[0]["paper_parameters"]["source_sha256"]},
        "environment": {"python": platform.python_version(), "sage": sage_version,
                        "platform": platform.platform()},
        "rows": rows,
        "full_random_issuance_signature_fault_history_tv": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("--output already exists")
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"rows": len(report["rows"]),
                      "nontrivial_issuance_histories": sum(
                          row["issuance_only_history_at_capacity_bound_nontrivial"]
                          for row in report["rows"]),
                      "nontrivial_fixed_key_two_sign_histories": sum(
                          row["same_fixture_key_two_adaptive_sign_calls_bound_nontrivial"]
                          for row in report["rows"]),
                      "full_history": report["full_random_issuance_signature_fault_history_tv"]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
