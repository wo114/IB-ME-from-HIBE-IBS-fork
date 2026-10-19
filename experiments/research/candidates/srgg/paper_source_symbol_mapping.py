"""Exact source-symbol and game-premise audit for the original SRGG rows.

This checks necessary source correspondence. It is not a reduction, attack
probability estimate, proposed parameter change, or HIBE composition.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles
from .paper_smoothing_eta import EPSILON, ROUNDED_R, theta_bounds


SCHEMA = "IBME/SRGG-PAPER-SOURCE-SYMBOL-MAPPING/1"
ROOT = Path(__file__).resolve().parents[4]
BOUND_SOURCES = (
    "experiments/research/candidates/srgg/paper_profiles.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_smoothing_eta.py",
    "experiments/research/candidates/srgg/paper_strong_game.py",
)


def normalized_sha256(name: str) -> str:
    """Bind text while allowing Git LF and Windows CRLF checkouts."""
    return sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def smallest_odd_above(value: Fraction) -> int:
    """Strict lower bound, with no floating-point rounding near integers."""
    if type(value) is not Fraction or value < 0:
        raise ValueError("nonnegative exact Fraction required")
    first = value.numerator // value.denominator + 1
    return first if first % 2 else first + 1


def modulus_correspondence(params: PaperParams) -> dict:
    """Map the source's FS q in Z_(2q) to the IBS verifier in R_(2Q)."""
    if type(params) is not PaperParams:
        raise TypeError("published PaperParams required")
    source = params.source
    gamma = Fraction(source.gamma)
    q_from_verification = (2 * params.modulus) // 2
    if (2 * params.modulus) != 2 * q_from_verification:
        raise ArithmeticError("verification modulus mapping failed")
    if q_from_verification != source.Q or source.Q != source.p * source.q:
        raise ArithmeticError("Table 3/4 and implementation Q differ")
    if params.signature_norm_cap != (gamma * gamma).numerator // (gamma * gamma).denominator:
        raise ArithmeticError("implementation changed the published gamma gate")
    return {
        "profile": source.name,
        "table3_p": source.p,
        "table3_q_gadget": source.q,
        "table3_Q_equals_p_times_q": source.Q,
        "ibS_verification_modulus_2Q": 2 * params.modulus,
        "theorem1_q_for_direct_same_modulus_mapping": q_from_verification,
        "theorem1_q_is_odd": q_from_verification % 2 == 1,
        "gamma_published": str(source.gamma),
        "twice_gamma_exact": str(2 * gamma),
        "theorem1_q_strictly_exceeds_2gamma": q_from_verification > 2 * gamma,
        "shortfall_below_2gamma": str(2 * gamma - q_from_verification),
        "smallest_odd_q_strictly_above_2gamma": smallest_odd_above(2 * gamma),
        "changing_q_would_change_original_table4_protocol": True,
        "gadget_q_preserves_ibS_verification_modulus": 2 * source.q == 2 * params.modulus,
        "taking_q_as_2Q_is_odd": (2 * params.modulus) % 2 == 1,
        "source_theorem1_other_s1_eta_gate_established": False,
        "source_theorem1_direct_application_established": False,
    }


def game_trace(*, target_id: bytes, target_message: bytes,
               target_signature: bytes, extraction_queries: tuple[bytes, ...],
               signing_answers: tuple[tuple[bytes, bytes, bytes], ...],
               x_members: frozenset[bytes], verifier_accepts: bool) -> dict:
    """Finite event check for the exact freshness/abort predicates as printed.

    `verifier_accepts` is a hypothetical transcript input, not a generated
    forgery. The resulting counterexample concerns query coverage only.
    """
    if any(type(item) is not bytes for item in
           (target_id, target_message, target_signature)):
        raise TypeError("canonical bytes required")
    if (type(extraction_queries) is not tuple or
            any(type(x) is not bytes for x in extraction_queries) or
            type(signing_answers) is not tuple or
            any(type(row) is not tuple or len(row) != 3 or
                any(type(x) is not bytes for x in row) for row in signing_answers) or
            type(x_members) is not frozenset or
            any(type(x) is not bytes for x in x_members) or
            type(verifier_accepts) is not bool):
        raise TypeError("finite canonical transcript required")
    no_target_extract = target_id not in extraction_queries
    exact_pair_fresh = all(
        (item_id, message) != (target_id, target_message)
        for item_id, message, _ in signing_answers
    )
    exact_triple_fresh = all(
        (item_id, message, signature) !=
        (target_id, target_message, target_signature)
        for item_id, message, signature in signing_answers
    )
    # G1 adds target in X and explicit extraction identities outside X.
    g0 = no_target_extract and exact_pair_fresh and verifier_accepts
    g1 = g0 and target_id in x_members and all(
        item_id not in x_members for item_id in extraction_queries
    )
    # The simulator described on PDF p.9 aborts on any signing id in X.
    printed_simulator_aborts = (
        any(item_id in x_members for item_id in extraction_queries) or
        any(item_id in x_members for item_id, _, _ in signing_answers)
    )
    return {
        "g0_euf_fresh_pair_wins_if_valid": g0,
        "g1_fresh_pair_and_X_restrictions_win_if_valid": g1,
        "native_strong_exact_triple_wins_if_valid": (
            no_target_extract and exact_triple_fresh and verifier_accepts
        ),
        "printed_p9_simulator_aborts_before_output": printed_simulator_aborts,
        "g1_win_but_printed_simulator_aborts": g1 and printed_simulator_aborts,
        "trace_assumes_a_valid_forgery": verifier_accepts,
        "actual_forgery_produced_by_this_audit": False,
    }


def g1_subset_probability(*, target_id: bytes,
                          extraction_queries: tuple[bytes, ...],
                          delta: Fraction) -> Fraction:
    """Independent X-inclusion probability for one fixed winning G0 trace."""
    if (type(target_id) is not bytes or type(extraction_queries) is not tuple
            or any(type(x) is not bytes for x in extraction_queries)
            or type(delta) is not Fraction or not 0 < delta < 1):
        raise TypeError("exact finite trace and delta in (0,1) required")
    if target_id in extraction_queries:
        raise ValueError("a G0 winning trace cannot explicitly extract target")
    return delta * (1 - delta) ** len(set(extraction_queries))


def smoothing_row(params: PaperParams) -> dict:
    """Keep formal eta and a hypothetical SD conversion visibly separate."""
    m = (2 + params.digits) * (params.rank + 1) * params.degree
    literal = theta_bounds(width=ROUNDED_R, dimension=m,
                           convention="literal-density-width")
    converted = theta_bounds(width=ROUNDED_R, dimension=m,
                             convention="physical-standard-deviation")
    return {
        "profile": params.profile_name,
        "table3_dimension": m,
        "epsilon": str(EPSILON),
        "printed_r_exact_decimal": "1.16",
        "formal_eta_literal_definition": {
            "theta_minus_one_lower_decimal_floor": literal[
                "theta_minus_one_lower_decimal_floor"],
            "lower_strictly_exceeds_epsilon": literal[
                "lower_exceeds_source_epsilon"],
            "printed_r_satisfies_formal_eta_gate": (
                False if literal["lower_exceeds_source_epsilon"] else
                True if literal["upper_below_source_epsilon"] else None),
        },
        "hypothetical_physical_sd_conversion": {
            "theta_minus_one_lower_decimal_floor": converted[
                "theta_minus_one_lower_decimal_floor"],
            "theta_minus_one_upper_decimal_ceiling": converted[
                "theta_minus_one_upper_decimal_ceiling"],
            "lower_strictly_exceeds_epsilon": converted[
                "lower_exceeds_source_epsilon"],
            "upper_strictly_below_epsilon": converted[
                "upper_below_source_epsilon"],
            "conversion_stated_by_source": False,
        },
    }


def build_report() -> dict:
    paper_digest = sha256((ROOT / SOURCE_PDF).read_bytes()).hexdigest()
    if paper_digest != SOURCE_SHA256:
        raise ValueError("reviewed PDF checksum changed")
    rows = [PaperParams(item.name) for item in profiles]
    modulus = [modulus_correspondence(item) for item in rows]
    if any(row["theorem1_q_strictly_exceeds_2gamma"] for row in modulus):
        raise ArithmeticError("published theorem-gate outcome unexpectedly changed")
    eta = [smoothing_row(item) for item in rows]
    if not all(row["formal_eta_literal_definition"][
            "lower_strictly_exceeds_epsilon"] for row in eta):
        raise ArithmeticError("formal eta discrepancy outcome changed")
    old = (b"target", b"old-message", b"original-signature")
    new = game_trace(
        target_id=old[0], target_message=b"new-message",
        target_signature=b"hypothetical-valid-fresh-signature",
        extraction_queries=(), signing_answers=(old,),
        x_members=frozenset((old[0],)), verifier_accepts=True,
    )
    same = game_trace(
        target_id=old[0], target_message=old[1],
        target_signature=b"different-valid-signature",
        extraction_queries=(), signing_answers=(old,),
        x_members=frozenset((old[0],)), verifier_accepts=True,
    )
    if not (new["g1_win_but_printed_simulator_aborts"] and
            same["native_strong_exact_triple_wins_if_valid"] and
            not same["g0_euf_fresh_pair_wins_if_valid"]):
        raise ArithmeticError("printed-game counterexample changed")
    delta = Fraction(1, 2)
    extraction_subset_probability = g1_subset_probability(
        target_id=b"target", extraction_queries=(b"other",), delta=delta)
    printed_qs_zero_lower = delta * (1 - delta * 0)
    if not extraction_subset_probability < printed_qs_zero_lower:
        raise ArithmeticError("printed G1 qS/qE counterexample changed")
    return {
        "schema": SCHEMA,
        "paper": {"path": SOURCE_PDF, "sha256": paper_digest,
                  "locations": "PDF p.3 Section 2.2; p.4 Definition 3/Theorem 1; "
                               "p.6 Table 3; p.8 Theorem 2/G0/G1; "
                               "p.9 simulator/Section 5.1; p.10 Table 4"},
        "bound_source_sha256_normalized_lf": {
            name: normalized_sha256(name) for name in BOUND_SOURCES},
        "original_table4_modulus_rows": modulus,
        "original_table3_eta_rows": eta,
        "source_security_statement_gap": {
            "theorem1_conclusion": "EUF-CMA for FS[ellipsoid G+G,H], under its conditions",
            "theorem2_premise": "SIG is sEUF-CMA secure",
            "theorem1_supplies_theorem2_strong_premise": False,
            "theorem2_stated_conclusion": "IBS is sEUF-ID-CMA in QROM",
            "definition3_and_G0_freshness": "new (id,message) pair",
            "definition3_and_G0_are_native_strong": False,
        },
        "finite_game_trace_under_assumed_valid_forgery": {
            "old_message_query_then_fresh_message_target_in_X": new,
            "same_message_different_signature": same,
            "printed_simulator_p9_can_answer_target_signing_query": False,
            "proof_view_equality_for_all_G1_allowed_queries_established": False,
            "conditional_trace_is_a_real_signature_attack": False,
        },
        "g1_query_count_lower_bound_counterexample": {
            "scope": "one fixed hypothetical G0-winning transcript; only X coin flips audited",
            "delta": str(delta),
            "signing_query_count_qS": 0,
            "explicit_extraction_query_count_qE": 1,
            "extracted_identity_distinct_from_target": True,
            "exact_G1_X_event_probability": str(extraction_subset_probability),
            "printed_p8_delta_times_1_minus_delta_qS_for_epsilon_1": str(
                printed_qs_zero_lower),
            "printed_lower_bound_holds_for_this_query_shape": False,
            "fixed_trace_X_exclusion_count_is_qE_not_qS": True,
            "underlying_valid_forgery_established": False,
        },
        "route_log": {
            "modulus_primary": "direct 2q=2Q forces q=Q; fails q>2gamma",
            "modulus_alternative_1": "gadget q=961 gives 2q != actual verifier modulus",
            "modulus_alternative_2": "q=2Q is even and gives 2q != actual modulus",
            "game_primary": "printed G0 freshness is a pair, not an exact signature triple",
            "game_alternative_1": "treat internal sign-oracle extraction as adversarial key query; changes stated game semantics",
            "game_alternative_2": "use SIG signing oracle for target X; requires an unstated simulator/reduction",
        },
        "author_intended_resolution": None,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(build_report(), indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        if args.output.exists():
            raise FileExistsError(args.output)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(rendered, end="")


if __name__ == "__main__":
    main()
