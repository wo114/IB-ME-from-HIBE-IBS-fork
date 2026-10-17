"""Zero-entropy accounting for the opt-in structured SRGG fixed issuer.

Read frozen public certificates, retain their hypotheses, and compose only
the stated arithmetic terms. No Sage import, key, draw, oracle programming,
filesystem fault probability, or complete security reduction is supplied.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform


SCHEMA = "IBME/SRGG-STRUCTURED-SERVICE-BUDGET/1"
ROOT = Path(__file__).resolve().parents[4]
BASE = "docs/research/team-b-delivery/"
INPUTS = {
    "integrated": BASE+"2026-10-16-srgg-bridge/integrated-bridge.json",
    "execution": BASE+"2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json",
    "native": BASE+"2026-10-16-srgg-reduction/native-sig.json",
    "public": BASE+"2026-10-16-srgg-classical-rom/reduction-samplers.json",
    "hash": BASE+"2026-10-16-srgg-classical-rom/seeded-xof.json",
}
SCHEMAS = {
    "integrated": "IBME/SRGG-INTEGRATED-BRIDGE/1",
    "execution": "IBME/SRGG-STRUCTURED-EXECUTION/1",
    "native": "IBME/SRGG-NATIVE-SIG-INTERACTIVE-BRIDGE/1",
    "public": "IBME/SRGG-REDUCTION-PUBLIC-SAMPLERS/1",
    "hash": "IBME/SRGG-SEEDED-XOF-EMBEDDING/1",
}
SOURCES = (
    "experiments/research/candidates/srgg/service_budget.py",
    "experiments/research/candidates/srgg/structured_backend.py",
    "experiments/research/candidates/srgg/structured_execution.py",
    "experiments/research/candidates/srgg/integrated_bridge.py",
    "experiments/research/candidates/srgg/native_sig.py",
    "experiments/research/candidates/srgg/oracle_ledger.py",
    "src/ibme/ibs/srgg/structured.py",
    "src/ibme/ibs/srgg/structured_registration.py",
    "src/ibme/ibs/srgg_structured_service.py",
    "src/ibme/ibs/srgg_service.py",
    "experiments/research/srgg_structured_service_audit.py",
    BASE+"2026-10-16-srgg-classical-rom/direct-ibs.md",
)


def _int(value, name, low=0, high=2**64):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def probability(value):
    if type(value) not in (str, int, Fraction):
        raise ValueError("exact probability required")
    result = Fraction(value)
    if not 0 <= result <= 1:
        raise ValueError("probability outside [0,1]")
    return result


def pack(value):
    """Exact probability plus its smallest dyadic upper bound, without floats.

    Alias denominators contain Q^(dn), exceeding Python's decimal digit cap.
    Hex numerator/denominator preserve the fraction without changing that cap.
    """
    value = probability(value)
    exponent = None
    if value:
        exponent = value.numerator.bit_length()-value.denominator.bit_length()
        covered = (value.numerator <= value.denominator << exponent if exponent >= 0
                   else value.numerator << -exponent <= value.denominator)
        exponent += not covered
    return {"numerator_hex": hex(value.numerator), "denominator_hex": hex(value.denominator),
            "dyadic_upper_exponent": exponent}


def unpack(record):
    if type(record) is not dict or set(record) != {
            "numerator_hex", "denominator_hex", "dyadic_upper_exponent"}:
        raise ValueError("exact probability record required")
    if record["dyadic_upper_exponent"] is not None and type(record["dyadic_upper_exponent"]) is not int:
        raise ValueError("exact dyadic exponent required")
    try:
        value = probability(Fraction(int(record["numerator_hex"], 16), int(record["denominator_hex"], 16)))
    except (TypeError, ValueError, ZeroDivisionError):
        raise ValueError("malformed exact probability record") from None
    if pack(value) != record:
        raise ValueError("noncanonical exact probability record")
    return value


def _capped(value):
    return pack(min(Fraction(1), value))


@dataclass(frozen=True)
class Counts:
    new_identities: int
    signatures: int
    identity_first_touches: int
    extra_h2_points: int
    max_sign_attempts: int = 16

    def __post_init__(self):
        for name in ("new_identities", "signatures", "extra_h2_points"):
            _int(getattr(self, name), name)
        _int(self.identity_first_touches, "identity first touches", 1)
        _int(self.max_sign_attempts, "sign attempts", 1, 16)
        if self.new_identities > self.identity_first_touches:
            raise ValueError("every new issuance requires an identity first touch")

    @property
    def attempts(self):
        return self.signatures*self.max_sign_attempts

    @property
    def h2_points(self):
        return self.extra_h2_points+self.attempts


def _read(root, name, schema):
    data = (root/name).read_bytes()
    if not 2 <= len(data) <= 2*1024*1024:
        raise ValueError("public receipt size outside resource bound")
    result = json.loads(data)
    if type(result) is not dict or result.get("schema") != schema:
        raise ValueError("matching frozen public certificate required")
    return result, hashlib.sha256(data).hexdigest()


def _profile(receipt):
    values = receipt["profiles"]
    matches = [value for value in values if value.get("profile") == "query-bounded-deep"]
    if len(matches) != 1:
        raise ValueError("one deep profile required")
    return matches[0]


def load_inputs(root=ROOT):
    """Validate cross-receipt parameters and frozen declared source hashes."""
    root = Path(root)
    receipts, hashes = {}, {}
    for label, name in INPUTS.items():
        receipts[label], hashes[name] = _read(root, name, SCHEMAS[label])
    integrated, native = _profile(receipts["integrated"]), _profile(receipts["native"])
    execution, public, hash_receipt = (receipts[label] for label in ("execution", "public", "hash"))
    params = integrated["parameters"]
    # This report corresponds only to the frozen n512 deep research point.
    if (params != execution["parameters"] or params != native["parameters"]
            or params != hash_receipt["parameters"] or params["degree"] != 512
            or params["rank"] != 2 or params["digits"] != 8 or params["r_squared"] != 64
            or params["sign_max_attempts"] != 16
            or execution["numerical_profile"] != "query-bounded-deep"
            or public["scalar_profile"] != "query-bounded-deep"
            or any(type(value) is not int for value in params.values())):
        raise ValueError("frozen complete n512 deep parameters differ")
    if any(value != params[name] for name, value in public["parameters"].items()):
        raise ValueError("public sampler parameters differ")
    if native["issuance_tv_premise_exact"] != integrated["hnf_common_gate_comparison"][
            "complete_issuance_to_common_hnf_gate_reference_tv_upper"]:
        raise ValueError("native key-law premise differs")
    if (native["finite_sign_tv_premise_exact"] != integrated["sign_attempt_finite_tv_upper"]
            or native["sign_norm_reject_premise_exact"] != integrated["sign_norm"][
                "ideal_sequential_sign_attempt_norm_reject_upper"]
            or native["runtime_key_filter_changed"] is not False
            or integrated["raw_gate_covers_repaired_user_gate"] is not True
            or public["all_samplers_admitted_under_public_caps"] is not True):
        raise ValueError("incompatible law or norm premise")
    integrated_hash = hashes[INPUTS["integrated"]]
    if receipts["native"].get("input_sha256") != integrated_hash or hash_receipt.get("input_sha256") != integrated_hash:
        raise ValueError("derived receipt does not bind the integrated input")
    declared_sources = {}
    for receipt in receipts.values():
        for name, digest in receipt.get("source_sha256", {}).items():
            if name in declared_sources and declared_sources[name] != digest:
                raise ValueError("conflicting frozen source hashes")
            if hashlib.sha256((root/name).read_bytes()).hexdigest() != digest:
                raise ValueError("frozen source differs: "+name)
            declared_sources[name] = digest
    for section in (integrated["master_sampler"], integrated["sign_sampler"]):
        probability(section["full_target_integer_tv_upper_including_abort"])
    return receipts, hashes, declared_sources


def components(receipts):
    """Read bound meanings separately; no post-HNF TV inversion is used."""
    i, n = _profile(receipts["integrated"]), _profile(receipts["native"])
    p, h = receipts["public"], receipts["hash"]
    master = probability(i["master_sampler"]["full_target_integer_tv_upper_including_abort"])
    gadget = probability(i["gadget"]["batch"]["scalar_kernel_tv_including_aggregate_exact"])
    sign = probability(i["sign_sampler"]["full_target_integer_tv_upper_including_abort"])
    u = probability(i["u_batch"]["scalar_kernel_tv_including_aggregate_exact"])
    raw = probability(i["raw_union_norm_reject"]["probability_upper"])
    common = probability(i["hnf_common_gate_comparison"][
        "complete_issuance_to_common_hnf_gate_reference_tv_upper"])
    finite_sign = probability(i["sign_attempt_finite_tv_upper"])
    result = {
        "master_finite": master, "gadget_finite": gadget,
        "sign_perturbation_finite": sign, "sign_u_finite": u,
        "issuance_finite_only": min(Fraction(1), master+gadget),
        "sign_attempt_finite_only": min(Fraction(1), sign+u),
        "gadget_ideal_recurrence_to_fiber": probability(i["gadget"][
            "ideal_recurrence_to_spherical_fiber_tv_upper"]),
        "ideal_raw_to_union": probability(i["convolution"]["ideal_raw_to_union_gaussian_tv_upper_exact"]),
        "issuance_to_common_final_gate": common,
        "issuance_to_latent_dual_gate": min(Fraction(1), common+raw),
        "raw_ideal_gate_bottom": raw,
        "final_gate_additional_after_raw_pass": Fraction(0),
        "actual_issuance_abort_excluding_infrastructure": probability(i["hnf_common_gate_comparison"][
            "actual_issuance_abort_upper_excluding_infrastructure"]),
        "ideal_bad_successful_key": probability(n["ideal_bad_issued_key_upper_exact"]),
        "sign_attempt_to_sequential_ideal": finite_sign,
        "ideal_sign_norm_reject": probability(i["sign_norm"]["ideal_sequential_sign_attempt_norm_reject_upper"]),
        "actual_sign_norm_reject": probability(i["actual_sign_norm_reject_upper"]),
        "image_to_uniform": probability(i["mixed_image_uniformity"]["unfiltered_image_to_uniform_tv_upper_exact"]),
        "public_u_finite": probability(p["public_u"]["finite_to_ideal_tv_upper_including_abort_exact"]),
        "public_e_finite": probability(p["uniform_e"]["finite_to_ideal_tv_upper_including_abort_exact"]),
        "simulator_z_finite": probability(p["simulator_z"]["finite_to_ideal_tv_upper_including_abort_exact"]),
        "simulator_binary_challenge_finite": probability(p["binary_challenge"]["finite_to_ideal_tv_upper_including_abort_exact"]),
        "good_key_joint_zk": probability(n["good_key_interactive"]["smoothing"]["interactive_joint_tv_upper_exact"]),
        # The second endpoint is ideal R -> finite known-key Sign in Run.
        "known_key_second_endpoint_finite": finite_sign,
    }
    for name, section in (("matrix_hash_failure", "matrix_expansion"),
                          ("identity_hash_failure", "identity_expansion")):
        record = h[section]
        if record["byte_budget_always_sufficient_under_trial_cap"] is not True:
            raise ValueError("hash byte budget is not covered")
        factored = record["exact_union_bound_factored"]
        result[name] = min(Fraction(1), factored["factor"]*probability(factored["base"])**factored["exponent"])
    params = i["parameters"]
    # A deterministic inequality proves zero EXTRA final-gate cost. It does
    # not say that raw/final failure, GoodKey failure, or IO has probability 0.
    if params["user_norm_cap"] < 2*params["raw_norm_cap"]+2*params["rank"]*params["degree"]*(params["p"]-1)**2:
        raise ValueError("raw gate no longer covers repaired key gate")
    frozen = receipts["execution"]["finite_sampling_query_certificate"]
    if (probability(frozen["fresh_issuance_finite_sampling_hybrid_tv_upper"]) != result["issuance_finite_only"]
            or probability(frozen["sign_attempt_finite_sampling_hybrid_tv_upper"]) != result["sign_attempt_finite_only"]):
        raise ValueError("finite-only query certificate differs")
    return result


def abort_components(receipts):
    """Algorithmic sampling abort bounds; TV and abort are not added twice."""
    i, p = _profile(receipts["integrated"]), receipts["public"]
    return {
        # Complete law TV to a non-aborting ideal law bounds its abort atom.
        # This does not assign a probability to an arithmetic/library fault.
        "master_samplef_via_complete_law_tv": probability(i["master_sampler"][
            "full_target_integer_tv_upper_including_abort"]),
        "gadget_scalar_and_local_aggregate": probability(i["gadget"]["batch"][
            "abort_upper_including_aggregate_exact"]),
        "sign_samplef_via_complete_law_tv": probability(i["sign_sampler"][
            "full_target_integer_tv_upper_including_abort"]),
        "sign_u_scalar_and_local_aggregate": probability(i["u_batch"][
            "abort_upper_including_aggregate_exact"]),
        "public_u": probability(p["public_u"]["abort_upper_exact"]),
        "public_simulator_z": probability(p["simulator_z"]["abort_upper_exact"]),
        "public_e": probability(p["uniform_e"]["batch_abort_upper_exact"]),
        "public_binary_challenge": probability(p["binary_challenge"]["abort_probability_exact"]),
    }


def scenario(counts, receipts, *, name):
    if type(counts) is not Counts:
        raise ValueError("validated Counts required")
    c = components(receipts)
    i, n = _profile(receipts["integrated"]), _profile(receipts["native"])
    params = i["parameters"]
    if counts.max_sign_attempts != params["sign_max_attempts"]:
        raise ValueError("attempt cap differs from complete parameter snapshot")
    nk, qs, qi, ns = counts.new_identities, counts.signatures, counts.identity_first_touches, counts.attempts
    mh = counts.h2_points
    abort = abort_components(receipts)
    sampling_abort = nk*(abort["master_samplef_via_complete_law_tv"]+abort["gadget_scalar_and_local_aggregate"])
    sampling_abort += ns*(abort["sign_samplef_via_complete_law_tv"]+abort["sign_u_scalar_and_local_aggregate"])
    finite = nk*c["issuance_finite_only"]+ns*c["sign_attempt_finite_only"]
    hash_failure = c["matrix_hash_failure"]+qi*c["identity_hash_failure"]
    delta0_known = nk*c["issuance_to_latent_dual_gate"]+ns*c["sign_attempt_to_sequential_ideal"]+hash_failure
    ideal_commitment_bits = n["full_cap_ideal_commitment_entropy"]["ideal_commitment_min_entropy_bits_lower"]
    _int(ideal_commitment_bits, "ideal commitment entropy bits", 1, 2**20)
    alias = Fraction(qi*(qi-1), 2*i["Q"]**(params["rank"]*params["degree"]))
    programming = Fraction(mh, 2**ideal_commitment_bits)
    public_pair = c["public_u_finite"]+c["public_e_finite"]
    direct = {
        "Delta0_known_arithmetic_part": delta0_known,
        "Delta_issue": nk*c["raw_ideal_gate_bottom"],
        "Delta_bad_key": nk*c["ideal_bad_successful_key"],
        "Delta_identity_alias": alias,
        "QI_image_plus_public_sampler": qi*(c["image_to_uniform"]+public_pair),
        "NS_programming_collision": ns*programming,
        "NS_good_key_joint_zk": ns*c["good_key_joint_zk"],
        "NS_ideal_sign_first_reject": ns*c["ideal_sign_norm_reject"],
        "NS_public_simulator_finite": ns*c["simulator_z_finite"],
        "NS_known_key_second_endpoint_finite": ns*c["known_key_second_endpoint_finite"],
    }
    sign_abort = min(Fraction(1), counts.max_sign_attempts*c["sign_attempt_to_sequential_ideal"]
                     +c["actual_sign_norm_reject"]**counts.max_sign_attempts)
    crypto_abort = nk*c["actual_issuance_abort_excluding_infrastructure"]+qs*sign_abort+hash_failure
    return {
        "name": name,
        "counts": {"roots": 1, "N_K": nk, "q_S": qs, "L": counts.max_sign_attempts,
            "N_S_upper": ns, "Q_I_upper": qi, "extra_H2_points_upper": counts.extra_h2_points,
            "M_H_upper": mh, "q_F_conservative_upper": max(1, mh)},
        "restart_and_cached_key_reuse_additional_sampler_calls": 0,
        "finite_sampler_transcript_tv": _capped(finite),
        "finite_sampling_abort_union_only_excluding_norm_hash_and_infrastructure": _capped(sampling_abort),
        "abort_is_already_included_in_finite_TV_not_an_extra_TV_charge": True,
        "finite_sampler_transcript_tv_at_most_2_minus_128": finite <= Fraction(1, 2**128),
        "transcript_to_common_final_gate_and_sequential_sign_reference_tv": _capped(
            nk*c["issuance_to_common_final_gate"]+ns*c["sign_attempt_to_sequential_ideal"]),
        "matrix_and_identity_decode_bad_in_ideal_XOF": _capped(hash_failure),
        "actual_algorithm_abort_conditional_on_no_infrastructure_or_extra_global_cap": _capped(crypto_abort),
        "actual_sign_operation_abort_excluding_infrastructure": pack(sign_abort),
        "full_service_abort_upper": None,
        "Delta0_complete_service_to_reference_upper": None,
        "raw_bottom_term_paid_per_new_key": _capped(nk*c["raw_ideal_gate_bottom"]),
        "final_gate_extra_after_raw_pass": pack(c["final_gate_additional_after_raw_pass"]),
        "ideal_GoodKey_failure_paid_per_new_key": _capped(nk*c["ideal_bad_successful_key"]),
        "direct_ibs_equation_7_known_numerator_terms": {key: _capped(value) for key, value in direct.items()},
        "direct_ibs_known_numerator_partial_sum": _capped(sum(direct.values(), Fraction(0))),
        "direct_ibs_complete_numerator_error_upper": None,
        "p0_or_IBS_advantage_bound": None,
        "ideal_commitment_entropy_bits_used": ideal_commitment_bits,
        "finite_commitment_min_entropy_claimed": False,
        "public_sampler_and_ideal_law_bridge_charges_are_conditional": True,
        "raw_prefix_decode_failure_already_paid_in_Delta0_known_part": True,
        "remaining_raw_prefix_kernel_and_adaptive_composition_cost": None,
        "one_service_identity_capacity_possible": nk <= 64,
        "snapshot_byte_capacity_certified_for_this_count": None,
        "large_query_row_is_arithmetic_not_an_executed_capacity_test": True,
    }


def _audit_caps(root):
    """Read the driver's two public integer constants without importing it."""
    source = (Path(root)/"experiments/research/srgg_structured_service_audit.py").read_text(encoding="utf-8")
    def integer(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return _int(node.value, "audit cap literal", 1, 2**32)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return _int(integer(node.left)*integer(node.right), "audit cap product", 1, 2**32)
        raise ValueError("audit cap must be an explicit bounded integer product")
    caps = {}
    for statement in ast.parse(source).body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in ("PARENT_ENTROPY_CAP", "CHILD_ENTROPY_CAP"):
                    if target.id in caps:
                        raise ValueError("audit cap assigned more than once")
                    caps[target.id] = integer(statement.value)
    if set(caps) != {"PARENT_ENTROPY_CAP", "CHILD_ENTROPY_CAP"}:
        raise ValueError("audit driver must declare both public entropy caps")
    return caps["PARENT_ENTROPY_CAP"], caps["CHILD_ENTROPY_CAP"]


def entropy_envelope(receipts, *, parent_cap, child_cap):
    """All admitted local caps do not automatically fit the audit's global cap."""
    i = _profile(receipts["integrated"])
    p = i["parameters"]
    issue = i["master_sampler"]["whole_entropy_cap_bytes"]+i["gadget"]["batch"]["selected_cap_bytes"]
    sign = i["sign_sampler"]["whole_entropy_cap_bytes"]+i["u_batch"]["selected_cap_bytes"]
    setup = 32+2*p["rank"]**2*p["digits"]*p["degree"]
    negative = 2*(p["rank"]*(2+p["digits"])+2)*p["degree"]
    parent = setup+2*issue+2*p["sign_max_attempts"]*sign+negative
    child = p["sign_max_attempts"]*sign
    _int(parent_cap, "parent audit cap", 1, 2**32)
    _int(child_cap, "child audit cap", 1, 2**32)
    return {"setup_exact_requested_bytes": setup, "per_new_issue_sum_of_local_caps": issue,
        "per_sign_attempt_sum_of_local_caps": sign, "parent_negative_forgery_draw_bytes": negative,
        "audit_parent_lifecycle_local_cap_envelope": parent,
        "audit_child_one_sign_local_cap_envelope": child,
        "audit_parent_entropy_cap_bytes": parent_cap,
        "audit_child_entropy_cap_bytes": child_cap,
        "parent_envelope_fits_global_cap": parent <= parent_cap,
        "child_envelope_fits_global_cap": child <= child_cap,
        "extra_parent_global_cap_abort_upper": pack(0) if parent <= parent_cap else None,
        "extra_child_global_cap_abort_upper": pack(0) if child <= child_cap else None,
        "zero_uses_deterministic_sum_of_all_local_caps_not_measured_entropy": True,
        "all_local_certificates_imply_global_cap_probability_zero": False,
        "FixedIssuer_itself_adds_a_CountingEntropy_cap": False,
        "audit_wrapper_caps_are_separate_from_sampler_local_caps": True,
        "runtime_or_filesystem_failure_probability": None}


def build_report(root=ROOT):
    root = Path(root)
    receipts, inputs, frozen_sources = load_inputs(root)
    terms = components(receipts)
    rows = (
        ("audit_lifecycle_two_keys_three_signatures", Counts(2, 3, 4, 6)),
        ("query_2pow40_with_two_fixed_keys", Counts(2, 2**40, 2**40, 2**40)),
        ("query_2pow40_new_keys_abstract_only", Counts(2**40, 2**40, 2**40, 2**40)),
    )
    current_sources = {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in SOURCES}
    parent_cap, child_cap = _audit_caps(root)
    envelope = entropy_envelope(receipts, parent_cap=parent_cap, child_cap=child_cap)
    uninstantiated = {
        "trusted_storage_IO_crash_and_recovery_coupling": None,
        "arithmetic_runtime_library_or_hardware_faults": None,
        "bounded_raw_prefix_kernel_in_whole_reduction_and_cost": None,
        "complete_adaptive_public_reduction_composition": None,
        "seeded_matrix_and_full_extractor_hardness_overlay": None,
        "actual_ring_CBD1_MLWE_and_HNF_MSIS_advantages": None,
        "SHAKE_to_ideal_XOF_computational_model_correspondence": None,
        "QROM_programming_and_extraction": None}
    if any(envelope[name] is None for name in (
            "extra_parent_global_cap_abort_upper", "extra_child_global_cap_abort_upper")):
        uninstantiated["extra_audit_global_entropy_cap_abort"] = None
    return {"schema": SCHEMA, "parameters": _profile(receipts["integrated"])["parameters"],
        "numerical_profile": "query-bounded-deep", "input_sha256": inputs,
        "frozen_declared_source_sha256_verified": frozen_sources,
        "selected_current_source_sha256": current_sources,
        "per_call_components": {name: pack(value) for name, value in terms.items()},
        "per_call_sampling_abort_upper": {name: pack(value) for name, value in abort_components(receipts).items()},
        "scenarios": [scenario(counts, receipts, name=name) for name, counts in rows],
        "entropy_envelope": envelope,
        "classical_matrix_seed_prequery_hit_2pow40": pack(Fraction(2**40, 2**256)),
        "seed_prequery_term_is_not_a_complete_hardness_overlay": True,
        "uninstantiated_terms": uninstantiated,
        "hypotheses": [
            "Frozen finite and ideal kernel bounds hold uniformly at every reachable admitted history.",
            "Sampler attempts receive independent uniform bytes; MPFR directed bounds are correct.",
            "All norm retries are counted; numerical and issuance failures never trigger reselection.",
            "Service operations are serialized in a trusted cooperating-writer state with no IO/crash/global-cap fault.",
            "Hashes are evaluated in the stated ideal classical XOF model, retaining decode failure.",
            "Source/parameter equality is correspondence evidence, not a proof of the full service game."],
        "actual_entropy_bytes": 0, "draw_performed": False, "private_payloads_read": False,
        "new_lifecycle_run": False, "production_algorithm_modified": False,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "scope": "exact conditional arithmetic and source correspondence; no complete service TV, security reduction or NIST admission",
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(build_report(), indent=2)+"\n"
    if args.output is None:
        print(payload, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)


if __name__ == "__main__":
    main()
