"""C64B read-only acceptance predicates; no estimator, grid or crypto lifecycle.
Exit 0 means candidate-freeze evidence passes, NEVER security admission.
All large output integers are decimal strings. JSON input uses Python exact ints.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

EXPECTED = dict(degree=256, k=11, l=10, q=274877844481, root=153250464611,
    eta=1, kappa=64, gamma1=190000, gamma2=60000000000, gamma3=27487784448,
    dropped_bits=28, identity_max_bytes=64, message_max_bytes=4096,
    max_extract_attempts=4096, max_sign_attempts=4096,
    max_uniform_attempts=128, max_cached_identities=64)
ESTIMATOR = "53da5982597709ba0fdf94ea37a84d822310fd84"
PACKAGE = "docs/research/2026-10-11-luo-abort-bound"


def unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON key: " + k)
        result[k] = v
    return result


def read_json(p):
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique)


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def exact_bounds(c):
    return {k: (v["direction"], int(v["numerator"]), v["denominator_power_of_two"])
            for k, v in c["bounds"].items()}


def run(repo, screen_override=None):
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    sys.path[:0] = [str(repo), str(repo/"src")]
    from ibme.ibs.luo_module import LuoModuleParams, HASH_BYTES
    from experiments.research.luo_robust_abort_certificate import profile, certificate
    from experiments.research.luo_module_security_screen import witness_rows
    p = profile("availability-k64")  # constructor/root/domain validation, no Setup
    base = repo/PACKAGE
    ev = base/"evidence"
    screen_path = screen_override or ev/"parameter-screen/C64B-screen.json"
    screen = read_json(screen_path)
    cert = read_json(ev/"k64-lifetime-certificate.json")
    prior = read_json(ev/"parameter-screen/current-profile-rerun.json")
    probe = read_json(ev/"candidate-k64-probe/probe.json")
    manifest = read_json(base/"MANIFEST.json")
    checks = {}
    def check(name, condition):
        checks[name] = bool(condition)

    # Files are observed, never rewritten. Restrict manifest access to this repo.
    manifest_ok = True
    for rel, expected in manifest["files"].items():
        target = (repo/rel).resolve()
        if not target.is_relative_to(repo) or not target.is_file() or digest(target) != expected:
            manifest_ok = False
    check("archive_manifest_integrity", manifest_ok)
    checksources = dict(screen["source_sha256_after"])
    checksources.update(probe["metadata"]["source_sha256"])
    check("current_source_fingerprints_match_receipts",
          screen["source_sha256_before"] == screen["source_sha256_after"]
          and probe["metadata"]["source_sha256"] == probe["metadata"]["source_sha256_final"]
          and all(digest(repo/f) == h for mapping in
                  (screen["source_sha256_after"], probe["metadata"]["source_sha256"])
                  for f, h in mapping.items()))
    check("exact_17_field_profile",
          asdict(p) == EXPECTED == screen["parameters"] == cert["parameters"] == probe["metadata"]["parameters"]
          and all(type(v) is int for v in asdict(p).values()))
    check("constructor_ring_rounding", True)
    check("root_crt", (p.q-1) % (2*p.degree) == 0 and p.l >= 2
          and pow(p.root, p.degree, p.q) == p.q-1 and pow(p.root, 2*p.degree, p.q) == 1)
    arithmetic = next(j["result"] for j in prior["jobs"] if j["job"] == "arithmetic")
    check("fixed_q_prior_sage_prime_evidence",
          arithmetic["arithmetic"]["prime"] is True and arithmetic["parameters"]["q"] == p.q)
    check("mask_and_hint_inequalities",
          1 <= p.kappa <= p.degree and p.gamma1 > p.beta1 and p.gamma2 > p.beta2
          and 2*p.gamma2 < p.q and p.beta2 < p.gamma3
          and p.kappa*2**(p.dropped_bits-1) < p.gamma3
          and (p.q-1) % (2*p.gamma3) == 0 and p.q > 4*p.gamma3)
    core = 2*p.gamma2-4*p.beta2-1
    check("robust_set_hypotheses",
          0 < core < p.q and p.gamma3 > 2*p.beta2 and p.gamma1 >= 2*p.beta1)
    check("finite_caps_and_xof",
          p.max_extract_attempts <= 4096 and p.max_sign_attempts <= 4096
          and p.kappa*(p.max_uniform_attempts+1) <= HASH_BYTES)
    expected_budget = dict(setups=1, new_identity_extract_calls=64, sign_calls=65536,
        external_fresh_oracle_queries=2**64, operating_system_entropy_failures_included=False,
        invalid_input_cache_capacity_or_storage_failures_included=False)
    check("budget_exact_integer_not_js_number",
          cert["budgets"] == expected_budget == screen["availability_certificate"]["budgets"]
          and type(screen["availability_certificate"]["budgets"]["external_fresh_oracle_queries"]) is int)
    recomputed = certificate(p, epsilon=Fraction(1,100), extracts=64, signs=65536,
                             oracle_queries=2**64, bits=1024)  # arithmetic only
    check("certificate_exact_dyadics_match",
          exact_bounds(recomputed) == exact_bounds(cert) == exact_bounds(screen["availability_certificate"])
          and cert["arithmetic"] == recomputed["arithmetic"]
          and cert["epsilon"] == "1/100" and cert["precision_bits"] == 1024)
    total = cert["bounds"]["finite_lifecycle_abort"]
    check("conditional_lifetime_abort_below_2pow_minus153",
          total["direction"] == "upper" and
          Fraction(int(total["numerator"]), 2**total["denominator_power_of_two"]) < Fraction(1, 2**153))
    rows = witness_rows(p)
    row_keys = ("name", "module_rows", "module_columns", "coefficient_rows", "coefficient_columns",
                "block_infinity_bounds", "uniform_screen_bound", "q", "below_q_half")
    check("both_branch_witness_bounds_match",
          len(rows) == len(screen["witnesses"]) == 4 and all(
              all(a[k] == b[k] for k in row_keys) for a,b in zip(rows,screen["witnesses"])))
    check("all_witness_bounds_nontrivial", all(2*r["uniform_screen_bound"] < p.q-1 for r in rows))
    check("fresh_branch_small_nonzero_product_condition", 2*p.kappa < p.q)
    count = math.comb(p.degree,p.kappa)*2**p.kappa
    check("challenge_count_exact", str(count) == screen["entropy"]["challenge_count"])
    check("single_target_quantum_challenge_proxy_ge_128", count >= 2**256)
    sis = {}
    for j in screen["jobs"]:
        mode = j["mode"]
        valid = j["status"] == "completed" and j["exit_code"] == 0
        result = j.get("result", {})
        valid = valid and result.get("estimator_commit") == ESTIMATOR
        valid = valid and all(result.get("input",{}).get(k) == rows[-1][k] for k in row_keys)
        records = result.get("estimates", {})
        valid = valid and bool(records) and all(
            x["status"] == "finite_heuristic_estimate" and x["rop_log2"] is not None
            and math.isfinite(x["rop_log2"]) and x["rop_log2"] >= 128
            and x["cost_fields"]["tag"] == "infinity" for x in records.values())
        check("sis_"+mode+"_archived_model_floor", valid)
        if records: sis[mode] = min(x["rop_log2"] for x in records.values())
    check("two_sis_models_present", len(screen["jobs"]) == 2 and set(sis) == {"classical","quantum"})
    lwe = {}
    for j in prior["jobs"]:
        if j["job"] not in ("lwe-classical","lwe-quantum"):
            continue
        result = j["result"]
        records = result["records"]
        same = all(result["parameters"][k] == EXPECTED[k] for k in ("degree","k","l","q","eta"))
        valid = j["status"] == "completed" and j["exit_code"] == 0 and same
        valid = valid and result["estimator_commit"] == ESTIMATOR and len(records) == 6
        valid = valid and all(x["status"] == "finite_heuristic_estimate" and
            x["rop_log2"] is not None and math.isfinite(x["rop_log2"]) and x["rop_log2"] >= 128
            for x in records.values())
        check(j["job"]+"_same_input_archived_floor",valid)
        lwe[result["mode"]] = min(x["rop_log2"] for x in records.values())
    check("two_mlwe_models_present", set(lwe) == {"classical","quantum"})
    calls, stages, meta = probe["calls"], probe["stages"], probe["metadata"]
    expected_calls = {(s,i,m,n) for s in range(3) for i in (1,5,64) for m in (0,256,4096) for n in range(2)}
    observed_calls = {(c["system"],c["identity_len"],c["message_len"],c["repetition"]) for c in calls}
    check("c64b_functional_probe_archived",
          meta["completed"] is True and meta["failure_type"] is None
          and len(calls) == 54 and observed_calls == expected_calls
          and meta["expected_sign_calls"] == meta["attempted_sign_calls"] == meta["successful_sign_calls"] == 54
          and all(c["called"] is True and c["status"] == "ok" and c["error_type"] is None
                  and c["reference_verify"] is True and c["compact_verify"] is True
                  and c["reference_bytes"] == 29455 and c["compact_bytes"] == 16383 for c in calls)
          and sum(c["sign_attempts"] for c in calls) == 315
          and all(type(c["sign_attempts"]) is int and 1 <= c["sign_attempts"] <= 4096 for c in calls))
    expected_stages = {(s,"setup",0) for s in range(3)} | {
        (s,kind,i) for s in range(3) for kind in ("extract","cache","master_restore") for i in (1,5,64)}
    check("cached_key_restore_stage_evidence", len(stages) == 30 and
          {(s["system"],s["stage"],s["identity_len"]) for s in stages} == expected_stages
          and all(s["status"] == "ok" and s["error_type"] is None for s in stages))
    suites = list(ET.parse(ev/"final-regression.xml").getroot().iter("testsuite"))
    check("archived_regression_269_passed", sum(int(s.get("tests","0")) for s in suites) == 269
          and all(int(s.get(k,"0")) == 0 for s in suites for k in ("failures","errors","skipped")))
    check("non_admission_flags_preserved", all(x["security_claim"] == "none"
          and x["backend_admitted"] is False and x["parameters_are_formal"] is False
          for x in (screen,cert,meta)) and screen["approved_security_bits"] is None
          and p.security_claim == "none" and p.backend_admitted is False)
    check("default_profile_not_silently_replaced", asdict(LuoModuleParams()) == screen["default_parameters"]
          and asdict(LuoModuleParams()) != EXPECTED)
    passed = all(checks.values())
    return dict(schema="IBME/LUO-C64B-PARAMETER-DECISION/1", generated_utc=datetime.now(timezone.utc).isoformat(),
        input_head=subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],text=True).strip(),
        decision_scope="Independent parameter arithmetic/evidence sufficiency audit, not citation review or a security reduction",
        candidate_choice=dict(recommendation="approve_explicit_research_candidate_freeze" if passed else "hold_for_failed_predicates",
            arithmetic_and_evidence_eligible=passed, freeze_applied=False,
            human_action="Integrator may formally select this exact research candidate; record profile, budgets, model and source receipt",
            is_formal_security_admission=False),
        parameters=EXPECTED,
        lifecycle_budget=dict(setups=1,QE=64,QS=65536,QH_decimal=str(2**64),epsilon="1/100",
            interpretation="classical fresh oracle input budget; not quantum superposition queries or unrestricted lifetime",
            conditional_abort_log2=cert["bounds"]["finite_lifecycle_abort"]["approx_log2_bound"]),
        predicates=checks, failed_predicates=[k for k,v in checks.items() if not v],
        reused_screens=dict(estimator_commit=ESTIMATOR,SIS_log2_rop=sis,MLWE_min_log2_rop=lwe,
            model="ADPS16 classical/quantum, LGSA, coefficient heuristic; common infinity box for SIS",
            exclusions="module/algebraic completeness, certified lower bounds, QROM reduction; MLWE excludes BKW and Arora-GB"),
        challenge=dict(count_decimal=str(count), entropy_log2=math.log2(count),
            quantum_search_proxy_log2=math.log2(count)/2, margin_above_128=math.log2(count)/2-128,
            exact_predicate="comb(256,64)*2**64 >= 2**256",
            warning="Single-target search scale only, not a bit guarantee; no unproved query-loss factor is subtracted",
            availability_QH_is_not_quantum_loss=True),
        limitations=[
            dict(id="S1",blocks="unqualified IBS bits/NIST claim, not candidate freeze",
                 reason="No concrete whole-scheme strength conclusion follows from heuristic costs and entropy; theorem/model coverage and any quantitative losses must support the specific claim.",
                 route="Use existing citation/implementation mapping being reviewed by DeepSeek; if it supports only a conditional classical-ROM statement, retain that scope. No demand to redo Luo full 4.4 or QROM."),
            dict(id="S2",blocks="unconditional actual-runtime availability or unrestricted lifetime claim, not scoped candidate freeze",
                 reason="Bound assumes uniform Setup A, fresh independent ideal source words, ideal XOF and finite classical budgets; real SHAKE/CSPRNG assumptions and operational exclusions remain explicit."),
            dict(id="S3",blocks="full IB-ME security/backend admission, not independent IBS parameter selection",
                 reason="Archived CHKP backend/combination gap is a separate owner dependency; this audit neither resolves nor makes it a freeze prerequisite.")
        ],
        not_required_for_freeze=["Redo Luo full section4.4 reduction","New QROM theorem","Exact joint LowBits uniformity","Estimator/grid rerun","Wait for CHKP delivery"],
        security_claim="none",backend_admitted=False,parameters_are_formal=False,
        approved_security_bits=None,NIST_category=None,
        semantics="formal candidate choice means recorded engineering/research selection; legacy parameters_are_formal is not flipped to represent selection",
        provenance=dict(repo=str(repo),package=PACKAGE,screen=str(screen_path),
            manifest_sha256=digest(base/"MANIFEST.json"),screen_sha256=digest(screen_path),
            certificate_sha256=digest(ev/"k64-lifetime-certificate.json"),
            proof_sha256=digest(base/"鲁棒接受集与中止界.md"),
            parameter_note_sha256=digest(base/"参数选择与安全边界.md"),
            selected_source_sha256=checksources,manifest_file_count=len(manifest["files"])),
        execution=dict(estimator_runs=0,grid_runs=0,crypto_lifecycle_runs=0,full_test_runs=0,
            certificate_arithmetic_recomputations=1,repository_writes=0,
            exit_zero_meaning="All recorded candidate-evidence predicates pass; not a security approval"))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--screen", type=Path, help="Optional evidence input for negative-control audit; never estimates")
    args = ap.parse_args()
    data = run(args.repo.resolve(), args.screen.resolve() if args.screen else None)
    print(json.dumps(data,ensure_ascii=False,indent=2))
    return 0 if not data["failed_predicates"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
