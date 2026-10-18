#!/usr/bin/env python3
"""Read-only consistency checks for the synchronized report and demo materials."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
FACTS_PATH = HERE / "materials.json"
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

checks = 0
errors: list[str] = []


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        errors.append(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repo_path(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    check(path == ROOT or ROOT in path.parents, f"path escapes repository: {relative}")
    return path


def check_markdown_links(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for raw_target in LINK_RE.findall(text):
        target = raw_target.strip()
        if target.startswith(("http://", "https://", "mailto:", "#", "<")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = (path.parent / target).resolve()
        check(resolved == ROOT or ROOT in resolved.parents,
              f"link escapes repository in {path.relative_to(ROOT)}: {raw_target}")
        check(resolved.exists(),
              f"missing link target in {path.relative_to(ROOT)}: {raw_target}")


facts = json.loads(FACTS_PATH.read_text(encoding="utf-8"))
check(facts["schema"] == "IBME-SAME-VERSION-MATERIALS/1", "unexpected material schema")
check(facts["status"] == "draft_synchronized", "materials are not marked synchronized draft")

cards_path = repo_path(facts["source"]["cards_path"])
check(cards_path.is_file(), "cards.json is missing")
check(sha256(cards_path) == facts["source"]["cards_sha256"], "cards.json SHA-256 changed")
cards = json.loads(cards_path.read_text(encoding="utf-8"))
check(cards["schema"] == facts["source"]["cards_schema"], "cards schema changed")
check(cards["status"] == "passed", "cards evidence is not passed")
check(cards["evidence_baseline_commit"] == facts["source"]["evidence_baseline_commit"],
      "cards evidence baseline commit changed")

primary_id = facts["primary_demo"]["card_id"]
check(cards["selection"]["current_primary_demo_candidate"] == primary_id,
      "cards select a different primary demo")
check(cards["selection"]["profiles_share_one_hibe"] is True,
      "cards no longer state that profiles share one HIBE")
check(cards["selection"]["final_three_representatives_selected"] is False,
      "cards unexpectedly mark the final three representatives selected")

matching = [card for card in cards["cards"] if card["id"] == primary_id]
check(len(matching) == 1, "primary card must occur exactly once")
primary = matching[0] if matching else {}

if primary:
    suite = primary["suite"]
    canonical_suite = json.dumps(
        suite, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    check(hashlib.sha256(canonical_suite).hexdigest() == facts["primary_demo"]["suite_digest"],
          "primary suite digest changed")

    expected_suite = facts["primary_demo"]["suite"]
    for field in ("hibe", "hibe_version", "ibs", "ibs_version", "transport", "protocol",
                  "signature_format", "allow_mock", "state_policy"):
        check(suite[field] == expected_suite[field], f"primary suite field changed: {field}")
    check(suite["hibe_params"]["message_mode"] == expected_suite["hibe_params"],
          "primary HIBE parameter profile changed")
    check(suite["ibs_params"]["base_algorithm"] == expected_suite["ibs_params"],
          "primary IBS parameter profile changed")

    timing_map = {
        "setup": "setup",
        "sender_key": "sender-key",
        "receiver_key": "receiver-key",
        "cold_encrypt": "cold-encrypt",
        "first_decrypt_with_leaf_generation": "first-decrypt-with-leaf-generation",
        "warm_encrypt": "warm-encrypt",
        "warm_decrypt": "warm-decrypt",
        "restore_objects": "restore-objects",
        "restored_decrypt": "restored-decrypt",
    }
    for material_name, card_name in timing_map.items():
        actual = primary["measurements"]["timing_seconds"][card_name]["median"]
        expected = facts["primary_demo"]["measurements"]["timing_seconds_median"][material_name]
        check(actual == expected, f"primary timing changed: {material_name}")

    card_bytes = primary["measurements"]["bytes"]
    fact_bytes = facts["primary_demo"]["measurements"]["bytes"]
    check(card_bytes["full_ciphertext"]["minimum"] == fact_bytes["full_ciphertext_minimum"],
          "primary minimum ciphertext size changed")
    check(card_bytes["full_ciphertext"]["maximum"] == fact_bytes["full_ciphertext_maximum"],
          "primary maximum ciphertext size changed")
    check(card_bytes["observed_process_tree_rss_maximum"]
          == fact_bytes["observed_process_tree_rss_maximum"],
          "primary observed RSS changed")

inputs = cards["benchmark"]["inputs"]
boundary = facts["benchmark_boundary"]
input_map = {
    "receiver_identity_bytes": "receiver_identity_bytes",
    "sender_identity_bytes": "sender_identity_bytes",
    "inner_receiver_identity_bytes": "inner_receiver_identity_bytes",
    "inner_sender_identity_bytes": "inner_sender_identity_bytes",
    "application_message_bytes": "message_bytes",
    "hibe_seed_bytes": "hibe_seed_bytes",
}
for material_name, card_name in input_map.items():
    check(boundary[material_name] == inputs[card_name], f"benchmark input changed: {material_name}")

repetitions = cards["benchmark"]["repetitions"]
for name in ("independent_cold_states", "warm_pairs_per_state", "warm_encryptions",
             "warm_decryptions", "restore_processes", "restored_decryptions"):
    check(boundary[name] == repetitions[name], f"benchmark repetition changed: {name}")
check(boundary["restore_public_entropy_bytes"]
      == cards["benchmark"]["method"]["restore_public_entropy_bytes"],
      "restore entropy observation changed")

for name in ("security_claim", "backend_admitted", "parameters_are_formal",
             "security_proofs_produced", "nist_level_claimed",
             "functional_or_performance_tests_are_security_proof"):
    check(facts["claims"][name] == cards["claims"][name], f"claim changed: {name}")
for name in ("profiles_share_one_hibe", "equal_security_targets_established",
             "final_three_representatives_selected"):
    check(facts["claims"][name] == cards["selection"][name], f"selection claim changed: {name}")

material_texts: dict[str, str] = {}
for name, record in facts["materials"].items():
    path = repo_path(record["path"])
    check(path.is_file(), f"material is missing: {name}")
    if not path.is_file():
        continue
    check(sha256(path) == record["sha256"], f"material SHA-256 changed: {name}")
    material_texts[name] = path.read_text(encoding="utf-8")
    check_markdown_links(path)

requirements = facts["material_requirements"]
for name, text in material_texts.items():
    for literal in requirements["shared_required_literals"]:
        check(literal in text, f"{name} is missing shared fact: {literal}")
    for literal in requirements["forbidden_literals"]:
        check(literal not in text, f"{name} contains stale material: {literal}")

for literal in requirements["report_required_literals"]:
    check(literal in material_texts.get("report", ""), f"report is missing fact: {literal}")
for literal in requirements["demo_required_literals"]:
    check(literal in material_texts.get("demo_and_defense", ""), f"demo is missing fact: {literal}")

preflight = facts["current_machine_preflight"]
check(preflight["exit_code"] == 2, "current-machine preflight exit code changed")
check(preflight["execution"] == "not_executed", "preflight must not be execution evidence")
check(preflight["runtime_available"] is False, "current machine unexpectedly marked runtime-ready")
check(len(preflight["errors"]) == 2, "current-machine preflight must retain both blockers")
check("--allow-mock" not in preflight["command_arguments"], "preflight must not allow mock backends")

if errors:
    print(f"FAILED: {len(errors)} of {checks} checks failed", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"passed: {checks} checks; primary={primary_id}; "
    f"suite_digest={facts['primary_demo']['suite_digest']}; "
    "materials=report,demo_and_defense"
)
