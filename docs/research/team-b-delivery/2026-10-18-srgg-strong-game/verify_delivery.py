"""Verify frozen SRGG strong-game receipt, source bindings and exact gates."""
from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGE = "docs/research/team-b-delivery/2026-10-18-srgg-strong-game"
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PDF_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
RECEIPT_SHA256 = "592fbe840317dbbd6646546bc0cd3b7f7263e8200d1d222e462448d84d6bcaf0"
SOURCE_FILES = {
    "experiments/research/candidates/srgg/paper_strong_game.py",
    "experiments/research/candidates/srgg/paper_schur_backend.py",
    "experiments/research/candidates/srgg/paper_backend.py",
    "experiments/research/candidates/srgg/paper_validation.py",
    "experiments/research/candidates/srgg/paper_objects.py",
    "experiments/research/candidates/srgg/paper_algebra.py",
    "experiments/research/candidates/srgg/paper_parameters.py",
    "experiments/research/candidates/srgg/paper_profiles.py",
}
REQUIRED = SOURCE_FILES | {
    PAPER,
    "tests/test_srgg_paper_strong_game.py",
    f"{PACKAGE}/README.md",
    f"{PACKAGE}/README_zh-CN.md",
    f"{PACKAGE}/strong-game.json",
    f"{PACKAGE}/validation.json",
    f"{PACKAGE}/verify_delivery.py",
}
GAMMA = {"PARAM-I": "42086491.7", "PARAM-II": "63653172.0",
         "PARAM-III": "86573930.5"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def repo_file(name):
    require(type(name) is str and bool(name) and "\\" not in name,
            "noncanonical file name")
    relative = Path(name)
    require(not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts),
            "unsafe relative path")
    path = (ROOT / relative).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(),
            "missing or escaped file: " + name)
    return path


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def read_json(name):
    value = json.loads(repo_file(f"{PACKAGE}/{name}").read_text(encoding="utf-8"))
    require(type(value) is dict, "JSON object required: " + name)
    return value


def check_security(value):
    require(type(value) is dict and
            value.get("security_claim") == "none" and
            value.get("backend_admitted") is False and
            value.get("parameters_are_formal") is False and
            "nist_security_category" in value and
            value["nist_security_category"] is None,
            "research-only markers changed")


def check_manifest():
    manifest = read_json("MANIFEST.json")
    require(manifest.get("schema") == "IBME/SRGG-PAPER-STRONG-GAME-MANIFEST/1",
            "manifest schema changed")
    entries = manifest.get("entries")
    require(type(entries) is dict and set(entries) == REQUIRED,
            "manifest coverage changed")
    for name, expected in entries.items():
        require(type(expected) is dict and set(expected) == {"bytes", "sha256"}
                and type(expected["bytes"]) is int and expected["bytes"] >= 0
                and type(expected["sha256"]) is str
                and len(expected["sha256"]) == 64,
                "malformed entry: " + name)
        path = repo_file(name)
        require(path.stat().st_size == expected["bytes"] and
                digest(path) == expected["sha256"],
                "byte binding failed: " + name)
    return len(entries)


def check_receipt():
    require(digest(repo_file(f"{PACKAGE}/strong-game.json")) == RECEIPT_SHA256,
            "strong-game receipt changed")
    report = read_json("strong-game.json")
    require(report.get("schema") == "IBME/SRGG-PAPER-STRONG-GAME/1",
            "receipt schema changed")
    check_security(report)
    paper = report.get("paper")
    require(type(paper) is dict and paper.get("path") == PAPER and
            paper.get("sha256") == PDF_SHA256 and
            digest(repo_file(PAPER)) == PDF_SHA256,
            "frozen paper binding failed")
    hashes = report.get("source_sha256")
    require(type(hashes) is dict and set(hashes) == SOURCE_FILES,
            "source coverage changed")
    for name, expected in hashes.items():
        require(digest(repo_file(name)) == expected,
                "source binding changed: " + name)
    game = report.get("game_freshness")
    require(type(game) is dict and
            game.get("paper_Definition_3_and_G0") == "fresh (identity,message)" and
            game.get("native_strong_target") ==
            "fresh exact canonical (identity,message,signature) triple" and
            game.get("same_message_replacement_wins_paper_G0") is False,
            "game freshness boundary changed")
    require(report.get("randomness") == "DeterministicRandom TEST ONLY" and
            report.get("private_material_exported") is False,
            "test randomness/export boundary changed")
    rows = report.get("rows")
    require(type(rows) is list and len(rows) == 6, "six source rows required")
    observed = set()
    successes = 0
    for row in rows:
        require(type(row) is dict, "row object required")
        name, interpretation = row.get("profile"), row.get("interpretation")
        require(name in GAMMA and interpretation in
                ("table-standard-deviation", "literal-density-width") and
                (name, interpretation) not in observed,
                "source row or interpretation changed")
        observed.add((name, interpretation))
        require(row.get("published_gamma") == GAMMA[name] and
                row.get("identity_bytes") == 5 and row.get("message_bytes") == 32 and
                row.get("signature_queries") == 1 and
                row.get("setup_attempts", 0) >= 1 and
                row.get("extraction_calls") == 1 and
                row.get("sign_attempts", 0) >= 1 and
                row.get("test_only_random_seed_utf8") ==
                "paper-baseline-" + name + "-" + interpretation,
                "replay configuration changed")
        require(type(row.get("public_key_sha256")) is str and
                len(row["public_key_sha256"]) == 64,
                "public key digest missing")
        probe = row.get("probe")
        check_security(probe)
        gamma = Fraction(Decimal(GAMMA[name]))
        cap = gamma.numerator**2 // gamma.denominator**2
        q = 15744063
        require(probe.get("original_valid") is True and
                probe.get("identity_block_2I_checked") is True and
                probe.get("modulus_Q") == q and
                probe.get("signature_norm_cap_squared") == cap and
                type(probe.get("original_norm_squared")) is int and
                0 <= probe["original_norm_squared"] <= cap and
                probe.get("tested_basis_positions") ==
                {"PARAM-I": 1024, "PARAM-II": 1536, "PARAM-III": 2048}[name] and
                type(probe.get("eligible_basis_positions")) is int and
                0 <= probe["eligible_basis_positions"] <=
                probe["tested_basis_positions"] and
                probe.get("same_identity") is True and
                probe.get("same_message") is True and
                probe.get("same_challenge") is True and
                probe.get("fresh_under_paper_G0_fresh_message_game") is False and
                probe.get("private_material_exported") is False,
                "paper verifier or scope condition changed")
        replacement = probe.get("replacement")
        if replacement is None:
            require(probe.get("single_basis_replacement_found") is False and
                    probe["eligible_basis_positions"] == 0 and
                    probe.get("best_shift_norm_squared", 0) > cap and
                    probe.get("best_shift_excess_over_cap") ==
                    probe["best_shift_norm_squared"] - cap and
                    probe.get("replacement_valid") is None and
                    probe.get("canonical_signature_distinct") is None and
                    probe.get("recovered_commitment_equal") is None and
                    probe.get("fresh_under_exact_signature_sEUF_game") is False,
                    "negative single-basis result changed")
            continue
        require(type(replacement) is dict and
                probe.get("single_basis_replacement_found") is True and
                probe["eligible_basis_positions"] > 0 and
                probe.get("replacement_valid") is True and
                probe.get("canonical_signature_distinct") is True and
                probe.get("recovered_commitment_equal") is True and
                probe.get("fresh_under_exact_signature_sEUF_game") is True and
                probe.get("best_shift_excess_over_cap") == 0,
                "positive replacement validation changed")
        t, delta = replacement.get("original_coefficient"), replacement.get("delta")
        require(type(t) is int and type(delta) is int and abs(delta) == q and
                delta * t <= 0 and
                replacement.get("changed_coefficient") == t + delta and
                replacement.get("norm_squared") ==
                probe["original_norm_squared"] + q*q + 2*t*delta and
                replacement["norm_squared"] == probe.get("best_shift_norm_squared") and
                replacement["norm_squared"] <= cap and
                type(replacement.get("row")) is int and
                0 <= replacement["row"] <
                {"PARAM-I": 2, "PARAM-II": 3, "PARAM-III": 4}[name] and
                type(replacement.get("coefficient_index")) is int and
                0 <= replacement["coefficient_index"] < 512 and
                replacement.get("original_signature_sha256") !=
                replacement.get("replacement_signature_sha256") and
                all(type(replacement.get(field)) is str and
                    len(replacement[field]) == 64 for field in
                    ("original_signature_sha256", "replacement_signature_sha256")),
                "exact Q-shift/norm/distinctness witness changed")
        successes += 1
    require(successes == 5, "accepted run count changed")
    return successes


def check_validation():
    value = read_json("validation.json")
    require(value.get("schema") == "IBME/SRGG-PAPER-STRONG-GAME-VALIDATION/1",
            "validation schema changed")
    check_security(value)
    require(value.get("receipt", {}).get("sha256") == RECEIPT_SHA256 and
            value.get("paper", {}).get("sha256") == PDF_SHA256,
            "validation evidence binding changed")
    runs = value.get("execution", {})
    require(runs.get("focused_tests_passed") == 4 and
            runs.get("focused_tests_failed") == 0 and
            runs.get("focused_tests_skipped") == 0 and
            runs.get("replay_runs") == 6 and
            runs.get("root_setups") == 6 and
            runs.get("key_extractions") == 6 and
            runs.get("successful_signatures") == 6 and
            runs.get("same_message_public_replacements_accepted") == 5 and
            runs.get("private_material_exported") is False,
            "validation run counts changed")
    scope = value.get("scope", {})
    require(scope.get("paper_G0_same_message_win") is False and
            scope.get("native_strong_same_message_candidate") is True and
            all(scope.get(field) is False for field in (
                "all_parameter_rows_or_all_signatures_vulnerable_proved",
                "random_key_attack_success_probability_estimated",
                "source_sampling_distribution_proved",
                "ROM_or_QROM_reduction_completed", "HIBE_composition_checked")),
            "research boundary changed")


def main():
    entries = check_manifest()
    successes = check_receipt()
    check_validation()
    print(json.dumps({"status": "verified", "manifest_entries": entries,
                      "table4_interpretation_runs": 6,
                      "accepted_same_message_replacements": successes,
                      "security_claim": "none"}, sort_keys=True))


if __name__ == "__main__":
    main()
