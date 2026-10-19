"""Verify showcase cards against public receipts and pinned source metadata.

This checker reads only committed public files.  It does not import a crypto
backend, open private states, generate keys, consume entropy, or require Sage.
"""

from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CARDS_PATH = HERE / "cards.json"
OBJECT_FILES = {
    "public_state": "public.bin",
    "master_state": "master.bin",
    "receiver_state": "receiver.bin",
    "sender_state": "sender.bin",
}
FORBIDDEN_RESTORE_OPERATIONS = {
    "latte:setup",
    "latte:delegate",
    "latte:extract",
    "latte:encrypt",
    "mldsa:keypair",
    "mldsa:sign",
    "falcon:keypair",
    "falcon:sign",
}


class Checks:
    def __init__(self):
        self.count = 0

    def equal(self, actual, expected, label):
        self.count += 1
        if actual != expected:
            raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")

    def true(self, condition, label):
        self.count += 1
        if not condition:
            raise AssertionError(label)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_sha256(path):
    return sha256(path.read_bytes()).hexdigest()


def source_literals(path):
    """Read literal top-level assignments without importing project code."""
    values = {}
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (TypeError, ValueError):
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            values[target.id] = value
        elif isinstance(target, ast.Tuple) and isinstance(value, tuple):
            for name, item in zip(target.elts, value, strict=True):
                if isinstance(name, ast.Name):
                    values[name.id] = item
    return values


def profile_constructor_args(path, profile_name):
    """Return literal positional arguments from a pinned PROFILES entry."""
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name) or node.targets[0].id != "PROFILES":
            continue
        if not isinstance(node.value, ast.Dict):
            break
        for key, value in zip(node.value.keys, node.value.values, strict=True):
            if ast.literal_eval(key) == profile_name and isinstance(value, ast.Call):
                return tuple(ast.literal_eval(arg) for arg in value.args)
    raise AssertionError(f"missing source profile {profile_name!r} in {path}")


def extrema(values):
    return {"minimum": min(values), "maximum": max(values)}


def verify_source_metadata(checks, cards):
    common = cards["common_stack"]["hibe"]
    latte_source = source_literals(ROOT / "src/ibme/hibe/latte/params.py")
    checks.equal(latte_source["REVISION"], common["upstream_source_revision"], "LATTE revision")
    checks.equal(latte_source["VERSION"], common["wire"], "LATTE wire version")
    checks.equal(latte_source["N"], common["parameters"]["N"], "LATTE N")
    checks.equal(latte_source["Q"], common["parameters"]["q"], "LATTE q")
    checks.equal(list(latte_source["SIGMA"]), common["parameters"]["sigma_standard_deviation"], "LATTE sigma")

    latte_manifest = load_json(ROOT / "src/ibme/hibe/latte/native/upstream/UPSTREAM.json")
    checks.equal(latte_manifest["commit"], common["upstream_source_revision"], "LATTE upstream manifest")

    by_id = {card["id"]: card for card in cards["cards"]}
    mldsa = by_id["latte3-bnn-mldsa44-hybrid-byteauth"]["ibs"]
    mldsa_args = profile_constructor_args(
        ROOT / "src/ibme/ibs/certified/mldsa.py", "ml-dsa-44"
    )
    checks.equal(mldsa_args[1], mldsa["base_public_key_bytes"], "ML-DSA public-key bytes")
    checks.equal(mldsa_args[3], mldsa["base_signature_bytes"], "ML-DSA signature bytes")
    mldsa_manifest = load_json(ROOT / "src/ibme/ibs/certified/native/upstream/UPSTREAM.json")
    checks.equal(mldsa_manifest["commit"], mldsa["base_source_revision"], "ML-DSA source revision")

    falcon = by_id["latte3-bnn-falcon512-hybrid-byteauth"]["ibs"]
    falcon_args = profile_constructor_args(
        ROOT / "src/ibme/ibs/certified/falcon.py", "falcon-padded-512"
    )
    checks.equal(falcon_args[1], falcon["base_public_key_bytes"], "Falcon public-key bytes")
    checks.equal(falcon_args[2], falcon["base_secret_key_bytes"], "Falcon secret-key bytes")
    checks.equal(falcon_args[3], falcon["base_padded_signature_bytes"], "Falcon signature bytes")
    falcon_manifest = load_json(ROOT / "src/ibme/ibs/certified/falcon_native/upstream/UPSTREAM.json")
    checks.equal(falcon_manifest["archive_sha256"], falcon["base_source_sha256"], "Falcon archive hash")

    luo_card = by_id["latte3-luo-module-default-compact-hybrid-byteauth"]
    luo_params = luo_card["suite"]["ibs_params"]
    # MODULE-COMPACT/1 has a 279-byte fixed frame for the 17 uint64
    # parameter fields and 64-byte public context.  The checked widths for
    # this exact profile are 36 bits for z and 11 bits for w1.
    fixed = 279
    compact_bytes = (
        fixed
        + (luo_params["l"] * luo_params["degree"] * 36 + 7) // 8
        + (luo_params["degree"] + 7) // 8
        + (luo_params["kappa"] + 7) // 8
        + (luo_params["k"] * luo_params["degree"] * 11 + 7) // 8
        + (luo_params["k"] * luo_params["degree"] + 7) // 8
    )
    checks.equal(compact_bytes, luo_card["ibs"]["full_ibs_signature_bytes"], "Luo compact signature bytes")


def verify_receipt(checks, cards, comparison_profile, card):
    receipt_path = ROOT / card["receipt"]["path"]
    checks.true(receipt_path.is_file(), f"missing receipt {receipt_path}")
    checks.equal(file_sha256(receipt_path), card["receipt"]["sha256"], f"{card['id']} receipt hash")
    report = load_json(receipt_path)

    checks.equal(report["schema"], "FULL-IBME-BENCHMARK/1", f"{card['id']} schema")
    checks.equal(report["status"], "passed", f"{card['id']} status")
    checks.equal(report["source_commit"], card["source_commit"], f"{card['id']} source commit")
    checks.equal(report["security_group"], card["security_group"], f"{card['id']} security group")
    checks.equal(report["suite"], card["suite"], f"{card['id']} suite")
    checks.equal(comparison_profile["suite"], card["suite"], f"{card['id']} comparison suite")
    checks.equal(comparison_profile["file"], card["receipt"]["path"], f"{card['id']} comparison path")
    checks.equal(comparison_profile["file_sha256"], card["receipt"]["sha256"], f"{card['id']} comparison hash")
    checks.equal(
        comparison_profile["provider_occurrences_verified"],
        card["receipt"]["provider_occurrences_verified"],
        f"{card['id']} provider checks",
    )

    for key, expected in (("security_claim", "none"), ("backend_admitted", False),
                          ("parameters_are_formal", False), ("uses_ROM", True),
                          ("cross_security_group_ranking", False)):
        checks.equal(report[key], expected, f"{card['id']} {key}")
    checks.equal(report["suite"]["allow_mock"], False, f"{card['id']} allow_mock")
    checks.equal(report["randomness"], "system CSPRNG, no fixed seed and no outer retry", f"{card['id']} randomness")

    inputs = cards["benchmark"]["inputs"]
    repetitions = cards["benchmark"]["repetitions"]
    checks.equal(report["identity_bytes"], inputs["receiver_identity_bytes"], f"{card['id']} identity bytes")
    checks.equal(report["message_bytes"], inputs["message_bytes"], f"{card['id']} message bytes")
    checks.equal(report["suite"]["hibe_params"]["identity_bytes"], inputs["inner_receiver_identity_bytes"], f"{card['id']} inner identity bytes")
    checks.equal(report["repetitions"], repetitions["independent_cold_states"], f"{card['id']} cold states")
    checks.equal(report["warm_repetitions_per_state"], repetitions["warm_pairs_per_state"], f"{card['id']} warm repetitions")

    expected_environment = dict(cards["benchmark"]["environment"])
    expected_environment.pop("sage_reported_by_run_readmes")
    checks.equal(report["environment"], expected_environment, f"{card['id']} environment")
    checks.equal(len(report["records"]), repetitions["independent_cold_states"], f"{card['id']} record count")

    generation_phases = []
    restore_phases = []
    full_ciphertexts = []
    for index, record in enumerate(report["records"]):
        generation = record["generation"]
        restore = record["restore"]
        for payload, mode in ((generation, "generation"), (restore, "restore")):
            checks.equal(payload["status"], "passed", f"{card['id']} {mode} {index} status")
            checks.equal(payload["security_claim"], "none", f"{card['id']} {mode} {index} claim")
            checks.equal(payload["backend_admitted"], False, f"{card['id']} {mode} {index} admission")
            checks.equal(payload["parameters_are_formal"], False, f"{card['id']} {mode} {index} formal params")
            checks.equal(payload["security_proofs_produced"], 0, f"{card['id']} {mode} {index} proofs")
            checks.equal(payload["native_engine_rebuild"], False, f"{card['id']} {mode} {index} engine rebuild")
            checks.true(all(phase["status"] == "passed" for phase in payload["phases"]), f"{card['id']} {mode} {index} phase failure")
        checks.equal(restore["entropy_reads"], 0, f"{card['id']} restore {index} entropy reads")
        checks.equal(restore["entropy_bytes"], 0, f"{card['id']} restore {index} entropy bytes")
        checks.equal(restore["state_unchanged"], True, f"{card['id']} restore {index} state")
        checks.true(
            FORBIDDEN_RESTORE_OPERATIONS.isdisjoint(restore["native_operation_counts_after_runtime_build"]),
            f"{card['id']} restore {index} repeated a forbidden native operation",
        )
        generation_phases.extend(generation["phases"])
        restore_phases.extend(restore["phases"])
        full_ciphertexts.extend(generation["full_ciphertext_bytes"])

    checks.equal(
        sum(phase["name"] == "warm-encrypt" for phase in generation_phases),
        repetitions["warm_encryptions"],
        f"{card['id']} warm encryption count",
    )
    checks.equal(
        sum(phase["name"] == "warm-decrypt" for phase in generation_phases),
        repetitions["warm_decryptions"],
        f"{card['id']} warm decryption count",
    )
    checks.equal(
        sum(phase["name"] == "first-decrypt-with-leaf-generation" for phase in generation_phases),
        repetitions["first_decryptions"],
        f"{card['id']} first decryption count",
    )
    checks.equal(
        sum(phase["name"] == "restored-decrypt" for phase in restore_phases),
        repetitions["restored_decryptions"],
        f"{card['id']} restored decryption count",
    )

    expected_full = card["measurements"]["bytes"]["full_ciphertext"]
    checks.equal(
        {"count": len(full_ciphertexts), **extrema(full_ciphertexts)},
        expected_full,
        f"{card['id']} full ciphertext range",
    )
    checks.equal(comparison_profile["ciphertext_bytes"], expected_full, f"{card['id']} comparison ciphertext range")

    for label, filename in OBJECT_FILES.items():
        values = [record["generation"]["sizes"][filename] for record in report["records"]]
        checks.equal(extrema(values), card["measurements"]["bytes"][label], f"{card['id']} {label} range")

    all_phases = generation_phases + restore_phases
    observed_rss = max(phase["sampled_process_tree_peak_rss_bytes"] for phase in all_phases)
    expected_rss = card["measurements"]["bytes"]["observed_process_tree_rss_maximum"]
    checks.equal(observed_rss, expected_rss, f"{card['id']} RSS")
    checks.equal(comparison_profile["observed_process_tree_rss_bytes"], expected_rss, f"{card['id']} comparison RSS")

    for metric, expected in card["measurements"]["timing_seconds"].items():
        observed = report["timing_seconds"][metric]
        checks.equal(observed["count"], expected["count"], f"{card['id']} {metric} count")
        checks.equal(round(observed["median"], 6), expected["median"], f"{card['id']} {metric} median")
        checks.equal(comparison_profile["timing_seconds"][metric], observed, f"{card['id']} {metric} comparison")


def main():
    checks = Checks()
    cards = load_json(CARDS_PATH)
    checks.equal(cards["schema"], "IBME-SHOWCASE-CARDS/1", "card schema")
    checks.equal(cards["status"], "passed", "card status")
    checks.equal(len(cards["cards"]), 3, "card count")

    comparison_path = ROOT / cards["comparison_receipt"]["path"]
    checks.equal(file_sha256(comparison_path), cards["comparison_receipt"]["sha256"], "comparison receipt hash")
    comparison = load_json(comparison_path)
    checks.equal(comparison["status"], "passed", "comparison status")
    checks.equal(comparison["security_claim"], "none", "comparison security claim")
    checks.equal(comparison["backend_admitted"], False, "comparison admission")
    checks.equal(comparison["parameters_are_formal"], False, "comparison formal parameters")
    checks.equal(comparison["equal_security_targets_established"], False, "equal security targets")
    checks.equal(comparison["cross_security_group_ranking"], False, "cross-group ranking")

    top_claims = cards["claims"]
    checks.equal(top_claims["security_claim"], "none", "card security claim")
    checks.equal(top_claims["backend_admitted"], False, "card admission")
    checks.equal(top_claims["parameters_are_formal"], False, "card formal parameters")
    checks.equal(top_claims["security_proofs_produced"], 0, "card proof count")
    checks.equal(top_claims["uses_ROM"], True, "card ROM flag")
    checks.equal(cards["selection"]["equal_security_targets_established"], False, "card equal-security flag")
    checks.equal(cards["selection"]["cross_security_group_ranking"], False, "card ranking flag")

    expected_ids = {
        "latte3-bnn-mldsa44-hybrid-byteauth",
        "latte3-bnn-falcon512-hybrid-byteauth",
        "latte3-luo-module-default-compact-hybrid-byteauth",
    }
    checks.equal({card["id"] for card in cards["cards"]}, expected_ids, "profile IDs")
    checks.equal(
        cards["selection"]["current_primary_demo_candidate"],
        "latte3-bnn-mldsa44-hybrid-byteauth",
        "primary demo candidate",
    )

    profile_by_file = {profile["file"]: profile for profile in comparison["profiles"]}
    checks.equal(set(profile_by_file), {card["receipt"]["path"] for card in cards["cards"]}, "comparison profile set")
    for card in cards["cards"]:
        verify_receipt(checks, cards, profile_by_file[card["receipt"]["path"]], card)

    verify_source_metadata(checks, cards)
    for path in [cards["common_stack"]["hibe"]["paper"]["path"]] + [card["ibs"]["paper_path"] for card in cards["cards"]]:
        checks.true((ROOT / path).is_file(), f"missing cited local source {path}")

    result = {
        "status": "passed",
        "schema": cards["schema"],
        "profiles": len(cards["cards"]),
        "checks": checks.count,
        "provider_occurrences_reused_from_verified_comparison": sum(
            card["receipt"]["provider_occurrences_verified"] for card in cards["cards"]
        ),
        "private_state_files_opened": 0,
        "keys_generated": 0,
        "entropy_bytes_consumed": 0,
        "security_proofs_produced": 0,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
