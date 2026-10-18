"""ABB full-basis representation feasibility stays public and fail-closed."""

import hashlib
import json
from pathlib import Path

import pytest

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.abb_rom.basis_representation_probe import (
    CURRENT_MAX_BLOB_BYTES,
    PAYLOAD_SAMPLEPRE_CALLS,
    build_representation_report,
    runtime_summary,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "docs/research/team-a-delivery/2026-10-18-abb-noise-tradeoff/parameter-card.json"
)
EVIDENCE = (
    ROOT
    / "docs/research/team-a-delivery/2026-10-18-abb-basis-representation/parameter-card.json"
)
RUNTIME = EVIDENCE.with_name("runtime-summary.json")


def test_target_rows_reject_external_storage_only_and_retain_public_size_blockers(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("ABB representation probe consumed entropy")

    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(DeterministicRandom, "read", forbidden)
    report = build_representation_report(SOURCE)
    assert report["complete_runtime_candidates"] == []
    assert report["root_or_key_generations"] == report["ciphertext_generations"] == 0
    assert report["private_entropy_bytes"] == 0
    assert report["not_an_impossibility_theorem"] is True
    assert all(not row["external_storage_only_runtime_candidate"] for row in report["rows"])
    assert all(row["public_matrix_minimum_bytes"] > 10**12 for row in report["rows"])
    assert all(row["raw_32_byte_ciphertext_minimum_bytes"] > 10**11 for row in report["rows"])


def test_n9600_exact_current_consumer_floors_are_reproducible():
    report = build_representation_report(SOURCE)
    row = next(row for row in report["rows"] if row["n"] == 9600)
    dimension = 15_974_400
    entries = dimension**2
    assert row["basis_dimension"] == dimension
    assert row["complete_basis_entries"] == entries
    assert row["current_private_codec_minimum_bytes"] == 6 * entries
    assert row["ideal_external_parent_read_plus_output_write_bytes"] == 12 * entries
    assert row["current_one_SamplePre_coefficient_touch_floor"] == 2 * entries
    assert row["current_256_SamplePre_coefficient_touch_floor"] == 2 * entries * 256
    assert row["current_successful_RandBasis_coefficient_touch_floor"] == 2 * entries * dimension
    assert row["fits_current_128_MiB_secret_blob"] is False
    assert row["current_private_codec_minimum_bytes"] > CURRENT_MAX_BLOB_BYTES
    assert PAYLOAD_SAMPLEPRE_CALLS == 256


def test_representation_options_do_not_mislabel_packed_seed_or_mp12_as_abb_solution():
    report = build_representation_report(SOURCE)
    options = {item["id"]: item for item in report["representation_options"]}
    packed = options["resident-packed-matrix-v1"]
    assert packed["backing"].startswith("resident immutable bytes")
    assert packed["current_consumer_compatible"] is False
    external = options["hypothetical-exact-external-chunks"]
    assert external["preserves_entrywise_full_basis"] is True
    assert external["reduces_complete_basis_entries"] is False
    assert external["runtime_candidate"] is False
    assert options["seed-only-replay"]["preserves_current_ABB_semantics"] is False
    assert options["MP12-or-gadget-trapdoor-substitution"]["changes_algorithm"] is True


def test_changed_security_or_wire_claims_fail_closed(tmp_path):
    card = json.loads(SOURCE.read_text(encoding="utf-8"))
    card["backend_admitted"] = True
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(ValueError, match="security metadata"):
        build_representation_report(changed)

    card["backend_admitted"] = False
    card["rows"][0]["minimum_wire_bytes"]["parent_stored_full_basis"] -= 1
    changed.write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(ValueError, match="basis wire floor"):
        build_representation_report(changed)


def test_runtime_summary_keeps_public_execution_and_security_separate():
    report = build_representation_report(SOURCE)
    summary = runtime_summary(report)
    assert summary["repetitions"] == 1
    assert summary["rng"].startswith("none")
    assert summary["root_or_key_generations"] == summary["private_entropy_bytes"] == 0
    assert summary["complete_runtime_candidates"] == []
    assert summary["security_claim"] == "none"
    assert summary["backend_admitted"] is summary["parameters_are_formal"] is False


def test_report_fingerprints_bind_the_source_card_code_and_fixed_paper():
    report = build_representation_report(SOURCE)
    assert report["source"]["sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    for name, digest in report["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest


def test_checked_in_public_evidence_is_current_and_has_no_runtime_candidate():
    report = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    runtime = json.loads(RUNTIME.read_text(encoding="utf-8"))
    assert report["source"]["sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    for name, digest in report["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    assert report["complete_runtime_candidates"] == runtime["complete_runtime_candidates"] == []
    assert report["root_or_key_generations"] == runtime["root_or_key_generations"] == 0
    assert report["private_entropy_bytes"] == runtime["private_entropy_bytes"] == 0
    assert report["security_claim"] == runtime["security_claim"] == "none"
