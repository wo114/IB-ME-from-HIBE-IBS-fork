"""CLI harness boundary regression; no CHKP/C64B key generation or sampling.

Receipts are explicitly synthetic fixtures. Subprocess outcomes are injected
to check fail-closed bookkeeping; they are not algorithm acceptance evidence.
"""

from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from experiments.research import chkp_cli_acceptance as driver
from ibme import cli
from ibme.cli_state import StateBusyError, key_issuance_lock


@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "BASE", tmp_path)
    path = tmp_path / "source"
    path.mkdir()
    (path / "suite.json").write_text(driver.selected_suite().to_json())
    return path


def _valid_receipt(phase, source):
    suite = driver.selected_suite()
    required = {name + "_exit" for name in driver.expected_commands(phase)}
    if phase == "setup":
        required.update({"fresh_setup_exact_suite", "fresh_setup_v2_metadata", "fresh_setup_public_master_bound",
                         "fresh_setup_no_issued_parent_or_sender", "fresh_setup_no_pending", "catalog_is_JSON"})
        provenance = dict(mode="fresh actual CLI setup with system CSPRNG", imported_objects=False,
                          parent_or_leaf_generated=False)
    else:
        required.update({"empty_plaintext_match", "small_plaintext_match", "maximum_plaintext_match",
                         "maximum_application_capacity_3924", "over_capacity_no_ciphertext"})
        for name in ("sender_reissue", "receiver_reissue", "empty", "small", "maximum", "wrong-sender",
                     "wrong-receiver", "both-wrong", "tampered", "truncated", "appended", "final"):
            required.update((name + "_key_and_metadata_bytes_unchanged", name + "_no_pending_state"))
        for name in ("wrong-sender", "wrong-receiver", "both-wrong", "tampered", "truncated", "appended"):
            required.add(name + "_no_plaintext_published")
        provenance = dict(mode="test import of completed real combination opaque objects",
                          imported_lifetime_was_generated_by_cli_setup=False,
                          source_relative=source.relative_to(driver.BASE).as_posix())
    provenance.update(suite_digest=suite.digest, public_sha256="a" * 64)
    commands = [dict(name=name, passed=True, returncode=code, expected_exit=code,
                     no_entropy_guard=guarded, timeout_seconds=timeout,
                     **({"bottom_token": True} if code == 1 else {}))
                for name, (code, guarded, timeout) in driver.expected_commands(phase).items()]
    return dict(phase=phase, passed=True, suite_digest=suite.digest, security_claim="none",
                backend_admitted=False, parameters_are_formal=False,
                checks=[dict(name=name, passed=True) for name in sorted(required)],
                commands=commands, executed_checks=len(required), executed_commands=len(commands),
                provenance=provenance, new_CHKP_parent_or_leaf_sampling=False,
                new_IBS_identity_sampling=False)


@pytest.mark.parametrize("phase", ["imported", "setup"])
def test_complete_synthetic_receipt_shape_is_valid(source, phase):
    driver.validate_cli_receipt(_valid_receipt(phase, source), phase, driver.selected_suite(), source)


@pytest.mark.parametrize("field,value", [
    ("phase", "incorrect"), ("passed", 1), ("suite_digest", "incorrect"),
    ("executed_checks", True), ("executed_commands", True), ("executed_checks", 0),
    ("commands", []), ("checks", []), ("security_claim", "secure"), ("backend_admitted", 0),
])
def test_receipt_rejects_wrong_fields(source, field, value):
    receipt = _valid_receipt("setup", source)
    receipt[field] = value
    with pytest.raises(ValueError):
        driver.validate_cli_receipt(receipt, "setup", driver.selected_suite(), source)


@pytest.mark.parametrize("change", ["missing_command", "duplicate_check", "bare_pass", "wrong_exit",
                                    "wrong_guard", "wrong_timeout", "no_bottom", "wrong_source", "wrong_provenance"])
def test_imported_receipt_requires_complete_execution_and_provenance(source, change):
    receipt = _valid_receipt("imported", source)
    if change == "missing_command":
        receipt["commands"].pop()
        receipt["executed_commands"] -= 1
    elif change == "duplicate_check":
        receipt["checks"].append(deepcopy(receipt["checks"][0]))
        receipt["executed_checks"] += 1
    elif change == "bare_pass":
        receipt["checks"] = [dict(name="nothing", passed=True)]
        receipt["executed_checks"] = 1
    elif change == "wrong_exit":
        receipt["commands"][0]["returncode"] = 2
    elif change == "wrong_guard":
        receipt["commands"][0]["no_entropy_guard"] = False
    elif change == "wrong_timeout":
        receipt["commands"][0]["timeout_seconds"] = 0
    elif change == "no_bottom":
        next(row for row in receipt["commands"] if row["expected_exit"] == 1)["bottom_token"] = False
    elif change == "wrong_source":
        receipt["provenance"]["source_relative"] = "different"
    else:
        receipt["provenance"]["imported_lifetime_was_generated_by_cli_setup"] = True
    with pytest.raises(ValueError):
        driver.validate_cli_receipt(receipt, "imported", driver.selected_suite(), source)


def _write_source_receipts(source):
    config = driver.selected_suite()
    for phase in driver.PHASES[1:]:
        required = {"prepare": {"existing_Bob_Alice_leaf_reused", "real_C64B_setup_and_sender"},
                    "receiver-Carol": {"address_completed"},
                    "checks": {"honest_roundtrip", "wrong_sender", "wrong_receiver", "both_wrong",
                               "raw_low_coefficient_change_keeps_seed", "hybrid_AAD_rejects_same_seed_capsule_change",
                               "full_BYTEAUTH_rejection_reaches_IBS", "capacity_plus_one_rejects_before_entropy"}}.get(
                                   phase, {"new_leaf_canonical_restore", "address_completed"})
        value = dict(phase=phase, passed=True, suite_digest=config.digest,
                     checks=[dict(name=name, passed=True) for name in sorted(required)], executed_checks=len(required))
        (source / (phase + ".json")).write_text(json.dumps(value))


def test_source_requires_whole_completed_chain_not_a_passed_flag(source):
    _write_source_receipts(source)
    assert driver.source_ready(source) == driver.selected_suite()
    (source / "leaf-Bob-Eve.json").write_text('{"passed":true}')
    with pytest.raises(ValueError):
        driver.source_ready(source)


def test_source_rejects_any_pending_even_unrelated_phase(source):
    _write_source_receipts(source)
    (source / "unknown.pending").write_bytes(b"fixture")
    with pytest.raises(ValueError, match="pending"):
        driver.source_ready(source)


def test_import_holds_source_lock_for_receipts_and_all_opaque_reads(source, tmp_path, monkeypatch):
    stages = []

    def assert_locked(name):
        with pytest.raises(StateBusyError):
            with key_issuance_lock(source, timeout=0):
                pass
        stages.append(name)

    def ready(path):
        assert path == source
        assert_locked("receipts")
        return "fixture-suite"

    def snapshot(path, destination, suite, receipt):
        assert path == source and suite == "fixture-suite"
        assert_locked("objects")
        return destination

    class StopAfterImport(Exception):
        pass

    def stopped(state):
        # The copy has completed before later CLI commands take their locks.
        with key_issuance_lock(source, timeout=0):
            stages.append("released_after_copy")
        raise StopAfterImport

    monkeypatch.setattr(driver, "source_ready", ready)
    monkeypatch.setattr(driver, "import_state", snapshot)
    monkeypatch.setattr(driver, "state_snapshot", stopped)
    with pytest.raises(StopAfterImport):
        driver.imported(source, tmp_path, {"checks": []})
    assert stages == ["receipts", "objects", "released_after_copy"]


def test_busy_source_is_rejected_before_any_snapshot_read(source, tmp_path, monkeypatch):
    def forbidden(*args):
        pytest.fail("busy source was read")
    monkeypatch.setattr(driver, "source_ready", forbidden)
    with key_issuance_lock(source, timeout=0):
        with pytest.raises(StateBusyError):
            driver.imported(source, tmp_path, {"checks": []})


@pytest.mark.parametrize("returncode,stdout,accepted", [(1, b"BOTTOM\n", True), (1, b"", False), (0, b"BOTTOM", False)])
def test_subprocess_bottom_requires_exact_exit_and_token(tmp_path, monkeypatch, returncode, stdout, accepted):
    def run(command, **kwargs):
        assert kwargs["timeout"] == 120 and kwargs["capture_output"] is True
        return subprocess.CompletedProcess(command, returncode, stdout, b"")
    monkeypatch.setattr(driver.subprocess, "run", run)
    receipt = dict(checks=[], commands=[])
    action = lambda: driver.run_cli(tmp_path, receipt, "bottom", ["decrypt"], expected=1, no_entropy=True)
    if accepted:
        action()
    else:
        with pytest.raises(AssertionError):
            action()
    assert (tmp_path / "commands/bottom.pending").exists() is not accepted
    assert receipt["commands"][0]["passed"] is accepted
    with pytest.raises(ValueError, match="attempted"):
        action()


def test_subprocess_timeout_keeps_private_logs_and_pending(tmp_path, monkeypatch):
    def timed_out(*args, **kwargs):
        raise subprocess.TimeoutExpired("fixture", 120, output=b"partial", stderr=b"diagnostic")
    monkeypatch.setattr(driver.subprocess, "run", timed_out)
    receipt = dict(checks=[], commands=[])
    with pytest.raises(AssertionError):
        driver.run_cli(tmp_path, receipt, "timeout", ["list-backends"])
    assert (tmp_path / "commands/timeout.pending").exists()
    assert receipt["commands"][0]["timed_out"] is True
    assert (tmp_path / "commands/timeout.stderr.bin").read_bytes() == b"diagnostic"


@pytest.mark.parametrize("marker", ["setup.pending", "commands/other.pending"])
def test_ready_reuse_rejects_any_phase_or_command_pending(tmp_path, source, marker):
    path = tmp_path / marker
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="pending"):
        driver.ready_cli_receipt(tmp_path, "setup", source)


def test_real_parser_uses_ibs_params_and_metadata_helper_not_stale_flags(tmp_path):
    path = tmp_path / "ibs.json"
    values = driver.selected_suite().to_dict()["ibs_params"]
    path.write_text(json.dumps(values))
    args = cli.build_parser().parse_args(["check", "--hibe", "chkp", "--ibs", "luo-module",
        "--transport", "hybrid", "--signature-format", "compact", "--ibs-params", str(path)])
    assert cli._suite_from_args(args).to_json() == driver.selected_suite().to_json()
    assert driver.helper_checks()["commands_executed"] == 0
    assert driver.cli_command(["list-backends"])[-3:] == ["-m", "ibme.cli", "list-backends"]
    guarded = driver.cli_command(["list-backends"], no_entropy=True)
    assert guarded[-3:] == ["-c", driver.NO_ENTROPY_CLI, "list-backends"]
