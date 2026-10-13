"""Real CLI acceptance with separately identified imported and fresh setup runs.

Run: PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.chkp_cli_acceptance preflight

``preflight`` is pure: no private input, sampling or CLI subprocess execution.
``imported`` imports the completed chkp_combination opaque objects into a NEW
CLI v2 state, then runs real CLI commands. This is explicitly a test import,
not evidence that CLI setup originally generated that imported lifetime.
``setup`` executes actual CLI setup in a different NEW state and checks its
metadata/public-master binding, without issuing any additional CHKP parent.

Run using the prescribed WSL Sage Python. Every subprocess has a hard timeout
(120 seconds; setup 180). Failed/timed-out commands retain pending markers;
the harness never deletes a failed marker, retries sampling, or resets state.
All secrets, test messages and process logs stay in ignored test-results.
Published JSON contains checks/counts/timings, never key or message bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from ibme import cli
from ibme.assembly import SuiteConfig, build_runtime, validate_suite
from ibme.cli_state import StateBusyError, key_issuance_lock
from ibme.protocol.baseline import MasterSecret, PublicKey, ReceiverKey, SenderKey

from experiments.research.chkp_combination import (
    BASE, PHASES, json_bytes, preflight, private_directory, ready_receipt, selected_suite, write,
)


# Instrument only the entropy boundary. All parsing, loading, dispatch and
# primitive calls run the actual ibme.cli.main in a separate interpreter.
NO_ENTROPY_CLI = """import sys
from ibme.core.randomness import SecureRandom
def forbidden(self, size):
    raise AssertionError('cached CLI operation attempted fresh entropy')
SecureRandom.read = forbidden
from ibme.cli import main
raise SystemExit(main(sys.argv[1:]))
"""


def pending(path):
    with path.open("xb") as stream:
        stream.write(b"IBME:CLI-ACCEPTANCE-PENDING:v1\nNo automatic retry or state reset.\n")
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def check(receipt, label, condition):
    receipt["checks"].append(dict(name=label, passed=bool(condition)))
    if not condition:
        raise AssertionError(label)


def cli_command(arguments, *, no_entropy=False):
    prefix = [sys.executable, "-B"]
    return prefix + (["-c", NO_ENTROPY_CLI] if no_entropy else ["-m", "ibme.cli"]) + list(arguments)


def run_cli(directory, receipt, label, arguments, *, expected=0, no_entropy=False, timeout=120):
    """One bounded, real subprocess; retain a marker on any incomplete result."""
    logs = directory / "commands"
    logs.mkdir(mode=0o700, exist_ok=True)
    marker = logs / (label + ".pending")
    if marker.exists() or (logs / (label + ".json")).exists():
        raise ValueError("command already attempted; no automatic repeat")
    pending(marker)
    started = time.monotonic()
    result = dict(name=label, expected_exit=expected, no_entropy_guard=no_entropy,
                  timeout_seconds=timeout, passed=False)
    try:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(BASE / "src") + os.pathsep + str(BASE)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(cli_command(arguments, no_entropy=no_entropy), cwd=BASE,
                                   env=environment, capture_output=True, timeout=timeout, check=False)
        write(logs / (label + ".stdout.bin"), completed.stdout)
        write(logs / (label + ".stderr.bin"), completed.stderr)
        result.update(returncode=completed.returncode, stdout_bytes=len(completed.stdout),
                      stderr_bytes=len(completed.stderr), passed=completed.returncode == expected)
        if expected == 1:
            result["bottom_token"] = completed.stdout.strip() == b"BOTTOM"
            result["passed"] = result["passed"] and result["bottom_token"]
    except subprocess.TimeoutExpired as exc:
        write(logs / (label + ".stdout.bin"), exc.stdout or b"")
        write(logs / (label + ".stderr.bin"), exc.stderr or b"")
        result["timed_out"] = True
    finally:
        result["seconds"] = time.monotonic() - started
        write(logs / (label + ".json"), json_bytes(result))
        receipt["commands"].append(result)
    check(receipt, label + "_exit", result["passed"])
    marker.unlink()


def source_ready(source):
    """Caller holds the source's key_issuance_lock through snapshot import."""
    if any(source.glob("*.pending")):
        raise ValueError("source combination has a pending attempt")
    suite = SuiteConfig.from_json((source / "suite.json").read_text())
    if suite.to_json() != selected_suite().to_json():
        raise ValueError("source suite differs from frozen CHKP/C64B compact selection")
    for phase in PHASES[1:]:
        ready_receipt(source, phase, suite)
    return suite


def expected_commands(phase):
    if phase == "setup":
        return {"fresh-setup": (0, False, 180), "catalog": (0, False, 120)}
    result = {"reissue-sender-Alice": (0, True, 120), "reissue-receiver-Bob": (0, True, 120)}
    for label in ("empty", "small", "maximum"):
        result["encrypt-" + label] = (0, False, 120)
        result["decrypt-" + label] = (0, True, 120)
    for label in ("wrong-sender", "wrong-receiver", "both-wrong", "tampered", "truncated", "appended"):
        result[label] = (1, True, 120)
    result["over-capacity"] = (2, True, 120)
    return result


def validate_cli_receipt(receipt, phase, suite, source):
    """Validate execution evidence, not a bare success flag or claimed count."""
    if (not isinstance(receipt, dict) or receipt.get("phase") != phase or receipt.get("passed") is not True
            or receipt.get("suite_digest") != suite.digest or "failure_type" in receipt
            or receipt.get("security_claim") != "none" or receipt.get("backend_admitted") is not False
            or receipt.get("parameters_are_formal") is not False):
        raise ValueError("CLI receipt does not match a successful current suite")
    checks, commands = receipt.get("checks"), receipt.get("commands")
    for rows, field in ((checks, "executed_checks"), (commands, "executed_commands")):
        if (not isinstance(rows, list) or not rows or type(receipt.get(field)) is not int
                or receipt[field] != len(rows) or any(not isinstance(row, dict)
                or row.get("passed") is not True or not isinstance(row.get("name"), str)
                or not row["name"] for row in rows)
                or len({row["name"] for row in rows}) != len(rows)):
            raise ValueError("CLI receipt has missing, failed, duplicate or miscounted execution rows")
    expected = expected_commands(phase)
    if {row["name"] for row in commands} != set(expected):
        raise ValueError("CLI receipt does not contain all expected real commands")
    for row in commands:
        exit_code, guarded, timeout = expected[row["name"]]
        if (type(row.get("returncode")) is not int or row["returncode"] != exit_code
                or type(row.get("expected_exit")) is not int or row["expected_exit"] != exit_code
                or row.get("no_entropy_guard") is not guarded or row.get("timed_out")
                or type(row.get("timeout_seconds")) is not int or row["timeout_seconds"] != timeout
                or (exit_code == 1 and row.get("bottom_token") is not True)):
            raise ValueError("CLI command receipt has wrong exit/guard/timeout evidence")
    names = {row["name"] for row in checks}
    required = {name + "_exit" for name in expected}
    if phase == "imported":
        required.update({"empty_plaintext_match", "small_plaintext_match", "maximum_plaintext_match",
                         "maximum_application_capacity_3924", "over_capacity_no_ciphertext"})
        for label in ("sender_reissue", "receiver_reissue", "empty", "small", "maximum",
                      "wrong-sender", "wrong-receiver", "both-wrong", "tampered", "truncated", "appended", "final"):
            required.update((label + "_key_and_metadata_bytes_unchanged", label + "_no_pending_state"))
        for label in ("wrong-sender", "wrong-receiver", "both-wrong", "tampered", "truncated", "appended"):
            required.add(label + "_no_plaintext_published")
    else:
        required.update({"fresh_setup_exact_suite", "fresh_setup_v2_metadata", "fresh_setup_public_master_bound",
                         "fresh_setup_no_issued_parent_or_sender", "fresh_setup_no_pending", "catalog_is_JSON"})
    if not required <= names:
        raise ValueError("CLI receipt omits required acceptance checks")
    provenance = receipt.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("suite_digest") != suite.digest:
        raise ValueError("CLI receipt lacks suite-bound provenance")
    if phase == "imported":
        if (provenance.get("mode") != "test import of completed real combination opaque objects"
                or provenance.get("imported_lifetime_was_generated_by_cli_setup") is not False
                or provenance.get("source_relative") != source.relative_to(BASE).as_posix()
                or receipt.get("new_CHKP_parent_or_leaf_sampling") is not False
                or receipt.get("new_IBS_identity_sampling") is not False):
            raise ValueError("imported CLI provenance is missing or does not match the source")
    elif (provenance.get("mode") != "fresh actual CLI setup with system CSPRNG"
            or provenance.get("imported_objects") is not False
            or provenance.get("parent_or_leaf_generated") is not False):
        raise ValueError("fresh setup receipt has wrong provenance")
    digest = provenance.get("public_sha256")
    if (type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
        raise ValueError("CLI provenance lacks a public context digest")


def ready_cli_receipt(directory, phase, source):
    if any(directory.glob("*.pending")) or any((directory / "commands").glob("*.pending")):
        raise ValueError("CLI phase or command is still pending")
    receipt = json.loads((directory / (phase + ".json")).read_bytes())
    suite = selected_suite()
    validate_cli_receipt(receipt, phase, suite, source)
    for row in receipt["commands"]:
        logs = directory / "commands"
        saved = json.loads((logs / (row["name"] + ".json")).read_bytes())
        if json.dumps(saved, sort_keys=True) != json.dumps(row, sort_keys=True):
            raise ValueError("phase receipt differs from its individual command receipt")
        for stream in ("stdout", "stderr"):
            size = row.get(stream + "_bytes")
            if type(size) is not int or size < 0 or (logs / (row["name"] + "." + stream + ".bin")).stat().st_size != size:
                raise ValueError("CLI command log size differs from its receipt")
    state = directory / ("imported-state" if phase == "imported" else "fresh-setup-state")
    with key_issuance_lock(state, timeout=0):
        meta = cli._load_state_meta(state)
        if (meta["suite"] != suite.to_dict() or meta["public_sha256"] != receipt["provenance"]["public_sha256"]
                or any(state.glob("*.pending"))):
            raise ValueError("CLI ready receipt differs from current state context or state is pending")
        cli._read_state_object(state / "mpk.bin", meta, "mpk")
    return receipt


def state_snapshot(state):
    """Only opaque byte fingerprints; never inspect any private matrix."""
    return {path.name: hashlib.sha256(path.read_bytes()).digest()
            for path in state.iterdir()
            if path.is_file() and (path.suffix == ".bin" or path.name == "state.json")}


def assert_unchanged(state, baseline, receipt, label):
    check(receipt, label + "_key_and_metadata_bytes_unchanged", state_snapshot(state) == baseline)
    check(receipt, label + "_no_pending_state", not list(state.glob("*.pending")))


def import_state(source, directory, suite, receipt):
    """Testing-only import through the same CLI v2 framing helpers as setup."""
    state = directory / "imported-state"
    state.mkdir(mode=0o700, exist_ok=False)
    report = validate_suite(suite)
    runtime = build_runtime(suite)
    readers = runtime.decoders
    blobs = {name: (source / filename).read_bytes() for name, filename in (
        ("public", "public.bin"), ("master", "master.bin"), ("sender", "sender-Alice.bin"),
        ("Bob", "receiver-Bob.bin"), ("Carol", "receiver-Carol.bin"))}
    public = PublicKey.from_bytes(blobs["public"], readers["hpk"], readers["ipk"])
    master = MasterSecret.from_bytes(blobs["master"], readers["hmsk"], readers["imsk"])
    sender = SenderKey.from_bytes(blobs["sender"], readers["sk"])
    runtime.validate_master(public, master)
    runtime.validate_sender(public, sender)
    for name in ("Bob", "Carol"):
        receiver = ReceiverKey.from_bytes(blobs[name], readers["sk1"])
        runtime.validate_receiver(public, receiver)
        check(receipt, "import_receiver_" + name + "_identity", receiver.identity == name.encode())
    check(receipt, "import_sender_Alice_identity", sender.identity == b"Alice")
    meta = cli._selected_metadata(suite, report, hashlib.sha256(blobs["public"]).hexdigest())
    objects = ((state / "mpk.bin", "public", "mpk"), (state / "msk.bin", "master", "msk"),
               (cli._sender_key_path(state, b"Alice"), "sender", "sender"),
               (cli._receiver_key_path(state, b"Bob"), "Bob", "receiver"),
               (cli._receiver_key_path(state, b"Carol"), "Carol", "receiver"))
    for path, blob_name, kind in objects:
        write(path, cli._state_object(blobs[blob_name], meta, kind))
        check(receipt, "import_" + blob_name + "_opaque_roundtrip",
              cli._read_state_object(path, meta, kind) == blobs[blob_name])
    write(state / "state.json", json_bytes(meta))
    check(receipt, "import_metadata_v2_valid", cli._load_state_meta(state) == meta)
    receipt["provenance"] = dict(mode="test import of completed real combination opaque objects",
                                  imported_lifetime_was_generated_by_cli_setup=False,
                                  source=source.name, source_relative=source.relative_to(BASE).as_posix(),
                                  public_sha256=meta["public_sha256"], suite_digest=suite.digest)
    return state


def imported(source, directory, receipt):
    # This is exactly the lock held by the source combination writer. Read
    # receipts and every opaque component within one stable source snapshot.
    with key_issuance_lock(source, timeout=0):
        suite = source_ready(source)
        state = import_state(source, directory, suite, receipt)
    baseline = state_snapshot(state)
    common = ["--state", str(state)]
    run_cli(directory, receipt, "reissue-sender-Alice", ["issue-sender-key", "Alice", *common], no_entropy=True)
    assert_unchanged(state, baseline, receipt, "sender_reissue")
    run_cli(directory, receipt, "reissue-receiver-Bob", ["issue-receiver-key", "Bob", *common], no_entropy=True)
    assert_unchanged(state, baseline, receipt, "receiver_reissue")
    data = directory / "data"
    data.mkdir(mode=0o700, exist_ok=False)
    maximum = validate_suite(suite).capacity["max_application_bytes"]
    check(receipt, "maximum_application_capacity_3924", maximum == 3924)
    ciphertexts = {}
    for label, message in (("empty", b""), ("small", b"\x00CHKP CLI acceptance\xff"),
                           ("maximum", b"M" * maximum)):
        plain, cipher, output = (data / (label + suffix) for suffix in (".input", ".cipher", ".output"))
        write(plain, message)
        arguments = [*common, "--sender", "Alice", "--receiver", "Bob"]
        run_cli(directory, receipt, "encrypt-" + label,
                ["encrypt", *arguments, "--in", str(plain), "--out", str(cipher)])
        run_cli(directory, receipt, "decrypt-" + label,
                ["decrypt", *arguments, "--in", str(cipher), "--out", str(output)], no_entropy=True)
        check(receipt, label + "_plaintext_match", output.read_bytes() == message)
        assert_unchanged(state, baseline, receipt, label)
        ciphertexts[label] = cipher
    cipher = ciphertexts["small"]
    for label, receiver, sender in (("wrong-sender", "Bob", "Eve"),
                ("wrong-receiver", "Carol", "Alice"), ("both-wrong", "Carol", "Eve")):
        output = data / (label + ".output")
        run_cli(directory, receipt, label,
                ["decrypt", *common, "--receiver", receiver, "--sender", sender,
                 "--in", str(cipher), "--out", str(output)], expected=1, no_entropy=True)
        check(receipt, label + "_no_plaintext_published", not output.exists())
        assert_unchanged(state, baseline, receipt, label)
    raw = cipher.read_bytes()
    for label, changed in (("tampered", raw[:-1] + bytes([raw[-1] ^ 1])),
                           ("truncated", raw[:-1]), ("appended", raw + b"\0")):
        bad, output = data / (label + ".cipher"), data / (label + ".output")
        write(bad, changed)
        run_cli(directory, receipt, label,
                ["decrypt", *common, "--receiver", "Bob", "--sender", "Alice",
                 "--in", str(bad), "--out", str(output)], expected=1, no_entropy=True)
        check(receipt, label + "_no_plaintext_published", not output.exists())
        assert_unchanged(state, baseline, receipt, label)
    over, output = data / "over-capacity.input", data / "over-capacity.cipher"
    write(over, b"M" * (maximum + 1))
    run_cli(directory, receipt, "over-capacity",
            ["encrypt", *common, "--receiver", "Bob", "--sender", "Alice",
             "--in", str(over), "--out", str(output)], expected=2, no_entropy=True)
    check(receipt, "over_capacity_no_ciphertext", not output.exists())
    assert_unchanged(state, baseline, receipt, "final")
    receipt.update(message_lengths=[0, 21, maximum],
                   ciphertext_sizes={name: path.stat().st_size for name, path in ciphertexts.items()},
                   new_CHKP_parent_or_leaf_sampling=False,
                   new_IBS_identity_sampling=False,
                   entropy_guard="SecureRandom.read forbidden for reissue/decrypt/capacity rejection subprocesses")


def fresh_setup(directory, receipt):
    state = directory / "fresh-setup-state"
    if state.exists():
        raise ValueError("fresh CLI setup requires a new state path")
    suite = selected_suite()
    parameters = directory / "setup-parameters"
    parameters.mkdir(mode=0o700, exist_ok=False)
    hibe_path, ibs_path = parameters / "hibe.json", parameters / "ibs.json"
    write(hibe_path, json_bytes(suite.to_dict()["hibe_params"]))
    write(ibs_path, json_bytes(suite.to_dict()["ibs_params"]))
    selection = ["--hibe", "chkp", "--ibs", "luo-module", "--transport", "hybrid",
                 "--protocol", "byteauth-v1", "--signature-format", "compact",
                 "--hibe-params", str(hibe_path), "--ibs-params", str(ibs_path)]
    run_cli(directory, receipt, "fresh-setup", ["setup", *selection, "--state", str(state)], timeout=180)
    meta = cli._load_state_meta(state)
    check(receipt, "fresh_setup_exact_suite", meta["suite"] == suite.to_dict())
    check(receipt, "fresh_setup_v2_metadata", meta["version"] == 2 and meta["max_application_bytes"] == 3924)
    runtime = build_runtime(suite)
    public = PublicKey.from_bytes(cli._read_state_object(state / "mpk.bin", meta, "mpk"),
                                  runtime.decoders["hpk"], runtime.decoders["ipk"])
    master = MasterSecret.from_bytes(cli._read_state_object(state / "msk.bin", meta, "msk"),
                                    runtime.decoders["hmsk"], runtime.decoders["imsk"])
    runtime.validate_master(public, master)
    check(receipt, "fresh_setup_public_master_bound", True)
    check(receipt, "fresh_setup_no_issued_parent_or_sender", not list(state.glob("receiver-*.bin"))
          and not list(state.glob("sender-*.bin")))
    check(receipt, "fresh_setup_no_pending", not list(state.glob("*.pending")))
    run_cli(directory, receipt, "catalog", ["list-backends", "--json"])
    catalog = json.loads((directory / "commands/catalog.stdout.bin").read_bytes())
    check(receipt, "catalog_is_JSON", isinstance(catalog, (dict, list)))
    receipt["provenance"] = dict(mode="fresh actual CLI setup with system CSPRNG",
                                  imported_objects=False, parent_or_leaf_generated=False,
                                  public_sha256=meta["public_sha256"], suite_digest=suite.digest)
    receipt["metadata"] = meta
    receipt["sizes"] = dict(public=(state / "mpk.bin").stat().st_size,
                            master=(state / "msk.bin").stat().st_size)


def helper_checks():
    """Parse real CLI argv and check guards without invoking any command."""
    parser = cli.build_parser()
    commands = [["issue-sender-key", "Alice", "--state", "unused"],
                ["issue-receiver-key", "Bob", "--state", "unused"],
                ["decrypt", "--state", "unused", "--receiver", "Bob", "--sender", "Alice",
                 "--in", "unused.input", "--out", "unused.output"],
                ["setup", "--state", "unused", "--hibe", "chkp", "--ibs", "luo-module",
                 "--transport", "hybrid", "--signature-format", "compact"]]
    for arguments in commands:
        parsed = parser.parse_args(arguments)
        assert callable(parsed.func)
        assert cli_command(arguments)[-len(arguments):] == arguments
        assert cli_command(arguments, no_entropy=True)[-len(arguments):] == arguments
    compile(NO_ENTROPY_CLI, "<entropy-guard>", "exec")
    return dict(cli_argument_sets_checked=len(commands), no_entropy_guard_compiles=True,
                commands_executed=0, private_files_read=0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("preflight", "imported", "setup"))
    parser.add_argument("--directory", help="new acceptance directory under ignored test-results")
    parser.add_argument("--source", default=str(BASE / "test-results/chkp-combination-2026-10-12"))
    args = parser.parse_args(argv)
    report = preflight()
    if args.phase == "preflight":
        report["CLI_helper_checks"] = helper_checks()
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if report["passed"] else 2
    if not report["passed"] or not args.directory:
        parser.error("Sage preflight must pass and --directory is required")
    directory, source = private_directory(args.directory), private_directory(args.source)
    if directory == source or directory.is_relative_to(source) or source.is_relative_to(directory):
        parser.error("acceptance and source directories must be separate")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    import fcntl
    with (directory / ".process.lock").open("a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error("another acceptance process owns this directory")
        marker, receipt_path = directory / (args.phase + ".pending"), directory / (args.phase + ".json")
        if any(directory.glob("*.pending")) or any((directory / "commands").glob("*.pending")):
            parser.error("attempted phase/command remains pending; no automatic retry/reset")
        if receipt_path.exists():
            try:
                receipt = ready_cli_receipt(directory, args.phase, source)
            except (StateBusyError, ValueError, OSError) as exc:
                parser.error(str(exc))
            print(json.dumps(dict(event="ready_phase_reused", receipt=receipt), sort_keys=True))
            return 0
        if args.phase == "imported":
            # Busy/unfinished source is detected before reserving this phase.
            try:
                with key_issuance_lock(source, timeout=0):
                    source_ready(source)
            except (StateBusyError, ValueError, OSError) as exc:
                parser.error(str(exc))
        pending(marker)
        receipt = dict(phase=args.phase, passed=False, checks=[], commands=[], repetition_count=1,
                       security_claim="none", backend_admitted=False, parameters_are_formal=False,
                       suite_digest=selected_suite().digest,
                       limitation="CLI functional acceptance only; n=2 CHKP has a public attack")
        started = time.monotonic()
        print(json.dumps(dict(event="started", phase=args.phase)), flush=True)
        try:
            if args.phase == "imported":
                imported(source, directory, receipt)
            else:
                fresh_setup(directory, receipt)
            receipt["passed"] = bool(receipt["checks"]) and all(row["passed"] for row in receipt["checks"])
            receipt.update(executed_checks=len(receipt["checks"]), executed_commands=len(receipt["commands"]))
            validate_cli_receipt(receipt, args.phase, selected_suite(), source)
        except BaseException as exc:
            receipt.update(passed=False, failure_type=type(exc).__name__)
        finally:
            receipt.update(seconds=time.monotonic() - started, executed_checks=len(receipt["checks"]),
                           executed_commands=len(receipt["commands"]))
            write(receipt_path, json_bytes(receipt))
            print(json.dumps(receipt, sort_keys=True), flush=True)
        if receipt["passed"]:
            marker.unlink()
            return 0
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
