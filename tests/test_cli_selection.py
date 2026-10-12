"""Independent CLI selection, fail-closed persistence and legacy coexistence.

Mock cases verify framework/state behavior only, never cryptographic security.
Real combination coverage lives in test_combination_matrix and the runner.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ibme import cli
from ibme.core.randomness import SecureRandom


def _setup_args(state, *options):
    return ["setup", "--state", str(state), "--hibe", "mock", "--ibs", "mock", "--allow-mock", *options]


@pytest.fixture
def selected_state(tmp_path):
    state = tmp_path / "selected"
    assert cli.main(_setup_args(state)) == 0
    return state


def _meta(state):
    return json.loads((state / "state.json").read_text(encoding="utf-8"))


def _write_meta(state, meta):
    (state / "state.json").write_text(json.dumps(meta), encoding="utf-8")


def _cli_process(arguments, cwd):
    source = Path(__file__).resolve().parents[1] / "src"
    return subprocess.run([sys.executable, "-B", "-m", "ibme.cli", *arguments],
                          cwd=cwd, env={**os.environ, "PYTHONPATH": str(source), "PYTHONIOENCODING": "utf-8"},
                          text=True, encoding="utf-8", capture_output=True, timeout=90)


def test_listing_and_static_matrix_do_not_consume_entropy(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("static CLI command consumed entropy")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    assert cli.main(["list-backends", "--json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert any(row["id"] == "chkp" and not row["available"] for row in catalog["hibe"])
    assert {"sis", "luo-matrix", "luo-module"} <= {row["id"] for row in catalog["ibs"]}
    assert cli.main(["matrix", "--json"]) == 0
    matrix = json.loads(capsys.readouterr().out)
    assert matrix["execution"] == "not_executed"
    assert matrix["rows"] and all(row["execution"] == "not_executed" for row in matrix["rows"])
    chkp = [row for row in matrix["rows"] if row["hibe"] == "chkp"]
    assert chkp and all(not row["compatibility"]["ok"] for row in chkp)


@pytest.mark.parametrize("options", [
    ["--hibe", "chkp", "--ibs", "luo-module", "--transport", "hybrid"],
    ["--hibe", "unknown", "--ibs", "sis"],
    ["--hibe", "abb10", "--ibs", "unknown"],
    ["--hibe", "abb10", "--ibs", "luo-module", "--transport", "direct"],
    ["--hibe", "abb10", "--ibs", "sis", "--signature-format", "compact"],
    ["--hibe", "mock", "--ibs", "mock"],
    ["--hibe", "abb10", "--params", "education"],
    ["--hibe", "abb10", "--mock"],
    ["--hibe", "abb10", "--hibe-params", "missing-preset"],
    ["--hibe", "abb10", "--protocol", "unknown"],
])
def test_invalid_selection_rejected_before_entropy_or_state(tmp_path, monkeypatch, options):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid selection consumed entropy")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    state = tmp_path / "must-not-exist"
    assert cli.main(["setup", "--state", str(state), *options]) == 2
    assert not state.exists()


def test_check_reports_frozen_selection_and_capacity(capsys):
    assert cli.main(["check", "--hibe", "abb10", "--ibs", "sis", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["execution"] == "not_executed"
    assert result["compatibility"]["ok"]
    assert result["compatibility"]["capacity"]["identity_bytes"] > 0
    assert len(result["suite_digest"]) == 64


def test_selected_state_reopens_in_new_process_without_selection_flags(tmp_path):
    state, message, cipher, output = [tmp_path / part for part in ("state", "message", "cipher", "output")]
    message.write_bytes(b"selected suite in separate processes")
    common = ["--state", str(state)]
    commands = [
        _setup_args(state),
        ["issue-sender-key", "Alice", *common],
        ["issue-receiver-key", "Bob", *common],
        ["encrypt", *common, "--sender", "Alice", "--receiver", "Bob", "--in", str(message), "--out", str(cipher)],
        ["decrypt", *common, "--sender", "Alice", "--receiver", "Bob", "--in", str(cipher), "--out", str(output)],
    ]
    for command in commands:
        result = _cli_process(command, tmp_path)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
    assert output.read_bytes() == message.read_bytes()
    meta = _meta(state)
    assert meta["version"] == 2 and meta["security_claim"] == "none"
    assert meta["backend_admitted"] is False and meta["parameters_are_formal"] is False
    assert (state / "mpk.bin").read_bytes().startswith(cli._STATE_OBJECT_MAGIC)
    result = _cli_process(["decrypt", *common, "--sender", "Carol", "--receiver", "Bob",
                           "--in", str(cipher), "--out", str(tmp_path / "wrong")], tmp_path)
    assert result.returncode == 1 and "BOTTOM" in result.stdout
    assert not (tmp_path / "wrong").exists()


@pytest.mark.parametrize("field,value", [
    ("version", True), ("backend", "mock"), ("suite_digest", "0" * 64),
    ("identity_bytes", 999), ("identity_bytes", True), ("max_application_bytes", 999999),
    ("security_claim", "128-bit"), ("backend_admitted", 1), ("parameters_are_formal", True),
    ("default_ciphertext_protocol", "baseline-v1"), ("master_persisted_before_key_publication", False),
    ("public_sha256", "G" * 64), ("capacity", {}),
])
def test_metadata_mutation_is_rejected(selected_state, field, value):
    meta = _meta(selected_state)
    meta[field] = value
    _write_meta(selected_state, meta)
    assert cli.main(["issue-sender-key", "Alice", "--state", str(selected_state)]) == 2
    assert not cli._sender_key_path(selected_state, b"Alice").exists()


def test_missing_and_duplicate_selection_fields_rejected(selected_state):
    original = (selected_state / "state.json").read_text(encoding="utf-8")
    meta = json.loads(original)
    del meta["suite"]
    _write_meta(selected_state, meta)
    assert cli.main(["issue-sender-key", "Alice", "--state", str(selected_state)]) == 2
    (selected_state / "state.json").write_text(original.rstrip()[:-1] + ',"version":2}', encoding="utf-8")
    assert cli.main(["issue-sender-key", "Alice", "--state", str(selected_state)]) == 2


def test_coherent_metadata_protocol_change_still_rejects_stored_objects(selected_state):
    from ibme.assembly import make_suite, validate_suite
    original = _meta(selected_state)
    changed = make_suite(hibe="mock", ibs="mock", protocol="baseline-v1", allow_mock=True)
    forged = cli._selected_metadata(changed, validate_suite(changed), original["public_sha256"])
    _write_meta(selected_state, forged)
    assert cli.main(["issue-sender-key", "Alice", "--state", str(selected_state)]) == 2
    assert not cli._sender_key_path(selected_state, b"Alice").exists()


@pytest.mark.parametrize("mutation", ["truncate", "append", "wrong-kind", "cross-setup"])
def test_master_envelope_rejects_corruption_and_context_mix(selected_state, tmp_path, mutation):
    path = selected_state / "msk.bin"
    original = path.read_bytes()
    if mutation == "truncate":
        path.write_bytes(original[:-1])
    elif mutation == "append":
        path.write_bytes(original + b"extra")
    elif mutation == "wrong-kind":
        path.write_bytes((selected_state / "mpk.bin").read_bytes())
    else:
        other = tmp_path / "other"
        assert cli.main(_setup_args(other)) == 0
        path.write_bytes((other / "msk.bin").read_bytes())
    assert cli.main(["issue-sender-key", "Alice", "--state", str(selected_state)]) == 2
    assert not cli._sender_key_path(selected_state, b"Alice").exists()


def test_selected_setup_cannot_be_overwritten_by_new_or_legacy_setup(selected_state):
    before = {name: hashlib.sha256((selected_state / name).read_bytes()).digest()
              for name in ("state.json", "mpk.bin", "msk.bin")}
    assert cli.main(_setup_args(selected_state)) == 2
    assert cli.main(["setup", "--state", str(selected_state), "--mock"]) == 2
    assert before == {name: hashlib.sha256((selected_state / name).read_bytes()).digest() for name in before}


def test_no_protocol_downgrade_for_selected_state(selected_state, tmp_path):
    assert cli.main(["issue-sender-key", "Alice", "--state", str(selected_state)]) == 0
    message = tmp_path / "message"
    output = tmp_path / "cipher"
    message.write_bytes(b"message")
    assert cli.main(["encrypt", "--sender", "Alice", "--receiver", "Bob", "--state", str(selected_state),
                     "--in", str(message), "--out", str(output), "--legacy-baseline"]) == 2
    assert not output.exists()


def test_legacy_preset_retains_version_one_and_explicit_baseline(tmp_path):
    state = tmp_path / "legacy"
    assert cli.main(["setup", "--state", str(state), "--mock"]) == 0
    assert _meta(state)["version"] == 1
    assert cli.main(["issue-sender-key", "Alice", "--state", str(state), "--mock"]) == 0
    assert cli.main(["issue-sender-key", "Alice", "--state", str(state)]) == 2


def test_duplicate_custom_parameter_fields_rejected_without_state(tmp_path):
    params = tmp_path / "params.json"
    params.write_text('{"n":2,"n":3}', encoding="utf-8")
    state = tmp_path / "state"
    assert cli.main(["setup", "--hibe", "abb10", "--hibe-params", str(params), "--state", str(state)]) == 2
    assert not state.exists()


def test_complete_independent_parameter_file_and_fixed_baseline(tmp_path):
    from ibme.assembly import make_suite
    suite = make_suite(hibe="mock", ibs="mock", protocol="baseline-v1", allow_mock=True)
    hibe_file, ibs_file = tmp_path / "hibe.json", tmp_path / "ibs.json"
    hibe_file.write_text(json.dumps(suite.to_dict()["hibe_params"]), encoding="utf-8")
    ibs_file.write_text(json.dumps(suite.to_dict()["ibs_params"]), encoding="utf-8")
    state = tmp_path / "state"
    assert cli.main(_setup_args(state, "--protocol", "baseline-v1", "--hibe-params", str(hibe_file),
                               "--ibs-params", str(ibs_file))) == 0
    assert _meta(state)["suite"] == suite.to_dict()
    assert cli.main(["issue-sender-key", "Alice", "--state", str(state)]) == 0
    assert cli.main(["issue-receiver-key", "Bob", "--state", str(state)]) == 0
    message, cipher, output = [tmp_path / name for name in ("message", "cipher", "output")]
    message.write_bytes(b"explicit baseline selection")
    common = ["--state", str(state), "--sender", "Alice", "--receiver", "Bob"]
    assert cli.main(["encrypt", *common, "--in", str(message), "--out", str(cipher)]) == 0
    assert cli.main(["decrypt", *common, "--in", str(cipher), "--out", str(output)]) == 0
    assert output.read_bytes() == message.read_bytes()


def test_real_luo_cache_persisted_before_key_publication_and_retry(tmp_path, monkeypatch):
    """Real Luo test parameters exercise persistence; HIBE remains TEST-ONLY."""
    from ibme.protocol.baseline import SenderKey
    state = tmp_path / "state"
    assert cli.main(["setup", "--state", str(state), "--hibe", "mock", "--ibs", "luo-module",
                     "--ibs-params", "test-small", "--transport", "hybrid", "--signature-format", "compact",
                     "--allow-mock"]) == 0
    common = ["--state", str(state)]
    assert cli.main(["issue-sender-key", "Alice", *common]) == 0
    alice = cli._sender_key_path(state, b"Alice").read_bytes()
    assert cli.main(["issue-sender-key", "Alice", *common]) == 0
    assert cli._sender_key_path(state, b"Alice").read_bytes() == alice
    output = cli._sender_key_path(state, b"Bob")
    original_replace = cli.os.replace
    def fail_key_publication(source, destination):
        if Path(destination) == output:
            raise OSError("injected key publication failure")
        return original_replace(source, destination)
    with monkeypatch.context() as patch:
        patch.setattr(cli.os, "replace", fail_key_publication)
        assert cli.main(["issue-sender-key", "Bob", *common]) == 2
    assert not output.exists()
    master, protocol, readers = cli._load_msk(state, False)
    assert set(master.imsk.cached_identities) == {b"Alice", b"Bob"}
    expected = protocol.skgen(master, b"Bob").to_bytes()
    assert cli.main(["issue-sender-key", "Bob", *common]) == 0
    recovered = SenderKey.from_bytes(cli._read_state_object(output, _meta(state), "sender"), readers["sk"])
    assert recovered.to_bytes() == expected
    assert cli._sender_key_path(state, b"Alice").read_bytes() == alice
    assert not list(state.glob(".ibme-state-*.tmp"))
    assert cli.main(["issue-sender-key", "Carol", *common, "--mock"]) == 2

    # Both codecs share the primitive key format. Changing the complete suite
    # metadata must still fail against the original storage configuration tag.
    from ibme.assembly import SuiteConfig, validate_suite
    original = _meta(state)
    changed = SuiteConfig.from_dict({**original["suite"], "signature_format": "reference"})
    _write_meta(state, cli._selected_metadata(changed, validate_suite(changed), original["public_sha256"]))
    assert cli.main(["issue-sender-key", "Carol", *common]) == 2
    assert not cli._sender_key_path(state, b"Carol").exists()


def test_partial_selected_setup_cannot_be_overwritten_via_legacy(selected_state):
    (selected_state / "state.json").unlink()
    before = (selected_state / "msk.bin").read_bytes()
    assert cli.main(["setup", "--state", str(selected_state), "--mock"]) == 2
    assert (selected_state / "msk.bin").read_bytes() == before


def test_v2_receiver_reissuance_reuses_authoritative_key_without_entropy(selected_state, monkeypatch):
    common = ["--state", str(selected_state)]
    assert cli.main(["issue-receiver-key", "Bob", *common]) == 0
    receiver = cli._receiver_key_path(selected_state, b"Bob")
    original = receiver.read_bytes()
    master = (selected_state / "msk.bin").read_bytes()
    def forbidden(*args, **kwargs):
        pytest.fail("reissuance discarded the existing receiver and sampled again")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    assert cli.main(["issue-receiver-key", "Bob", *common]) == 0
    assert receiver.read_bytes() == original
    assert (selected_state / "msk.bin").read_bytes() == master


def _receiver_driver(selected_state, monkeypatch, *, outcome="success"):
    """Inject an opaque state update, using only TEST-ONLY mock storage.

    This checks v2 envelope publication, not real CHKP or Gaussian sampling.
    The existing upstream tests separately exercise the delivered Sage cache.
    """
    assert cli.main(["issue-receiver-key", "Bob", "--state", str(selected_state)]) == 0
    factory = cli._runtime_for_state
    calls = []
    def runtime_factory(*args, **kwargs):
        proto, readers, runtime = factory(*args, **kwargs)
        def mutate_receiver(public, receiver, sender, data):
            from ibme.protocol.baseline import BOTTOM
            calls.append(sender)
            # Fault injection changes a serializable mock private field. The
            # caller still handles it through the opaque ReceiverKey interface.
            object.__setattr__(receiver.level1_key, "k1", b"z" * 32)
            if outcome == "raise":
                raise ValueError("injected post-update failure")
            if outcome == "bottom":
                return BOTTOM
            return b"opaque receiver state committed"
        proto.decrypt = mutate_receiver
        return proto, readers, runtime
    monkeypatch.setattr(cli, "_runtime_for_state", runtime_factory)
    return calls


@pytest.mark.parametrize("outcome,expected", [("success", 0), ("bottom", 1), ("raise", 2)])
def test_v2_receiver_transaction_preserves_envelope_on_all_outcomes(selected_state, tmp_path, monkeypatch, outcome, expected):
    from ibme.protocol.baseline import ReceiverKey
    from ibme.hibe.mock import MockHIBELevel1SecretKey
    from ibme.cli_state import receiver_pending_path
    calls = _receiver_driver(selected_state, monkeypatch, outcome=outcome)
    source, output = tmp_path / "input", tmp_path / "output"
    source.write_bytes(b"test driver")
    assert cli.main(["decrypt", "--state", str(selected_state), "--receiver", "Bob", "--sender", "Alice",
                     "--in", str(source), "--out", str(output)]) == expected
    key_path = cli._receiver_key_path(selected_state, b"Bob")
    assert key_path.read_bytes().startswith(cli._STATE_OBJECT_MAGIC)
    key = ReceiverKey.from_bytes(cli._read_state_object(key_path, _meta(selected_state), "receiver"), MockHIBELevel1SecretKey)
    assert key.level1_key.k1 == b"z" * 32 and calls == [b"Alice"]
    assert not receiver_pending_path(key_path).exists()
    assert output.exists() == (outcome == "success")
    if outcome == "success":
        assert output.read_bytes() == b"opaque receiver state committed"


def test_v2_receiver_publication_failure_blocks_retry_and_reissue(selected_state, tmp_path, monkeypatch, capsys):
    from ibme.cli_state import receiver_pending_path
    calls = _receiver_driver(selected_state, monkeypatch)
    key_path = cli._receiver_key_path(selected_state, b"Bob")
    before = key_path.read_bytes()
    source, output = tmp_path / "input", tmp_path / "output"
    source.write_bytes(b"test driver")
    command = ["decrypt", "--state", str(selected_state), "--receiver", "Bob", "--sender", "Alice",
               "--in", str(source), "--out", str(output)]
    original_replace = cli.os.replace
    def fail_key_publication(source, destination):
        if Path(destination) == key_path:
            raise OSError("injected receiver publication failure")
        return original_replace(source, destination)
    capsys.readouterr()
    with monkeypatch.context() as patch:
        patch.setattr(cli.os, "replace", fail_key_publication)
        assert cli.main(command) == 2
    assert not capsys.readouterr().out
    assert not output.exists() and key_path.read_bytes() == before
    assert receiver_pending_path(key_path).exists() and calls == [b"Alice"]
    assert cli.main(command) == 2
    assert cli.main(["issue-receiver-key", "Bob", "--state", str(selected_state)]) == 2
    assert calls == [b"Alice"] and key_path.read_bytes() == before
    assert not list(selected_state.glob(".ibme-state-*.tmp"))


@pytest.mark.parametrize("kind", ["msk", "mpk", "metadata", "sender", "receiver", "pending", "lock"])
def test_v2_data_output_cannot_replace_state(selected_state, tmp_path, kind):
    from ibme.cli_state import LOCK_FILE, receiver_pending_path
    targets = {"msk": selected_state / "msk.bin", "mpk": selected_state / "mpk.bin",
               "metadata": selected_state / "state.json", "sender": cli._sender_key_path(selected_state, b"Alice"),
               "receiver": cli._receiver_key_path(selected_state, b"Bob"),
               "pending": receiver_pending_path(cli._receiver_key_path(selected_state, b"Bob")),
               "lock": selected_state / LOCK_FILE}
    source = tmp_path / "input"
    source.write_bytes(b"message")
    before = {p.name: p.read_bytes() for p in selected_state.iterdir() if p.is_file()}
    for operation in ("encrypt", "decrypt"):
        assert cli.main([operation, "--state", str(selected_state), "--receiver", "Bob", "--sender", "Alice",
                         "--in", str(source), "--out", str(targets[kind])]) == 2
    assert before == {p.name: p.read_bytes() for p in selected_state.iterdir() if p.is_file()}


def test_data_output_rejects_hardlink_alias_to_authoritative_state(selected_state, tmp_path):
    alias = tmp_path / "innocent-output.bin"
    alias.hardlink_to(selected_state / "msk.bin")
    with pytest.raises(ValueError, match="protected key state"):
        cli._check_data_output(selected_state, alias)
