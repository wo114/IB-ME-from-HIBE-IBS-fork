"""Opaque issuer transactions using a stateful TEST ONLY primitive.

This exercises the real CLI's persistence and OS locking, not a CHKP sampler.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from ibme import cli
from ibme.cli_state import MasterStatePendingError, StateBusyError, key_issuance_lock
from ibme.protocol.baseline import MasterSecret, PublicKey, ReceiverKey, SenderKey


class FixturePublic:
    def __init__(self, raw=b"master-transaction-fixture"):
        self.raw = raw

    def to_bytes(self):
        return self.raw

    @classmethod
    def from_bytes(cls, raw):
        return cls(raw)


class FixtureSecret:
    def __init__(self, identity, token):
        self.identity, self.token = identity, token
        self.public_key = FixturePublic()

    def to_bytes(self):
        return json.dumps([self.identity.hex(), self.token]).encode()

    @classmethod
    def from_bytes(cls, raw):
        identity, token = json.loads(raw)
        return cls(bytes.fromhex(identity), token)


class FixtureMaster:
    def __init__(self, entries=None):
        self.entries = {} if entries is None else entries
        self.public_key = FixturePublic()

    def to_bytes(self):
        return json.dumps(self.entries, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, raw):
        return cls(json.loads(raw))


class FixtureProtocol:
    def __init__(self, root):
        self.root = root

    def _issue(self, component, identity, role):
        address = identity.decode()
        if address in component.entries:
            if component.entries[address] == "FAILED":
                raise ValueError("fixture address blocked")
            return FixtureSecret(identity, component.entries[address])
        assert (self.root / "state/msk.bin.pending").exists()
        component.entries[address] = "FAILED"
        with (self.root / "draws.log").open("a") as handle:
            handle.write(role + ":" + address + "\n")
        mode_file = self.root / (address + ".mode")
        mode = mode_file.read_text() if mode_file.exists() else "ok"
        if mode == "hold":
            (self.root / "entered").write_text("ready")
            deadline = time.monotonic() + 20
            while not (self.root / "release").exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("fixture barrier timed out")
                time.sleep(0.01)
        if mode == "fail":
            raise ValueError("injected sampling failure")
        if mode == "interrupt":
            raise KeyboardInterrupt("injected interruption")
        if mode == "exit":
            os._exit(17)
        if mode == "reenter":
            cli.cmd_issue_receiver_key(arguments(self.root, "nested"))
        component.entries[address] = os.urandom(16).hex()
        return FixtureSecret(identity, component.entries[address])

    def rkgen(self, master, identity):
        return ReceiverKey(self._issue(master.hmsk, identity, "receiver"))

    def skgen(self, master, identity):
        return SenderKey(self._issue(master.imsk, identity, "sender"))


def install_driver(root):
    protocol = FixtureProtocol(root)
    classes = dict(hpk=FixturePublic, ipk=FixturePublic, hmsk=FixtureMaster,
                   imsk=FixtureMaster, sk1=FixtureSecret, sk=FixtureSecret)
    cli._make_runtime = lambda *args, **kwargs: (protocol, classes)


def arguments(root, identity="Bob"):
    return SimpleNamespace(state=root / "state", name=identity, mock=False)


def read_master(root):
    return MasterSecret.from_bytes((root / "state/msk.bin").read_bytes(), FixtureMaster, FixtureMaster)


def draws(root):
    path = root / "draws.log"
    return path.read_text().splitlines() if path.exists() else []


@pytest.fixture
def state(tmp_path, monkeypatch):
    directory = tmp_path / "state"
    directory.mkdir()
    meta = dict(version=1, backend="abb10-hybrid+luo-module", params_preset="luo-module-research",
                identity_bytes=64, max_message_bytes=65536, max_application_bytes=3924,
                inner_hibe_payload_bytes=32, inner_hibe_identity_bytes=86, security_claim="none",
                backend_admitted=False, persistent_identity_cache=True,
                default_ciphertext_protocol="byteauth-v1", hibe_params_name="hybrid-hibe-research-v1",
                ibs_params_name="luo2024-module-ref1", signature_format="reference")
    (directory / "state.json").write_text(json.dumps(meta))
    (directory / "mpk.bin").write_bytes(PublicKey(FixturePublic(), FixturePublic()).to_bytes())
    (directory / "msk.bin").write_bytes(MasterSecret(FixtureMaster(), FixtureMaster()).to_bytes())
    monkeypatch.setattr(cli, "_make_runtime", cli._make_runtime)
    install_driver(tmp_path)
    return tmp_path


def test_master_is_published_before_receiver_and_existing_key_is_reused(state, monkeypatch):
    original = cli._atomic_write_state
    def publish(path, raw):
        if path.name.startswith("receiver-"):
            assert "Bob" in read_master(state).hmsk.entries
            assert (state / "state/msk.bin.pending").exists()
        original(path, raw)
    monkeypatch.setattr(cli, "_atomic_write_state", publish)
    assert cli.cmd_issue_receiver_key(arguments(state)) == 0
    key = cli._receiver_key_path(state / "state", b"Bob").read_bytes()
    assert not (state / "state/msk.bin.pending").exists()
    assert cli.cmd_issue_receiver_key(arguments(state)) == 0
    assert cli._receiver_key_path(state / "state", b"Bob").read_bytes() == key
    assert draws(state) == ["receiver:Bob"]


@pytest.mark.parametrize("role", ["sender", "receiver"])
@pytest.mark.parametrize("mode,error", [("fail", ValueError), ("interrupt", KeyboardInterrupt)])
def test_abort_saves_changed_master_and_blocks_all_issuance(state, role, mode, error, capsys):
    (state / "Bob.mode").write_text(mode)
    command = getattr(cli, "cmd_issue_" + role + "_key")
    with pytest.raises(error):
        command(arguments(state))
    master = read_master(state)
    assert getattr(master, "imsk" if role == "sender" else "hmsk").entries == {"Bob": "FAILED"}
    assert not capsys.readouterr().out
    assert (state / "state/msk.bin.pending").exists()
    assert not list((state / "state").glob(role + "-*.bin"))
    for retry in (cli.cmd_issue_sender_key, cli.cmd_issue_receiver_key):
        with pytest.raises(MasterStatePendingError):
            retry(arguments(state, "Carol"))
    assert draws(state) == [role + ":Bob"]


@pytest.mark.parametrize("target", ["msk.bin", "receiver"])
def test_publication_failure_keeps_master_pending_and_returns_no_key(state, monkeypatch, target, capsys):
    original = cli._atomic_write_state
    def fail(path, raw):
        if path.name == target or (target == "receiver" and path.name.startswith("receiver-")):
            raise OSError("injected publication failure")
        original(path, raw)
    monkeypatch.setattr(cli, "_atomic_write_state", fail)
    with pytest.raises(OSError, match="publication"):
        cli.cmd_issue_receiver_key(arguments(state))
    assert not capsys.readouterr().out
    assert (state / "state/msk.bin.pending").exists()
    assert not cli._receiver_key_path(state / "state", b"Bob").exists()
    if target == "receiver":
        assert read_master(state).hmsk.entries["Bob"] != "FAILED"
    assert not list((state / "state").glob(".ibme-state-*.tmp"))
    with pytest.raises(MasterStatePendingError):
        cli.cmd_issue_receiver_key(arguments(state))
    assert len(draws(state)) == 1


@pytest.mark.parametrize("failure", ["marker-write", "serialize", "marker-remove"])
def test_incomplete_finalization_stays_closed(state, monkeypatch, failure, capsys):
    if failure == "marker-write":
        def fail(*args):
            raise OSError("marker fsync failed")
        monkeypatch.setattr(cli.os, "fsync", fail)
    elif failure == "serialize":
        original = FixtureMaster.to_bytes
        def fail(master):
            if master.entries:
                raise ValueError("master serialization failed")
            return original(master)
        monkeypatch.setattr(FixtureMaster, "to_bytes", fail)
    else:
        original = Path.unlink
        def fail(path, *args, **kwargs):
            if path.name == "msk.bin.pending":
                raise OSError("marker removal failed")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, "unlink", fail)
    with pytest.raises((OSError, ValueError)):
        cli.cmd_issue_receiver_key(arguments(state))
    assert not capsys.readouterr().out
    assert (state / "state/msk.bin.pending").exists()
    before = draws(state)
    with pytest.raises(MasterStatePendingError):
        cli.cmd_issue_receiver_key(arguments(state))
    assert draws(state) == before
    if failure == "marker-write":
        assert before == []


def test_modified_same_thread_reentry_is_immediate_and_preserves_failure(state):
    (state / "Bob.mode").write_text("reenter")
    begin = time.monotonic()
    with pytest.raises(StateBusyError, match="reentry"):
        cli.cmd_issue_receiver_key(arguments(state))
    assert time.monotonic() - begin < 2
    assert read_master(state).hmsk.entries == {"Bob": "FAILED"}
    assert draws(state) == ["receiver:Bob"]


def test_distinct_threads_wait_and_serialize_successfully(state):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: cli.cmd_issue_receiver_key(arguments(state)), range(2)))
    assert results == [0, 0]
    assert draws(state) == ["receiver:Bob"]
    with key_issuance_lock(state / "state"):
        pass


@pytest.mark.parametrize("alias", [False, True])
def test_data_output_cannot_overwrite_master_pending_or_hardlink(state, alias):
    marker = state / "state/msk.bin.pending"
    marker.write_bytes(b"fixed pending marker")
    output = marker
    if alias:
        output = state / "alias.out"
        os.link(marker, output)
    with pytest.raises(ValueError, match="protected key state"):
        cli._check_data_output(state / "state", output)
    assert marker.read_bytes() == b"fixed pending marker"


WORKER = """import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location('master_driver',sys.argv[1])
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
root=pathlib.Path(sys.argv[2]);driver.install_driver(root)
sys.exit(driver.cli.cmd_issue_receiver_key(driver.arguments(root,sys.argv[3])))
"""


def worker(root, identity="Bob"):
    source = Path(__file__).resolve().parents[1] / "src"
    return subprocess.Popen([sys.executable, "-B", "-c", WORKER, str(Path(__file__).resolve()),
                             str(root), identity], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env={**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"})


def finish(process, expected=0):
    out, err = process.communicate(timeout=25)
    assert process.returncode == expected, out + err


def test_hard_exit_retains_pending_and_fresh_process_cannot_resample(state):
    (state / "Bob.mode").write_text("exit")
    finish(worker(state), expected=17)
    assert (state / "state/msk.bin.pending").exists()
    again = worker(state)
    out, err = again.communicate(timeout=10)
    assert again.returncode != 0 and "master state pending" in err
    assert out == "" and draws(state) == ["receiver:Bob"]
    assert not cli._receiver_key_path(state / "state", b"Bob").exists()


def test_forcibly_killed_sampler_leaves_issuer_closed(state):
    (state / "Bob.mode").write_text("hold")
    process = worker(state)
    try:
        deadline = time.monotonic() + 10
        while not (state / "entered").exists():
            assert process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.01)
        process.kill()
        process.communicate(timeout=5)
        assert process.returncode != 0
        assert (state / "state/msk.bin.pending").read_bytes() == b"IBME:MASTER-PENDING:v1\n"
        with pytest.raises(MasterStatePendingError):
            cli.cmd_issue_receiver_key(arguments(state))
        assert draws(state) == ["receiver:Bob"]
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


@pytest.mark.parametrize("identity", ["Bob", "Carol"])
def test_concurrent_processes_refresh_master_and_preserve_all_issued_keys(state, identity):
    (state / "Bob.mode").write_text("hold")
    first, second = worker(state), None
    try:
        deadline = time.monotonic() + 10
        while not (state / "entered").exists():
            assert first.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.01)
        second = worker(state, identity)
        (state / "release").write_text("ready")
        finish(first)
        finish(second)
        expected = ["receiver:Bob"] + ([] if identity == "Bob" else ["receiver:Carol"])
        assert draws(state) == expected
        assert set(read_master(state).hmsk.entries) == {"Bob", identity}
        assert not (state / "state/msk.bin.pending").exists()
        # A third, fresh process must load the published receiver instead of
        # delegating again from the newly restored master.
        finish(worker(state, identity))
        assert draws(state) == expected
    finally:
        for process in (first, second):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
