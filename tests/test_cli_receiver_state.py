"""Durable opaque receiver state; the portable driver is TEST ONLY.

The driver supplies a serializable stateful component to the real CLI and
protocol key containers. It is not a CHKP implementation or a security test.
An additional Sage test below uses the delivered real Gaussian leaf cache.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from ibme import cli
from ibme.core.errors import IBMEError
from ibme.core.encoding import decode_bytes, encode_bytes
from ibme.protocol.baseline import BOTTOM, PublicKey, ReceiverKey


class TestPublic:
    __test__ = False

    def __init__(self, raw=b"public-receiver-fixture"):
        self.raw = raw

    def to_bytes(self):
        return self.raw

    @classmethod
    def from_bytes(cls, raw):
        return cls(raw)


class TestLeaf:
    __test__ = False

    def __init__(self, identity=b"Bob", cache=None, public=None):
        self.identity = identity
        self.cache = {} if cache is None else cache
        self.public_key = TestPublic() if public is None else public

    def to_bytes(self):
        return json.dumps(dict(identity=self.identity.hex(), cache=self.cache,
                               public=self.public_key.to_bytes().hex()), sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, raw):
        data = json.loads(raw)
        return cls(bytes.fromhex(data["identity"]), data["cache"],
                   TestPublic(bytes.fromhex(data["public"])))


class TestProtocol:
    __test__ = False

    def __init__(self, root):
        self.root = root

    def decrypt(self, public, receiver, sender, data):
        cache = receiver.level1_key.cache
        address = sender.decode()
        if cache.get(address) == "FAILED":
            raise IBMEError("test address blocked after sampling failure")
        if address not in cache:
            cache[address] = "FAILED"
            with (self.root / "draws.log").open("a", encoding="utf-8") as log:
                log.write(address + "\n")
            if data == b"sampling-failure":
                raise ValueError("injected sampling failure")
            cache[address] = os.urandom(16).hex()
        if data == b"hold":
            (self.root / "entered-A").write_text("ready")
            deadline = time.monotonic() + 20
            while not (self.root / "release-A").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("receiver worker barrier timeout")
                time.sleep(0.01)
        if data == b"kill":
            os._exit(17)
        if data == b"bottom":
            return BOTTOM
        if data == b"raise":
            raise ValueError("injected post-sampling exception")
        if data == b"interrupt":
            raise KeyboardInterrupt("injected interruption")
        return bytes.fromhex(cache[address])

    def rkgen(self, master, identity):
        with (self.root / "reissues.log").open("a", encoding="utf-8") as log:
            log.write("fresh receiver\n")
        return ReceiverKey(TestLeaf(identity))


def install_driver(root):
    """Only used in these tests/subprocesses; never select as a CLI preset."""
    protocol = TestProtocol(root)
    cli._make_runtime = lambda *args, **kwargs: (protocol, dict(hpk=TestPublic,
                                                               ipk=TestPublic, sk1=TestLeaf))
    cli._load_msk = lambda *args, **kwargs: (
        SimpleNamespace(hmsk=SimpleNamespace(public_key=TestPublic()),
                        to_bytes=lambda: b"unchanged-test-master"),
        protocol, dict(sk1=TestLeaf))
    return protocol


def arguments(root, *, sender="Alice", label="one"):
    path = root / (label + ".ct")
    if not path.exists():
        path.write_bytes(b"success")
    return SimpleNamespace(state=root / "state", receiver="Bob", sender=sender,
                           mock=False, legacy_baseline=False, in_path=path,
                           out=root / (label + ".plain"))


@pytest.fixture
def state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    # Match the existing fixed profile without invoking cryptographic setup.
    meta = dict(version=1, backend="abb10-hybrid+luo-module", params_preset="luo-module-research",
                identity_bytes=64, max_message_bytes=65536, max_application_bytes=3924,
                inner_hibe_payload_bytes=32, inner_hibe_identity_bytes=86, security_claim="none",
                backend_admitted=False, persistent_identity_cache=True,
                default_ciphertext_protocol="byteauth-v1", hibe_params_name="hybrid-hibe-research-v1",
                ibs_params_name="luo2024-module-ref1", signature_format="reference")
    (state / "state.json").write_text(json.dumps(meta))
    (state / "mpk.bin").write_bytes(PublicKey(TestPublic(), TestPublic(b"ibs-fixture")).to_bytes())
    (state / "msk.bin").write_bytes(b"unchanged-test-master")
    cli._receiver_key_path(state, b"Bob").write_bytes(ReceiverKey(TestLeaf()).to_bytes())
    # monkeypatch owns restoration even though install_driver is shared with
    # fresh child processes that have no pytest monkeypatch fixture.
    monkeypatch.setattr(cli, "_make_runtime", cli._make_runtime)
    monkeypatch.setattr(cli, "_load_msk", cli._load_msk)
    install_driver(tmp_path)
    return tmp_path


def restored(root):
    return ReceiverKey.from_bytes(cli._receiver_key_path(root / "state", b"Bob").read_bytes(), TestLeaf)


def draws(root):
    path = root / "draws.log"
    return path.read_text().splitlines() if path.exists() else []


WORKER = r"""
import importlib.util, pathlib, sys
spec=importlib.util.spec_from_file_location('receiver_driver',sys.argv[1])
driver=importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
root=pathlib.Path(sys.argv[2])
driver.install_driver(root)
args=driver.arguments(root,sender=sys.argv[3],label=sys.argv[4])
(root/('started-'+sys.argv[4])).write_text('ready')
sys.exit(driver.cli.cmd_decrypt(args))
"""


def worker(root, sender, label):
    source = Path(__file__).resolve().parents[1] / "src"
    return subprocess.Popen([sys.executable, "-B", "-c", WORKER, str(Path(__file__).resolve()),
                             str(root), sender, label], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            env={**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"})


def finish(process, expected=0):
    output, error = process.communicate(timeout=25)
    assert process.returncode == expected, output + error


def wait_file(path, process):
    deadline = time.monotonic() + 10
    while not path.exists():
        if process.poll() is not None:
            output, error = process.communicate()
            pytest.fail("receiver worker exited early: " + output + error)
        if time.monotonic() >= deadline:
            pytest.fail("receiver worker readiness timeout")
        time.sleep(0.01)


def test_fresh_process_reuses_persisted_receiver_address(state):
    for label in ("first", "second"):
        finish(worker(state, "Alice", label))
    assert (state / "first.plain").read_bytes() == (state / "second.plain").read_bytes()
    assert draws(state) == ["Alice"]
    assert list(restored(state).level1_key.cache) == ["Alice"]


@pytest.mark.parametrize("mode", ["bottom", "raise", "interrupt", "sampling-failure"])
def test_bottom_exceptions_and_interruption_preserve_changed_state(state, mode):
    args = arguments(state)
    args.in_path.write_bytes(mode.encode())
    if mode == "bottom":
        assert cli.cmd_decrypt(args) == 1
    else:
        with pytest.raises(KeyboardInterrupt if mode == "interrupt" else ValueError):
            cli.cmd_decrypt(args)
    assert "Alice" in restored(state).level1_key.cache
    assert draws(state) == ["Alice"]
    assert not args.out.exists()
    args.in_path.write_bytes(b"success")
    if mode == "sampling-failure":
        with pytest.raises(IBMEError, match="blocked"):
            cli.cmd_decrypt(args)
    else:
        assert cli.cmd_decrypt(args) == 0
    assert draws(state) == ["Alice"]


def test_reissuance_reuses_receiver_and_keeps_fixed_addresses(state):
    assert cli.cmd_decrypt(arguments(state)) == 0
    before = cli._receiver_key_path(state / "state", b"Bob").read_bytes()
    assert cli.cmd_issue_receiver_key(SimpleNamespace(state=state / "state", name="Bob", mock=False)) == 0
    assert cli._receiver_key_path(state / "state", b"Bob").read_bytes() == before
    assert not (state / "reissues.log").exists()


@pytest.mark.parametrize("other", ["Alice", "Carol"])
def test_concurrent_decrypts_preserve_same_and_distinct_addresses(state, other):
    arguments(state, label="A").in_path.write_bytes(b"hold")
    processes = []
    try:
        first = worker(state, "Alice", "A")
        processes.append(first)
        wait_file(state / "entered-A", first)
        second = worker(state, other, "B")
        processes.append(second)
        wait_file(state / "started-B", second)
        time.sleep(0.3)
        blocked = second.poll() is None
        (state / "release-A").write_text("go")
        for process in processes:
            finish(process)
        assert blocked, "second process decrypted from a stale receiver snapshot"
        assert set(restored(state).level1_key.cache) == {"Alice", other}
        assert draws(state) == (["Alice"] if other == "Alice" else ["Alice", "Carol"])
        if other == "Alice":
            assert (state / "A.plain").read_bytes() == (state / "B.plain").read_bytes()
    finally:
        (state / "release-A").write_text("go")
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


@pytest.mark.parametrize("operation", ["decrypt", "issue"])
def test_hard_exit_blocks_retry_and_reissuance_without_resampling(state, operation):
    arguments(state, label="kill").in_path.write_bytes(b"kill")
    finish(worker(state, "Alice", "kill"), expected=17)
    with pytest.raises(IBMEError, match="pending"):
        if operation == "decrypt":
            cli.cmd_decrypt(arguments(state))
        else:
            cli.cmd_issue_receiver_key(SimpleNamespace(state=state / "state", name="Bob", mock=False))
    assert draws(state) == ["Alice"]
    assert not (state / "one.plain").exists()
    assert not (state / "reissues.log").exists()


@pytest.mark.parametrize("stdout", [False, True])
def test_failed_state_publication_releases_no_plaintext_and_blocks_retry(state, monkeypatch, capsys, stdout):
    args = arguments(state)
    if stdout:
        args.out = None
    key_path = cli._receiver_key_path(args.state, b"Bob")
    original = cli.os.replace
    def fail(source, destination):
        if Path(destination) == key_path:
            raise OSError("injected receiver publication failure")
        return original(source, destination)
    with monkeypatch.context() as patch:
        patch.setattr(cli.os, "replace", fail)
        with pytest.raises(OSError, match="publication"):
            cli.cmd_decrypt(args)
    assert args.out is None or not args.out.exists()
    assert not capsys.readouterr().out
    assert not list(args.state.glob(".ibme-state-*.tmp"))
    with pytest.raises(IBMEError, match="pending"):
        cli.cmd_decrypt(args)
    assert draws(state) == ["Alice"]


@pytest.mark.parametrize("failure", ["serialize", "marker-remove", "marker-fsync"])
def test_incomplete_finalization_keeps_receiver_blocked(state, monkeypatch, failure):
    args = arguments(state)
    key_path = cli._receiver_key_path(args.state, b"Bob")
    marker = Path(str(key_path) + ".pending")
    with monkeypatch.context() as patch:
        if failure == "serialize":
            def fail(*a):
                raise ValueError("injected serialization failure")
            patch.setattr(TestLeaf, "to_bytes", fail)
        elif failure == "marker-remove":
            original = Path.unlink
            def unlink(path, *a, **k):
                if path == marker:
                    raise OSError("injected marker removal failure")
                return original(path, *a, **k)
            patch.setattr(Path, "unlink", unlink)
        else:
            def fsync(*a):
                raise OSError("injected marker fsync failure")
            patch.setattr(cli.os, "fsync", fsync)
        with pytest.raises((ValueError, OSError)):
            cli.cmd_decrypt(args)
    assert marker.exists() and not args.out.exists()
    before = draws(state)
    with pytest.raises(IBMEError, match="pending"):
        cli.cmd_decrypt(args)
    assert draws(state) == before


@pytest.mark.parametrize("kind", ["identity", "public", "wire"])
def test_reissuance_rejects_inconsistent_existing_receiver(state, kind):
    key_path = cli._receiver_key_path(state / "state", b"Bob")
    value = TestLeaf(identity=b"Carol" if kind == "identity" else b"Bob",
                     public=TestPublic(b"foreign-root") if kind == "public" else None)
    raw = b"broken" if kind == "wire" else ReceiverKey(value).to_bytes()
    key_path.write_bytes(raw)
    with pytest.raises((IBMEError, ValueError)):
        cli.cmd_issue_receiver_key(SimpleNamespace(state=state / "state", name="Bob", mock=False))
    assert key_path.read_bytes() == raw
    assert not (state / "reissues.log").exists()


@pytest.mark.parametrize("name", ["msk.bin", "mpk.bin", "state.json", ".ibme-issue.lock", "receiver", "sender"])
def test_plaintext_output_cannot_overwrite_key_state(state, name):
    args = arguments(state)
    args.out = (cli._receiver_key_path(args.state, b"Bob") if name == "receiver" else
                cli._sender_key_path(args.state, b"Alice") if name == "sender" else args.state / name)
    before = {path.name: path.read_bytes() for path in args.state.glob("*.bin")}
    with pytest.raises(ValueError, match="state"):
        cli.cmd_decrypt(args)
    assert before == {path.name: path.read_bytes() for path in args.state.glob("*.bin")}
    assert not draws(state)


def test_ciphertext_output_also_cannot_overwrite_receiver_state(state):
    args = arguments(state)
    args.out = cli._receiver_key_path(args.state, b"Bob")
    original = args.out.read_bytes()
    with pytest.raises(ValueError, match="state"):
        cli.cmd_encrypt(args)
    assert args.out.read_bytes() == original and not draws(state)


def test_decrypt_rejects_receiver_from_another_public_context_before_sampling(state):
    key_path = cli._receiver_key_path(state / "state", b"Bob")
    key_path.write_bytes(ReceiverKey(TestLeaf(public=TestPublic(b"another-root"))).to_bytes())
    with pytest.raises(ValueError, match="context"):
        cli.cmd_decrypt(arguments(state))
    assert not draws(state) and not Path(str(key_path) + ".pending").exists()


@pytest.mark.parametrize("mode", ["success", "bottom", "sampling-failure"])
def test_delivered_sage_leaf_cache_survives_cli_restore_and_failed_sampling(state, monkeypatch, mode):
    pytest.importorskip("sage.all", reason="real CHKP cache needs prescribed WSL Sage")
    from hashlib import sha256
    from ibme.core.randomness import DeterministicRandom
    from experiments.research.chkp_basis import ModMatrixReference, complete_kernel_basis
    from experiments.research.chkp_gpv import CHKPGPVSampler
    from experiments.research.chkp_leaf_cache import FixedLeafCache, CacheBlockedError
    from experiments.research.chkp_leaf_cache_types import CacheScope, LeafPlan
    from experiments.research.gaussian_reference import SamplingAbort

    sampler = CHKPGPVSampler(complete_kernel_basis(ModMatrixReference([[1, 0]], 2)),
                            512, epsilon_bits=16)
    scope = CacheScope(b"public-receiver-fixture", b"Bob", 2, 2)
    plan = LeafPlan.from_sampler(sampler, [(0,), (1,)])
    calls = []
    original_sample = sampler.sample
    def sample(target, *, rng=None):
        calls.append(target)
        if mode == "sampling-failure" and len(calls) == 2:
            raise SamplingAbort("injected second Gaussian vector failure")
        return original_sample(target, rng=rng)
    monkeypatch.setattr(sampler, "sample", sample)

    class CacheLeaf(TestLeaf):
        def to_bytes(self):
            return b"SAGE-CACHE-TEST/1" + encode_bytes(self.identity) + encode_bytes(self.cache.to_bytes())

        @classmethod
        def from_bytes(cls, raw):
            assert raw.startswith(b"SAGE-CACHE-TEST/1")
            identity, offset = decode_bytes(raw, len(b"SAGE-CACHE-TEST/1"))
            blob, offset = decode_bytes(raw, offset)
            assert offset == len(raw) and identity == b"Bob"
            return cls(identity, FixedLeafCache.from_bytes(blob, expected_scope=scope))

    class CacheProtocol(TestProtocol):
        def decrypt(self, public, receiver, sender, data):
            try:
                batch = receiver.level1_key.cache.resolve(
                    sender, plan, sampler=sampler, rng=DeterministicRandom(b"cli-cache-public-test"))
            except CacheBlockedError as exc:
                raise IBMEError("real research cache address blocked") from exc
            if data == b"bottom":
                return BOTTOM
            # A public test digest, not an actual CHKP/HIBE decapsulation.
            return sha256(repr(batch.preimages).encode()).digest()

    protocol = CacheProtocol(state)
    monkeypatch.setattr(cli, "_make_runtime", lambda *a, **k: (
        protocol, dict(hpk=TestPublic, ipk=TestPublic, sk1=CacheLeaf)))
    key_path = cli._receiver_key_path(state / "state", b"Bob")
    key_path.write_bytes(ReceiverKey(CacheLeaf(cache=FixedLeafCache(scope))).to_bytes())
    args = arguments(state)
    args.in_path.write_bytes(mode.encode())
    if mode == "sampling-failure":
        with pytest.raises(SamplingAbort):
            cli.cmd_decrypt(args)
    else:
        assert cli.cmd_decrypt(args) == (1 if mode == "bottom" else 0)
    restored_leaf = ReceiverKey.from_bytes(key_path.read_bytes(), CacheLeaf).level1_key
    if mode == "sampling-failure":
        with pytest.raises(CacheBlockedError):
            restored_leaf.cache.lookup(b"Alice", plan)
    else:
        assert len(restored_leaf.cache.lookup(b"Alice", plan).preimages) == 2
    assert len(calls) == 2
    args.in_path.write_bytes(b"success")
    if mode == "sampling-failure":
        with pytest.raises(IBMEError, match="blocked"):
            cli.cmd_decrypt(args)
    else:
        assert cli.cmd_decrypt(args) == 0
    assert len(calls) == 2  # restore did not re-enter actual Gaussian sampling


def test_real_research_receiver_reissuance_uses_validated_existing_key(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    from ibme.core.randomness import DeterministicRandom
    from ibme.protocol.luo_hybrid import make_research_runtime, RESEARCH_HIBE_PARAMS, RESEARCH_IBS_PARAMS

    protocol, readers = make_research_runtime(ibs_rng=DeterministicRandom(b"real-fixed-receiver-ibs"))
    public, master = protocol.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS,
                                   rng=DeterministicRandom(b"real-fixed-receiver-hibe"))
    receiver = protocol.rkgen(master, b"Bob", rng=DeterministicRandom(b"real-fixed-receiver-rk"))
    state = tmp_path / "state"
    state.mkdir()
    (state / "mpk.bin").write_bytes(public.to_bytes())
    (state / "msk.bin").write_bytes(master.to_bytes())
    cli._write_state_meta(state, mock=False, preset="luo-module-research",
                          hibe_params=RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS)
    key_path = cli._receiver_key_path(state, b"Bob")
    key_path.write_bytes(receiver.to_bytes())
    before = key_path.read_bytes()
    master_before = (state / "msk.bin").read_bytes()
    def no_new_receiver(*a, **k):
        pytest.fail("existing real receiver was delegated again")
    monkeypatch.setattr(protocol, "rkgen", no_new_receiver)
    monkeypatch.setattr(cli, "_make_runtime", lambda *a, **k: (protocol, readers))
    assert cli.cmd_issue_receiver_key(SimpleNamespace(state=state, name="Bob", mock=False)) == 0
    assert key_path.read_bytes() == before
    assert (state / "msk.bin").read_bytes() == master_before
    assert ReceiverKey.from_bytes(before, readers["sk1"]).identity == b"Bob"
