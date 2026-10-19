"""Real CLI, same-root acceptance and isolated recovery for RSIS v3 + LATTE.

Only allowlisted outcomes, sizes, timings, source hashes and environment are
published. Secret state and captured command diagnostics stay in a new private
directory. A failure preserves that directory; the harness never retries Setup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ALICE, BOB, CAROL, EVE = (c*64 for c in "ABCE")
CHILD = r'''
import contextlib, hashlib, io, json, resource, sys, time
from pathlib import Path
from ibme.core.randomness import SecureRandom
from ibme.hibe.latte.engine import Native
from experiments.research.candidates.sageloli.ring.backend import RingBackend
forbid = sys.argv[1] == 'zero'
reads = entropy = 0
calls = {}
original = SecureRandom.read
def counted(self, count):
    global reads, entropy
    reads += 1; entropy += count
    if forbid: raise AssertionError('recovery attempted entropy')
    return original(self, count)
SecureRandom.read = counted
def ring_guard(name, function):
    def call(self, *args, **kwargs):
        label = 'ring:' + name; calls[label] = calls.get(label, 0) + 1
        if forbid and name in ('setup', 'key_extract', 'sign'):
            raise AssertionError('recovery attempted generation/signing')
        return function(self, *args, **kwargs)
    return call
for name in ('setup','key_extract','sign','verify','load_master','load_signing_key'):
    setattr(RingBackend, name, ring_guard(name, getattr(RingBackend, name)))
native_call = Native.call
def native_guard(self, operation, *args, **kwargs):
    label = 'latte:' + operation; calls[label] = calls.get(label, 0) + 1
    if forbid and operation not in ('meta','decrypt'):
        raise AssertionError('recovery attempted native generation')
    return native_call(self, operation, *args, **kwargs)
Native.call = native_guard
from ibme.cli import main
out = io.StringIO(); err = io.StringIO(); started = time.perf_counter(); exception = None
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    try: code = main(sys.argv[2:])
    except BaseException as exc: code = 99; exception = type(exc).__name__
providers = {}
for name, module in list(sys.modules.items()):
    path = getattr(module, '__file__', None)
    if name.startswith(('ibme.', 'experiments.research.')) and path and path.endswith('.py'):
        providers[name] = dict(path=str(Path(path).resolve()), sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
print(json.dumps(dict(code=code, exception=exception, seconds=time.perf_counter()-started,
    entropy_reads=reads, entropy_bytes=entropy, calls=calls, providers=providers,
    peak_process_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
    stdout=out.getvalue(), stderr=err.getvalue())))
'''


def require(condition, label):
    if not condition: raise AssertionError(label)


def snapshot(state):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in state.iterdir() if p.is_file() and p.suffix in (".bin", ".json")}


def command(directory, label, args, *, zero=False, expected=0):
    process = subprocess.run([sys.executable, "-c", CHILD, "zero" if zero else "system", *map(str, args)],
                             capture_output=True, text=True, timeout=300, check=False)
    require(process.returncode == 0, label+": child interpreter failed")
    row = json.loads(process.stdout)
    (directory/(label+".private-log.json")).write_text(json.dumps(row, indent=2), encoding="utf-8")
    require(row["code"] == expected, label+": unexpected exit code "+str(row["code"]))
    row.pop("stdout"); row.pop("stderr"); row.update(name=label, expected_code=expected)
    return row


def replay(directory):
    state = directory/"state"; before = snapshot(state)
    out = directory/"restored.bin"
    row = command(directory, "zero-entropy-restore", ["decrypt", "--state", state,
        "--sender", ALICE, "--receiver", BOB, "--in", directory/"cipher.bin", "--out", out], zero=True)
    require(out.read_bytes() == (directory/"message.bin").read_bytes(), "restored plaintext")
    require(snapshot(state) == before and row["entropy_reads"] == row["entropy_bytes"] == 0, "unchanged zero-entropy recovery")
    require(not list(state.glob("*.pending")), "unexpected pending state")
    return dict(status="passed", original_state_unchanged=True, command=row)


def acceptance(directory, source_commit):
    from ibme.assembly import SuiteConfig
    from ibme.cli import _read_state_object
    from ibme.protocol.baseline import PublicKey, MasterSecret
    from experiments.run_combination_matrix import run_case
    state = directory/"state"; meta = json.loads((state/"state.json").read_bytes())
    suite = SuiteConfig.from_dict(meta["suite"])
    selection = {key: value for key, value in suite.to_dict().items() if key in
        ("hibe", "ibs", "hibe_params", "ibs_params", "transport", "protocol", "signature_format", "hybrid_limits")}
    def original_root(runtime, unused_test_rng):
        require(runtime.config.digest == suite.digest, "same CLI suite")
        readers = runtime.decoders
        public = PublicKey.from_bytes(_read_state_object(state/"mpk.bin", meta, "mpk"), readers["hpk"], readers["ipk"])
        master = MasterSecret.from_bytes(_read_state_object(state/"msk.bin", meta, "msk"), readers["hmsk"], readers["imsk"])
        runtime.validate_master(public, master)
        return public, master, dict(origin="original CLI CSPRNG root and issued key", source_commit=source_commit,
                                    original_state_unchanged=True, suite_digest=suite.digest)
    before = snapshot(state)
    result = run_case("latte-sageloli-ring-v3-paper", selection, setup_callback=original_root,
                      identities=tuple(x.encode() for x in (ALICE, BOB, CAROL, EVE)))
    require(snapshot(state) == before, "acceptance changed original CLI state")
    (directory/"acceptance.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    require(result["status"] == "pass" and result["executed_checks"] >= 32, "complete combination acceptance")
    return result


def generate(directory, source_commit, profile):
    directory.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter(); stage = "setup"; records = []
    state = directory/"state"
    try:
        from ibme.assembly import default_registry
        from ibme.ibs.sageloli import ring_registration as reg
        from experiments.research.full_system_benchmark import environment
        hibe_version = default_registry().get("hibe", "latte").version
        limits = dict(backend_id=hibe_version, identity_max_bytes=64,
                      max_payload_bytes=8*2**20, max_capsule_bytes=4*2**20)
        (directory/"limits.json").write_text(json.dumps(limits), encoding="utf-8")
        message = hashlib.sha256(b"Sageloli ring v3 full system acceptance").digest()
        (directory/"message.bin").write_bytes(message)
        def run(name, args, expected=0):
            nonlocal stage
            stage = name; row = command(directory, name, args, expected=expected); records.append(row)
        run("setup", ["setup", "--state", state, "--hibe", "latte", "--hibe-params", "seed32",
            "--ibs", "sageloli-rsis", "--ibs-params", profile, "--transport", "hybrid",
            "--hybrid-limits", directory/"limits.json"])
        run("sender", ["issue-sender-key", ALICE, "--state", state])
        for name, identity in (("receiver", BOB), ("other-receiver", CAROL)):
            run(name, ["issue-receiver-key", identity, "--state", state])
        before = snapshot(state)
        run("same-sender", ["issue-sender-key", ALICE, "--state", state])
        run("same-receiver", ["issue-receiver-key", BOB, "--state", state])
        require(snapshot(state) == before, "fixed reissuance changed state")
        require(all(row["entropy_bytes"] == 0 for row in records[-2:]), "cached keys consumed entropy")
        run("encrypt", ["encrypt", "--state", state, "--sender", ALICE, "--receiver", BOB,
            "--in", directory/"message.bin", "--out", directory/"cipher.bin"])
        run("decrypt", ["decrypt", "--state", state, "--sender", ALICE, "--receiver", BOB,
            "--in", directory/"cipher.bin", "--out", directory/"recovered.bin"])
        require((directory/"recovered.bin").read_bytes() == message, "CLI roundtrip")
        for name, sender, receiver in (("wrong-sender", EVE, BOB), ("wrong-receiver", ALICE, CAROL), ("both-wrong", EVE, CAROL)):
            output = directory/(name+".bin")
            run(name, ["decrypt", "--state", state, "--sender", sender, "--receiver", receiver,
                "--in", directory/"cipher.bin", "--out", output], expected=1)
            require(not output.exists(), name+" published plaintext")
        wire = (directory/"cipher.bin").read_bytes()
        for name, raw in (("truncated", wire[:-1]), ("appended", wire+b"!"),
                          ("duplicate", wire+wire), ("changed", wire[:-1]+bytes([wire[-1]^1]))):
            path = directory/(name+".input"); path.write_bytes(raw); output = directory/(name+".output")
            run(name, ["decrypt", "--state", state, "--sender", ALICE, "--receiver", BOB,
                "--in", path, "--out", output], expected=1)
            require(not output.exists(), name+" published plaintext")
        stage = "zero-entropy-restore"; restored = replay(directory)
        stage = "same-root-acceptance"; accepted = acceptance(directory, source_commit)
        providers = {}
        for row in records+[restored["command"]]:
            for name, value in row.pop("providers").items():
                require(name not in providers or providers[name] == value, "CLI provider changed")
                providers[name] = value
        meta = json.loads((state/"state.json").read_bytes())
        native = reg.factory(None, "reference").execution_metadata()
        receipt = dict(schema="SAGELOLI-RING-INTEGRATION/1", status="passed", source_commit=source_commit,
            profile=profile, parameters=meta["suite"], state_version=meta["version"],
            identity_bytes=64, message_bytes=32, repetitions=1, environment=environment(), native=native,
            commands=records, restore=restored, acceptance=accepted, providers=providers,
            ciphertext_bytes=len(wire), state_file_sizes={p.name:p.stat().st_size for p in state.glob("*.bin")},
            total_seconds=time.perf_counter()-started,
            randomness="CLI: default system CSPRNG, no outer retry; same-root acceptance: explicit fixed test streams",
            security_claim="none", backend_admitted=False, parameters_are_formal=False)
        (directory/"receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n", encoding="utf-8")
        return dict(status="passed", commands=len(records), acceptance_checks=accepted["executed_checks"],
                    zero_entropy_restore=True, seconds=receipt["total_seconds"])
    except BaseException as exc:
        (directory/"failure.json").write_text(json.dumps(dict(status="failed", stage=stage,
            exception=type(exc).__name__, no_outer_retry=True, private_outputs_preserved=True), indent=2)+"\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II"), default="PARAM-I")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--restore-only", action="store_true")
    args = parser.parse_args(); directory = args.private_directory.resolve()
    if args.restore_only:
        result = replay(directory)
        (directory/"installed-restore.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
        result = dict(status=result["status"], entropy_bytes=result["command"]["entropy_bytes"])
    else:
        result = generate(directory, args.source_commit, args.profile)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__": main()
