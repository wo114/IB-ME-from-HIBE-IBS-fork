"""Same-Suite, installed-wheel optimization ablations of full IB-ME APIs.

Private keys stay in exclusive durable directories and are backed up before
long operations. There is no root retry. C is a single-root state amortization
study, separate from the three-root A/B/Luo/Falcon timing experiments.
"""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
from unittest.mock import patch


def expected_suite(label):
    from ibme.assembly import make_suite
    choices = dict(A=("cert-ml-dsa", "ml-dsa-44", "reference", 65536),
                   B=("srgg2025-paper", "PARAM-I", "compact", 131072),
                   C=("sageloli-rsis", "PARAM-I", "reference", 8388608),
                   Luo=("luo-module", "research", "compact", 65536),
                   Falcon=("cert-falcon", "falcon-padded-512", "reference", 65536))
    if label not in choices:
        raise ValueError("unknown experiment label")
    ibs, ip, fmt, budget = choices[label]
    return make_suite(hibe="lai-ideal-hibe" if label == "C" else "latte",
        hibe_params="target-research" if label == "C" else "seed32",
        ibs=ibs, ibs_params=ip, transport="hybrid", signature_format=fmt,
        hybrid_limits=dict(backend_id="lai-a-256-v1" if label == "C" else "latte3-cosac-fix-v1",
                           identity_max_bytes=64, max_payload_bytes=budget, max_capsule_bytes=4194304))


def validate_inputs(label, config, *, roots, repetitions):
    if config.to_dict() != expected_suite(label).to_dict():
        raise ValueError("experiment differs from its frozen Suite")
    if type(roots) is not int or roots != (1 if label == "C" else 3):
        raise ValueError("C requires one root; other experiments require three independent roots")
    if type(repetitions) is not int or not 3 <= repetitions <= 9:
        raise ValueError("use 3..9 within-root repetitions")


def assert_installed_providers(providers, root):
    root = Path(root).resolve()
    if not providers:
        raise ValueError("no installed providers observed")
    for item in providers.values():
        path = Path(item["path"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("provider is outside installed runtime")


def public_failure(stage, exc):
    return dict(status="failed", failure_stage=stage, exception_type=type(exc).__name__, no_outer_retry=True)


def failed_batch(label, records, failure):
    return dict(label=label, records=records, **{name:failure[name] for name in
                ("status", "failure_stage", "exception_type", "no_outer_retry")})


def summarize_pairs(records):
    result = {}
    for record in records:
        groups = {}
        for row in record["phases"]:
            if row["name"] not in ("encrypt", "decrypt"):
                continue
            if row["status"] != "passed":
                raise ValueError("failed timing cannot enter successful summary")
            groups.setdefault(row["name"], {}).setdefault(row["mode"], []).append(row["seconds"])
        for name, modes in groups.items():
            if set(modes) != {"off", "on"} or len(modes["off"]) != len(modes["on"]):
                raise ValueError("incomplete same-root ablation")
            off, on = (statistics.median(modes[mode]) for mode in ("off", "on"))
            row = result.setdefault(name, dict(root_off_medians=[], root_on_medians=[], root_speedups=[]))
            row["root_off_medians"].append(off)
            row["root_on_medians"].append(on)
            row["root_speedups"].append(off/on)
    for row in result.values():
        row.update(independent_roots=len(row["root_speedups"]),
                   median_root_speedup=statistics.median(row["root_speedups"]))
    return result


def _write(path, value):
    raw = value if type(value) is bytes else (json.dumps(value, indent=2, sort_keys=True)+"\n").encode()
    with Path(path).open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _deadline(seconds):
    def expired(*_args):
        raise TimeoutError("operation budget exhausted; preserve occupied state")
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _configure(backend, label, enabled):
    if label in ("A", "Falcon"):
        backend.configure_certificate_cache(64 if enabled else 0)
    elif label == "B":
        backend.configure_sign_plan_cache(2 if enabled else 0)
    elif label == "Luo":
        backend.configure_ntt_preparation(enabled)


def _backup(directory, destination, name):
    backup = directory/(name+".private.tar")
    with tarfile.open(backup, "x") as archive:
        for path in sorted(directory.glob("*.bin")):
            archive.add(path, arcname=path.name, recursive=False)
    os.chmod(backup, 0o600)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination/(directory.parent.name+"-"+directory.name+"-"+backup.name)
    if target.exists():
        raise FileExistsError("private backup target already occupied")
    shutil.copyfile(backup, target)
    os.chmod(target, 0o600)
    if target.stat().st_size != backup.stat().st_size:
        raise OSError("private backup size mismatch")


def worker(directory):
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.core.encoding import encode_bytes
    from ibme.core.randomness import SecureRandom
    from ibme.core.lamport_ots import generate_lamport_key
    from ibme.protocol.baseline import BOTTOM, Ciphertext, encode_message, encode_signature
    from ibme.protocol.byteauth import authenticate_inner, encode_bound_message
    from ibme.protocol.prepared import prepare_receiver
    from .runtime_metrics import measured_phase, environment
    from .full_system_benchmark import source_providers

    args = json.loads((directory/"inputs.json").read_bytes())
    label = args["label"]
    config = SuiteConfig.from_json((directory/"suite.json").read_bytes())
    validate_inputs(label, config, roots=args["roots"], repetitions=args["repetitions"])
    manifest = json.loads(Path(args["manifest"]).read_bytes())
    installed = Path(args["installed_root"]).resolve()
    if manifest["source_commit"] != args["source_commit"]:
        raise ValueError("source commit manifest mismatch")
    for relative, digest in manifest["files"].items():
        path = installed/relative
        if not path.resolve().is_relative_to(installed) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("installed source manifest mismatch")
    assert_installed_providers(source_providers(), installed)
    report = dict(schema="IBME-BACKEND-OPTIMIZATION/1", root=args["root"], label=label,
                  suite=config.to_dict(), suite_digest=config.digest, source_commit=args["source_commit"],
                  wheel_sha256=manifest["wheel_sha256"], phases=[], environment=environment(),
                  identity_bytes=64, message_bytes=32, security_claim="none", backend_admitted=False,
                  parameters_are_formal=False, no_outer_retry=True, randomness="fresh system CSPRNG",
                  scope="full Suite protocol, validation, Hybrid, BYTEAUTH, IBS, wire encode/decode",
                  status="started")
    entropy, calls = dict(bytes=0, reads=0), {}
    stage = "build-runtime"
    original_read = SecureRandom.read

    def counted(source, count):
        entropy["bytes"] += count
        entropy["reads"] += 1
        return original_read(source, count)

    def guard(family, method):
        def observed(self, operation, *a, **kw):
            name = family+":"+operation
            calls[name] = calls.get(name, 0)+1
            return method(self, operation, *a, **kw)
        return observed

    def phase(name, mode, operation):
        nonlocal stage
        stage = name+":"+mode
        before_entropy, before_calls = dict(entropy), dict(calls)
        print(json.dumps(dict(root=args["root"], label=label, stage=stage)), flush=True)
        with measured_phase(name, report["phases"]) as row, _deadline(args["operation_timeout"]):
            row["mode"] = mode
            result = operation()
        row["entropy"] = {k:entropy[k]-before_entropy[k] for k in entropy}
        row["native_calls"] = {k:v-before_calls.get(k, 0) for k,v in calls.items() if v != before_calls.get(k, 0)}
        return result

    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(SecureRandom, "read", counted))
            from ibme.hibe.latte.engine import Native
            from ibme.ibs.certified.mldsa import MLDSA
            from ibme.ibs.certified.falcon import Falcon
            for cls, method, family in ((Native, "call", "latte"), (MLDSA, "_run", "mldsa"), (Falcon, "_run", "falcon")):
                stack.enter_context(patch.object(cls, method, guard(family, getattr(cls, method))))
            runtime = build_runtime(config)
            proto = runtime.proto
            sender_id, receiver_id, message = b"A"*64, b"B"*64, bytes(range(32))
            _write(directory/"generation.pending", b"single attempt; do not replace or retry\n")
            public, master = phase("setup", "shared", lambda: proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params))
            _write(directory/"public.bin", public.to_bytes())
            _write(directory/"master-initial.bin", master.to_bytes())
            sender = phase("sender-key", "shared", lambda: proto.skgen(master, sender_id))
            _write(directory/"sender.bin", sender.to_bytes())
            receiver = phase("receiver-key", "shared", lambda: proto.rkgen(master, receiver_id))
            _write(directory/"receiver.bin", receiver.to_bytes())
            _write(directory/"master-issued.bin", master.to_bytes())
            _backup(directory, Path(args["backup_directory"]), "issued")
            derive = runtime.hibe.derive

            def observed_derive(*a, **kw):
                calls["hibe:derive"] = calls.get("hibe:derive", 0)+1
                return derive(*a, **kw)

            stack.enter_context(patch.object(runtime.hibe, "derive", observed_derive))
            checks = {}
            if label == "C":
                wire = phase("encrypt", "shared", lambda: proto.encrypt(public, sender, receiver_id, message).to_bytes())
                _write(directory/"ciphertext.bin", wire)
                _backup(directory, Path(args["backup_directory"]), "encrypted")
                for _ in range(2):
                    result = phase("original-stateless-decrypt", "off", lambda: proto.decrypt(public, receiver, sender_id, wire))
                    if result != message:
                        raise AssertionError("original C decrypt mismatch")
                session = phase("receiver-preparation", "on", lambda: prepare_receiver(proto, public, receiver, sender_id))
                stack.callback(session.close)
                for _ in range(args["repetitions"]):
                    if phase("prepared-decrypt", "on", lambda: session.decrypt(wire)) != message:
                        raise AssertionError("prepared C decrypt mismatch")
                decrypt = session.decrypt
                report["prepared_session"] = session.info()
            else:
                # Both runtimes use identical original objects. LATTE's existing
                # persistent leaf is prepared before the paired warm comparison.
                off, on = build_runtime(config), build_runtime(config)
                _configure(off.ibs, label, False)
                _configure(on.ibs, label, True)
                if label == "B":
                    phase("signing-preparation", "on", lambda: on.ibs.prepare_signing(sender.signing_key))
                for mode, rt in (("off", off), ("on", on)):
                    warm = phase("prime-encrypt", mode, lambda rt=rt: rt.proto.encrypt(public, sender, receiver_id, message).to_bytes())
                    if phase("prime-decrypt", mode, lambda rt=rt: rt.proto.decrypt(public, receiver, sender_id, warm)) != message:
                        raise AssertionError("priming decrypt mismatch")
                wires = []
                for index in range(args["repetitions"]):
                    order = (("off", off), ("on", on)) if (index+args["root"]) % 2 == 0 else (("on", on), ("off", off))
                    for mode, rt in order:
                        wire = phase("encrypt", mode, lambda rt=rt: rt.proto.encrypt(public, sender, receiver_id, message).to_bytes())
                        report["phases"][-1]["ciphertext_bytes"] = len(wire)
                        if phase("decrypt", mode, lambda rt=rt: rt.proto.decrypt(public, receiver, sender_id, wire)) != message:
                            raise AssertionError("paired decrypt mismatch")
                        wires.append(len(wire))
                _write(directory/"ciphertext.bin", wire)
                _write(directory/"receiver-prepared.bin", receiver.to_bytes())
                _backup(directory, Path(args["backup_directory"]), "encrypted")
                report["ciphertext_bytes"] = wires
                decrypt = lambda raw: on.proto.decrypt(public, receiver, sender_id, raw)
                proto = on.proto
                if label in ("A", "Falcon"):
                    report["cache"] = on.ibs.certificate_cache_info()
                elif label == "B":
                    report["cache"] = on.ibs.sign_plan_cache_info()
            # Strict wire/byte/identity rejection runs outside timed observations.
            for name, bad in (("truncated", wire[:-1]), ("appended", wire+b"!"), ("duplicated", wire+wire),
                              ("byte-change", wire[:-1]+bytes([wire[-1]^1]))):
                checks[name] = phase("negative-"+name, "validation", lambda bad=bad: decrypt(bad)) is BOTTOM
            # New outer OTS remains valid; altered envelope retains an honest IBS
            # signature on a different message. Verify must be reached and fail.
            ots = generate_lamport_key()
            original = encode_bound_message(ots.public_key.commitment(), b"original")
            changed = encode_bound_message(ots.public_key.commitment(), b"modified")
            signature = proto.ibs_backend.sign(sender.signing_key, encode_message(receiver_id, original))
            inner = Ciphertext(proto.hibe_backend.encrypt(public.hpk, receiver_id, sender_id,
                              encode_signature(signature)+encode_bytes(changed)))
            invalid = authenticate_inner(public, inner.to_bytes(), ots)
            outcomes, verify = [], proto.ibs_backend.verify

            def observed_verify(*a, **kw):
                accepted = verify(*a, **kw)
                outcomes.append(accepted)
                return accepted

            with patch.object(proto.ibs_backend, "verify", observed_verify):
                checks["valid-outer-invalid-inner"] = phase("negative-inner-ibs", "validation", lambda: decrypt(invalid.to_bytes())) is BOTTOM
            checks["ibs-reached-and-false"] = outcomes == [False]
            for name, rcv, snd in (("wrong-receiver", b"D"*64, sender_id),
                                    ("wrong-sender", receiver_id, b"E"*64),
                                    ("both-wrong", b"D"*64, b"E"*64)):
                # Actual wrong-address HIBE encryption, same opaque prepared key;
                # no extra roots, sender extraction or slow delegation required.
                bad_inner = Ciphertext(proto.hibe_backend.encrypt(public.hpk, rcv, snd, b"invalid"))
                bad = authenticate_inner(public, bad_inner.to_bytes(), generate_lamport_key())
                checks[name] = phase("negative-"+name, "validation", lambda: decrypt(bad.to_bytes())) is BOTTOM
            if not all(checks.values()):
                raise AssertionError("a required full-protocol rejection failed")
            providers = source_providers()
            assert_installed_providers(providers, installed)
            report.update(status="passed", checks=checks, providers=providers,
                          native_calls=calls, entropy=entropy,
                          serialized_private_sizes={p.name:p.stat().st_size for p in directory.glob("*.bin")})
            os.replace(directory/"generation.pending", directory/"generation.done")
    except BaseException as exc:
        report.update(public_failure(stage, exc))
        _write(directory/"failure.json", report)
        raise
    _write(directory/"receipt.json", report)
    return report


def run(args):
    from ibme.assembly import SuiteConfig
    config = SuiteConfig.from_json(args.suite_file.read_bytes())
    roots = 1 if args.label == "C" else 3
    validate_inputs(args.label, config, roots=roots, repetitions=args.repetitions)
    if not args.private_directory.resolve().is_relative_to(Path.home().resolve()):
        raise ValueError("private experiment directory must be in durable user home")
    if not 60 <= args.operation_timeout <= 1800:
        raise ValueError("operation timeout must be 60..1800 seconds")
    args.private_directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    records = []
    for index in range(roots):
        directory = args.private_directory/f"root-{index}"
        directory.mkdir(mode=0o700)
        _write(directory/"suite.json", config.to_json().encode("ascii"))
        _write(directory/"inputs.json", dict(label=args.label, root=index, roots=roots,
            repetitions=args.repetitions, source_commit=args.source_commit,
            installed_root=str(args.installed_root.resolve()), manifest=str(args.manifest.resolve()),
            operation_timeout=args.operation_timeout, backup_directory=str(args.backup_directory.resolve())))
        command = [sys.executable, "-m", __spec__.name, "--worker-directory", str(directory)]
        # Stages, errors and native output remain private. The caller can inspect
        # this durable log while a slow C derivation runs.
        with (directory/"worker.private.log").open("xb") as log:
            os.chmod(log.name, 0o600)
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        if process.returncode:
            failure = json.loads((directory/"failure.json").read_bytes()) if (directory/"failure.json").exists() else public_failure("worker", RuntimeError())
            _write(args.public_output, failed_batch(args.label, records, failure))
            raise RuntimeError("optimization worker failed; original occupied state retained")
        records.append(json.loads((directory/"receipt.json").read_bytes()))
        print(json.dumps(dict(label=args.label, completed_root=index, status="passed")), flush=True)
    result = dict(schema="IBME-BACKEND-OPTIMIZATION-BATCH/1", status="passed", label=args.label,
                  independent_roots=roots, repetitions_per_root=args.repetitions, records=records,
                  comparison="single-root explicit receiver-state amortization" if args.label == "C" else "interleaved paired same-root warm full-protocol ablation",
                  security_claim="none", backend_admitted=False, parameters_are_formal=False,
                  cross_security_group_ranking=False, summary={} if args.label == "C" else summarize_pairs(records))
    _write(args.public_output, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-directory", type=Path)
    parser.add_argument("--private-directory", type=Path)
    parser.add_argument("--backup-directory", type=Path)
    parser.add_argument("--public-output", type=Path)
    parser.add_argument("--suite-file", type=Path)
    parser.add_argument("--label", choices=("A", "B", "C", "Luo", "Falcon"))
    parser.add_argument("--installed-root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--operation-timeout", type=int, default=1200)
    args = parser.parse_args()
    if args.worker_directory:
        worker(args.worker_directory)
    else:
        for name in ("private_directory", "backup_directory", "public_output", "suite_file", "label", "installed_root", "manifest", "source_commit"):
            if getattr(args, name) is None:
                parser.error("missing --"+name.replace("_", "-"))
        run(args)


if __name__ == "__main__":
    main()
