"""Staged real CHKP + Luo C64B / BYTEAUTH acceptance in the shared assembly.

Run: PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m experiments.research.chkp_combination preflight

Run ``preflight`` first; it neither reads private files nor samples anything.
Then, in WSL Sage, run prepare, receiver-Carol, leaf-Bob-Eve,
leaf-Carol-Alice, leaf-Carol-Eve, and checks against the same --directory.
The existing Bob/Alice lifetime is imported, never regenerated. Every phase
has a durable pending marker: a failure/crash is NOT permission to resample.
Ready phase receipts are returned unchanged. Private objects stay under the
repository's ignored test-results tree; published receipts contain no keys.

This is one research run, not a security admission: the n=2 CHKP profile has
a demonstrated public small-noise attack. No timing here is a benchmark.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from ibme.cli_state import StateBusyError, key_issuance_lock
from ibme.assembly import build_runtime, make_suite, validate_suite
from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import SecureRandom
from ibme.ibs.luo_module_profiles import c64b_params
from ibme.protocol.baseline import (
    BOTTOM, BaselineIBME, Ciphertext, DOMAIN_SIGNATURE, MasterSecret,
    PublicKey, ReceiverKey, SenderKey, parse_payload,
)
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message
from experiments.research.chkp_lifecycle import require_lifetime_ready, sync_directory


PHASES = ("preflight", "prepare", "receiver-Carol", "leaf-Bob-Eve",
          "leaf-Carol-Alice", "leaf-Carol-Eve", "checks")
BASE = Path(__file__).resolve().parents[2]


class CountedSystem:
    def __init__(self):
        self.source, self.bytes_used = SecureRandom(), 0

    def read(self, size):
        value = self.source.read(size)
        self.bytes_used += len(value)
        return value


class NoEntropy:
    def read(self, size):
        raise AssertionError("existing fixed address attempted new sampling")


def write(path, data):
    """Replace one private checkpoint durably; never print its contents."""
    temp = path.with_name(path.name + ".tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    if os.name == "posix":
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def selected_suite(signature_format="compact"):
    return make_suite(hibe="chkp", ibs="luo-module", transport="hybrid",
                      protocol="byteauth-v1", signature_format=signature_format,
                      ibs_params=c64b_params())


def preflight():
    rows = []
    for fmt, expected_signature in (("reference", 29455), ("compact", 16383)):
        config = selected_suite(fmt)
        report = validate_suite(config)
        exact_capacity = (report.capacity.get("max_application_bytes") == 3924
                          and report.capacity.get("signature_max_bytes") == expected_signature
                          and report.capacity.get("inner_hibe_payload_bytes") == 32
                          and report.capacity.get("inner_hibe_identity_bytes") == 86)
        rows.append(dict(signature_format=fmt, expected_capacity_pass=exact_capacity,
                         validation=report.to_dict(), suite_digest=config.digest))
    return dict(phase="preflight", passed=all(row["validation"]["ok"] and
                row["expected_capacity_pass"] for row in rows), variants=rows,
                sampled=False, security_claim="none", backend_admitted=False,
                parameters_are_formal=False)


def private_directory(value):
    path = Path(value).resolve()
    if path == BASE / "test-results" or not path.is_relative_to(BASE / "test-results"):
        raise ValueError("private files require their own directory below test-results")
    result = subprocess.run(["git", "check-ignore", "--quiet", "--",
                             str((path / "private.bin").relative_to(BASE))],
                            cwd=BASE, capture_output=True, check=False)
    if result.returncode != 0:
        raise ValueError("private output path is not ignored by Git")
    return path


def load_public(runtime, directory):
    return PublicKey.from_bytes((directory / "public.bin").read_bytes(),
                                runtime.decoders["hpk"], runtime.decoders["ipk"])


def load_master(runtime, directory):
    return MasterSecret.from_bytes((directory / "master.bin").read_bytes(),
                                   runtime.decoders["hmsk"], runtime.decoders["imsk"])


def load_receiver(runtime, directory, name):
    return ReceiverKey.from_bytes((directory / ("receiver-" + name + ".bin")).read_bytes(),
                                  runtime.decoders["sk1"])


def require(checks, label, condition):
    checks.append(dict(name=label, passed=bool(condition)))
    if not condition:
        raise AssertionError(label)


def ready_receipt(directory, phase, config):
    """A bare passed flag is not evidence that this phase executed checks."""
    try:
        receipt = json.loads((directory / (phase + '.json')).read_bytes())
    except (OSError, ValueError):
        raise ValueError('phase receipt is missing or invalid: ' + phase) from None
    validate_receipt(receipt, phase, config)
    return receipt


def validate_receipt(receipt, phase, config):
    if (not isinstance(receipt, dict) or receipt.get('phase') != phase
            or receipt.get('passed') is not True
            or receipt.get('suite_digest') != config.digest):
        raise ValueError('phase receipt does not match a successful current suite: ' + phase)
    rows, count = receipt.get('checks'), receipt.get('executed_checks')
    if (not isinstance(rows, list) or not rows or type(count) is not int or count != len(rows)
            or any(not isinstance(row, dict) or row.get('passed') is not True
                   or not isinstance(row.get('name'), str) or not row['name'] for row in rows)):
        raise ValueError('phase receipt lacks successful executed checks: ' + phase)
    names = {row['name'] for row in rows}
    if len(names) != len(rows):
        raise ValueError('phase receipt has duplicate checks: ' + phase)
    required = {'prepare': {'existing_Bob_Alice_leaf_reused', 'real_C64B_setup_and_sender'},
                'receiver-Carol': {'address_completed'},
                'checks': {'honest_roundtrip', 'wrong_sender', 'wrong_receiver', 'both_wrong',
                           'raw_low_coefficient_change_keeps_seed',
                           'hybrid_AAD_rejects_same_seed_capsule_change',
                           'full_BYTEAUTH_rejection_reaches_IBS',
                           'capacity_plus_one_rejects_before_entropy'}}.get(
                               phase, {'new_leaf_canonical_restore', 'address_completed'})
    if not required <= names:
        raise ValueError('phase receipt omits required checks: ' + phase)


def prepare(runtime, directory, lifetime, source, receipt):
    from ibme.hibe.chkp import (
        CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey, CHKPLevel2SecretKey,
    )
    from ibme.protocol.hybrid_hibe import (
        HybridPublicKey, HybridMasterSecret, HybridLevel1SecretKey,
    )
    native_public = CHKPPublicKey.from_bytes((lifetime / "public.bin").read_bytes())
    native_master = CHKPMasterSecret.from_bytes((lifetime / "master.bin").read_bytes())
    native_receiver = CHKPLevel1SecretKey.from_bytes((lifetime / "parent.bin").read_bytes())
    native_child = CHKPLevel2SecretKey.from_bytes((lifetime / "child.bin").read_bytes())
    native_backend = runtime.hibe.inner_backend
    if not all(native_backend.validate_key_binding(native_public, key)
               for key in (native_master, native_receiver, native_child)):
        raise AssertionError('source lifetime public/key binding mismatch')
    public_hibe = HybridPublicKey(runtime.hibe_params.limits, native_public)
    master_hibe = HybridMasterSecret(public_hibe, native_master)
    receiver = ReceiverKey(HybridLevel1SecretKey(public_hibe, native_receiver, (b"Bob",)))
    # The saved parent.bin is authoritative for Bob's newer leaf cache; do not
    # extract the stale parent cached in the older master checkpoint instead.
    child = runtime.hibe.derive(receiver.level1_key, b"Alice", rng=NoEntropy())
    require(receipt["checks"], "existing_Bob_Alice_leaf_reused",
            child.inner.to_bytes() == native_child.to_bytes())
    ipk, imsk = runtime.ibs.setup(runtime.ibs_params)
    public, master = PublicKey(public_hibe, ipk), MasterSecret(master_hibe, imsk)
    runtime.validate_master(public, master)
    runtime.validate_receiver(public, receiver)
    write(directory / "public.bin", public.to_bytes())
    write(directory / "receiver-Bob.bin", receiver.to_bytes())
    try:
        sender = runtime.proto.skgen(master, b"Alice")
        runtime.validate_sender(public, sender)
    finally:
        write(directory / "master.bin", master.to_bytes())
    write(directory / "sender-Alice.bin", sender.to_bytes())
    write(directory / "leaf-Bob-Alice.bin", child.to_bytes())
    receipt["sizes"] = dict(public=len(public.to_bytes()), master=len(master.to_bytes()),
                            receiver_Bob=len(receiver.to_bytes()), sender_Alice=len(sender.to_bytes()))
    require(receipt["checks"], "real_C64B_setup_and_sender", source.bytes_used > 0)


def sample_address(runtime, directory, phase, source, receipt):
    public = load_public(runtime, directory)
    if phase == "receiver-Carol":
        master = load_master(runtime, directory)
        runtime.validate_master(public, master)
        try:
            receiver = runtime.proto.rkgen(master, b"Carol", rng=source)
        finally:
            write(directory / "master.bin", master.to_bytes())
        write(directory / "receiver-Carol.bin", receiver.to_bytes())
        runtime.validate_receiver(public, receiver)
        receipt["sizes"] = dict(receiver_Carol=len(receiver.to_bytes()))
    else:
        _, receiver_name, sender_name = phase.split("-")
        receiver = load_receiver(runtime, directory, receiver_name)
        runtime.validate_receiver(public, receiver)
        try:
            child = runtime.hibe.derive(receiver.level1_key, sender_name.encode("ascii"), rng=source)
        finally:
            write(directory / ("receiver-" + receiver_name + ".bin"), receiver.to_bytes())
        write(directory / (phase + ".bin"), child.to_bytes())
        require(receipt["checks"], "new_leaf_canonical_restore",
                runtime.decoders["sk2"].from_bytes(child.to_bytes()).to_bytes() == child.to_bytes())
        receipt["sizes"] = dict(leaf=len(child.to_bytes()), receiver=len(receiver.to_bytes()))
    require(receipt["checks"], "address_completed", True)


def checks(runtime, directory, source, receipt):
    public, master = load_public(runtime, directory), load_master(runtime, directory)
    sender = SenderKey.from_bytes((directory / "sender-Alice.bin").read_bytes(), runtime.decoders["sk"])
    receivers = {name: load_receiver(runtime, directory, name) for name in ("Bob", "Carol")}
    p, assertions = runtime.proto, receipt["checks"]

    def check(label, condition):
        require(assertions, label, condition)

    try:
        runtime.validate_master(public, master)
        runtime.validate_sender(public, sender)
        for name, receiver in receivers.items():
            runtime.validate_receiver(public, receiver)
            for signer in ("Alice", "Eve"):
                child = runtime.hibe.derive(receiver.level1_key, signer.encode(), rng=NoEntropy())
                saved = (directory / ("leaf-" + name + "-" + signer + ".bin")).read_bytes()
                check("fixed_leaf_reuse_" + name + "_" + signer, child.to_bytes() == saved)

        message = b"\x00real-CHKP-C64B\xff"
        cipher = p.encrypt(public, sender, b"Bob", message, rng=source)
        wire = cipher.to_bytes()
        check("honest_roundtrip", p.decrypt(public, receivers["Bob"], b"Alice", wire, rng=NoEntropy()) == message)
        check("ciphertext_roundtrip", p.load_ciphertext(wire).to_bytes() == wire)
        for label, receiver_name, signer in (("wrong_sender", "Bob", b"Eve"),
                ("wrong_receiver", "Carol", b"Alice"), ("both_wrong", "Carol", b"Eve")):
            check(label, p.decrypt(public, receivers[receiver_name], signer, wire, rng=NoEntropy()) is BOTTOM)

        readers = runtime.decoders
        restored_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
        restored_master = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
        restored_sender = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
        restored_receiver = ReceiverKey.from_bytes(receivers["Bob"].to_bytes(), readers["sk1"])
        runtime.validate_master(restored_public, restored_master)
        for label, restored, original in (("public", restored_public, public), ("master", restored_master, master),
                ("sender", restored_sender, sender), ("receiver", restored_receiver, receivers["Bob"])):
            check(label + "_restore", restored.to_bytes() == original.to_bytes())
        before = source.bytes_used
        check("fixed_IBS_identity_after_restore", p.skgen(restored_master, b"Alice").to_bytes() == sender.to_bytes())
        check("fixed_IBS_cache_no_entropy", source.bytes_used == before)
        check("restored_decrypt", p.decrypt(restored_public, restored_receiver, b"Alice", wire,
                                             rng=NoEntropy()) == message)

        for label, bad in (("truncated", wire[:-1]), ("appended", wire + b"\0"),
                           ("duplicate", wire + wire), ("wrong_version", b"?" + wire[1:])):
            rejected = False
            try:
                p.load_ciphertext(bad)
            except SerializationError:
                rejected = True
            check(label + "_loader", rejected)
            check(label + "_decrypt", p.decrypt(public, receivers["Bob"], b"Alice", bad, rng=NoEntropy()) is BOTTOM)
        for field in ("context", "inner_bytes", "signature"):
            raw = getattr(cipher, field)
            modified = replace(cipher, **{field: raw[:-1] + bytes([raw[-1] ^ 1])})
            check("byteauth_" + field, p.decrypt(public, receivers["Bob"], b"Alice", modified, rng=NoEntropy()) is BOTTOM)
        replacement_ots = generate_lamport_key(rng=source)
        check("byteauth_ots_key", p.decrypt(public, receivers["Bob"], b"Alice",
              replace(cipher, ots_key=replacement_ots.public_key), rng=NoEntropy()) is BOTTOM)

        baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
        inner = baseline.load_ciphertext(cipher.inner_bytes)
        child = runtime.hibe.derive(receivers["Bob"].level1_key, b"Alice", rng=NoEntropy())
        payload = runtime.hibe.decrypt(child, inner.hibe_ct, rng=NoEntropy())
        sig_raw, signed_payload = parse_payload(payload)
        signature = runtime.ibs.load_signature(public.ipk, sig_raw)
        signed = encode_message(b"Bob", signed_payload)
        check("C64B_compact_signature_size", len(sig_raw) == 16383)
        check("ibs_honest", runtime.ibs.verify(public.ipk, b"Alice", signed, signature) is True)
        check("ibs_wrong_message", runtime.ibs.verify(public.ipk, b"Alice", signed + b"!", signature) is False)
        check("ibs_wrong_identity", runtime.ibs.verify(public.ipk, b"Eve", signed, signature) is False)
        for label, guess in (("changed_signature", sig_raw[:-1] + bytes([sig_raw[-1] ^ 1])),
                             ("random_signature", source.read(len(sig_raw)))):
            try:
                value = runtime.ibs.load_signature(public.ipk, guess)
            except SerializationError:
                check(label + "_wire_rejected", True)
            else:
                check(label + "_verify_rejected", runtime.ibs.verify(public.ipk, b"Alice", signed, value) is False)

        native = runtime.hibe.inner_backend
        raw_capsule = native.load_ciphertext(inner.hibe_ct.capsule)
        terminals = raw_capsule.capsule.terminals
        mutated = replace(raw_capsule, capsule=replace(raw_capsule.capsule,
                          terminals=((terminals[0] + 1) % raw_capsule.capsule.q,) + terminals[1:]))
        seed = native.decrypt(child.inner, raw_capsule, rng=NoEntropy())
        check("raw_low_coefficient_change_keeps_seed", seed is not None and
              native.decrypt(child.inner, mutated, rng=NoEntropy()) == seed)
        check("hybrid_AAD_rejects_same_seed_capsule_change", runtime.hibe.decrypt(child,
              replace(inner.hibe_ct, capsule=mutated.to_bytes()), rng=NoEntropy()) is None)

        attacker_ots = generate_lamport_key(rng=source)
        altered_payload = encode_bound_message(attacker_ots.public_key.commitment(), message + b"!")
        check("old_IBS_rejects_new_OTS_bound_message", runtime.ibs.verify(public.ipk, b"Alice",
              encode_message(b"Bob", altered_payload), signature) is False)
        forged_inner = Ciphertext(runtime.hibe.encrypt(public.hpk, b"Bob", b"Alice",
              DOMAIN_SIGNATURE + encode_bytes(sig_raw) + encode_bytes(altered_payload), rng=source))
        forged = authenticate_inner(public, forged_inner.to_bytes(), attacker_ots)
        check("forged_outer_OTS_is_valid", forged.ots_key.verify(forged.signed_body(), forged.signature) is True)
        original_verify, verification_results = runtime.ibs.verify, []

        def observed_verify(*args, **kwargs):
            answer = original_verify(*args, **kwargs)
            verification_results.append(answer)
            return answer

        runtime.ibs.verify = observed_verify
        try:
            rejected = p.decrypt(public, receivers["Bob"], b"Alice", forged, rng=NoEntropy()) is BOTTOM
        finally:
            runtime.ibs.verify = original_verify
        check("full_BYTEAUTH_rejects_valid_OTS_old_IBS", rejected)
        check("full_BYTEAUTH_rejection_reaches_IBS", verification_results == [False])

        maximum = runtime.capacity["max_application_bytes"]
        check("capacity_frozen_3924", maximum == 3924)
        sizes = dict(signature=len(sig_raw), ciphertext=len(wire), raw_capsule=len(raw_capsule.to_bytes()))
        for label, value in (("empty", b""), ("maximum", b"M" * maximum)):
            encrypted = p.encrypt(public, sender, b"Bob", value, rng=source)
            check(label + "_message_roundtrip", p.decrypt(public, receivers["Bob"], b"Alice", encrypted,
                                                          rng=NoEntropy()) == value)
            sizes[label + "_ciphertext"] = len(encrypted.to_bytes())
        before, rejected = source.bytes_used, False
        try:
            p.encrypt(public, sender, b"Bob", b"M" * (maximum + 1), rng=source)
        except InvalidParameterError:
            rejected = True
        check("capacity_plus_one_rejects_before_entropy", rejected and before == source.bytes_used)
        receipt.update(sizes=sizes, message_bytes=len(message), max_message_bytes=maximum,
                       raw_identity_bytes=dict(receiver=3, sender=5), inner_identity_bytes=86)
    finally:
        write(directory / "master.bin", master.to_bytes())
        for name, receiver in receivers.items():
            write(directory / ("receiver-" + name + ".bin"), receiver.to_bytes())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    parser.add_argument("--directory", help="new private combination directory under ignored test-results")
    parser.add_argument("--lifetime", default=str(BASE / "test-results/chkp-lifetime-2026-10-12"))
    args = parser.parse_args(argv)
    report = preflight()
    if args.phase == "preflight":
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["passed"] else 2
    if not report["passed"]:
        parser.error("assembly preflight failed; run preflight for public diagnostics")
    if not args.directory:
        parser.error("--directory is required for actual phases")
    try:
        directory, lifetime = private_directory(args.directory), private_directory(args.lifetime)
    except ValueError as exc:
        parser.error(str(exc))
    if directory == lifetime:
        parser.error("combination directory must differ from the input CHKP lifetime")
    if args.phase == "prepare":
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not directory.is_dir():
        parser.error("run prepare first")
    # One process owns all mutable snapshots. The OS releases this lock after
    # a crash, while the per-phase pending marker still forbids that retry.
    try:
        with key_issuance_lock(directory, timeout=0):
            return run_phase(args, parser, directory, lifetime)
    except StateBusyError:
        parser.error('another writer owns this combination or source lifetime directory')


def run_phase(args, parser, directory, lifetime):
    # Shared checkpoints may have changed in ANY failed phase. No ready
    # receipt or independent address permits continuing that lifetime.
    if any(directory.glob('*.pending')):
        parser.error('combination has a pending attempt; no automatic continuation')
    marker = directory / (args.phase + ".pending")
    receipt_path = directory / (args.phase + ".json")
    config = selected_suite()
    suite_path = directory / "suite.json"
    if args.phase != 'prepare' or receipt_path.exists():
        if not suite_path.is_file() or suite_path.read_bytes() != config.to_json().encode():
            parser.error('saved suite differs; no automatic parameter migration')
    try:
        completed = {phase: ready_receipt(directory, phase, config) for phase in PHASES[1:]
                     if (directory / (phase + '.json')).exists()}
    except ValueError as exc:
        parser.error(str(exc))
    prerequisites = (["prepare"] if args.phase != "prepare" else [])
    if args.phase in ("leaf-Carol-Alice", "leaf-Carol-Eve"):
        prerequisites.append("receiver-Carol")
    if args.phase == "checks":
        prerequisites.extend(PHASES[2:6])
    for prerequisite in prerequisites:
        if prerequisite not in completed:
            parser.error("required phase is not ready: " + prerequisite)
    if args.phase in completed:
        print(json.dumps(dict(event='ready_phase_reused', receipt=completed[args.phase]), sort_keys=True))
        return 0
    if args.phase == 'prepare':
        if not lifetime.is_dir():
            parser.error('source lifetime does not exist')
        # Acquire the source lock before checking its receipts or reading
        # its snapshots. A busy source causes no marker or RNG read.
        with key_issuance_lock(lifetime, timeout=0):
            try:
                require_lifetime_ready(lifetime, 'leaf')
            except ValueError as exc:
                parser.error(str(exc))
            return execute_phase(args, directory, lifetime, config, marker, receipt_path, suite_path)
    return execute_phase(args, directory, lifetime, config, marker, receipt_path, suite_path)


def execute_phase(args, directory, lifetime, config, marker, receipt_path, suite_path):
    with marker.open("xb") as stream:
        stream.write(b"Attempted address. Never delete this marker to resample.\n")
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(directory)
    source = CountedSystem()
    receipt = dict(phase=args.phase, passed=False, checks=[], repetition_count=1,
                   randomness="system CSPRNG", security_claim="none", backend_admitted=False,
                   parameters_are_formal=False, suite_digest=config.digest,
                   environment=dict(python=sys.version.split()[0], platform=platform.platform()),
                   limitation="n=2 CHKP is publicly attackable; functional acceptance only")
    started = time.monotonic()
    print(json.dumps(dict(event="started", phase=args.phase)), flush=True)
    try:
        runtime = build_runtime(config, ibs_rng=source, ots_rng=source)
        if args.phase == "prepare":
            if any((directory / name).exists() for name in ("public.bin", "master.bin", "suite.json")):
                raise ValueError("prepare refuses existing objects")
            write(suite_path, config.to_json().encode())
            prepare(runtime, directory, lifetime, source, receipt)
        elif args.phase == "checks":
            checks(runtime, directory, source, receipt)
        else:
            sample_address(runtime, directory, args.phase, source, receipt)
        receipt["passed"] = bool(receipt["checks"]) and all(row["passed"] for row in receipt["checks"])
        receipt['executed_checks'] = len(receipt['checks'])
        validate_receipt(receipt, args.phase, config)
    except BaseException as exc:
        # Exception messages and reprs can include private arithmetic. Only
        # the type and already public check labels enter the public receipt.
        receipt.update(passed=False, failure_type=type(exc).__name__)
    finally:
        receipt.update(seconds=time.monotonic() - started, entropy_bytes=source.bytes_used,
                       executed_checks=len(receipt["checks"]))
        write(receipt_path, json_bytes(receipt))
        print(json.dumps(receipt, sort_keys=True), flush=True)
    if receipt["passed"]:
        marker.unlink()
        sync_directory(directory)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
