"""Run the same public-interface checks for independently selected primitives.

Uses public fixed test randomness, never production keys. Receipts contain only
configuration, sizes, timings and outcomes; no key or ciphertext bytes. These
checks establish functional observations, not cryptographic security.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import platform
from pathlib import Path
import sys
import time

from ibme.assembly import build_runtime, make_suite, validate_suite
from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.errors import SerializationError
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.protocol.baseline import (
    BOTTOM, BaselineIBME, Ciphertext, DOMAIN_SIGNATURE, MasterSecret, PublicKey,
    ReceiverKey, SenderKey, parse_payload,
)
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message


def case_definitions():
    cases = {}
    for ibs, fmt in (("sis", "reference"), ("luo-matrix", "reference"),
                     ("luo-module", "reference"), ("luo-module", "compact")):
        for protocol in ("baseline-v1", "byteauth-v1"):
            name = f"abb10-hybrid-{ibs}-{fmt}-{protocol}"
            cases[name] = dict(hibe="abb10", ibs=ibs, transport="hybrid",
                               protocol=protocol, signature_format=fmt)
    cases["abb10-direct-sis-byteauth"] = dict(hibe="abb10", ibs="sis")
    # Mixed test combinations ensure choices are genuinely independent.
    cases["mock-direct-mock-byteauth"] = dict(hibe="mock", ibs="mock", allow_mock=True)
    cases["mock-hybrid-luo-matrix-byteauth"] = dict(hibe="mock", ibs="luo-matrix",
                                                  transport="hybrid", allow_mock=True)
    cases["abb10-hybrid-mock-byteauth"] = dict(hibe="abb10", ibs="mock",
                                             transport="hybrid", allow_mock=True)
    cases["latte-pending"] = dict(hibe="latte", ibs="luo-module", transport="hybrid")
    return cases


DEFAULT_CASES = tuple(name for name, options in case_definitions().items()
                      if options["hibe"] == "abb10" and options["ibs"] != "mock")


def run_case(name, options):
    """Run actual calls for one configuration; every check has an outcome."""
    started = time.perf_counter()
    checks = []
    result = dict(case=name, selection=options, status="not_executed", checks=checks,
                  security_claim="none", backend_admitted=False,
                  parameters_are_formal=False, randomness="fixed public test streams",
                  repetition_count=1)
    stage = "configuration"

    def rng(label):
        return DeterministicRandom(("IBME:ASSEMBLY-MATRIX:v1:" + name + ":" + label).encode())

    def check(label, condition):
        if not condition:
            checks.append(dict(name=label, status="fail"))
            raise AssertionError(label)
        checks.append(dict(name=label, status="pass"))

    try:
        config = make_suite(**options)
        preflight = validate_suite(config)
        result["preflight"] = preflight.to_dict()
        if not preflight.ok:
            result["status"] = "blocked"
            return result
        result["suite"] = config.to_dict()
        result["suite_digest"] = config.digest
        stage = "build_runtime"
        runtime = build_runtime(config, ibs_rng=rng("ibs"), ots_rng=rng("ots"))
        p = runtime.proto
        stage = "honest_lifecycle"
        public, master = p.setup(runtime.hibe_params, ibs_params=runtime.ibs_params, rng=rng("setup"))
        sender = p.skgen(master, b"Alice")
        receiver = p.rkgen(master, b"Bob", rng=rng("receiver"))
        other_receiver = p.rkgen(master, b"Carol", rng=rng("other-receiver"))
        message = b"\x00assembly\xff"
        cipher = p.encrypt(public, sender, b"Bob", message, rng=rng("encrypt"))
        wire = cipher.to_bytes()
        check("honest_roundtrip", p.decrypt(public, receiver, b"Alice", wire, rng=rng("decrypt")) == message)
        check("ciphertext_roundtrip", p.load_ciphertext(wire).to_bytes() == wire)
        check("wrong_sender", p.decrypt(public, receiver, b"Eve", wire, rng=rng("wrong-sender")) is BOTTOM)
        check("wrong_receiver", p.decrypt(public, other_receiver, b"Alice", wire, rng=rng("wrong-receiver")) is BOTTOM)
        check("both_wrong", p.decrypt(public, other_receiver, b"Eve", wire, rng=rng("both-wrong")) is BOTTOM)

        stage = "object_restore"
        readers = runtime.decoders
        restored_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
        restored_master = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
        restored_sender = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
        restored_receiver = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
        runtime.validate_master(restored_public, restored_master)
        check("public_restore", restored_public.to_bytes() == public.to_bytes())
        check("master_restore", restored_master.to_bytes() == master.to_bytes())
        check("sender_restore", restored_sender.to_bytes() == sender.to_bytes())
        check("receiver_restore", restored_receiver.to_bytes() == receiver.to_bytes())
        check("restored_decrypt", p.decrypt(restored_public, restored_receiver, b"Alice", wire,
                                             rng=rng("restored-decrypt")) == message)
        if options["ibs"] in ("luo-matrix", "luo-module"):
            check("fixed_identity_after_restore", p.skgen(restored_master, b"Alice").to_bytes() == sender.to_bytes())

        stage = "wire_rejections"
        for label, bad in (("truncated", wire[:-1]), ("appended", wire + b"\0"),
                           ("duplicate", wire + wire), ("wrong_version", b"?" + wire[1:])):
            rejected = False
            try:
                p.load_ciphertext(bad)
            except SerializationError:
                rejected = True
            check(label + "_loader", rejected)
            check(label + "_decrypt", p.decrypt(public, receiver, b"Alice", bad, rng=rng(label)) is BOTTOM)
        byteauth = options.get("protocol", "byteauth-v1") == "byteauth-v1"
        if byteauth:
            for field in ("context", "inner_bytes", "signature"):
                raw = getattr(cipher, field)
                modified = replace(cipher, **{field: raw[:-1] + bytes([raw[-1] ^ 1])})
                check("byteauth_" + field, p.decrypt(public, receiver, b"Alice", modified) is BOTTOM)
            new_ots = generate_lamport_key(rng=rng("different-ots"))
            check("byteauth_ots_key", p.decrypt(public, receiver, b"Alice",
                                                   replace(cipher, ots_key=new_ots.public_key)) is BOTTOM)

        stage = "inner_signature_checks"
        # Use only published primitive methods and public key wrapper fields.
        baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
        inner = baseline.load_ciphertext(cipher.inner_bytes) if byteauth else cipher
        child = p.hibe_backend.derive(receiver.level1_key, b"Alice", rng=rng("leaf"))
        payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng("raw-decrypt"))
        sig_raw, signed_payload = parse_payload(payload)
        signature = p.ibs_backend.load_signature(public.ipk, sig_raw)
        signed = encode_message(b"Bob", signed_payload)
        check("ibs_honest", p.ibs_backend.verify(public.ipk, b"Alice", signed, signature) is True)
        check("ibs_wrong_message", p.ibs_backend.verify(public.ipk, b"Alice", signed + b"!", signature) is False)
        check("ibs_wrong_identity", p.ibs_backend.verify(public.ipk, b"Eve", signed, signature) is False)
        for label, guess in (("changed_signature", sig_raw[:-1] + bytes([sig_raw[-1] ^ 1])),
                             ("random_signature", rng("guess").read(len(sig_raw)))):
            try:
                guessed = p.ibs_backend.load_signature(public.ipk, guess)
            except SerializationError:
                check(label + "_wire_rejected", True)
            else:
                check(label + "_verify_rejected", p.ibs_backend.verify(public.ipk, b"Alice", signed, guessed) is False)

        # A valid old signature is rebound to a different message. The outer OTS
        # is valid, and the new bound envelope matches it: rejection reaches IBS.
        attacker_ots = generate_lamport_key(rng=rng("attacker-ots")) if byteauth else None
        forged_message = message + b"!"
        altered_payload = (encode_bound_message(attacker_ots.public_key.commitment(), forged_message)
                           if byteauth else forged_message)
        check("reused_signature_rejects_altered_payload",
              p.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", altered_payload), signature) is False)
        forged_inner = Ciphertext(p.hibe_backend.encrypt(
            public.hpk, b"Bob", b"Alice", DOMAIN_SIGNATURE + encode_bytes(sig_raw) + encode_bytes(altered_payload),
            rng=rng("forged-encrypt")))
        forged = (authenticate_inner(public, forged_inner.to_bytes(), attacker_ots) if byteauth else forged_inner)
        if byteauth:
            check("forged_outer_ots_valid", forged.ots_key.verify(forged.signed_body(), forged.signature) is True)
        original_verify = p.ibs_backend.verify
        verification_results = []

        def observed_verify(*args, **kwargs):
            answer = original_verify(*args, **kwargs)
            verification_results.append(answer)
            return answer

        p.ibs_backend.verify = observed_verify
        try:
            rejected = p.decrypt(public, receiver, b"Alice", forged, rng=rng("forged-decrypt")) is BOTTOM
        finally:
            p.ibs_backend.verify = original_verify
        check("inner_authentication_rejects", rejected)
        check("inner_rejection_reached_ibs", verification_results == [False])

        stage = "empty_message"
        empty = p.encrypt(public, sender, b"Bob", b"", rng=rng("empty-encrypt"))
        check("empty_roundtrip", p.decrypt(public, receiver, b"Alice", empty, rng=rng("empty-decrypt")) == b"")
        result.update(status="pass", classification="test_only" if options.get("allow_mock") else "research",
                      sizes=dict(public_key=len(public.to_bytes()), sender_key=len(sender.to_bytes()),
                                 receiver_key=len(receiver.to_bytes()), signature=len(sig_raw), ciphertext=len(wire)),
                      message_bytes=len(message), sender_identity_bytes=5, receiver_identity_bytes=3)
    except Exception as exc:
        result.update(status="fail", failed_stage=stage, error_type=type(exc).__name__, error=str(exc))
    finally:
        result["elapsed_seconds"] = round(time.perf_counter() - started, 6)
        result["executed_checks"] = len(checks)
    return result


def summarize(results):
    counts = {status: sum(item["status"] == status for item in results)
              for status in ("pass", "fail", "blocked", "not_executed")}
    complete = (bool(results) and counts["pass"] == len(results)
                and all(item.get("executed_checks", 0) > 0 for item in results))
    return dict(schema="ibme-combination-run-v1", status="pass" if complete else "incomplete",
                counts=counts, executed_checks=sum(item.get("executed_checks", 0) for item in results),
                environment=dict(python=sys.version.split()[0], platform=platform.platform()),
                security_claim="none", backend_admitted=False,
                limitations=["Functional checks do not establish security.",
                             "ABB10 and SIS use teaching parameters; known attacks remain applicable.",
                             "Random signature rejection is a bounded negative input check.",
                             "No unavailable backend is substituted; CHKP has a separate Sage lifecycle driver."],
                results=results)


def main(argv=None):
    definitions = case_definitions()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=tuple(definitions), dest="cases")
    parser.add_argument("--list", action="store_true", help="list cases without executing cryptographic operations")
    parser.add_argument("--output", type=Path, help="new receipt file; never writes secret material")
    args = parser.parse_args(argv)
    if args.list:
        print(json.dumps({"default_cases": DEFAULT_CASES, "cases": definitions}, ensure_ascii=False, indent=2))
        return 0
    selected = args.cases if args.cases is not None else DEFAULT_CASES
    if len(set(selected)) != len(selected):
        parser.error("duplicate cases are not counted as distinct combinations")
    if args.output and args.output.exists():
        parser.error("output already exists; choose a new receipt path")
    results = []
    for name in selected:
        result = run_case(name, definitions[name])
        results.append(result)
        print(f"{name}: {result['status']} ({result['executed_checks']} checks)", file=sys.stderr, flush=True)
    report = summarize(results)
    raw = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(raw)
    else:
        print(raw, end="")
    return 0 if report["status"] == "pass" and report["executed_checks"] > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
