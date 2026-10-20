"""Run the same public-interface checks for independently selected primitives.

Uses public fixed test randomness, never production keys. Receipts contain only
configuration, sizes, timings and outcomes; no key or ciphertext bytes. These
checks establish functional observations, not cryptographic security.

With no selection (or --plan), enumerate registered parameter presets, both
transports/protocols and every declared IBS format without constructing backends
or generating keys. Explicit --case selections retain the legacy names.
--suite-file accepts only a JSON list of {"name": "...", "selection": {...}}
records, where selection contains make_suite options, never Python imports.
Optional parameter_labels describe teaching/research inputs, not security
admission. --suite-name selects named records from that file for separate runs.
Use --plan --suite-file to preflight those selections without executing them.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from itertools import product
import json
import platform
from pathlib import Path
import sys
import time

from ibme.assembly import BackendRegistry, SuiteConfig, build_runtime, default_registry, make_suite, validate_suite
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

TRANSPORTS = ("direct", "hybrid")
PROTOCOLS = ("baseline-v1", "byteauth-v1")
SELECTION_FIELDS = frozenset(("hibe", "ibs", "hibe_params", "ibs_params", "transport",
                              "protocol", "signature_format", "allow_mock", "hybrid_limits",
                              "state_policy"))


def generate_cases(*, registry=None, allow_mock=False):
    """Enumerate configurations, not distinct algorithms or execution evidence.

    Include unavailable descriptors so missing routes remain visible. Presets
    are explicit: arbitrary registered names need no driver-specific defaults.
    Compatibility (including transport-specific presets) belongs to preflight.
    """
    registry = registry if registry is not None else default_registry()
    registered = registry.list()
    cases = {}
    for hibe, ibs in product(registered["hibe"], registered["ibs"]):
        for hp, ip, transport, protocol, fmt in product(
                hibe["parameter_presets"] or (None,), ibs["parameter_presets"] or (None,),
                TRANSPORTS, PROTOCOLS, ibs["signature_formats"] or ("reference",)):
            # JSON tuples remain unambiguous even when IDs contain separators.
            name = json.dumps([hibe["id"], ibs["id"], hp, ip, transport, protocol, fmt],
                              ensure_ascii=True, separators=(",", ":"))
            cases[name] = dict(hibe=hibe["id"], ibs=ibs["id"], hibe_params=hp, ibs_params=ip,
                               transport=transport, protocol=protocol, signature_format=fmt,
                               allow_mock=allow_mock)
    return cases


def plan_case(name, options, *, registry=None):
    """Static selection/preflight only; never call backend factories or Setup."""
    registry = registry if registry is not None else default_registry()
    result = dict(case=name, selection=options, status="preflight_failed", checks=[],
                  executed_checks=0, execution="not_executed", preflight_only=True,
                  classification="unresolved", security_claim="none", backend_admitted=False,
                  parameters_are_formal=False, security_proof_count=0, repetition_count=0)
    try:
        if type(options) is not dict or set(options) - SELECTION_FIELDS:
            raise ValueError("selection must contain only make_suite selection fields")
        specs = [registry.get(role, options.get(role, default))
                 for role, default in (("hibe", "abb10"), ("ibs", "sis"))]
        result["classification"] = "test_only" if any(s.test_only for s in specs) else "research"
        result["unavailable_backends"] = [dict(role=s.role, id=s.id, reason=s.reason)
                                           for s in specs if not s.available]
        if result["unavailable_backends"]:
            result["status"] = "unavailable"
        config = make_suite(**options, registry=registry)
        preflight = validate_suite(config, registry=registry)
        suite=config.to_dict()
        result.update(suite=suite, suite_digest=config.digest, preflight=preflight.to_dict(),
                      security_claim=suite["security_claim"],
                      backend_admitted=suite["backend_admitted"],
                      parameters_are_formal=suite["parameters_are_formal"])
        # The negative checks need a different message within the input budget.
        result["acceptance_errors"] = (["acceptance checks require at least one application byte"]
                                       if preflight.ok and preflight.capacity["max_application_bytes"] < 1 else [])
        if preflight.ok and not result["acceptance_errors"]:
            result["status"] = "planned"
        elif preflight.metadata.get("runtime_available") is False:
            result["status"] = "unavailable"
    except Exception as exc:
        result.update(error_type=type(exc).__name__, error=str(exc))
    return result


def load_suite_file(path, *, with_labels=False):
    """Read bounded, strict JSON data; config cannot register/import code."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError(f"nonfinite JSON value: {value}")

    with Path(path).open("rb") as handle:
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("suite file exceeds 1 MiB budget")
    rows = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    if type(rows) is not list or not rows or len(rows) > 256:
        raise ValueError("suite file must contain 1..256 explicit selections")
    cases = {}
    labels = {}
    for row in rows:
        if (type(row) is not dict or not {"name", "selection"} <= set(row)
                or set(row) - {"name", "selection", "parameter_labels"}):
            raise ValueError("suite records require name/selection and optional parameter_labels")
        name, selection = row["name"], row["selection"]
        if type(name) is not str or not name.strip() or len(name) > 256 or name in cases:
            raise ValueError("suite names must be nonempty, unique strings of at most 256 characters")
        if (type(selection) is not dict or not {"hibe", "ibs"} <= set(selection)
                or set(selection) - SELECTION_FIELDS):
            raise ValueError("selection requires hibe/ibs and only make_suite selection fields")
        tags = row.get("parameter_labels", {})
        if (type(tags) is not dict or set(tags) - {"hibe", "ibs"}
                or any(value not in ("teaching", "research", "test_only") for value in tags.values())):
            raise ValueError("parameter_labels must describe hibe/ibs as teaching, research or test_only")
        labels[name] = tags
        cases[name] = selection
    return (cases, labels) if with_labels else cases


class _VerificationObserver:
    """Forward the public IBS interface, including immutable backend objects."""
    def __init__(self, backend, answers):
        self.backend = backend
        self.answers = answers

    def __getattr__(self, name):
        return getattr(self.backend, name)

    def verify(self, *args, **kwargs):
        answer = self.backend.verify(*args, **kwargs)
        self.answers.append(answer)
        return answer


def run_case(name, options, *, registry=None, setup_callback=None, identities=None):
    """Run actual calls for one configuration; every check has an outcome."""
    started = time.perf_counter()
    registry = registry if registry is not None else default_registry()
    result = plan_case(name, options, registry=registry)
    result["planning_status"] = result["status"]
    checks = result["checks"]
    stage = "configuration"

    def rng(label):
        return DeterministicRandom(("IBME:ASSEMBLY-MATRIX:v1:" + name + ":" + label).encode())

    def check(label, condition):
        if not condition:
            checks.append(dict(name=label, status="fail"))
            raise AssertionError(label)
        checks.append(dict(name=label, status="pass"))

    try:
        if result["status"] != "planned":
            result["status"] = "blocked"
            return result
        config = SuiteConfig.from_dict(result["suite"])
        stage = "build_runtime"
        verification_results = []
        ibs_spec = registry.get("ibs", config.ibs)
        observed_registry = BackendRegistry([
            registry.get("hibe", config.hibe),
            replace(ibs_spec, factory=lambda source, fmt: _VerificationObserver(
                ibs_spec.factory(source, fmt), verification_results)),
        ])
        runtime = build_runtime(config, ibs_rng=rng("ibs"), ots_rng=rng("ots"), registry=observed_registry)
        p = runtime.proto
        stage = "honest_lifecycle"
        result.update(execution="executed", preflight_only=False, repetition_count=1,
                      randomness="fixed public test streams")
        width = runtime.capacity["identity_bytes"]
        if identities is None:
            identities=tuple(value[:width] for value in (b"Alice",b"Bob",b"Carol",b"Eve"))
        if (not isinstance(identities,(tuple,list)) or len(identities)!=4
                or any(type(value) is not bytes or not 1<=len(value)<=width for value in identities)
                or len(set(identities))!=4):
            raise ValueError("four distinct bounded byte identities required")
        alice,bob,carol,eve=identities
        if setup_callback is None:
            public,master=p.setup(runtime.hibe_params,ibs_params=runtime.ibs_params,rng=rng("setup"))
            result["setup_source"]="new primitive Setup"
        else:
            # Python-only research harness hook; JSON cannot supply code or
            # select a substitute backend. All later checks use the same
            # registered factories, decoders and actual protocol operations.
            public,master,provenance=setup_callback(runtime,rng("setup"))
            result["setup_source"]="explicit research harness"
            result["setup_provenance"]=provenance
        sender = p.skgen(master, alice)
        fixed_ibs = runtime.metadata["primitive_persistent_identity_cache"]["ibs"]
        if fixed_ibs:
            check("fixed_identity_repeated_extract", p.skgen(master, alice).to_bytes() == sender.to_bytes())
        receiver = p.rkgen(master, bob, rng=rng("receiver"))
        other_receiver = p.rkgen(master, carol, rng=rng("other-receiver"))
        message = b"\x00assembly\xff"[:runtime.capacity["max_application_bytes"] - 1]
        cipher = p.encrypt(public, sender, bob, message, rng=rng("encrypt"))
        wire = cipher.to_bytes()
        check("honest_roundtrip", p.decrypt(public, receiver, alice, wire, rng=rng("decrypt")) == message)
        check("ciphertext_roundtrip", p.load_ciphertext(wire).to_bytes() == wire)
        check("wrong_sender", p.decrypt(public, receiver, eve, wire, rng=rng("wrong-sender")) is BOTTOM)
        check("wrong_receiver", p.decrypt(public, other_receiver, alice, wire, rng=rng("wrong-receiver")) is BOTTOM)
        check("both_wrong", p.decrypt(public, other_receiver, eve, wire, rng=rng("both-wrong")) is BOTTOM)

        stage = "object_restore"
        readers = runtime.decoders
        restored_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
        restored_master = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
        restored_sender = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
        restored_receiver = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
        runtime.validate_master(restored_public, restored_master)
        runtime.validate_sender(restored_public, restored_sender)
        runtime.validate_receiver(restored_public, restored_receiver)
        check("public_restore", restored_public.to_bytes() == public.to_bytes())
        check("master_restore", restored_master.to_bytes() == master.to_bytes())
        check("sender_restore", restored_sender.to_bytes() == sender.to_bytes())
        check("receiver_restore", restored_receiver.to_bytes() == receiver.to_bytes())
        check("restored_decrypt", p.decrypt(restored_public, restored_receiver, alice, wire,
                                             rng=rng("restored-decrypt")) == message)
        if fixed_ibs:
            # A fresh backend prevents process-local state from hiding lost cache.
            fresh = build_runtime(config, ibs_rng=rng("restored-ibs"), ots_rng=rng("restored-ots"), registry=registry)
            check("fixed_identity_after_restore", fresh.proto.skgen(restored_master, alice).to_bytes() == sender.to_bytes())

        stage = "wire_rejections"
        for label, bad in (("truncated", wire[:-1]), ("appended", wire + b"\0"),
                           ("duplicate", wire + wire), ("wrong_version", b"?" + wire[1:])):
            rejected = False
            try:
                p.load_ciphertext(bad)
            except SerializationError:
                rejected = True
            check(label + "_loader", rejected)
            check(label + "_decrypt", p.decrypt(public, receiver, alice, bad, rng=rng(label)) is BOTTOM)
        byteauth = config.protocol == "byteauth-v1"
        if byteauth:
            for field in ("context", "inner_bytes", "signature"):
                raw = getattr(cipher, field)
                modified = replace(cipher, **{field: raw[:-1] + bytes([raw[-1] ^ 1])})
                check("byteauth_" + field, p.decrypt(public, receiver, alice, modified) is BOTTOM)
            new_ots = generate_lamport_key(rng=rng("different-ots"))
            check("byteauth_ots_key", p.decrypt(public, receiver, alice,
                                                   replace(cipher, ots_key=new_ots.public_key)) is BOTTOM)

        stage = "inner_signature_checks"
        # Use only published primitive methods and public key wrapper fields.
        baseline = BaselineIBME(p.hibe_backend, p.ibs_backend)
        inner = baseline.load_ciphertext(cipher.inner_bytes) if byteauth else cipher
        child = p.hibe_backend.derive(receiver.level1_key, alice, rng=rng("leaf"))
        payload = p.hibe_backend.decrypt(child, inner.hibe_ct, rng=rng("raw-decrypt"))
        sig_raw, signed_payload = parse_payload(payload)
        signature = p.ibs_backend.load_signature(public.ipk, sig_raw)
        signed = encode_message(bob, signed_payload)
        check("ibs_honest", p.ibs_backend.verify(public.ipk, alice, signed, signature) is True)
        check("ibs_wrong_message", p.ibs_backend.verify(public.ipk, alice, signed + b"!", signature) is False)
        check("ibs_wrong_identity", p.ibs_backend.verify(public.ipk, eve, signed, signature) is False)
        for label, guess in (("changed_signature", sig_raw[:-1] + bytes([sig_raw[-1] ^ 1])),
                             ("random_signature", rng("guess").read(len(sig_raw)))):
            try:
                guessed = p.ibs_backend.load_signature(public.ipk, guess)
            except SerializationError:
                check(label + "_wire_rejected", True)
            else:
                check(label + "_verify_rejected", p.ibs_backend.verify(public.ipk, alice, signed, guessed) is False)

        # A valid old signature is rebound to a different message. The outer OTS
        # is valid, and the new bound envelope matches it: rejection reaches IBS.
        attacker_ots = generate_lamport_key(rng=rng("attacker-ots")) if byteauth else None
        forged_message = message + b"!"
        altered_payload = (encode_bound_message(attacker_ots.public_key.commitment(), forged_message)
                           if byteauth else forged_message)
        check("reused_signature_rejects_altered_payload",
              p.ibs_backend.verify(public.ipk, alice, encode_message(bob, altered_payload), signature) is False)
        forged_inner = Ciphertext(p.hibe_backend.encrypt(
            public.hpk, bob, alice, DOMAIN_SIGNATURE + encode_bytes(sig_raw) + encode_bytes(altered_payload),
            rng=rng("forged-encrypt")))
        forged = (authenticate_inner(public, forged_inner.to_bytes(), attacker_ots) if byteauth else forged_inner)
        if byteauth:
            check("forged_outer_ots_valid", forged.ots_key.verify(forged.signed_body(), forged.signature) is True)
        verification_results.clear()
        rejected = p.decrypt(public, receiver, alice, forged, rng=rng("forged-decrypt")) is BOTTOM
        check("inner_authentication_rejects", rejected)
        check("inner_rejection_reached_ibs", verification_results == [False])

        stage = "empty_message"
        empty = p.encrypt(public, sender, bob, b"", rng=rng("empty-encrypt"))
        check("empty_roundtrip", p.decrypt(public, receiver, alice, empty, rng=rng("empty-decrypt")) == b"")
        result.update(status="pass",
                      sizes=dict(public_key=len(public.to_bytes()), sender_key=len(sender.to_bytes()),
                                 receiver_key=len(receiver.to_bytes()), signature=len(sig_raw), ciphertext=len(wire)),
                      message_bytes=len(message), sender_identity_bytes=len(alice), receiver_identity_bytes=len(bob))
    except Exception as exc:
        result.update(status="fail", failed_stage=stage, error_type=type(exc).__name__, error=str(exc))
    finally:
        result["elapsed_seconds"] = round(time.perf_counter() - started, 6)
        result["executed_checks"] = len(checks)
    return result


def summarize(results):
    counts = {status: sum(item["status"] == status for item in results)
              for status in ("pass", "fail", "blocked", "not_executed", "planned", "unavailable", "preflight_failed")}
    # Only actual driver execution can contribute checks, including failures.
    executed = [item for item in results if item.get("execution") == "executed"]
    complete = (bool(results) and counts["pass"] == len(results)
                and len(executed) == len(results)
                and all(item.get("executed_checks", 0) > 0 for item in executed))
    claims={item.get("security_claim","none") for item in results}
    claim=(next(iter(claims)) if len(claims)==1 else "mixed") if results else "none"
    admitted=bool(results) and all(item.get("backend_admitted") is True for item in results)
    formal=bool(results) and all(item.get("parameters_are_formal") is True for item in results)
    return dict(schema="ibme-combination-run-v1", status="pass" if complete else "incomplete",
                counts=counts, executed_checks=sum(item.get("executed_checks", 0) for item in executed),
                executed_cases=len(executed), security_proof_count=0,
                evidence_counts={kind: dict(cases=sum(item.get("classification") == kind for item in executed),
                    checks=sum(item.get("executed_checks", 0) for item in executed if item.get("classification") == kind))
                    for kind in ("test_only", "research")},
                environment=dict(python=sys.version.split()[0], platform=platform.platform()),
                security_claim=claim, backend_admitted=admitted, parameters_are_formal=formal,
                limitations=["Functional checks do not establish security.",
                             "Project admission is explicit registry metadata; this runner never grants it from a passing test.",
                             "Preset/format/transport variants are not distinct primitive algorithms.",
                             "Random signature rejection is a bounded negative input check.",
                             "No unavailable backend is substituted; dependency/policy gates remain in force.",
                             "Restore checks use fresh objects/backends in one process, not crash or disk transactions."],
                results=results)


def main(argv=None, *, registry=None):
    definitions = case_definitions()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=tuple(definitions), dest="cases")
    parser.add_argument("--suite-file", type=Path, help="execute only the explicit JSON selections (or preflight with --plan)")
    parser.add_argument("--suite-name", action="append", help="select named records within --suite-file")
    parser.add_argument("--plan", action="store_true", help="plan/preflight only; never generate keys")
    parser.add_argument("--allow-mock", action="store_true", help="allow test-only entries in the generated plan")
    parser.add_argument("--list", action="store_true", help="list cases without executing cryptographic operations")
    parser.add_argument("--output", type=Path, help="new receipt file; never writes secret material")
    args = parser.parse_args(argv)
    if args.cases and args.suite_file:
        parser.error("--case and --suite-file are mutually exclusive")
    if args.suite_name and not args.suite_file:
        parser.error("--suite-name requires --suite-file")
    if args.allow_mock and (args.cases or args.suite_file):
        parser.error("explicit selections must set their own allow_mock policy")
    if args.list and (args.cases or args.suite_file or args.plan or args.allow_mock or args.output):
        parser.error("--list only lists legacy case definitions")
    if args.list:
        print(json.dumps({"default_cases": DEFAULT_CASES, "cases": definitions}, ensure_ascii=False, indent=2))
        return 0
    if args.cases and len(set(args.cases)) != len(args.cases):
        parser.error("duplicate cases are not counted as distinct combinations")
    if args.output and args.output.exists():
        parser.error("output already exists; choose a new receipt path")
    registry = registry if registry is not None else default_registry()
    labels = {}
    try:
        if args.suite_file:
            selected, labels = load_suite_file(args.suite_file, with_labels=True)
            if args.suite_name:
                if len(set(args.suite_name)) != len(args.suite_name) or set(args.suite_name) - set(selected):
                    raise ValueError("suite names must be distinct records present in --suite-file")
                selected = {name: selected[name] for name in args.suite_name}
        else:
            selected = ({name: definitions[name] for name in args.cases} if args.cases else
                        generate_cases(registry=registry, allow_mock=args.allow_mock))
    except (OSError, ValueError, RecursionError) as exc:
        parser.error(str(exc))
    planning = args.plan or not (args.cases or args.suite_file)
    # Reject aliases of the same resolved suite before executing any selection.
    if not planning:
        digests = set()
        for name, options in selected.items():
            digest = plan_case(name, options, registry=registry).get("suite_digest")
            if digest is not None:
                if digest in digests:
                    parser.error("duplicate suites are not counted as distinct combinations")
                digests.add(digest)
    results = []
    for name, options in selected.items():
        result = (plan_case if planning else run_case)(name, options, registry=registry)
        if labels.get(name):
            result["parameter_labels"] = labels[name]
        results.append(result)
        if not planning:
            print(f"{name}: {result['status']} ({result['executed_checks']} checks)", file=sys.stderr, flush=True)
    report = summarize(results)
    report["mode"] = "plan" if planning else "execute"
    if planning:
        report.update(schema="ibme-combination-plan-v1", status="preflight_only")
    raw = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(raw)
    else:
        print(raw, end="")
    if planning:
        return 0  # A plan may contain blockers; this never denotes acceptance.
    return 0 if report["status"] == "pass" and report["executed_checks"] > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
