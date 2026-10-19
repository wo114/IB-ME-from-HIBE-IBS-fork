"""Reproducible A09/R4 random-input batch for the primary real IB-ME suite.

Test identities and messages are expanded from a public test seed.  That seed
is never injected into any cryptographic backend: roots, user keys,
signatures, Hybrid nonces/seeds, and BYTEAUTH one-time keys use SecureRandom.
Each root runs in a fresh process, is attempted exactly once, and retains a
failure receipt instead of silently replacing a failed sample.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from unittest.mock import patch

from experiments.research.runtime_metrics import environment, measured_phase


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "IBME-A09-RANDOM-BATCH/1"
ROOT_SCHEMA = "IBME-A09-RANDOM-BATCH-ROOT/1"
INPUT_DOMAIN = b"IBME:A09:RANDOM-BATCH:INPUTS:v1"
SUITE_NAME = "latte3-hybrid-cert-ml-dsa-ml-dsa-44-reference-byteauth-v1"
ROOT_COUNT = 3
RECEIVERS_PER_ROOT = 2
SENDERS_PER_ROOT = 2
IDENTITY_BYTES = 64
MESSAGE_LENGTHS = (0, 1, 32, 1024)
CHECK_NAMES = (
    "honest_roundtrip",
    "wrong_sender_rejected",
    "wrong_receiver_rejected",
    "both_wrong_rejected",
    "tampered_ciphertext_rejected",
)


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def write_new(path: Path, value) -> None:
    raw = value if type(value) is bytes else (
        json.dumps(value, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def parse_seed(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("input seed must be exactly 32 bytes encoded as 64 hex digits")
    return bytes.fromhex(value)


def _expand(seed: bytes, root_index: int, label: bytes, index: int, length: int) -> bytes:
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError("public input seed must be exactly 32 bytes")
    if type(root_index) is not int or not 0 <= root_index < ROOT_COUNT:
        raise ValueError("root index outside the fixed batch")
    if type(label) is not bytes or not label or len(label) > 255:
        raise ValueError("invalid input-expansion label")
    if type(index) is not int or not 0 <= index < 256:
        raise ValueError("input-expansion index outside one-byte range")
    if type(length) is not int or not 0 <= length <= 65536:
        raise ValueError("input-expansion length outside the batch bound")
    framed = (
        INPUT_DOMAIN
        + root_index.to_bytes(4, "big")
        + bytes((len(label),))
        + label
        + bytes((index,))
        + length.to_bytes(4, "big")
    )
    return hashlib.shake_256(framed + seed).digest(length)


def case_inputs(seed: bytes, root_index: int) -> dict:
    receivers = tuple(
        _expand(seed, root_index, b"receiver-identity", index, IDENTITY_BYTES)
        for index in range(RECEIVERS_PER_ROOT)
    )
    senders = tuple(
        _expand(seed, root_index, b"sender-identity", index, IDENTITY_BYTES)
        for index in range(SENDERS_PER_ROOT)
    )
    identities = receivers + senders
    require(len(set(identities)) == len(identities), "public test seed produced an identity collision")
    messages = tuple(
        _expand(seed, root_index, b"message", index, length)
        for index, length in enumerate(MESSAGE_LENGTHS)
    )
    cases = []
    for receiver_slot in range(RECEIVERS_PER_ROOT):
        for sender_slot in range(SENDERS_PER_ROOT):
            index = receiver_slot * SENDERS_PER_ROOT + sender_slot
            cases.append(
                dict(
                    case_index=index,
                    case_id=f"root-{root_index}-receiver-{receiver_slot}-sender-{sender_slot}",
                    receiver_slot=receiver_slot,
                    sender_slot=sender_slot,
                    receiver=receivers[receiver_slot],
                    sender=senders[sender_slot],
                    message=messages[index],
                )
            )
    return dict(receivers=receivers, senders=senders, cases=tuple(cases))


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def public_input_manifest(seed: bytes, root_index: int) -> dict:
    inputs = case_inputs(seed, root_index)
    return dict(
        root_index=root_index,
        receiver_identity_digests=[digest(value) for value in inputs["receivers"]],
        sender_identity_digests=[digest(value) for value in inputs["senders"]],
        cases=[
            dict(
                case_id=case["case_id"],
                receiver_slot=case["receiver_slot"],
                sender_slot=case["sender_slot"],
                receiver_identity_bytes=len(case["receiver"]),
                receiver_identity_sha256=digest(case["receiver"]),
                sender_identity_bytes=len(case["sender"]),
                sender_identity_sha256=digest(case["sender"]),
                message_bytes=len(case["message"]),
                message_sha256=digest(case["message"]),
            )
            for case in inputs["cases"]
        ],
    )


def source_providers() -> dict:
    providers = {}
    for module in list(sys.modules.values()):
        value = getattr(module, "__file__", None)
        if not value or not str(value).endswith(".py"):
            continue
        path = Path(value).resolve()
        if path.is_relative_to(ROOT):
            relative = path.relative_to(ROOT).as_posix()
            if relative.startswith(("src/ibme/", "experiments/research/")):
                providers[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(providers.items()))


def _mutated_ciphertext(ciphertext, seed: bytes, root_index: int, case_index: int):
    inner = ciphertext.inner_bytes
    require(type(inner) is bytes and inner, "BYTEAUTH inner ciphertext must be nonempty bytes")
    selector = _expand(seed, root_index, b"tamper-selector", case_index, 9)
    position = int.from_bytes(selector[:8], "big") % len(inner)
    mask = 1 << (selector[8] & 7)
    changed = inner[:position] + bytes((inner[position] ^ mask,)) + inner[position + 1 :]
    return replace(ciphertext, inner_bytes=changed), position, mask


def _native_guards(runtime, stack: ExitStack) -> dict:
    counts = {}

    def guard(family, original):
        def call(self, operation, *args, **kwargs):
            name = family + ":" + operation
            counts[name] = counts.get(name, 0) + 1
            return original(self, operation, *args, **kwargs)

        return call

    for module_name, class_name, method, family in (
        ("ibme.hibe.latte.engine", "Native", "call", "latte"),
        ("ibme.ibs.certified.mldsa", "MLDSA", "_run", "mldsa"),
    ):
        module = sys.modules.get(module_name)
        require(module is not None, family + " runtime module was not loaded")
        cls = getattr(module, class_name)
        stack.enter_context(patch.object(cls, method, guard(family, getattr(cls, method))))
    return counts


def _root_worker(directory: Path) -> dict:
    from ibme.assembly import SuiteConfig, build_runtime, validate_suite
    from ibme.core.randomness import SecureRandom
    from ibme.protocol.baseline import BOTTOM

    plan = json.loads((directory / "plan.json").read_bytes())
    config = SuiteConfig.from_json((directory / "suite.json").read_bytes())
    root_index = plan["root_index"]
    seed = parse_seed(plan["input_seed_hex"])
    expected_manifest = public_input_manifest(seed, root_index)
    require(plan["input_manifest"] == expected_manifest, "worker input manifest changed")
    phases = []
    report = dict(
        schema=ROOT_SCHEMA,
        status="started",
        source_commit=plan["source_commit"],
        root_index=root_index,
        input_manifest=expected_manifest,
        phases=phases,
        cases=[],
        security_claim="none",
        backend_admitted=False,
        parameters_are_formal=False,
        security_proofs_produced=0,
        uses_ROM=True,
    )
    stage = "runtime"
    entropy = dict(reads=0, bytes=0)
    original_read = SecureRandom.read

    def counted_read(self, count):
        value = original_read(self, count)
        entropy["reads"] += 1
        entropy["bytes"] += len(value)
        return value

    try:
        with patch.object(SecureRandom, "read", counted_read):
            with measured_phase("build-runtime", phases):
                preflight = validate_suite(config)
                require(preflight.ok, "selected suite public preflight failed")
                runtime = build_runtime(config)
            require(runtime.capacity["identity_bytes"] >= IDENTITY_BYTES, "identity capacity too small")
            require(
                runtime.capacity["max_application_bytes"] >= max(MESSAGE_LENGTHS),
                "application-message capacity too small",
            )
            inputs = case_inputs(seed, root_index)
            with ExitStack() as stack:
                native_counts = _native_guards(runtime, stack)
                proto = runtime.proto
                stage = "setup"
                with measured_phase("setup", phases):
                    public, master = proto.setup(
                        runtime.hibe_params, ibs_params=runtime.ibs_params
                    )
                sender_keys = []
                for index, identity in enumerate(inputs["senders"]):
                    stage = f"sender-key-{index}"
                    with measured_phase(stage, phases):
                        sender_keys.append(proto.skgen(master, identity))
                receiver_keys = []
                for index, identity in enumerate(inputs["receivers"]):
                    stage = f"receiver-key-{index}"
                    with measured_phase(stage, phases):
                        receiver_keys.append(proto.rkgen(master, identity))

                live = []
                for case in inputs["cases"]:
                    stage = "encrypt-" + case["case_id"]
                    with measured_phase(stage, phases):
                        ciphertext = proto.encrypt(
                            public,
                            sender_keys[case["sender_slot"]],
                            case["receiver"],
                            case["message"],
                        )
                        wire = ciphertext.to_bytes()
                        loaded = proto.load_ciphertext(wire)
                        require(loaded.to_bytes() == wire, "ciphertext canonical round trip failed")
                    stage = "honest-" + case["case_id"]
                    with measured_phase(stage, phases):
                        recovered = proto.decrypt(
                            public,
                            receiver_keys[case["receiver_slot"]],
                            case["sender"],
                            wire,
                        )
                    require(recovered == case["message"], "honest batch decryption failed")
                    public_case = expected_manifest["cases"][case["case_index"]]
                    row = dict(
                        **public_case,
                        ciphertext_bytes=len(wire),
                        ciphertext_sha256=digest(wire),
                        checks={"honest_roundtrip": True},
                    )
                    report["cases"].append(row)
                    live.append((case, ciphertext, wire, row))

                # All four honest leaves now exist.  Negative cases therefore
                # stay inside the declared 2-receiver x 2-child LATTE capacity.
                for case, ciphertext, wire, row in live:
                    other_sender = 1 - case["sender_slot"]
                    other_receiver = 1 - case["receiver_slot"]
                    checks = row["checks"]
                    for name, receiver_slot, sender_slot in (
                        ("wrong_sender_rejected", case["receiver_slot"], other_sender),
                        ("wrong_receiver_rejected", other_receiver, case["sender_slot"]),
                        ("both_wrong_rejected", other_receiver, other_sender),
                    ):
                        stage = name + "-" + case["case_id"]
                        with measured_phase(stage, phases):
                            result = proto.decrypt(
                                public,
                                receiver_keys[receiver_slot],
                                inputs["senders"][sender_slot],
                                wire,
                            )
                        checks[name] = result is BOTTOM
                        require(checks[name], stage)

                    tampered, position, mask = _mutated_ciphertext(
                        ciphertext, seed, root_index, case["case_index"]
                    )
                    tampered_wire = tampered.to_bytes()
                    stage = "tampered-ciphertext-" + case["case_id"]
                    with measured_phase(stage, phases):
                        loaded_tamper = proto.load_ciphertext(tampered_wire)
                        parse_preserving = loaded_tamper.to_bytes() == tampered_wire
                        result = proto.decrypt(
                            public,
                            receiver_keys[case["receiver_slot"]],
                            case["sender"],
                            tampered_wire,
                        )
                    checks["tampered_ciphertext_rejected"] = parse_preserving and result is BOTTOM
                    require(checks["tampered_ciphertext_rejected"], stage)
                    row["tamper"] = dict(
                        component="byteauth.inner_bytes",
                        byte_offset=position,
                        xor_mask=mask,
                        wire_length_unchanged=len(tampered_wire) == len(wire),
                        canonical_loader_accepted=parse_preserving,
                    )

        require(entropy["reads"] > 0 and entropy["bytes"] > 0, "cryptographic CSPRNG was not consumed")
        expected_native = {
            "latte:setup": 1,
            "latte:delegate": 2,
            "latte:extract": 4,
            "latte:encrypt": 4,
            "latte:decrypt": 16,
            "mldsa:keypair": 3,
            "mldsa:sign": 6,
        }
        for name, count in expected_native.items():
            require(native_counts.get(name) == count, f"unexpected real native operation count for {name}")
        report.update(
            status="passed",
            suite=config.to_dict(),
            suite_digest=config.digest,
            preflight=preflight.to_dict(),
            runtime_metadata=runtime.metadata,
            environment=environment(),
            cryptographic_randomness=dict(
                source="SecureRandom / operating-system CSPRNG",
                deterministic_test_seed_injected=False,
                reads=entropy["reads"],
                bytes=entropy["bytes"],
            ),
            native_operation_counts=native_counts,
            source_providers=source_providers(),
            completed_checks=len(report["cases"]) * len(CHECK_NAMES),
            failed_checks=0,
        )
        write_new(directory / "root-receipt.json", report)
        os.replace(directory / "attempt.pending", directory / "attempt.done")
        return report
    except BaseException as exc:
        report.update(
            status="failed",
            failure_stage=stage,
            exception_type=type(exc).__name__,
            cryptographic_randomness=dict(
                source="SecureRandom / operating-system CSPRNG",
                deterministic_test_seed_injected=False,
                reads=entropy["reads"],
                bytes=entropy["bytes"],
            ),
            no_retry=True,
        )
        write_new(directory / "root-failure.json", report)
        raise


def _run_child(directory: Path, timeout_seconds: int) -> dict:
    command = [
        sys.executable,
        "-m",
        "experiments.research.random_batch_acceptance",
        "worker",
        "--private-directory",
        str(directory),
    ]
    with (directory / "worker.private-log").open("xb") as log:
        os.chmod(log.name, 0o600)
        process = subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            returncode = process.returncode
            timed_out = True
    if timed_out:
        timeout = dict(status="failed", timed_out=True, timeout_seconds=timeout_seconds, no_retry=True)
        write_new(directory / "worker-timeout.json", timeout)
    return dict(returncode=returncode, timed_out=timed_out)


def _suite_from_file(path: Path):
    from ibme.assembly import make_suite, validate_suite

    suites = json.loads(path.read_bytes())
    matches = [row for row in suites if row.get("name") == SUITE_NAME]
    require(len(matches) == 1, "primary suite selection must be unique")
    selection = matches[0]["selection"]
    require(selection.get("allow_mock") is False, "batch requires real backends")
    config = make_suite(**selection)
    preflight = validate_suite(config)
    require(preflight.ok, "primary suite preflight failed")
    return config, preflight


def require_fixed_source(source_commit: str, suite_file: Path) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit or ""):
        raise ValueError("source commit must be a full lowercase Git object id")
    suite_path = suite_file.resolve()
    if not suite_path.is_relative_to(ROOT):
        raise ValueError("suite manifest must be inside the repository")
    relative_suite = suite_path.relative_to(ROOT).as_posix()
    commit = subprocess.run(
        ["git", "cat-file", "-e", source_commit + "^{commit}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if commit.returncode != 0:
        raise ValueError("source commit does not identify an existing Git commit")
    fixed_paths = ("src/ibme", "experiments/research/random_batch_acceptance.py", relative_suite)
    comparison = subprocess.run(
        ["git", "diff", "--quiet", source_commit, "--", *fixed_paths],
        cwd=ROOT,
        check=False,
    )
    if comparison.returncode != 0:
        raise ValueError("runtime source or suite manifest differs from the declared commit")
    return source_commit


def build_plan(suite_file: Path, seed_hex: str, source_commit: str) -> dict:
    source_commit = require_fixed_source(source_commit, suite_file)
    seed = parse_seed(seed_hex)
    config, preflight = _suite_from_file(suite_file)
    return dict(
        schema="IBME-A09-RANDOM-BATCH-PLAN/1",
        source_commit=source_commit,
        input_seed_hex=seed.hex(),
        input_generation=dict(
            algorithm="SHAKE256",
            domain=INPUT_DOMAIN.decode("ascii"),
            public_reproducible_seed=True,
            cryptographic_rng_separation=True,
        ),
        root_count=ROOT_COUNT,
        receivers_per_root=RECEIVERS_PER_ROOT,
        senders_per_root=SENDERS_PER_ROOT,
        pairs_per_root=RECEIVERS_PER_ROOT * SENDERS_PER_ROOT,
        identity_bytes=IDENTITY_BYTES,
        message_lengths=list(MESSAGE_LENGTHS),
        suite=config.to_dict(),
        suite_digest=config.digest,
        preflight=preflight.to_dict(),
        roots=[public_input_manifest(seed, index) for index in range(ROOT_COUNT)],
    )


def _aggregate(plan: dict, attempts: list[dict]) -> dict:
    roots = []
    for attempt in attempts:
        directory = Path(attempt["directory"])
        receipt = directory / "root-receipt.json"
        failure = directory / "root-failure.json"
        if failure.is_file():
            row = json.loads(failure.read_bytes())
        elif receipt.is_file():
            row = json.loads(receipt.read_bytes())
        else:
            row = dict(
                schema=ROOT_SCHEMA,
                status="failed",
                root_index=attempt["root_index"],
                failure_stage="worker-process",
                exception_type="TimeoutOrProcessFailure",
                no_retry=True,
            )
        row["process"] = {
            "returncode": attempt["returncode"],
            "timed_out": attempt["timed_out"],
            "fresh_process_wall_seconds": attempt["wall_seconds"],
        }
        roots.append(row)
    passed = all(
        root.get("status") == "passed"
        and root["process"].get("returncode") == 0
        and root["process"].get("timed_out") is False
        for root in roots
    )
    total_cases = sum(len(root.get("cases", [])) for root in roots)
    totals = {
        name: sum(
            case.get("checks", {}).get(name) is True
            for root in roots
            for case in root.get("cases", [])
        )
        for name in CHECK_NAMES
    }
    return dict(
        schema=SCHEMA,
        status="passed" if passed else "failed",
        source_commit=plan["source_commit"],
        suite_name=SUITE_NAME,
        suite=plan["suite"],
        suite_digest=plan["suite_digest"],
        execution=dict(
            fresh_process_per_root=True,
            failed_samples_retried=False,
            failed_samples_discarded=False,
            roots_planned=ROOT_COUNT,
            roots_completed=sum(root.get("status") == "passed" for root in roots),
            pairs_planned=ROOT_COUNT * RECEIVERS_PER_ROOT * SENDERS_PER_ROOT,
            cases_recorded=total_cases,
        ),
        input_generation=plan["input_generation"],
        input_seed_hex=plan["input_seed_hex"],
        identity_bytes=IDENTITY_BYTES,
        message_lengths=list(MESSAGE_LENGTHS),
        totals=totals,
        total_checks_passed=sum(totals.values()),
        total_checks_planned=ROOT_COUNT * RECEIVERS_PER_ROOT * SENDERS_PER_ROOT * len(CHECK_NAMES),
        roots=roots,
        security=dict(
            security_claim="none",
            backend_admitted=False,
            parameters_are_formal=False,
            security_proofs_produced=0,
            functional_tests_are_security_proof=False,
            selected_algorithm_security_and_hibe_anonymity="project working assumptions with cited sources",
        ),
        scope=[
            "Twelve full public-protocol cases: three independent CSPRNG roots and four random identity/message pairs per root.",
            "Every case checks honest recovery, wrong sender, wrong receiver, both wrong, and a parse-preserving protected ciphertext mutation.",
            "The finite batch is an implementation acceptance result, not a failure-probability estimate or security proof.",
        ],
    )


def validate_public_report(report: dict, *, expected_commit: str | None = None) -> int:
    from ibme.assembly import SuiteConfig

    require(type(report) is dict and report.get("schema") == SCHEMA, "public report schema")
    require(report.get("status") == "passed", "public report status")
    if expected_commit is not None:
        require(report.get("source_commit") == expected_commit, "public report source commit")
    require(re.fullmatch(r"[0-9a-f]{40}", report.get("source_commit", "")), "source commit format")
    require(report.get("suite_name") == SUITE_NAME, "suite name")
    suite = report.get("suite", {})
    require(suite.get("allow_mock") is False, "real suite required")
    require(suite.get("hibe") == "latte" and suite.get("ibs") == "cert-ml-dsa", "primitive selection")
    require(suite.get("ibs_params", {}).get("base_algorithm") == "ml-dsa-44", "ML-DSA-44 profile")
    require(suite.get("transport") == "hybrid" and suite.get("protocol") == "byteauth-v1", "wrapper selection")
    require(SuiteConfig.from_dict(suite).digest == report.get("suite_digest"), "suite digest")
    require(report.get("identity_bytes") == IDENTITY_BYTES, "identity length")
    require(report.get("message_lengths") == list(MESSAGE_LENGTHS), "message lengths")
    seed = parse_seed(report.get("input_seed_hex"))
    generation = report.get("input_generation", {})
    require(generation.get("algorithm") == "SHAKE256", "input expansion algorithm")
    require(generation.get("domain") == INPUT_DOMAIN.decode("ascii"), "input expansion domain")
    require(generation.get("public_reproducible_seed") is True, "public input seed")
    require(generation.get("cryptographic_rng_separation") is True, "input/crypto RNG separation")
    execution = report.get("execution", {})
    require(execution.get("fresh_process_per_root") is True, "fresh roots")
    require(execution.get("failed_samples_retried") is False, "no retries")
    require(execution.get("failed_samples_discarded") is False, "no discarded failures")
    require(execution.get("roots_planned") == execution.get("roots_completed") == ROOT_COUNT, "root count")
    require(execution.get("pairs_planned") == execution.get("cases_recorded") == 12, "case count")
    roots = report.get("roots")
    require(type(roots) is list and len(roots) == ROOT_COUNT, "root records")
    require({root.get("root_index") for root in roots} == set(range(ROOT_COUNT)), "root indexes")
    seen_cases = set()
    runner_hash = None
    for root in roots:
        require(root.get("schema") == ROOT_SCHEMA and root.get("status") == "passed", "root status")
        require(root.get("source_commit") == report["source_commit"], "root source commit")
        process = root.get("process", {})
        require(process.get("returncode") == 0 and process.get("timed_out") is False, "root process")
        require(
            type(process.get("fresh_process_wall_seconds")) in (int, float)
            and process["fresh_process_wall_seconds"] > 0,
            "root wall time",
        )
        require(root.get("failed_checks") == 0 and root.get("completed_checks") == 20, "root checks")
        require(root.get("suite") == suite and root.get("suite_digest") == report["suite_digest"], "root suite")
        require(root.get("security_claim") == "none", "root security claim")
        require(root.get("backend_admitted") is False, "root backend admission")
        require(root.get("parameters_are_formal") is False, "root formal parameters")
        entropy = root.get("cryptographic_randomness", {})
        require(entropy.get("source") == "SecureRandom / operating-system CSPRNG", "crypto RNG source")
        require(entropy.get("deterministic_test_seed_injected") is False, "test/crypto RNG separation")
        require(type(entropy.get("reads")) is int and entropy["reads"] > 0, "crypto RNG reads")
        require(type(entropy.get("bytes")) is int and entropy["bytes"] > 0, "crypto RNG bytes")
        native = root.get("native_operation_counts", {})
        for name, count in {
            "latte:setup": 1,
            "latte:delegate": 2,
            "latte:extract": 4,
            "latte:encrypt": 4,
            "latte:decrypt": 16,
            "mldsa:keypair": 3,
            "mldsa:sign": 6,
        }.items():
            require(native.get(name) == count, "native count " + name)
        providers = root.get("source_providers", {})
        value = providers.get("experiments/research/random_batch_acceptance.py")
        require(re.fullmatch(r"[0-9a-f]{64}", value or ""), "runner source hash")
        if runner_hash is None:
            runner_hash = value
        require(value == runner_hash, "runner source changed across roots")
        cases = root.get("cases")
        require(type(cases) is list and len(cases) == 4, "cases per root")
        expected_manifest = public_input_manifest(seed, root["root_index"])
        require(root.get("input_manifest") == expected_manifest, "reproducible root input manifest")
        expected_cases = {case["case_id"]: case for case in expected_manifest["cases"]}
        require(sorted(case.get("message_bytes") for case in cases) == list(MESSAGE_LENGTHS), "root message coverage")
        for case in cases:
            require(case.get("case_id") not in seen_cases, "duplicate case id")
            seen_cases.add(case.get("case_id"))
            require(case.get("receiver_identity_bytes") == IDENTITY_BYTES, "receiver identity length")
            require(case.get("sender_identity_bytes") == IDENTITY_BYTES, "sender identity length")
            expected_case = expected_cases.get(case.get("case_id"))
            require(expected_case is not None, "unplanned case id")
            require(
                all(case.get(name) == value for name, value in expected_case.items()),
                "case input differs from public seed expansion",
            )
            for name in ("receiver_identity_sha256", "sender_identity_sha256", "message_sha256", "ciphertext_sha256"):
                require(re.fullmatch(r"[0-9a-f]{64}", case.get(name, "")), name)
            checks = case.get("checks")
            require(type(checks) is dict and set(checks) == set(CHECK_NAMES), "case check names")
            require(all(checks[name] is True for name in CHECK_NAMES), "case check result")
            tamper = case.get("tamper", {})
            require(tamper.get("component") == "byteauth.inner_bytes", "tamper component")
            require(tamper.get("wire_length_unchanged") is True, "tamper wire length")
            require(tamper.get("canonical_loader_accepted") is True, "parse-preserving tamper")
            require(type(tamper.get("byte_offset")) is int and tamper["byte_offset"] >= 0, "tamper offset")
            require(tamper.get("xor_mask") in (1, 2, 4, 8, 16, 32, 64, 128), "tamper mask")
    require(report.get("totals") == {name: 12 for name in CHECK_NAMES}, "aggregate check totals")
    require(report.get("total_checks_passed") == report.get("total_checks_planned") == 60, "aggregate total")
    security = report.get("security", {})
    require(security.get("security_claim") == "none", "security claim")
    require(security.get("backend_admitted") is False, "backend admission")
    require(security.get("parameters_are_formal") is False, "formal parameters")
    require(security.get("functional_tests_are_security_proof") is False, "test/security separation")

    forbidden = {"receiver_identity_hex", "sender_identity_hex", "message_hex", "ciphertext_hex"}

    def scan(value):
        if type(value) is dict:
            require(not (set(value) & forbidden), "public report contains raw test/private material")
            for child in value.values():
                scan(child)
        elif type(value) is list:
            for child in value:
                scan(child)

    scan(report)
    return 60


def run(
    private_directory: Path,
    suite_file: Path,
    seed_hex: str,
    source_commit: str,
    timeout_seconds: int,
) -> dict:
    require(not private_directory.exists(), "choose a new private output directory")
    private_directory.mkdir(parents=True, mode=0o700)
    plan = build_plan(suite_file, seed_hex, source_commit)
    write_new(private_directory / "plan.json", plan)
    attempts = []
    for root_index, manifest in enumerate(plan["roots"]):
        directory = private_directory / f"root-{root_index}"
        directory.mkdir(mode=0o700)
        write_new(directory / "suite.json", plan["suite"])
        write_new(
            directory / "plan.json",
            dict(
                source_commit=source_commit,
                root_index=root_index,
                input_seed_hex=plan["input_seed_hex"],
                input_manifest=manifest,
            ),
        )
        write_new(directory / "attempt.pending", b"one predeclared attempt; never replace a failure\n")
        started = time.perf_counter()
        process = _run_child(directory, timeout_seconds)
        process.update(root_index=root_index, directory=str(directory), wall_seconds=time.perf_counter() - started)
        attempts.append(process)
        print(
            json.dumps(
                dict(root=root_index, returncode=process["returncode"], timed_out=process["timed_out"])
            ),
            flush=True,
        )
    report = _aggregate(plan, attempts)
    write_new(private_directory / "report.json", report)
    require(report["status"] == "passed", "one or more predeclared roots failed; no sample was replaced")
    validate_public_report(report, expected_commit=source_commit)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "worker", "verify"))
    parser.add_argument("--private-directory", type=Path)
    parser.add_argument("--suite-file", type=Path, default=Path("ci/c-combinations.json"))
    parser.add_argument("--input-seed")
    parser.add_argument("--source-commit")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.mode == "worker":
        if args.private_directory is None:
            parser.error("worker requires --private-directory")
        _root_worker(args.private_directory.resolve())
        return
    if args.mode == "verify":
        if args.report is None:
            parser.error("verify requires --report")
        count = validate_public_report(json.loads(args.report.read_bytes()))
        print(f"validated {count} random-batch checks")
        return
    if not args.input_seed or not args.source_commit:
        parser.error("plan/run require --input-seed and --source-commit")
    if args.mode == "plan":
        plan = build_plan(args.suite_file, args.input_seed, args.source_commit)
        print(json.dumps(plan, indent=2, sort_keys=True))
        return
    if args.private_directory is None:
        parser.error("run requires --private-directory")
    report = run(
        args.private_directory.resolve(),
        args.suite_file,
        args.input_seed,
        args.source_commit,
        args.timeout_seconds,
    )
    print(json.dumps(dict(status=report["status"], checks=report["total_checks_passed"])))


if __name__ == "__main__":
    main()
