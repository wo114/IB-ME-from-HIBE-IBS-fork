"""Refresh current SRGG delivery bindings, without changing numeric evidence.

Historical commits and sampling receipts are retained. This script updates only
the current, in-place delivery envelopes already maintained by the DeepSeek v3
branch. It neither draws entropy nor establishes any probability/security claim.
Run from the repository with standard Python; then run the independent verifiers.
"""
from hashlib import sha256
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[4]
DELIVERY = ROOT / "docs/research/team-b-delivery"
SRGG = ROOT / "experiments/research/candidates/srgg"
CHANGED = set()


def raw(path):
    data = path.read_bytes()
    return data.replace(b"\r\n", b"\n") if path.suffix != ".pdf" else data


def digest(path):
    return sha256(raw(path)).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    if load(path) == value:
        return
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if path.read_bytes() != encoded:
        path.write_bytes(encoded)
        CHANGED.add(path.relative_to(ROOT).as_posix())


def refresh_maps(value):
    if isinstance(value, list):
        for item in value:
            refresh_maps(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in {"selected_current_source_sha256", "source_sha256",
                       "current_source_sha256", "dependent_file_sha256",
                       "current_dependency_sha256"} and isinstance(item, dict):
                for name in item:
                    path = ROOT / name
                    if path.is_file() and path.resolve().is_relative_to(ROOT):
                        item[name] = digest(path)
            elif isinstance(item, (dict, list)):
                refresh_maps(item)


def manifests():
    for path in sorted(DELIVERY.glob("2026-10-18-srgg-*/MANIFEST.json")):
        value = load(path)
        for key in ("entries", "files"):
            entries = value.get(key)
            if not isinstance(entries, dict):
                continue
            for name, entry in entries.items():
                target = ROOT / name
                if not target.is_file() or not target.resolve().is_relative_to(ROOT):
                    raise ValueError("missing manifest dependency: " + name)
                if isinstance(entry, dict) and "sha256" in entry:
                    entry["sha256"] = digest(target)
                    if "bytes" in entry:
                        entry["bytes"] = len(raw(target))
                elif isinstance(entry, str) and len(entry) == 64:
                    entries[name] = digest(target)
        write(path, value)


def set_pin(path, name, target):
    text = path.read_text(encoding="utf-8")
    text, count = re.subn(name + r' = "[0-9a-f]{64}"',
                         name + ' = "' + digest(target) + '"', text)
    if count != 1:
        raise ValueError("missing current pin: " + name)
    if path.read_bytes() != text.encode():
        path.write_bytes(text.encode())
        CHANGED.add(path.relative_to(ROOT).as_posix())


def current_bound_envelopes():
    # These are current v3 mathematical/audit envelopes, not the historical
    # runtime/performance measurements or initial-failure/lifecycle receipts.
    names = {
        "2026-10-18-srgg-finite-chain": ("finite-fixed-root.json", "joint-fixed-root.json"),
        "2026-10-18-srgg-closure-followup": ("schur-fixed-root-numerical-normalizer.json",),
        "2026-10-18-srgg-covariance-correspondence": ("covariance-correspondence.json",),
        "2026-10-18-srgg-strong-game": ("strong-game.json",),
        "2026-10-18-srgg-service-resource-envelope": ("service-resource-envelope.json",),
        "2026-10-18-srgg-structural-attack-followup": ("structural-attack-followup.json",),
    }
    for folder, files in names.items():
        for name in files:
            path = DELIVERY / folder / name
            value = load(path)
            refresh_maps(value)
            write(path, value)
    finite = DELIVERY / "2026-10-18-srgg-finite-chain"
    set_pin(SRGG / "paper_schur_joint_bound_audit.py", "FINITE_REPORT_SHA256",
            finite / "finite-fixed-root.json")
    value = load(finite / "joint-fixed-root.json")
    value["finite_report_sha256"] = digest(finite / "finite-fixed-root.json")
    write(finite / "joint-fixed-root.json", value)
    for folder, name in (("2026-10-18-srgg-strong-game", "strong-game.json"),
                         ("2026-10-18-srgg-covariance-correspondence", "covariance-correspondence.json")):
        package = DELIVERY / folder
        set_pin(package / "verify_delivery.py", "RECEIPT_SHA256", package / name)
        value = load(package / "validation.json")
        value["receipt"]["sha256"] = digest(package / name)
        write(package / "validation.json", value)
    package = DELIVERY / "2026-10-18-srgg-service-resource-envelope"
    value = load(package / "validation.json")
    value["frozen_report_sha256"] = digest(package / "service-resource-envelope.json")
    write(package / "validation.json", value)


def predecessor_envelopes():
    finite = DELIVERY / "2026-10-18-srgg-finite-chain"
    previous = DELIVERY / "2026-10-18-srgg-source-schur"
    source = DELIVERY / "2026-10-18-srgg-source-issuance"
    history = DELIVERY / "2026-10-18-srgg-history-law-followup"
    random = DELIVERY / "2026-10-18-srgg-random-key-sign-law"
    module = SRGG / "paper_source_issuance_bridge.py"
    text = module.read_text(encoding="utf-8")
    for key, path in (("FINITE_MANIFEST_LF_SHA256", finite / "MANIFEST.json"),
                      ("PREVIOUS_MANIFEST_SHA256", previous / "MANIFEST.json")):
        text, count = re.subn(key + r' = "[0-9a-f]{64}"', key + ' = "' + digest(path) + '"', text)
        if count != 1:
            raise ValueError("missing source pin: " + key)
    if module.read_bytes() != text.encode():
        module.write_bytes(text.encode())
        CHANGED.add(module.relative_to(ROOT).as_posix())
    verifier = source / "verify_delivery.py"
    text = verifier.read_text(encoding="utf-8")
    for key, path in (("FINITE_MANIFEST_LF_SHA256", finite / "MANIFEST.json"),
                      ("PREVIOUS_MANIFEST_SHA256", previous / "MANIFEST.json")):
        text, count = re.subn(key + r' = "[0-9a-f]{64}"', key + ' = "' + digest(path) + '"', text)
        if count != 1:
            raise ValueError("missing source-issuance verifier pin: " + key)
    if verifier.read_bytes() != text.encode():
        verifier.write_bytes(text.encode())
        CHANGED.add(verifier.relative_to(ROOT).as_posix())
    value = load(source / "source-issuance.json")
    refresh_maps(value)
    for row in value["rows"]:
        row["inherited_source_manifest_sha256"] = digest(previous / "MANIFEST.json")
        row["finite_report_sha256"] = digest(finite / "finite-fixed-root.json")
        row["joint_report_sha256"] = digest(finite / "joint-fixed-root.json")
        binding = row["finite_chain_manifest_binding"]
        binding["normalized_lf_sha256"] = digest(finite / "MANIFEST.json")
        refresh_maps(binding)
    write(source / "source-issuance.json", value)
    value = load(source / "validation.json")
    value.update(receipt_sha256=digest(source / "source-issuance.json"),
                 finite_chain_manifest_normalized_lf_sha256=digest(finite / "MANIFEST.json"),
                 inherited_source_manifest_sha256=digest(previous / "MANIFEST.json"))
    write(source / "validation.json", value)
    value = load(history / "history-law.json")
    for row in value["rows"]:
        binding = row["authenticated_predecessors"]
        binding.update(source_issuance_sha256=digest(source / "source-issuance.json"),
                       source_package_manifest_sha256=digest(source / "MANIFEST.json"),
                       finite_sha256=digest(finite / "finite-fixed-root.json"),
                       joint_sha256=digest(finite / "joint-fixed-root.json"))
    write(history / "history-law.json", value)
    value = load(random / "random-key-sign-law.json")
    value["predecessor"].update(history_law_sha256=digest(history / "history-law.json"),
                                history_manifest_sha256=digest(history / "MANIFEST.json"))
    write(random / "random-key-sign-law.json", value)
    value = load(random / "validation.json")
    value["report_generation"]["frozen_report_sha256"] = digest(random / "random-key-sign-law.json")
    write(random / "validation.json", value)


def new_envelopes():
    for name in ("2026-10-18-srgg-distribution-guard-deepseek",
                 "2026-10-18-srgg-distribution-chain"):
        package = DELIVERY / name
        namespace = runpy.run_path(str(package / "verify_delivery.py"))
        path = package / "validation.json"
        value = load(path)
        value["current_dependency_sha256"] = {
            relative: digest(ROOT / relative)
            for relative in sorted(namespace["REQUIRED_DEPENDENCIES"])}
        value["frozen_receipts"] = {
            relative: digest(ROOT / relative)
            for relative in sorted(namespace["REQUIRED_FROZEN"])}
        if name.endswith("-chain"):
            report_path = package / "distribution-chain.json"
            report = load(report_path)
            old = report["dependency_sha256"]
            current = {relative: digest(ROOT / relative) for relative in old}
            if old != current:
                value.setdefault("witness_replay_dependency_sha256_before_pin_refresh", old)
                value["witness_replay_binding_note"] = (
                    "Current source pins were refreshed after fixture replay. The changed "
                    "issuance-bridge constants authenticate predecessor files; the numerical "
                    "results and six lifecycle witnesses are retained, not re-estimated.")
                report["dependency_sha256"] = current
                write(report_path, report)
            value["delivery_file_sha256"] = {
                relative: digest(package / relative)
                for relative in sorted(namespace["REQUIRED_DELIVERY"])}
            value["report_sha256"] = value["delivery_file_sha256"]["distribution-chain.json"]
        else:
            value["digests"] = {
                relative: digest(ROOT / relative)
                for relative in sorted(namespace["REQUIRED_DIGESTS"])}
            report = load(package / "distribution-guard.json")
            value["probes"] = report["probes"]
            for row in value["rows"]:
                current = next(item for item in report["rows"] if
                               (item["profile"], item["interpretation"]) ==
                               (row["profile"], row["interpretation"]))
                row["setup_attempts"] = current["setup_attempts"]
                row["setup_gate_rejections"] = current["setup_gate_rejections"]
                row["one_sign_call_dyadic_upper"] = current["sign_call"]["one_sign_call_tv_dyadic_upper"]
        value["repair_provenance"] = {
            "date": "2026-10-19", "unified_guard_input_commit": "7131eaa60e874a1a48a355c6369de7efc3185873",
            "chain_input_commit": "9af579d32d574a4cf626ec40a258db721c89e105",
            "historical_test_records_preserved": True,
            "current_repair_validation": "../2026-10-19-srgg-deepseek-repairs/validation.json",
            "new_security_proof_attempted": False,
            "parameters_or_sampling_widths_changed": False}
        write(path, value)


def main():
    # Dependencies form a finite DAG: manifests bind predecessors; the pinned
    # source-issuance module is intentionally outside its predecessor manifests.
    for _ in range(24):
        before = {p: digest(p) for p in DELIVERY.glob("2026-10-18-srgg-*/*.json")}
        before[SRGG / "paper_source_issuance_bridge.py"] = digest(SRGG / "paper_source_issuance_bridge.py")
        pin_verifier = DELIVERY / "2026-10-18-srgg-source-issuance/verify_delivery.py"
        before[pin_verifier] = digest(pin_verifier)
        before[SRGG / "paper_schur_joint_bound_audit.py"] = digest(SRGG / "paper_schur_joint_bound_audit.py")
        current_bound_envelopes()
        for path in DELIVERY.glob("2026-10-18-srgg-*/validation.json"):
            value = load(path)
            refresh_maps(value)
            write(path, value)
        manifests()
        predecessor_envelopes()
        new_envelopes()
        if all(digest(path) == expected for path, expected in before.items()):
            print(json.dumps({"status": "stable", "changed_files": sorted(CHANGED)}))
            return
    raise RuntimeError("current delivery bindings did not reach a fixed point")


if __name__ == "__main__":
    main()
