"""Inspect public IBS descriptors/parameters and preflight explicit candidates.

Run collection in the prescribed Sage environment; --verify uses stdlib/Git.
No backend factory, key generation, signing, or private-state reader is called.
"""

import argparse
from dataclasses import asdict, is_dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parents[3]
ALGORITHMS = (
    "luo-matrix", "luo-module", "srgg2025", "wang-pw", "cert-ml-dsa",
    "cert-falcon", "foo-li", "yu2026", "sageloli-sis", "sageloli-rsis",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def public_record(value):
    if is_dataclass(value):
        return public_record(asdict(value))
    if isinstance(value, dict):
        return {str(k): public_record(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [public_record(v) for v in value]
    if value is None or type(value) in (str, int, bool, float):
        return value
    return str(value)


def collect(source_commit, output, suite_file):
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit), "pin the full source commit")
    from ibme.core.randomness import SecureRandom

    entropy_reads = 0

    def denied_read(self, count):
        nonlocal entropy_reads
        entropy_reads += 1
        raise RuntimeError("inventory must not consume project private randomness")

    previous_read = SecureRandom.read
    SecureRandom.read = denied_read
    try:
        from ibme.assembly import BackendRegistry, default_registry, make_suite, validate_suite
        from ibme.ibs.foo_li.registration import backend_spec as foo_spec
        from ibme.ibs.yu.registration import backend_spec as yu_spec
        from ibme.ibs.luo_module_profiles import c64b_params
        from ibme.ibs.srgg.structured_registration import backend_spec as structured_spec
        from experiments.research.candidates.sageloli.config import SISParams, RSISParams
        from experiments.research.candidates.srgg.paper_profiles import profile

        registry = default_registry()
        listing = registry.list()
        rows = []
        by_id = {row["id"]: row for row in listing["ibs"]}
        for identifier in ALGORITHMS:
            spec = registry.get("ibs", identifier)
            rows.append(dict(id=identifier, default_selector=by_id[identifier],
                             presets=public_record(spec.presets or {})))

        independent = [foo_spec(), yu_spec(), structured_spec()]
        standalone = [dict(id=s.id, version=s.version,
                           presets=public_record(s.presets),
                           registered_in_default_selector=any(
                               r["id"] == s.id and r["available"] for r in listing["ibs"]))
                      for s in independent]
        standalone.extend([
            dict(id="sageloli-sis", params=public_record(SISParams()),
                 registered_in_default_selector=False),
            dict(id="sageloli-rsis", params=public_record(RSISParams()),
                 registered_in_default_selector=False),
            dict(id="srgg-paper", published_profiles=[public_record(profile(name))
                 for name in ("PARAM-I", "PARAM-II", "PARAM-III")],
                 published_reports_are_not_local_security_acceptance=True,
                 registered_in_default_selector=False),
        ])

        selection = dict(hibe="latte", hibe_params="seed32", ibs="luo-module",
                         ibs_params=public_record(c64b_params()), transport="hybrid",
                         protocol="byteauth-v1", signature_format="compact", allow_mock=False)
        suite = make_suite(**selection, registry=registry)
        preflight = validate_suite(suite, registry=registry).to_dict()
        require(preflight["ok"], "C64B candidate preflight failed: " + str(preflight))

        separate_preflights = []
        for spec in independent[:2]:
            specs = [registry.get(role, row["id"]) for role, entries in listing.items()
                     for row in entries if not (role == "ibs" and row["id"] == spec.id)]
            scratch = BackendRegistry(specs + [spec])
            candidate = make_suite(hibe="latte", hibe_params="seed32", ibs=spec.id,
                                   ibs_params=next(iter(spec.presets)), transport="hybrid",
                                   protocol="byteauth-v1", signature_format="reference",
                                   registry=scratch)
            separate_preflights.append(dict(id=spec.id, caller_owned_registry_only=True,
                report=validate_suite(candidate, registry=scratch).to_dict()))

        providers = {}
        for module_name, module in tuple(sys.modules.items()):
            if module_name == "__main__":
                continue
            path = getattr(module, "__file__", None)
            if not path or not str(path).endswith(".py"):
                continue
            resolved = Path(path).resolve()
            try:
                relative = resolved.relative_to(ROOT).as_posix()
            except ValueError:
                continue
            if relative.startswith(("src/", "experiments/")):
                providers[relative] = sha256(resolved.read_bytes()).hexdigest()

        available = [r["id"] for r in rows if r["default_selector"]["available"]]
        unavailable = [r["id"] for r in rows if not r["default_selector"]["available"]]
        require(entropy_reads == 0, "unexpected private randomness")
        result = dict(schema="PUBLIC-IBS-INVENTORY/1", status="passed",
            audited_runtime_source_commit=source_commit,
            audit_script_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
            counts=dict(complete_research_ibs_algorithms=len(ALGORITHMS),
                        default_selector_algorithms=len(available),
                        not_in_default_selector_algorithms=len(unavailable)),
            default_selector_algorithm_ids=available, not_in_default_selector_algorithm_ids=unavailable,
            algorithm_rows=rows, independent_implementations=standalone,
            separate_descriptor_preflights=separate_preflights,
            c64b_candidate=dict(selection=selection, suite=suite.to_dict(), preflight=preflight,
                                 status="preflight_only", actual_new_combination_execution=False),
            source_providers=providers, project_secure_random_read_calls=entropy_reads,
            key_generation_signing_or_private_state_read_performed=False,
            security_claim="none", backend_admitted=False, parameters_are_formal=False)
    finally:
        SecureRandom.read = previous_read

    require(not output.exists(), "refusing to overwrite existing audit output: " + str(output))
    suite_record = [dict(name="latte3-hybrid-luo-module-c64b-compact-byteauth-v1",
        parameter_labels=dict(hibe="research", ibs="research"),
        selection=selection)]
    if suite_file.exists():
        require(json.loads(suite_file.read_text(encoding="utf-8")) == suite_record,
                "existing public suite differs; choose a new filename")
    else:
        suite_file.parent.mkdir(parents=True, exist_ok=True)
        with suite_file.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(suite_record, handle, indent=2, sort_keys=True)
            handle.write("\n")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(dict(status="passed", counts=result["counts"], providers=len(providers),
                         project_secure_random_read_calls=entropy_reads,
                         c64b_preflight=preflight["ok"]), indent=2))


def verify(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    require(data["schema"] == "PUBLIC-IBS-INVENTORY/1", "unexpected schema")
    require(data["audit_script_sha256"] == sha256(Path(__file__).read_bytes()).hexdigest(),
            "audit script changed")
    commit = data["audited_runtime_source_commit"]
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid source commit")
    for relative, digest in data["source_providers"].items():
        require(relative.startswith(("src/", "experiments/")) and ".." not in Path(relative).parts,
                "unexpected provider path")
        blob = subprocess.check_output(["git", "show", commit + ":" + relative], cwd=ROOT)
        working_bytes = (ROOT / relative).read_bytes()
        require(sha256(working_bytes).hexdigest() == digest,
                "provider changed after collection: " + relative)
        # Windows core.autocrlf creates CRLF Python sources on the WSL mount.
        # Keep the actual loaded-byte hash, and compare Git after ONLY CRLF
        # normalization. No whitespace/content normalization is permitted.
        require(blob.replace(b"\r\n", b"\n") == working_bytes.replace(b"\r\n", b"\n"),
                "provider content differs from pinned Git: " + relative)
    ids = data["default_selector_algorithm_ids"] + data["not_in_default_selector_algorithm_ids"]
    require(sorted(ids) == sorted(ALGORITHMS), "algorithm count or identity mismatch")
    require(data["project_secure_random_read_calls"] == 0, "private entropy was consumed")
    require(data["key_generation_signing_or_private_state_read_performed"] is False,
            "inventory crossed execution boundary")
    require(data["c64b_candidate"]["status"] == "preflight_only", "preflight scope changed")
    require(data["c64b_candidate"]["preflight"]["ok"], "candidate preflight failed")
    print(json.dumps(dict(status="passed", providers=len(data["source_providers"]),
                         counts=data["counts"], private_states_read=0), indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--suite-file", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
    else:
        parser.error("collection requires --source-commit, --output and --suite-file") if not all(
            (args.source_commit, args.output, args.suite_file)) else None
        collect(args.source_commit, args.output, args.suite_file)
