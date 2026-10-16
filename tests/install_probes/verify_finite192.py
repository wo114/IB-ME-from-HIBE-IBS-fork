"""Outside-cwd, isolated installed v2 recovery of one original saved tree."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from unittest.mock import patch


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--source-budget", type=Path, required=True)
    parser.add_argument("--legacy-budget", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[2]
    if (not sys.flags.isolated or args.output.exists()
            or Path.cwd().resolve().is_relative_to(checkout)):
        raise ValueError("isolated Python, outside cwd and a new receipt required")
    site = args.site.resolve(strict=True)
    sys.path.insert(0, str(site))
    from ibme.core.randomness import SecureRandom
    from ibme.assembly import SuiteConfig, validate_suite
    from ibme.hibe.mp12_structured import StructuredHIBEParams, StructuredHIBEParams192
    from experiments.research.structured_finite192_probe import selected_registry
    from experiments.research.structured_framework_probe import restore
    from experiments.research.structured_service_budget import service_budget
    expected = json.loads(args.source_budget.read_text(encoding="utf-8"))
    legacy_expected = json.loads(args.legacy_budget.read_text(encoding="utf-8"))
    if "public_budget" in expected:
        expected = expected["public_budget"]
    reads = 0
    def forbidden(*args, **kwargs):
        nonlocal reads
        reads += 1
        raise AssertionError("installed v2 recovery attempted fresh entropy")
    # The actual private bytes stay in the explicitly supplied ignored store.
    before = {p.name:sha256(p.read_bytes()).hexdigest()
              for p in args.private_directory.glob("*.bin")}
    if not before or not (args.private_directory/"completed").is_file():
        raise ValueError("completed original private tree required")
    with patch.object(SecureRandom, "read", forbidden):
        actual = service_budget(StructuredHIBEParams192())
        if digest(service_budget(StructuredHIBEParams())) != digest(legacy_expected):
            raise AssertionError("legacy v1 probability ledger changed")
        if digest(actual) != digest(expected):
            raise AssertionError("installed/source finite192 ledgers differ")
        restored = restore(args.private_directory, registry=selected_registry())
        config = SuiteConfig.from_json((args.private_directory/"suite.json").read_bytes())
        rejected = not validate_suite(config).ok
        if not rejected:
            raise AssertionError("default v1 registry accepted a v2 suite")
        if sha256(StructuredHIBEParams().to_bytes()).hexdigest() != "d567a43d2799de8086ab501e8d03306eff2b3153e9f587fab227bb964d6f870a":
            raise AssertionError("v1 public parameter bytes changed")
    after = {p.name:sha256(p.read_bytes()).hexdigest()
             for p in args.private_directory.glob("*.bin")}
    if before != after or reads:
        raise AssertionError("installed recovery mutated state or consumed entropy")
    providers = {}
    for name, module in sorted(sys.modules.items()):
        if name.split(".")[0] not in ("ibme", "experiments"):
            continue
        for folder in getattr(module, "__path__", ()):
            Path(folder).resolve().relative_to(site)
        origin = getattr(module, "__file__", None)
        if origin is not None:
            path = Path(origin).resolve(strict=True)
            providers[name] = dict(path=path.relative_to(site).as_posix(),
                                  sha256=sha256(path.read_bytes()).hexdigest())
    report = dict(schema="A-FINITE192-INSTALLED-RESTORE/1", status="passed",
        isolated_python=True, cwd_outside_checkout=True, sole_project_provider_root=True,
        providers=providers, provider_count=len(providers), restored=restored,
        source_budget_sha256=digest(expected), installed_budget_sha256=digest(actual),
        probability_exponent=actual["modeled_probability_dyadic_exponent"],
        default_v1_registry_rejected_v2=rejected, legacy_v1_parameter_bytes_unchanged=True,
        legacy_v1_probability_ledger_unchanged=True,
        original_private_state_unchanged=True, private_values_exported=False,
        entropy_reads=reads, new_roots=0, new_keys=0,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="passed", provider_count=len(providers),
                         matching_paths=restored["restored_matching_paths"], entropy_reads=reads)))


if __name__ == "__main__":
    main()
