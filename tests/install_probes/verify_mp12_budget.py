"""Run with python -I outside the checkout against one installed package root."""

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
    parser.add_argument("--source-budget", type=Path, required=True)
    parser.add_argument("--source-domain", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not sys.flags.isolated or args.output.exists():
        raise ValueError("isolated Python and a new receipt required")
    checkout = Path(__file__).resolve().parents[2]
    if Path.cwd().resolve().is_relative_to(checkout):
        raise ValueError("installed replay must run outside the checkout")
    site = args.site.resolve(strict=True)
    sys.path.insert(0, str(site))
    from ibme.core.randomness import SecureRandom
    from ibme.hibe.mp12_structured import StructuredHIBEParams
    from ibme.lattice.matrix_sampling import mp12_structured as tool
    from experiments.research.structured_service_budget import service_budget
    from experiments.research.structured_feasibility import feasibility_screen
    def forbidden(*args, **kwargs):
        raise AssertionError("installed public ledger attempted a root, sample or entropy read")
    with patch.object(SecureRandom, "read", forbidden), \
            patch.object(tool.MatrixFiniteGaussian, "sample", forbidden), \
            patch.object(tool.StructuredPreimageSampler, "__init__", forbidden), \
            patch.object(tool.StructuredTrapdoor, "__post_init__", forbidden):
        budget = service_budget(StructuredHIBEParams())
        domain = feasibility_screen()
    source_budget = json.loads(args.source_budget.read_text(encoding="utf-8"))
    source_domain = json.loads(args.source_domain.read_text(encoding="utf-8"))
    if digest(budget) != digest(source_budget) or digest(domain) != digest(source_domain):
        raise AssertionError("installed/source public reports differ")
    providers = {}
    for name, module in sorted(sys.modules.items()):
        if name.split(".")[0] not in ("ibme", "experiments"):
            continue
        for folder in getattr(module, "__path__", ()):
            Path(folder).resolve().relative_to(site)
        origin = getattr(module, "__file__", None)
        if origin is not None:
            path = Path(origin).resolve(strict=True)
            relative = path.relative_to(site).as_posix()
            providers[name] = dict(path=relative, sha256=sha256(path.read_bytes()).hexdigest())
    report = dict(schema="A-PUBLIC-BUDGET-INSTALLED-REPLAY/1", status="passed",
        isolated_python=True, cwd_outside_checkout=True,
        sole_project_provider_root=True, providers=providers,
        provider_count=len(providers), source_budget_sha256=digest(source_budget),
        installed_budget_sha256=digest(budget), source_domain_sha256=digest(source_domain),
        installed_domain_sha256=digest(domain), entropy_reads=0, sampler_calls=0,
        root_or_key_generations=0, probability_exponent=budget["modeled_probability_dyadic_exponent"],
        complete_HG_necessary_n_upper=domain["complete_HG_necessary_n_upper"],
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="passed", providers=len(providers), entropy_reads=0)))


if __name__ == "__main__":
    main()
