"""Isolated wide-q public sampling and unchanged target-definition replay."""

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--source-targets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[2]
    if (not sys.flags.isolated or args.output.exists()
            or Path.cwd().resolve().is_relative_to(checkout)):
        raise ValueError("isolated Python, outside cwd and a new receipt required")
    site = args.site.resolve(strict=True)
    sys.path.insert(0, str(site))
    from sage.all import previous_prime
    from sage.version import version as sage_version
    from ibme.core.randomness import DeterministicRandom, SecureRandom
    from ibme.lattice.chkp.joint_parameters import smoothing_factor
    from ibme.lattice.matrix_sampling.prime_gadget import PrimeGadgetSampler
    from ibme.lattice.matrix_sampling.scalar import MatrixFiniteOptions
    from experiments.research.structured_target_screen import target_row
    source = json.loads(args.source_targets.read_text(encoding="utf-8"))
    expected = [dict(row, estimator_results={}) for row in source["rows"]]
    actual = [target_row(row["n"]) for row in source["rows"]]
    if digest(actual) != digest(expected):
        raise AssertionError("public gadget extraction changed target definitions or budgets")
    opts = MatrixFiniteOptions(tail_bits=192, gaussian_abort_bits=192,
        mass_bits=320, precision_bits=384, max_uniform_trials=256)
    q77 = next(row["complete_group"]["q"] for row in actual if row["n"] == 4096)
    cases = []
    for q, targets, source_rng, label in (
            (q77, (0, 1, q77-1), DeterministicRandom(b"A3-installed-q77-TEST"), "fixed-test"),
            (q77, (0, 1, q77-1), SecureRandom(), "system-public-sample"),
            (int(previous_prime(2**256)), (0,),
             DeterministicRandom(b"A3-installed-q256-TEST"), "fixed-test")):
        sampler = PrimeGadgetSampler(len(targets), q,
            20*smoothing_factor((q-1).bit_length(), 192), epsilon_bits=192, options=opts)
        values = sampler.sample(targets, rng=source_rng)
        equations = all(sum(2**j*values[i*sampler.k+j] for j in range(sampler.k)) % q == target
                        for i,target in enumerate(targets))
        if not equations:
            raise AssertionError("installed gadget coset equation failed")
        certificate = sampler.public_certificate()
        cases.append(dict(q=str(q), modulus_bits=q.bit_length(), rows=len(targets),
            width_squared=str(sampler.block.width_squared), epsilon_bits=192,
            canonical_syndromes=[str(value) for value in targets],
            randomness=label, complete_coset_equations=equations,
            expanded_product_basis_entries=0,
            certificate_sha256=digest(certificate),
            tv_upper_including_abort=certificate["tv_upper_including_abort"],
            random_tape_bytes=certificate["random_tape_bytes"]))
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
    report = dict(schema="A-WIDE-PRIME-GADGET-INSTALLED/1", status="passed",
        isolated_python=True, cwd_outside_checkout=True, sole_project_provider_root=True,
        providers=providers, provider_count=len(providers), sage=sage_version,
        python=sys.version.split()[0], finite_options=asdict(opts), public_sample_cases=cases,
        target_rows_recomputed=len(actual), source_projection_sha256=digest(expected),
        installed_projection_sha256=digest(actual), estimator_calls_reexecuted=0,
        HIBE_root_or_key_generations=0, private_inputs_read=0, private_values_exported=False,
        current_HIBE_or_wire_domain_extended=False,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="passed", public_sample_cases=len(cases),
                         targets=len(actual), providers=len(providers))))


if __name__ == "__main__":
    main()
