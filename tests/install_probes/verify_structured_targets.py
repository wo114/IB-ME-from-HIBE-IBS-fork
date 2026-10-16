"""Isolated installed replay of every target projection and the public n2 view."""

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
    parser.add_argument("--source-targets", type=Path, required=True)
    parser.add_argument("--source-negative-control", type=Path, required=True)
    parser.add_argument("--public-file", type=Path, required=True)
    parser.add_argument("--ciphertext-file", type=Path, required=True)
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
    from ibme.lattice.matrix_sampling import mp12_structured as tool
    from experiments.research.structured_target_screen import target_row
    from experiments.research.structured_identity_view import public_negative_control
    source = json.loads(args.source_targets.read_text(encoding="utf-8"))
    expected = [dict(row, estimator_results={}) for row in source["rows"]]
    expected_attack = json.loads(args.source_negative_control.read_text(encoding="utf-8"))
    def forbidden(*args, **kwargs):
        raise AssertionError("installed target replay requested a root, sampler or entropy")
    with patch.object(SecureRandom, "read", forbidden), \
            patch.object(tool.MatrixFiniteGaussian, "sample", forbidden), \
            patch.object(tool.StructuredPreimageSampler, "__init__", forbidden), \
            patch.object(tool.StructuredTrapdoor, "__post_init__", forbidden):
        actual = [target_row(row["n"]) for row in source["rows"]]
        attack = public_negative_control(args.public_file, args.ciphertext_file)
    if digest(actual) != digest(expected) or digest(attack) != digest(expected_attack):
        raise AssertionError("installed target definitions/budgets or original public attack differ")
    providers = {}
    for name, module in sorted(sys.modules.items()):
        if name.split(".")[0] not in ("ibme", "experiments"):
            continue
        for directory in getattr(module, "__path__", ()):
            Path(directory).resolve().relative_to(site)
        origin = getattr(module, "__file__", None)
        if origin is not None:
            path = Path(origin).resolve(strict=True)
            providers[name] = dict(path=path.relative_to(site).as_posix(),
                                  sha256=sha256(path.read_bytes()).hexdigest())
    report = dict(schema="A-STRUCTURED-TARGETS-INSTALLED-REPLAY/1", status="passed",
        isolated_python=True, cwd_outside_checkout=True, sole_project_provider_root=True,
        projected_rows_recomputed=len(actual), source_projection_sha256=digest(expected),
        installed_projection_sha256=digest(actual), source_attack_sha256=digest(expected_attack),
        installed_attack_sha256=digest(attack), estimator_calls_reexecuted=0,
        original_public_ciphertext_replayed=True, private_inputs_read=0,
        entropy_reads=0, root_or_key_generations=0, sampler_calls=0,
        providers=providers, provider_count=len(providers),
        security_claim="none", backend_admitted=False, parameters_are_formal=False)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="passed", target_rows=len(actual),
        providers=len(providers), original_public_attack=True)))


if __name__ == "__main__": main()
