"""No-entropy ABB same-input execution/target screen. Estimates are not runs."""

import argparse
import json
from pathlib import Path

from sage.all import ZZ

from ibme.hibe.abb_rom import ABBTrapGenParams, abb_parameter_screen


def build_report():
    profiles = [
        ("root-bit-execution-only", ABBTrapGenParams(1, 549755813911, 56, 56, 192, hadamard_scale=32)),
        ("larger-root-statistical-distance", ABBTrapGenParams(1, 2**61 - 1, 224, 224, 576, hadamard_scale=48)),
        ("wide-q-conditional-noise-target", ABBTrapGenParams(1, int(ZZ(2**159).next_prime()), 320, 320, 960,
                                                          hadamard_scale=56)),
    ]
    reports = []
    for name, params in profiles:
        report = abb_parameter_screen(params)
        report["name"] = name
        report["hypothetical_signed_256bit_basis_bytes_each"] = params.dimension**2 * 32
        report["hypothetical_basis_width_is_not_actual_codec"] = True
        reports.append(report)
    # First finite input rejection is established before constructing a
    # disallowed root. None of its Gaussian/noise conditions are evaluated.
    targets = []
    for n in [2, 128, 256]:
        m_min = 6 * n * 160 + 1
        targets.append({"n": n, "modulus_bits": 160,
            "conservative_ABB_dimension_minimum": m_min,
            "first_execution_blocker": "AP09 complete-basis hard dimension 1536",
            "root_executed": False, "sampling_or_noise_evaluated": False,
            "minimum_basis_entry_count": m_min**2,
            "hypothetical_signed_256bit_basis_bytes_each": m_min**2 * 32,
            "hypothetical_basis_width_is_not_actual_codec": True})
    return {"schema": "ABB-ROM-PARAMETER-PROBE/1", "profiles": reports, "larger_n_targets": targets,
        "parameter_source": "ABB10 section4 / AP09 section3.3 with explicit project sufficient bounds",
        "root_or_identity_entropy_consumed": 0,
        "n1_inputs_are_hardness_negative_controls": True,
        "full_backend_available": False, "security_claim": "none",
        "backend_admitted": False, "parameters_are_formal": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        raise FileExistsError("new public report required")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(build_report(), stream, indent=2)
        stream.write("\n")
    print("3 same-input profiles, 3 larger-n blocked targets; no key generation")


if __name__ == "__main__":
    main()
