"""Exhaustive optimistic bit-interval screen of the current full H/G domain.

No keys, lattice estimator or sampling. For each n and modulus bit length,
use the largest q (even if composite), smallest root width and smallest
noise. A rejected optimistic interval contains no passing actual profile.
Passing intervals are only necessary conditions, not candidate admission.
"""

import argparse
from fractions import Fraction
import json
from math import isqrt
from pathlib import Path

from ibme.hibe.mp12_structured.params import output_width
from ibme.lattice.chkp.joint_parameters import evaluate_noise


def optimistic_interval(n, q_bits, *, strict_noise_prerequisite=False):
    if (type(n) is not int or not 2 <= n <= 128 or type(q_bits) is not int
            or not 2 <= q_bits <= 61 or type(strict_noise_prerequisite) is not bool):
        raise ValueError("current exact n/bit domain and boolean prerequisite required")
    q = 2**q_bits-1
    w, root_r_squared = n*q_bits, 4*n
    m = 2*n+w
    parent_dimension, leaf_dimension = 2*m-w, 3*m
    b0 = 2*n*w*root_r_squared
    parent_squared = output_width(w, b0)
    b1 = parent_dimension*w*parent_squared
    leaf_squared = output_width(w, b1)
    q_alpha = isqrt(4*n)+1 if strict_noise_prerequisite else 1
    resources = (leaf_dimension-w <= 512 and leaf_dimension <= 8192
                 and (leaf_dimension-w)*w <= 2**22 and leaf_squared <= 2**192
                 and b1 <= 2**256)
    noise = None if q_alpha >= q else evaluate_noise(q=q, dimension=leaf_dimension,
        width_squared=leaf_squared, alpha=Fraction(q_alpha, q), error_bits=128,
        seed_bits=256, encapsulations=2**20)
    noise_ok = noise is not None and noise["conditional_noise_sufficient"]
    return dict(n=n, q_bits=q_bits, optimistic_q_upper=q,
        optimistic_root_R_squared=root_r_squared, optimistic_q_alpha=q_alpha,
        w=w, m=m, parent_sample_dimension=parent_dimension,
        complete_leaf_dimension=leaf_dimension, complete_leaf_prefix=leaf_dimension-w,
        parent_width_squared=str(parent_squared), parent_R_bound=str(b1),
        leaf_width_squared=str(leaf_squared), resource_necessary_conditions=resources,
        conditional_noise_necessary_condition=noise_ok,
        interval_not_excluded=bool(resources and noise_ok),
        prime_modulus_verified=False, actual_execution=False)


def feasibility_screen():
    rows = []
    feasible = {}
    for strict in (False, True):
        candidates = {}
        for n in range(2, 129):
            intervals = [optimistic_interval(n, k, strict_noise_prerequisite=strict)
                         for k in range(2, 62)]
            bits = [r["q_bits"] for r in intervals if r["interval_not_excluded"]]
            if bits:
                candidates[n] = bits
            rows.append(dict(n=n, strict_Regev_scaled_noise_prerequisite=strict,
                resource_not_excluded_q_bits=[r["q_bits"] for r in intervals
                                             if r["resource_necessary_conditions"]],
                noise_not_excluded_q_bits=[r["q_bits"] for r in intervals
                                          if r["conditional_noise_necessary_condition"]],
                combined_not_excluded_q_bits=bits))
        feasible[str(strict).lower()] = candidates
    maximum_n = max(feasible["false"], default=0)
    return dict(schema="STRUCTURED-HG-EXHAUSTIVE-OPTIMISTIC-DOMAIN/1",
        domain=dict(n_min=2, n_max=128, modulus_bits_min=2, modulus_bits_max=61,
                    root_R_squared_min="4*n", root_R_squared_max=str(2**80),
                    q_alpha_min=1, q_alpha_max=1024, error_bits=128,
                    seed_bits=256, encapsulations=2**20),
        evaluated_intervals=len(rows)*60, rows=rows,
        optimistic_intervals_by_prerequisite=feasible,
        complete_HG_necessary_n_upper=maximum_n,
        argument=["root and delegated squared widths are nondecreasing in root R squared width",
                  "with fixed modulus bit length the widths and dimensions are independent of q",
                  "q=2^k-1 maximizes the decode phase radius within its bit interval",
                  "q*alpha=1 minimizes continuous-noise width in the implemented integer domain",
                  "primality, snapshots, tape and actual-key precision can only exclude further inputs"],
        secret_list_enumeration=dict(
            reason="the first n public root columns are I; each rounded-noise coordinate is in [-8192,8192]",
            true_secret_in_list=True, entries_upper=str((2*8192+1)**maximum_n),
            exponent_ceiling=((2*8192+1)**maximum_n-1).bit_length(),
            unique_recovery_or_payload_distinguishing_proved=False,
            enumeration_runtime_measured=False,
            not_an_attack_success_or_security_estimate=True),
        consequence="increasing n within this version cannot reach a large-dimensional full H/G profile; implementation domain must change",
        no_feasible_interval_is_a_security_admission=True,
        root_or_key_generations=0, entropy_reads=0, sampler_calls=0,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = feasibility_screen()
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2)+"\n")
    print(json.dumps(dict(status="computed", intervals=report["evaluated_intervals"],
        complete_HG_necessary_n_upper=report["complete_HG_necessary_n_upper"],
        security_claim="none")))


if __name__ == "__main__":
    main()
