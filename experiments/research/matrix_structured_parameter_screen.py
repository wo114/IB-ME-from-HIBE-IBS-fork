"""No-entropy root-role screen for the actual structured tool diagnostic inputs.

There is no ciphertext role: this batch has not implemented noisy encryption
or a HIBE backend. Cost comparators, finite root coupling and norm conditioning
are independent from the observed preimage equations and memory boundary.
"""

import argparse
from pathlib import Path
import json

from sage.all import ZZ
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian
from ibme.lattice.chkp.joint_parameters import smoothing_factor
from experiments.research.abb_rom.scaled_parameter_screen import run_estimators


def input_row(n, q, squared):
    if any(type(x) is not int for x in (n, q, squared)) or not 2 <= n <= 128 or not 3 <= q <= 2**61-1 or not 4*n <= squared <= 2**80:
        raise ValueError("exact structured diagnostic profile required")
    if q % 2 == 0 or not ZZ(q).is_prime(proof=True):
        raise ValueError("proven odd prime required")
    k, prefix = (q-1).bit_length(), 2*n
    w, dimension = n*k, prefix+n*k
    scalar = MatrixFiniteGaussian(squared, squared)
    entries = prefix*w
    factor = scalar.field(2).sqrt()*(-scalar.field.pi()/2).exp()*(1+scalar.theta)/(1-scalar.theta)
    if factor.upper() > 1/2:
        raise ValueError("root ideal norm-tail factor unverified")
    r2 = 4*smoothing_factor(w, 128)
    output_squared = max(7*r2*(1+entries*squared), 10*r2*(w+entries*squared))
    return dict(family="mp12-structured-tool-diagnostic", n=n, q=q, q_bits=k,
        root_R_squared=squared, prefix=prefix, gadget_columns=w, total_dimension=dimension,
        root_R_entries=entries, public_root_frobenius_bound=entries*squared,
        finite_root_R_scalar_coupling_upper=str(min(1, entries*scalar.tv_upper)),
        ideal_root_R_norm_abort_upper=f"2^-{entries}", finite_R_support_injective_mod_q=2*scalar.radius<q,
        SampleD_r_squared=r2, SampleD_output_squared=output_squared,
        root_lwe=dict(n=n, q=q, m=n, secret="small-Gaussian", squared_width=squared,
            independent_columns=w, target_columns_for_alternative_trapdoor=w,
            distribution="ideal small Gaussian secret/error; finite PMF and whole-R norm cutoff separate",
            attack_goal="one root column search/decision, not a full trapdoor recovery attack"),
        ciphertext_lwe=None, ciphertext_role_absence_reason="no noisy encryption/HIBE implemented in this tool batch",
        estimator_results={}, root_or_key_generated=False, entropy_bytes=0,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--estimator-path", type=Path, required=True)
    args=parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write('{"status":"public-input-screen-started"}\n')
    report=dict(schema="MP12-STRUCTURED-ACTUAL-INPUT-SCREEN/1",
        rows=[input_row(2, 257, 16), input_row(128, 65537, 529)],
        ciphertext_estimates_executed=False, whole_service_or_HIBE_security_estimated=False,
        cost_goal="limited Gaussian comparator for root role only; no safety admission",
        root_or_key_generations=0, entropy_bytes=0, security_claim="none",
        backend_admitted=False, parameters_are_formal=False)
    def save():
        args.output.write_text(json.dumps(report, indent=2)+"\n")
    run_estimators(report, args.estimator_path, checkpoint=save)
    save()


if __name__ == "__main__":
    main()
