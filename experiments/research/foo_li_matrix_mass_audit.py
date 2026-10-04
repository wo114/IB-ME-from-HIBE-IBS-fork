"""Finite upper bounds for a draft's prime-q good-matrix mass condition.

Sage MPFI evaluates a scalar theta-tail bound; no matrices, Gaussian samples,
keys or signatures are generated. The probability inequality is derived in the
round-six report, not a claim that Foo-Li's security proof has been completed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, ZZ, RealIntervalField
from sage.version import version as sage_version

from .gaussian_reference import interval_bounds


def good_matrix_bound(*, q, n, m, s, epsilon, precision_bits=192):
    """Bound rank failure plus Pr[theta_A(s)>epsilon] for uniform A.

    Research resource range is explicit. It does not restrict the mathematical
    inequality in the report, but unsupported inputs do not receive a certificate.
    Returned decimals are for display; exact rational upper bounds are decisive.
    """
    if any(isinstance(v,bool) or not isinstance(v,int) for v in (q,n,m,precision_bits)):
        raise ValueError("Dimensions, modulus and precision must be integers")
    if not (2 <= q <= 2**32 and ZZ(q).is_prime() and 1 <= n <= m <= 256):
        raise ValueError("Need prime q<=2^32 and 1<=n<=m<=256")
    if not 96 <= precision_bits <= 512:
        raise ValueError("precision_bits must be in [96,512]")
    if any(isinstance(v,(bool,float)) for v in (s,epsilon)):
        raise ValueError("s and epsilon must be exact rationals")
    s,epsilon = QQ(s),QQ(epsilon)
    if not 1 <= s <= 64 or not 0 < epsilon < 1:
        raise ValueError("Need 1<=s<=64 and 0<epsilon<1")
    field = RealIntervalField(precision_bits)
    # Very tiny positive bounds may be conservatively enlarged for compact
    # serialization; this floor is an UPPER-bound relaxation, not underflow.
    def upper(value):
        endpoint = field(value).upper().exact_rational()
        return max(endpoint,QQ(1)/2**512) if endpoint > 0 else endpoint
    a = (-field.pi()*field(s*s)).exp()
    scalar_tail_upper = upper(2*a/(1-a**3))
    # Exact rational powering is followed by an outward dyadic rounding, to
    # avoid archiving enormous rational denominators created by the mth power.
    theta_z_upper = upper((1+scalar_tail_upper)**m-1)
    nonzero_cosets_upper = upper((q**n-1)*(QQ(1)/q+QQ(1)/s)**m)
    expected_theta_upper = upper(theta_z_upper+nonzero_cosets_upper)
    rank_failure_upper = upper(sum((QQ(q)**(i-m) for i in range(n)),QQ(0)))
    bad_unclamped = upper(rank_failure_upper+expected_theta_upper/epsilon)
    eta = 2*epsilon/(1+epsilon)
    # Poisson summation gives rho_s(Z)>=s. This is a mathematical lower
    # bound, not a numerical approximation to the normalizer.
    atom_unclamped = upper(QQ(q)**n/((1-eta)*s**m))
    return {"parameters":{"q":q,"n":n,"m":m,"s":str(s),"epsilon":str(epsilon),
                "precision_bits":precision_bits},
        "uniform_A_rank_failure_upper":str(rank_failure_upper),
        "ambient_dual_theta_upper":str(theta_z_upper),
        "nonzero_cosets_expectation_upper":str(nonzero_cosets_upper),
        "expected_dual_theta_upper":str(expected_theta_upper),
        "bad_matrix_upper_unclamped":str(bad_unclamped),
        "bad_matrix_upper":str(min(QQ(1),bad_unclamped)),
        "pointwise_relative_image_error":str(eta),
        "conditional_column_max_atom_unclamped":str(atom_unclamped),
        "conditional_column_max_atom_upper":str(min(QQ(1),atom_unclamped)),
        "display_bad_matrix_approx":float(bad_unclamped),
        "covers_all_syndromes_on_good_A":True,
        "covers_wider_widths_on_same_good_A":True,
        "parameter_source":"hand-selected proof-arithmetic examples; no complete parameter chain",
        "security_claim":"none", "gaussian_samples":0}


def audit_report():
    return {"schema_version":1, "security_claim":"none", "proof_status":"WIP conditional ROM draft",
        "environment":{"python":sys.version.split()[0],"sage":sage_version,"platform":platform.platform()},
        "method":"exact rational rank and Markov bounds plus outward MPFI theta-tail arithmetic",
        "monte_carlo_repetitions":0,"matrices_generated":0,"gaussian_samples":0,
        "identity_length_bytes":None,"message_length_bytes":None,"rom_use":"none in arithmetic",
        "cases":[good_matrix_bound(q=17,n=1,m=32,s=6,epsilon="1/1099511627776"),
            good_matrix_bound(q=257,n=2,m=128,s=8,epsilon="1/18446744073709551616"),
            good_matrix_bound(q=7,n=1,m=2,s=1,epsilon="1/16")],
        "limitations":["No TrapGen, DelTrap or SampleD correctness/distribution certificate",
            "No complete SIS hardness estimate, signature norm or backend admission",
            "Small n examples are not secure cryptographic parameters; tiny TV is not security bits",
            "Proof assumptions and two-reduction adaptive coupling still require final review"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    value = json.dumps(audit_report(),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(value,encoding="utf-8",newline="\n")
    else:
        print(value,end="")


if __name__ == "__main__":
    main()
