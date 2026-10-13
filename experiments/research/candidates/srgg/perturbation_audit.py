"""Public whitelist audit of SRGG correlated perturbation and extraction.

Only public dimensions, equation counts and component error scalars leave the
audit. No actual witness, covariance, perturbation, gadget trace, target, seed,
or user vector is exported. This is not a complete SRGG IBS implementation.
"""

import argparse
from hashlib import sha256
import json

from sage.all import ZZ, PolynomialRing, matrix, vector

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer
from .algebra import Params, build_public, integer
from .audit import ROOT, PAPER, PAPER_SHA
from .geometry import Widths
from .perturbation import MasterPerturbation, extract_with_perturbation
from .sampling import GadgetSampler


def _independent_equations(params, public, target, result):
    """Check both equations directly in a Sage quotient ring."""
    polynomials = PolynomialRing(ZZ, "X")
    x = polynomials.gen()
    ring = polynomials.quotient(x**params.degree + 1, "a")
    def poly(values): return ring(polynomials(list(values)))
    def values(entries): return vector(ring, [poly(entry) for entry in entries])
    a = matrix(ring, [[poly(entry) for entry in row] for row in public.a])
    def zero_mod(entries):
        return all(all(int(c) % params.modulus == 0 for c in entry.lift().list())
                   for entry in entries)
    approximate = zero_mod(a * values(result.raw.raw_vector) - values(target) + values(result.raw.error))
    exact = zero_mod(a * values(result.reconstructed) - values(target))
    return approximate, exact


def audit(*, repetitions=64, rng=None):
    integer(repetitions, 1, 4096, "audit repetitions")
    if sha256((ROOT / PAPER).read_bytes()).hexdigest() != PAPER_SHA:
        raise ValueError("SRGG source PDF fingerprint differs")
    p, widths = Params(degree=2, rank=1, p=5, base=3, digits=1), Widths(512, 128, 4)
    source = SecureRandom() if rng is None else rng
    def uniform(bound): return draw_uniform_integer(source, bound)
    a_hat = tuple(tuple(tuple(uniform(p.modulus) for _ in range(p.degree))
                        for _ in range(p.rank)) for _ in range(p.rank))
    witness = tuple(tuple(tuple(uniform(2) - uniform(2) for _ in range(p.degree))
                          for _ in range(p.rank * p.digits)) for _ in range(2 * p.rank))
    public = build_public(p, a_hat, witness)
    target = tuple(tuple(uniform(p.modulus) for _ in range(p.degree)) for _ in range(p.rank))
    sampler, gadget = MasterPerturbation(p, witness, widths), GadgetSampler(p, 36)
    approximate, exact, changed, aborted = 0, 0, 0, 0
    for _ in range(repetitions):
        try:
            result = extract_with_perturbation(public, target, sampler, gadget,
                                              perturbation_rng=rng, gadget_rng=rng)
        except SamplingAbort:
            aborted += 1
            continue  # Retain the attempted count; do not retry or substitute.
        valid_raw, valid_hnf = _independent_equations(p, public, target, result)
        if not valid_raw or not valid_hnf:
            raise RuntimeError("independent SRGG extraction equation failed")
        approximate += int(valid_raw)
        exact += int(valid_hnf)
        changed += int(result.reconstructed[:p.rank] != result.raw.raw_vector[:p.rank])
    certificate = sampler.public_certificate()
    # Deliberately construct the public report field by field. Do not merge
    # any private object's __dict__ or the underlying sampler certificate.
    return {
        "schema": "IBME/SRGG-CORRELATED-PERTURBATION-COMPONENT/1",
        "parameters": {"degree": p.degree, "rank": p.rank, "digits": p.digits,
                       "p": p.p, "b": p.base, "q": p.gadget_modulus, "Q": p.modulus,
                       "coefficient_dimension": certificate["dimension"]},
        "perturbation": {"attempts": repetitions,
                         "target_tv_upper_including_abort": certificate["target_tv_upper_including_abort"],
                         "public_tape_bytes": certificate["public_tape_bytes"],
                         "gadget_fiber_tv_upper_including_abort":
                             gadget.certificate(blocks=p.rank * p.degree)["total_fiber_tv_upper_including_abort"]},
        "raw_approximate": {"equation_passes": approximate, "equation_failures": 0,
                            "full_key_distribution_claim": False},
        "hnf_reconstructed": {"equation_passes": exact, "equation_failures": 0,
                              "first_block_changed": changed, "same_Gaussian_claim": False},
        "observed_aborts": aborted,
        "literal_SampleF_implemented": False,
        "full_IBS_implemented": False,
        "security_claim": "none",
        "backend_admitted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=64)
    args = parser.parse_args()
    print(json.dumps(audit(repetitions=args.repetitions), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
