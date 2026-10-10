"""Sage independently checks SRGG public algebra and rational shape geometry."""

import argparse
from dataclasses import asdict
from hashlib import sha256
from itertools import product as all_bits
import json
from pathlib import Path
import platform
import sys

from ibme.core.randomness import DeterministicRandom
from .algebra import (
    Params, build_public, extraction_from_values, gadget, reconstruct_vector,
    signing_matrix, response_from_values, recover_commitment,
)
from .geometry import Widths, master_geometry, signature_geometry

ROOT = Path(__file__).resolve().parents[4]
PAPER = "papers/2025_efficient_ibs_jia.pdf"
PAPER_SHA = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"


def require(condition, label):
    if not condition: raise RuntimeError(label)


def example(p, label):
    source = DeterministicRandom(b"srgg-component-audit:" + label)
    def below(bound):
        width = max(1, ((bound - 1).bit_length() + 7) // 8)
        ceiling = 2**(8 * width)
        limit = ceiling - ceiling % bound
        for _ in range(128):
            value = int.from_bytes(source.read(width), "big")
            if value < limit: return value % bound
        raise RuntimeError("teaching entropy budget exhausted")
    a = tuple(tuple(tuple(below(p.modulus) for _ in range(p.degree)) for _ in range(p.rank)) for _ in range(p.rank))
    # CBD1 support and probabilities for teaching master fixtures. This is not
    # Gaussian sampling, XOF expansion or the paper's parameter admission.
    r = tuple(tuple(tuple(below(2) - below(2) for _ in range(p.degree)) for _ in range(p.rank * p.digits)) for _ in range(2 * p.rank))
    target = tuple(tuple(below(p.modulus) for _ in range(p.degree)) for _ in range(p.rank))
    perturb = tuple(tuple(below(5) - 2 for _ in range(p.degree)) for _ in range(p.columns))
    return build_public(p, a, r), r, target, perturb


def sage_case(p, public, r, target, trace, y, master_geo, sig_one, sig_two):
    from sage.all import ZZ, QQ, PolynomialRing, matrix, vector, identity_matrix
    polynomials = PolynomialRing(ZZ, "X")
    x = polynomials.gen()
    ring = polynomials.quotient(x**p.degree + 1, "a")
    def rp(poly): return ring(polynomials(list(poly)))
    def rm(rows): return matrix(ring, [[rp(poly) for poly in row] for row in rows])
    def rv(values): return vector(ring, [rp(poly) for poly in values])
    def mod_equal(left, right, modulus):
        difference = left - right
        return all(all(int(coefficient) % modulus == 0 for coefficient in value.lift().list()) for value in difference.list())
    a, trap = rm(public.a), rm(r).stack(identity_matrix(ring, p.rank * p.digits))
    require(mod_equal(a * trap, rm(gadget(p)), p.modulus), "independent module master relation")
    require(mod_equal(a * rv(trace.raw_vector), rv(target) - rv(trace.error), p.modulus), "independent approximate error relation")
    require(mod_equal(a * rv(y), rv(target), p.modulus), "independent reconstructed exact relation")
    abar = rm(signing_matrix(public, target))
    j = vector(ring, [1 - ring(x**(p.degree // 2))] + [ring(0)] * (p.rank - 1))
    require(mod_equal(abar * vector(ring, list(rv(y)) + [ring(1)]), p.modulus * j, 2 * p.modulus), "independent signing relation")

    def operator(rows):
        blocks = []
        for row in rows:
            pieces = []
            for f in row:
                cols = [(rp(f) * ring(x**index)).lift() for index in range(p.degree)]
                pieces.append(matrix(QQ, p.degree, p.degree, lambda i, index: int(cols[index][i])))
            current = pieces[0]
            for piece in pieces[1:]: current = current.augment(piece)
            blocks.append(current)
        result = blocks[0]
        for block in blocks[1:]: result = result.stack(block)
        return result

    def shape_check(top, geometry):
        target_shape = matrix(QQ, geometry.target)
        stacked = top.stack(identity_matrix(QQ, top.ncols()))
        raw = target_shape - QQ(geometry.noise_squared) * stacked * stacked.transpose()
        require(raw == matrix(QQ, geometry.perturbation), "independent perturbation shape")
        shifted = raw - QQ(geometry.floor_squared) * identity_matrix(QQ, raw.nrows())
        require(shifted.is_positive_definite(), "independent strict floor positivity")
        k = top.nrows()
        aa, bb, dd = raw[:k, :k], raw[:k, k:], raw[k:, k:]
        conditional = aa - bb * dd.inverse() * bb.transpose()
        require(conditional == matrix(QQ, geometry.conditional_shape), "independent unshifted Schur shape")
        require(bb * dd.inverse() == matrix(QQ, geometry.center_operator), "independent conditional center operator")
        gap = QQ(geometry.floor_squared)
        margin_schur = aa - gap * identity_matrix(QQ, k) - bb * (dd - gap * identity_matrix(QQ, dd.nrows())).inverse() * bb.transpose()
        require(margin_schur == matrix(QQ, geometry.shifted_schur), "independent shifted Schur positivity condition")
        require(margin_schur.is_positive_definite(), "independent shifted Schur positivity")
        return int(raw.nrows())

    master_dim = shape_check(operator(r), master_geo)
    signing_top = operator(tuple((poly,) for poly in y))
    sig_dim = shape_check(signing_top, sig_one)
    require(shape_check(signing_top, sig_two) == sig_dim, "alternate noise geometry dimension")
    zeta_op = operator(((tuple(int(i in (0, p.degree // 2)) for i in range(p.degree)),),))
    require(zeta_op * zeta_op.transpose() == 2 * identity_matrix(QQ, p.degree), "zeta exact coefficient shape scale")
    return ring, x, rp, rv, abar, j, master_dim, sig_dim


def digest(values): return sha256(json.dumps(values, separators=(",", ":")).encode("ascii")).hexdigest()


def audit():
    from sage.version import version
    require(sha256((ROOT / PAPER).read_bytes()).hexdigest() == PAPER_SHA, "SRGG source version differs")
    rows, challenges, perturbations = [], 0, 0
    master_widths, signature_widths = Widths(4096, 64, 1), Widths(2**20, 2**18, 1)
    for label, p in (("degree2-rank1", Params(degree=2, digits=1)), ("degree4-rank1", Params()), ("degree4-rank2", Params(rank=2, p=7))):
        public, r, target, perturb = example(p, label.encode())
        trace = extraction_from_values(public, r, target, perturb)
        y = reconstruct_vector(public, target, trace.tail)
        master_geo = master_geometry(p, r, master_widths)
        sig_one = signature_geometry(p, y, signature_widths, noise_factor=1)
        sig_two = signature_geometry(p, y, signature_widths, noise_factor=2)
        ring, x, rp, rv, abar, j, master_dim, sig_dim = sage_case(p, public, r, target, trace, y, master_geo, sig_one, sig_two)
        perturb_sig = tuple(tuple((i + k) % 5 - 2 for k in range(p.degree)) for i in range(p.columns + 1))
        u = tuple(i - 2 for i in range(p.degree))
        commitment = abar * rv(perturb_sig)
        traces = []
        for c in all_bits((0, 1), repeat=p.degree):
            response = response_from_values(public, target, y, perturb_sig, u, c)
            # Construct the response independently using the quotient ring.
            shift = (1 + ring(x**(p.degree // 2))) * rp(u) + rp(c)
            witness = list(rv(y)) + [ring(1)]
            expected_response = tuple(rv(perturb_sig)[i] + witness[i] * shift for i in range(p.columns + 1))
            require(tuple(tuple(int(value.lift()[k]) for k in range(p.degree)) for value in expected_response) == response,
                    "independent integer response differs")
            recovered = recover_commitment(public, target, response, c)
            direct = abar * rv(response) - p.modulus * rp(c) * j
            require(all(all(int(value.lift()[k]) % (2 * p.modulus) == recovered[i][k] for k in range(p.degree)) for i, value in enumerate(direct)),
                    "independent commitment recovery differs")
            require(all(all((int(commitment[i].lift()[k]) - recovered[i][k]) % (2 * p.modulus) == 0 for k in range(p.degree)) for i in range(p.rank)),
                    "honest algebra commitment mismatch")
            changed = (1 - c[0],) + c[1:]
            require(recover_commitment(public, target, response, changed) != recovered, "changed challenge recovery control failed")
            perturbed = ((response[0][0] + 1,) + response[0][1:],) + response[1:]
            require(recover_commitment(public, target, perturbed, c) != recovered, "changed response recovery control failed")
            challenges += 1
            perturbations += 2
            traces.append(dict(challenge_bits=c, commitment_sha256=digest(recovered), response_public_sha256=digest(response)))
        rows.append(dict(name=label, parameters=asdict(p), Q=p.modulus, q_gadget=p.gadget_modulus,
                         master_columns=p.columns, signing_columns=p.columns + 1,
                         master_geometry_dimension=master_dim, signature_geometry_dimension=sig_dim,
                         approximate_error_nonzero_coefficients=sum(x != 0 for poly in trace.error for x in poly),
                         exact_key_reconstruction=True, master_shifted_positive=True, signature_literal_positive=True,
                         signature_factor_two_positive=True, zeta_coefficient_shape_factor=2,
                         gadget_scalar_shape_factor=p.base**2, traces=traces))
    names = tuple("experiments/research/candidates/srgg/" + name for name in ("algebra.py", "geometry.py", "audit.py"))
    return dict(security_claim="none", backend_admitted=False, full_IBS_implemented=False, gaussian_sampler_implemented=False,
                XOF_and_challenge_hash_implemented=False, paper_source=PAPER, paper_sha256=PAPER_SHA,
                paper_locations="§4/Table3 PDF6; Algorithms1--6 PDF7; Algorithms7/8 PDF8; prose mismatch PDF5",
                python=sys.version, sage=version, platform=platform.platform(), processor=platform.processor(),
                repeats=1, identity_message_lengths="Not applicable: public target vectors and supplied binary polynomial challenges only",
                entropy="Deterministic CBD1/algebra fixtures; supplied perturbation/u values are not Gaussian samples",
                master_widths={key: str(value) for key, value in asdict(master_widths).items()},
                signature_widths={key: str(value) for key, value in asdict(signature_widths).items()},
                cases=rows, binary_challenges_checked=challenges, altered_recovery_values_detected=perturbations,
                covariance_shape_checks=9, signature_noise_scale_interpretation_resolved=False,
                gadget_noise_width_mapping_resolved=False, teaching_parameters=True,
                rom="No instantiated H/Hbar or ROM/QROM claim in this algebra/geometry component",
                source_sha256_lf={name: sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in names},
                limitations=["Canonical gadget digits are not Algorithm6 Gaussian sampling; covariance identities are not a distribution certificate.",
                             "Algorithm3 uses sigma^2=b^2*r^2 while prose uses r^2; reference follows Table3/Algorithm3.",
                             "Zeta multiplication scales coefficient shape by2; literal signature covariance and this noise-width interpretation still need sampler mapping.",
                             "Algorithm6 prints width r on bZ+v; the text's b*SampleZ(-v/b)+v with SampleZ width r instead gives width b*r. No interpretation is silently used as sampling.",
                             "Underlying strong-signature and q/Q/gamma conditions remain open; no ROM/QROM security proof is granted.",
                             "No master/user vectors, random seeds or Gaussian state are exported."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({name: result[name] for name in ("binary_challenges_checked", "covariance_shape_checks", "security_claim")}))


if __name__ == "__main__": main()
