"""Reproducible Sageloli ternary-trapdoor math probes, not an IBS backend.

Extracted from the completed local probes. H1/H2 outputs are independent
uniform test targets: identities, nonce hashing and persistent keys are not
implemented here. Real correlated perturbations and coset Gaussians are
sampled; numerical continuous-stage TV remains uncertified.
"""
import argparse
from functools import lru_cache
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

from sage.all import QQ, ZZ, identity_matrix, matrix, vector
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module_math import negacyclic_schoolbook
from ibme.lattice.chkp.gaussian import build_gaussian_table_squared, draw_uniform_integer
from experiments.research.candidates.srgg.full_sampling import (
    FullSamplingOptions, prepare_f, prepare_p)
from experiments.research.online_mp12_reference import exact_psd_pivots

OPTIONS = FullSamplingOptions(precision_bits=192, ticket_bits=128,
    tail_bits=80, mass_bits=128, gaussian_abort_bits=80, max_uniform_trials=192)
R_SQUARED = 16


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gadget(rows, k):
    require(type(rows) is int and type(k) is int and rows > 0 and k > 0
            and rows*k <= 128, "bounded gadget dimensions required")
    # Digit-major: [I, 3I, ..., 3^(k-1)I].
    return matrix(ZZ, rows, rows*k,
                  lambda i, j: 3**(j//rows) if i == j % rows else 0)


@lru_cache(maxsize=1)
def coset_tables():
    return tuple(build_gaussian_table_squared(9*R_SQUARED, step=3,
        residue=a, tail_bits=80, mass_bits=128, precision_bits=192,
        max_trials=128, max_radius=128) for a in range(3))


def ternary_preimage(targets, k, rng):
    rows = len(targets)
    gadget(rows, k)  # Admit dimensions before building tables or drawing.
    q = 3**k
    tables, digits = coset_tables(), []
    for target in targets:
        require(target in ZZ, "integer syndrome required")
        state, coefficients = int(target) % q, []
        for _ in range(k):
            value = int(tables[state % 3].sample(rng=rng))
            coefficients.append(value)
            state = (state-value)//3
        # A nonzero final carry is permitted modulo 3^k.
        require((sum(3**i*x for i, x in enumerate(coefficients))-target) % q == 0,
                "ternary Gaussian carry relation failed")
        digits.append(coefficients)
    return vector(ZZ, [digits[i][h] for h in range(k) for i in range(rows)])


def expand_polynomials(polys):
    require(isinstance(polys, (tuple, list)) and len(polys) > 0,
            "nonempty polynomial matrix required")
    rows, cols, degree = len(polys), len(polys[0]), len(polys[0][0])
    require(cols > 0 and degree > 0 and rows*degree <= 128 and cols*degree <= 128,
            "bounded polynomial matrix required")
    require(all(len(row) == cols and all(len(poly) == degree for poly in row)
                for row in polys), "rectangular same-degree polynomial matrix required")
    result = matrix(ZZ, rows*degree, cols*degree)
    for i, row in enumerate(polys):
        for j, poly in enumerate(row):
            for column in range(degree):
                basis = tuple(int(column == h) for h in range(degree))
                product = negacyclic_schoolbook(poly, basis)
                for h, coefficient in enumerate(product):
                    result[i*degree+h, j*degree+column] = coefficient
    return result


def prepare_sampler(a, t, k, width_squared, *, mode, block_size):
    """Check A[-T;I]=G and s²I-11r²JJ^t >=0 before any entropy."""
    require(mode in ("global", "block-schur"), "explicit perturbation mode required")
    require(width_squared in ZZ and width_squared > 0, "positive integer width squared required")
    a, t = matrix(ZZ, a), matrix(ZZ, t)
    g = gadget(a.nrows(), k)
    require(1 <= a.ncols() <= OPTIONS.max_dimension
            and t.dimensions() == (a.ncols()-g.ncols(), g.ncols()),
            "trapdoor dimensions do not match public matrix")
    j = (-t).stack(identity_matrix(ZZ, g.ncols()))
    q = 3**k
    require(all(x % q == 0 for x in (a*j-g).list()), "trapdoor relation failed")
    identity = identity_matrix(QQ, a.ncols())
    exact_psd_pivots(QQ(width_squared)*identity-11*R_SQUARED*j*j.transpose())
    shape = QQ(width_squared)*identity-9*R_SQUARED*j*j.transpose()
    if mode == "global":
        plan = prepare_f(shape, (0,)*a.ncols(), R_SQUARED, options=OPTIONS)
    else:
        plan = prepare_p(shape, (0,)*a.ncols(), block_size, R_SQUARED, options=OPTIONS)
    return j, plan


def sample_preimage(a, prepared, targets, k, rng):
    j, plan = prepared
    q = 3**k
    require(len(targets) == a.nrows(), "syndrome dimension mismatch")
    u = vector(ZZ, targets)
    perturbation = vector(ZZ, plan.sample(rng=rng))
    residual = tuple(int(x) % q for x in u-a*perturbation)
    z = perturbation+j*ternary_preimage(residual, k, rng)
    require(all(x % q == 0 for x in a*z-u), "SampleD modular equation failed")
    return z


def run_probe(kind):
    require(kind in ("matrix", "ring"), "choose matrix or ring explicitly")
    rng = DeterministicRandom(("Sageloli probe "+kind).encode())
    start = perf_counter()
    cbd = lambda: (-1, 0, 0, 1)[draw_uniform_integer(rng, 4)]
    uniform = lambda q: draw_uniform_integer(rng, q)
    if kind == "matrix":
        rows, k, m, block, sid2, ssign2 = 2, 4, 16, 1, 2**28, 2**56
        q, w, mode = 3**k, rows*k, "global"
        abar = matrix(ZZ, rows, m-w, lambda i, j: uniform(q))
        raw = matrix(ZZ, m-w, w, lambda i, j: cbd())
        parameters = {"n": rows, "k": k, "m": m}
    else:
        degree, k, l, block, sid2, ssign2 = 4, 9, 22, 4, 2**36, 2**66
        rows, m, w, q, mode = degree, degree*l, degree*k, 3**k, "block-schur"
        abar_polys = (tuple(tuple(uniform(q) for _ in range(degree))
                            for _ in range(l-k)),)
        # Paper p.9: first/last quarters 4*P_(1/2), middle half P_(1/2).
        raw_polys = tuple(tuple(tuple((4 if h < degree//4 or h >= 3*degree//4 else 1)*cbd()
                                     for h in range(degree))
                                for _ in range(k)) for _ in range(l-k))
        abar, raw = expand_polynomials(abar_polys), expand_polynomials(raw_polys)
        parameters = {"d": degree, "k": k, "l": l}
    g, t = gadget(rows, k), -raw
    a = abar.augment(g-abar*raw).apply_map(lambda x: ZZ(x) % q)
    root = prepare_sampler(a, t, k, sid2, mode=mode, block_size=block)
    root_seconds = perf_counter()-start
    before = perf_counter()
    if kind == "matrix":
        h = matrix(ZZ, rows, w, lambda i, j: uniform(q))
    else:
        h = expand_polynomials((tuple(tuple(uniform(q) for _ in range(degree))
                                      for _ in range(k)),))
    targets = h-g
    calls = w if kind == "matrix" else k
    columns = [sample_preimage(a, root, targets.column(index if kind == "matrix" else index*degree),
                              k, rng) for index in range(calls)]
    if kind == "matrix":
        tid = matrix(ZZ, columns).transpose()
    else:
        # k ring calls produce l polynomials each, then expand their rotations.
        tid_polys = tuple(tuple(tuple(int(columns[j][i*degree+h]) for h in range(degree))
                                for j in range(k)) for i in range(l))
        tid = expand_polynomials(tid_polys)
    delegated = all(x % q == 0 for x in (a*tid-targets).list())
    require(delegated, "delegated ring/matrix relation failed")
    extraction_seconds = perf_counter()-before
    extended = a.augment(h)
    before = perf_counter()
    user = prepare_sampler(extended, tid, k, ssign2, mode=mode, block_size=block)
    plan_seconds = perf_counter()-before
    u = tuple(uniform(q) for _ in range(rows))
    before = perf_counter()
    z = sample_preimage(extended, user, u, k, rng)
    sign_seconds = perf_counter()-before
    raw_norms = (sum(int(x)**2 for x in z[:m]), sum(int(x)**2 for x in z[m:]))
    centered = tuple((int(x)+q//2) % q-q//2 for x in z)
    centered_norms = (sum(x*x for x in centered[:m]), sum(x*x for x in centered[m:]))
    bounds = (2*m*ssign2, 2*w*ssign2)
    raw_pass = all(norm <= bound for norm, bound in zip(raw_norms, bounds))
    centered_pass = all(norm <= bound for norm, bound in zip(centered_norms, bounds))
    require(raw_pass and centered_pass and any(centered), "probe signature norm/nonzero check failed")
    return {"kind": kind, "parameters": parameters, "q": q,
        "root_coefficient_dimension": m, "coefficient_dimension": extended.ncols(),
        "delegation_sample_calls": calls, "perturbation_mode": mode, "block_size": block,
        "sid_squared": sid2, "ssign_squared": ssign2, "r_squared": R_SQUARED,
        "timings_seconds": {"root_generation_and_plan": root_seconds,
            "delegation": extraction_seconds, "user_plan": plan_seconds,
            "signature_math": sign_seconds, "total": perf_counter()-start},
        "root_relation": True, "delegated_relation": delegated, "sign_equation": True,
        "raw_split_norm_passed": raw_pass, "centered_split_norm_passed": centered_pass,
        "profile_norm_check_is_vacuous": all(size*(q//2)**2 <= bound
                                             for size, bound in zip((m, w), bounds)),
        "continuous_tv_certified": user[1].public_certificate()["continuous_stage_tv_certified"],
        "security_claim": "none", "backend_admitted": False, "complete_ibs_backend": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("matrix", "ring", "both"), default="both")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    kinds = ("matrix", "ring") if args.kind == "both" else (args.kind,)
    report = {"schema_version": 1, "scope": "real sampling math probes, not complete IBS",
        "environment": {"python": sys.version.split()[0], "sage": sage_version,
                        "platform": platform.platform(), "rng": "DeterministicRandom test streams"},
        "results": [run_probe(kind) for kind in kinds]}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
