"""Reproducible, exact T1 audit; public algebra examples, never secret keys.

Run under the prescribed Sage environment, from the repository root:
  PYTHONPATH=src python -m experiments.research.chkp_t1_audit --output report.json
The independent oracle uses the INTEGER kernel of [A | -q I] and row HNF,
not the reference implementation's modular pivot construction. GS lengths
are also checked using ratios of leading Gram determinants, not its GS loop.
Both paths still trust Sage and its exact-arithmetic dependencies.
"""

import argparse
import hashlib
import json
import platform
from itertools import product
from pathlib import Path
from random import Random

from sage.all import GF, QQ, ZZ, identity_matrix, matrix, vector
from sage.version import version as sage_version

from experiments.research.chkp_basis import (
    KernelBasis, ModMatrixReference, complete_kernel_basis, ext_basis,
    gram_schmidt_squared_lengths,
)


ROOT = Path(__file__).resolve().parents[2]
SEED = 20261009
EXHAUSTIVE_CONFIGS = ((2, 1, 1, 1), (2, 1, 2, 1), (3, 1, 2, 1),
                      (2, 2, 2, 1), (2, 2, 3, 1))
RANDOM_PRIMES = (2, 3, 5, 17, 65537, 2**61 - 1)


def _require(condition, message):
    # Certificates must not silently become successful under python -O.
    if not condition:
        raise AssertionError(message)


def integer_kernel_hnf(public):
    """Canonical row lattice of all x such that A x = q y over ZZ.

    Projection of ker_Z([A|-qI]) onto its first m coordinates is a bijection
    onto Lambda_perp(A): y is uniquely A x / q. An integer kernel (not a
    rational nullspace with denominators cleared) is essential here.
    """
    a = matrix(ZZ, public.rows)
    augmented = a.augment(-public.q * identity_matrix(ZZ, a.nrows()))
    kernel_rows = augmented.right_kernel().basis_matrix()
    _require(kernel_rows.base_ring() == ZZ, "oracle must use an integer kernel")
    _require(augmented * kernel_rows.transpose() == 0, "integer kernel equation")
    projected = kernel_rows.matrix_from_columns(range(a.ncols()))
    _require(projected.nrows() == a.ncols(), "projected kernel rank")
    return projected.hermite_form()


def gram_determinant_lengths(basis_rows):
    """Squared column-GS lengths via det(S_i^T S_i)/det(S_{i-1}^T S_{i-1})."""
    s = matrix(ZZ, basis_rows)
    previous, lengths = ZZ(1), []
    for i in range(1, s.ncols() + 1):
        prefix = s.matrix_from_columns(range(i))
        determinant = (prefix.transpose() * prefix).det()
        _require(determinant > 0, "positive leading Gram determinant")
        lengths.append(QQ(determinant) / previous)
        previous = determinant
    return tuple(lengths)


def check_basis(basis):
    a, s, q = matrix(ZZ, basis.public.rows), matrix(ZZ, basis.basis_rows), basis.public.q
    _require((s.nrows(), s.ncols()) == (a.ncols(), a.ncols()), "square column basis")
    _require(all(x % q == 0 for x in (a * s).list()), "kernel congruence")
    _require(s.rank() == a.ncols(), "full integer rank")
    _require(abs(s.det()) == q**a.nrows(), "surjective kernel index")
    _require(s.transpose().hermite_form() == integer_kernel_hnf(basis.public),
             "independent integer-kernel HNF mismatch")
    lengths = gram_schmidt_squared_lengths(basis.basis_rows)
    _require(lengths == gram_determinant_lengths(basis.basis_rows), "independent GS mismatch")
    _require(basis.security_claim == "none" and not basis.is_randomized, "security boundary")
    return lengths


def check_extension(parent, child, block):
    s, t = matrix(ZZ, parent.basis_rows), matrix(ZZ, child.basis_rows)
    m, k = s.ncols(), block.ncols
    _require(child.public == parent.public.append(block), "public block order")
    _require(t[:m, :m] == s, "unchanged visible parent subblock")
    _require(t[m:, :m] == 0, "zero lower left block")
    _require(t[m:, m:] == identity_matrix(ZZ, k), "identity lower right block")
    w = t[:m, m:]
    a, b = matrix(ZZ, parent.public.rows), matrix(ZZ, block.rows)
    _require(all(x % parent.public.q == 0 for x in (a * w + b).list()), "negative W sign")
    before, after = gram_determinant_lengths(parent.basis_rows), check_basis(child)
    _require(after == before + (QQ(1),) * k, "exact ordered GS extension")
    _require(max(after) == max(before), "maximum GS length preserved")


def exhaustive_audit():
    configurations, roots, extensions, membership_checks = [], 0, 0, 0
    for q, n, m, k in EXHAUSTIVE_CONFIGS:
        root_count, extension_count, member_count = 0, 0, 0
        for entries in product(range(q), repeat=n * m):
            a = matrix(GF(q), n, m, entries)
            if a.rank() != n:
                continue
            parent = complete_kernel_basis(ModMatrixReference(a, q))
            check_basis(parent)
            root_count += 1
            for extra in product(range(q), repeat=n * k):
                block = ModMatrixReference(matrix(ZZ, n, k, extra), q)
                child = ext_basis(parent, block)
                check_extension(parent, child, block)
                inverse = matrix(QQ, child.basis_rows).inverse()
                # Together with this inclusion, residue enumeration checks all
                # integer vectors for this particular finite matrix example.
                _require(all(x.denominator() == 1 for x in (q * inverse).list()),
                         "q Z^d must be contained in the candidate lattice")
                az = matrix(ZZ, child.public.rows)
                for values in product(range(q), repeat=m + k):
                    v = vector(ZZ, values)
                    in_kernel = all(x % q == 0 for x in az * v)
                    in_basis = all(x.denominator() == 1 for x in inverse * v)
                    _require(in_kernel == in_basis, "exhaustive membership mismatch")
                    member_count += 1
                extension_count += 1
        configurations.append(dict(q=q, n=n, m=m, k=k, roots=root_count,
                                   extensions=extension_count, membership_checks=member_count))
        roots += root_count
        extensions += extension_count
        membership_checks += member_count
    return dict(configurations=configurations, roots=roots, extensions=extensions,
                membership_checks=membership_checks)


def seeded_audit():
    rng, cases, bases, extensions = Random(SEED), 0, 0, 0
    fractional_gs_seen, negative_determinant_seen = False, False
    for q in RANDOM_PRIMES:
        for n in (1, 2, 3):
            for extra_columns in (0, 2):
                m = n + extra_columns
                for _ in range(10000):
                    entries = [rng.randrange(q) for _ in range(n * m)]
                    a = matrix(GF(q), n, m, entries)
                    if a.rank() == n:
                        break
                else:
                    raise AssertionError("bounded test fixture generation exhausted")
                parent = complete_kernel_basis(ModMatrixReference(a, q))
                # Unimodular column operations change the basis, not its lattice.
                u = identity_matrix(ZZ, m)
                u.rescale_col(0, -1)
                if m > 1:
                    u.swap_columns(0, m - 1)
                    for _ in range(5):
                        i, j = rng.sample(range(m), 2)
                        u.add_multiple_of_column(i, j, rng.choice((-7, -2, -1, 1, 2, 7)))
                _require(abs(u.det()) == 1, "test basis change must be unimodular")
                parent = KernelBasis(parent.public, matrix(ZZ, parent.basis_rows) * u)
                lengths = check_basis(parent)
                fractional_gs_seen |= any(x.denominator() != 1 for x in lengths)
                negative_determinant_seen |= matrix(ZZ, parent.basis_rows).det() < 0
                bases += 1
                for k in (1, 2):
                    block = ModMatrixReference(
                        matrix(ZZ, n, k, [rng.randrange(-q, q + 1) for _ in range(n * k)]), q)
                    child = ext_basis(parent, block)
                    check_extension(parent, child, block)
                    parent = child
                    bases += 1
                    extensions += 1
                cases += 1
    _require(fractional_gs_seen, "fixtures must exercise nonintegral GS lengths")
    _require(negative_determinant_seen, "fixtures must exercise signed determinants")
    return dict(seed=SEED, primes=list(RANDOM_PRIMES), n_values=[1, 2, 3],
                extra_root_columns=[0, 2], extension_widths=[1, 2], cases=cases,
                bases=bases, extensions=extensions, fractional_gs_seen=bool(fractional_gs_seen),
                negative_determinant_seen=bool(negative_determinant_seen))


def permutation_regression():
    """For the column convention A -> AP, the basis becomes P^T S, not PS."""
    a = matrix(ZZ, [[1, 0, 0]])
    s = matrix(ZZ, [[5, 0, 0], [0, 1, 0], [0, 0, 1]])
    p = matrix(ZZ, [[0, 1, 0], [0, 0, 1], [1, 0, 0]])
    correct, wrong = p.transpose() * s, p * s
    _require(p * p != identity_matrix(ZZ, 3), "use a non-involutive permutation")
    correct_residue = (a * p * correct).apply_map(lambda x: x % 5)
    wrong_residue = (a * p * wrong).apply_map(lambda x: x % 5)
    _require(correct_residue == 0 and wrong_residue != 0, "inverse permutation regression")
    changed = KernelBasis(ModMatrixReference(a * p, 5), correct)
    check_basis(changed)
    _require(gram_determinant_lengths(correct) == gram_determinant_lengths(s),
             "orthogonal coordinate permutation preserves ordered GS lengths")
    return dict(q=5, public=_matrix_json(a), permutation=_matrix_json(p),
                basis=_matrix_json(s), correct_residue=_matrix_json(correct_residue),
                wrong_residue=_matrix_json(wrong_residue),
                convention="A -> A P requires S -> P^T S; append API is unaffected")


def _matrix_json(s):
    return [[int(x) for x in row] for row in s.rows()]


def public_example():
    q = 17
    basis = complete_kernel_basis(ModMatrixReference([[1, 0, 2, 3], [0, 1, 5, 7]], q))
    levels = []
    blocks = ([[4, 6, 8, 10], [3, 5, 9, 11]], [[2, 4, 6, 8], [1, 3, 7, 9]])
    for level in range(3):
        if level:
            child = ext_basis(basis, ModMatrixReference(blocks[level - 1], q))
            check_extension(basis, child, ModMatrixReference(blocks[level - 1], q))
            basis = child
        lengths = check_basis(basis)
        a, s = matrix(ZZ, basis.public.rows), matrix(ZZ, basis.basis_rows)
        levels.append(dict(level=level, public=_matrix_json(a), basis=_matrix_json(s),
                           rank=int(s.rank()), determinant=str(s.det()),
                           residue=_matrix_json((a * s).apply_map(lambda x: x % q)),
                           gs_squared=[str(x) for x in lengths],
                           kernel_hnf=_matrix_json(integer_kernel_hnf(basis.public))))
    return dict(q=q, n=2, m=4, depth=2, security_claim="none", is_randomized=False,
                purpose="public algebra examples, not cryptographic keys", levels=levels)


def run_audit():
    sources = ("papers/2010_bonsai_trees_cash.pdf", "experiments/research/chkp_basis.py",
               "experiments/research/chkp_t1_audit.py", "tests/test_chkp_basis.py",
               "tests/test_chkp_basis_boundaries.py", "tests/test_chkp_t1_audit.py")
    evidence = dict(schema="chkp-t1-exact-audit-v1", security_claim="none",
                    scope="prime modulus, surjective A, complete integer column basis, append extension",
                    environment=dict(python=platform.python_version(), sage=sage_version,
                                     system=platform.system(), machine=platform.machine()),
                    source_sha256={p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
                    exhaustive=exhaustive_audit(), seeded=seeded_audit(),
                    permutation=permutation_regression(), public_example=public_example())
    evidence["status"] = "passed"
    evidence["limitations"] = ["No GenBasis, RandBasis, SampleD, HIBE or security proof",
                               "Finite tests complement, not replace, the symbolic proof",
                               "Independent algorithms share Sage exact-arithmetic dependencies"]
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="optional reproducible JSON evidence file")
    args = parser.parse_args()
    evidence = run_audit()
    serialized = json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
        print(json.dumps({key: evidence[key] for key in ("status", "security_claim", "exhaustive", "seeded")}))
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
