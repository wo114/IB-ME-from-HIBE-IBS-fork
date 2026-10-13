"""Archive of the in-memory linear-algebra diagnostics run on 2026-10-13.

The original five diagnostic groups retain their enumeration bounds, reference
algorithms, random seeds and assertions. A separate MP12 Lemma 5.3 block audit
and optional regression runner were added after the source repair. Composite
moduli are deliberately excluded from this archive's scope.

Usage (from the repository root):
    python -B experiments/research/wang_pw_linear_audit.py --expected-sha256 SHA
Add --baseline-source PATH to rerun the frozen original under its own module
name and SHA; add --regressions to run the owned pytest file. --output PATH
writes the JSON receipt; without it the receipt goes only to stdout.

--expected-sha256 is mandatory for the current source. The optional baseline
has its own fixed expected SHA. JSON records the versions in separate runs.
Exit 0 means this diagnostic run completed, including any recorded defects.
An unexpected assertion/exception or source mismatch exits nonzero. Counts are
computed, never loaded from a previous receipt. No setup, keys, samplers, outer
protocol, external dependencies or security claims are involved.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import re
import subprocess
import sys
import time

# Keep imported project modules from creating bytecode, even without -B.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "ibme" / "ibs" / "wang_pw.py"
BASELINE_SHA256 = "119f1168003b99a39172ce1cb2513658a2ad56ca4925b6c33bcdeb09890c1b8d"
w = None  # Imported only after checking the requested source hash.


# Independent reference arithmetic retained from the original diagnostics.
def det(A):
    n=len(A)
    return sum((-1)**sum(p[i]>p[j] for i in range(n) for j in range(i+1,n))*math.prod(A[i][p[i]] for i in range(n)) for p in itertools.permutations(range(n)))
def gram(C):
    star=[]; norms=[]; mus=[]
    for b in C:
        v=list(map(Fraction,b)); mu=[]
        for s,z in zip(star,norms):
            t=sum(Fraction(x)*y for x,y in zip(b,s))/z
            mu.append(t);v=[x-t*y for x,y in zip(v,s)]
        z=sum(x*x for x in v); assert z>0,('dependent result',C)
        star.append(v);norms.append(z);mus.append(mu)
    return norms,mus
def reduced(C):
    norms,mus=gram(C)
    assert all(abs(t)<=Fraction(1,2) for r in mus for t in r),('size',C,mus)
    assert all(norms[k]>=(Fraction(3,4)-mus[k][k-1]**2)*norms[k-1] for k in range(1,len(C))),('Lovasz',C)
def minor_gcd(C,m):
    return math.gcd(*(abs(det(list(S))) for S in itertools.combinations(C,m)))


def audit_gf():
    """GF rank/kernel/solve: exhaustive q=2,3 shapes up to 2x3 and 3x2; 160 seeded q=5,7 cases."""
    start=time.monotonic()
    counts={'matrices':0,'rhs':0,'random_matrices':0,'failures':0}
    failures=[]
    def check(A,q,random_case=False):
        n,m=len(A),len(A[0]); before=[row[:] for row in A]
        def mv(v): return tuple(sum(a*x for a,x in zip(row,v))%q for row in A)
        image={}; zeros=(0,)*n; kernel=set()
        for v in itertools.product(range(q),repeat=m):
            y=mv(v); image.setdefault(y,v)
            if y==zeros: kernel.add(v)
        rank=0; size=len(image)
        while size>1: assert size%q==0; size//=q; rank+=1
        assert w._gf_rank(A,q)==rank,('rank',A,q,rank)
        K=w._gf_kernel_basis(A,q)
        assert len(K)==m-rank,('nullity',A,q,K)
        assert all(len(v)==m and all(0<=x<q for x in v) for v in K)
        span={tuple(sum(c*v[j] for c,v in zip(cs,K))%q for j in range(m)) for cs in itertools.product(range(q),repeat=len(K))}
        assert span==kernel,('kernel',A,q,K)
        for rhs in itertools.product(range(q),repeat=n):
            x=w._gf_solve(A,list(rhs),q)
            assert (x is None)==(rhs not in image),('solve existence',A,rhs,q,x)
            assert x is None or (len(x)==m and mv(x)==rhs),('solve value',A,rhs,q,x)
            counts['rhs']+=1
        assert A==before
        counts['matrices']+=1; counts['random_matrices']+=random_case
    for q in (2,3):
        for n,m in ((1,1),(1,2),(1,3),(2,1),(2,2),(2,3),(3,2)):
            for flat in itertools.product(range(q),repeat=n*m):
                check([list(flat[i*m:(i+1)*m]) for i in range(n)],q)
    rng=random.Random(20261013)
    for q in (5,7):
        for n,m in ((1,3),(2,2),(2,3),(3,2)):
            for _ in range(20):
                check([[rng.randrange(-2*q,3*q) for _ in range(m)] for _ in range(n)],q,True)
    return {'counts': counts, 'elapsed_seconds': time.monotonic()-start}


def audit_bareiss():
    """Bareiss: exhaustive {-1,0,1} square matrices of sizes 0..3; 800 seeded cases of sizes 1..8."""
    start=time.monotonic()
    def determinant_permutation(A):
        n=len(A)
        return sum((-1)**sum(p[i]>p[j] for i in range(n) for j in range(i+1,n))*math.prod(A[i][p[i]] for i in range(n)) for p in itertools.permutations(range(n)))
    def determinant_fraction(A):
        n=len(A); M=[[Fraction(x) for x in r] for r in A]; det=Fraction(1)
        for k in range(n):
            p=next((i for i in range(k,n) if M[i][k]),None)
            if p is None:return 0
            if p!=k: M[k],M[p]=M[p],M[k];det=-det
            pivot=M[k][k];det*=pivot
            for j in range(k,n):M[k][j]/=pivot
            for i in range(k+1,n):
                f=M[i][k]
                for j in range(k,n):M[i][j]-=f*M[k][j]
        assert det.denominator==1
        return int(det)
    counts={'exhaustive':0,'random':0,'singular':0,'row_swap_first_pivot':0}
    def check(A,reference,kind):
        before=[r[:] for r in A]; expected=reference(A); got=w._det_bareiss(A)
        assert got==expected,(A,expected,got)
        assert A==before
        counts[kind]+=1
        counts['singular']+=expected==0
        counts['row_swap_first_pivot']+=bool(len(A)>1 and A[0][0]==0 and any(r[0] for r in A[1:]))
    check([],determinant_permutation,'exhaustive')
    for n in (1,2,3):
        for flat in itertools.product((-1,0,1),repeat=n*n):
            check([list(flat[i*n:(i+1)*n]) for i in range(n)],determinant_permutation,'exhaustive')
    rng=random.Random(20261013)
    for n in range(1,9):
        for t in range(100):
            A=[[rng.randint(-1000000,1000000) for _ in range(n)] for _ in range(n)]
            if n>1 and t%4==0:A[0][0]=0
            if n>1 and t%4==1:A[-1]=A[0][:]
            check(A,determinant_fraction,'random')
    return {'counts': counts, 'elapsed_seconds': time.monotonic()-start}


def audit_integer_kernel():
    """Integer kernel: the original 1749 exhaustive and 360 seeded matrix inputs; all counts computed below."""
    start=time.monotonic()
    count={'exhaustive':0,'random':0,'failures':0}; distributions={}; examples=[]
    def rank_ref(A,q):
        m=len(A[0])
        image={tuple(sum(a*x for a,x in zip(row,v))%q for row in A) for v in itertools.product(range(q),repeat=m)}
        r=0;s=len(image)
        while s>1: assert s%q==0;s//=q;r+=1
        return r
    def check(A,q,kind):
        before=[r[:] for r in A];m=len(A[0]);rank=rank_ref(A,q)
        B=w.integer_kernel_basis(A,q)
        assert len(B)==m and all(len(v)==m for v in B)
        assert all(all(sum(a*x for a,x in zip(row,v))%q==0 for row in A) for v in B)
        d=abs(det(B));assert d==q**rank,('det',A,q,B,d,rank)
        assert w.verify_kernel_basis_is_complete(B,A,q)
        reduced(B);assert A==before
        count[kind]+=1
        distributions[str((q,len(A),m,rank))]=distributions.get(str((q,len(A),m,rank)),0)+1
    for q in (2,3):
        for n,m in ((1,1),(1,2),(1,3),(2,1),(2,2),(2,3),(3,2)):
            for flat in itertools.product(range(q),repeat=n*m):
                check([list(flat[i*m:(i+1)*m]) for i in range(n)],q,'exhaustive')
    rng=random.Random(20261013)
    for q in (5,7,11):
        for n,m in ((1,4),(2,3),(2,4),(3,3),(3,4),(4,2)):
            for t in range(20):
                A=[[rng.randrange(-2*q,3*q) for _ in range(m)] for _ in range(n)]
                if n>1 and t%4==0:A[-1]=A[0][:]
                check(A,q,'random')
    return {'counts': count, 'elapsed_seconds': time.monotonic()-start}


def audit_lll():
    """Original 1D/2D enumerations and 250 seeded 3D generator sets; wrong-lattice counts are findings."""
    start=time.monotonic()
    count={'one_dim':0,'one_dim_wrong_lattice':0,'independent_2d':0,'dependent_2d_full_rank':0,'dependent_2d_wrong_lattice':0,'random_3d_full_rank':0,'random_3d_wrong_lattice':0}
    examples={}
    for a,b in itertools.product(range(-5,6),repeat=2):
        if a==b==0:continue
        B=w.lll_reduce([[a],[b]],max_swaps=2000)
        expected=math.gcd(a,b);actual=abs(B[0][0])
        count['one_dim']+=1;count['one_dim_wrong_lattice']+=expected!=actual
    for flat in itertools.product(range(-2,3),repeat=4):
        C=[list(flat[:2]),list(flat[2:])]
        if not det(C):continue
        before=[v[:] for v in C];B=w.lll_reduce(C,max_swaps=2000)
        assert abs(det(B))==abs(det(C));reduced(B);assert C==before
        count['independent_2d']+=1
    for flat in itertools.product((-1,0,1),repeat=6):
        C=[list(flat[i:i+2]) for i in range(0,6,2)];expected=minor_gcd(C,2)
        if not expected:continue
        before=[v[:] for v in C];B=w.lll_reduce(C,max_swaps=2000);actual=abs(det(B))
        reduced(B);assert C==before
        count['dependent_2d_full_rank']+=1
        if actual!=expected:
            count['dependent_2d_wrong_lattice']+=1
            examples.setdefault('2d',{'in':C,'out':B,'expected_index':expected,'actual_index':actual})
    rng=random.Random(20261013)
    for _ in range(250):
        C=[[rng.randint(-3,3) for _ in range(3)] for _ in range(4)];expected=minor_gcd(C,3)
        if not expected:continue
        B=w.lll_reduce(C,max_swaps=2000);actual=abs(det(B));reduced(B)
        count['random_3d_full_rank']+=1
        if actual!=expected:
            count['random_3d_wrong_lattice']+=1
            examples.setdefault('3d',{'in':C,'out':B,'expected_index':expected,'actual_index':actual})
    return {'counts': count, 'counterexamples': examples, 'elapsed_seconds': time.monotonic()-start}


def audit_completeness():
    """Original square-basis enumeration; redundant generators are an interface-boundary counterexample."""
    start=time.monotonic()
    count={'square_basis_cases':0,'false_positive':0,'false_negative':0,'chained_false_positive':0,'chained_false_negative':0}
    examples={}
    for dim,values in ((1,range(-6,7)),(2,range(-2,3))):
        for avec in itertools.product(range(3),repeat=dim):
            A=[list(avec)];r=int(any(avec));target=3**r
            for flat in itertools.product(values,repeat=dim*dim):
                B=[list(flat[i*dim:(i+1)*dim]) for i in range(dim)]
                expected=all(sum(a*x for a,x in zip(A[0],b))%3==0 for b in B) and abs(det(B))==target
                got=w.verify_kernel_basis_is_complete(B,A,3)
                chained=w.check_kernel_saturation(B,A,3) and got
                count['square_basis_cases']+=1
                count['false_positive']+=bool(got and not expected)
                count['false_negative']+=bool(expected and not got)
                count['chained_false_positive']+=bool(chained and not expected)
                count['chained_false_negative']+=bool(expected and not chained)
                if got and not expected: examples.setdefault(str(dim),{'A':A,'B':B,'det':det(B),'expected_det':target})
    return {'counts': count, 'counterexamples': examples, 'elapsed_seconds': time.monotonic()-start}


def minimal_examples():
    """The original explicit counterexamples, without calling sampling or setup."""
    residual = 3 - round(Fraction(3, 2)) * 2
    return {
        "lll_dependent_1d": {
            "input": [[2], [1]],
            "expected_lattice_index_in_Z": 1,
            "actual": w.lll_reduce([[2], [1]]),
        },
        "completeness_strict_superlattice": {
            "A": [[1]], "q": 3, "basis": [[1]], "expected": False,
            "actual": w.verify_kernel_basis_is_complete([[1]], [[1]], 3),
            "membership_shape_check": w.check_kernel_saturation([[1]], [[1]], 3),
        },
        "redundant_generators_interface_boundary": {
            "A": [[1]], "q": 3, "basis": [[6], [9]],
            "generated_lattice": "3Z; not an independent square basis",
            "actual": w.verify_kernel_basis_is_complete([[6], [9]], [[1]], 3),
        },
        "delaying_zero_GS_deletion_is_insufficient": {
            "input": [[2], [3]], "size_reduced_residual": residual,
            "residual_GS_norm": int(w._gram_schmidt_full([[2], [residual]])[1][1]),
        },
    }


def determinant_fraction(matrix):
    """Independent rational elimination, retained from the original Bareiss oracle."""
    n = len(matrix)
    work = [[Fraction(x) for x in row] for row in matrix]
    result = Fraction(1)
    for k in range(n):
        pivot = next((i for i in range(k, n) if work[i][k]), None)
        if pivot is None:
            return 0
        if pivot != k:
            work[k], work[pivot] = work[pivot], work[k]
            result = -result
        value = work[k][k]
        result *= value
        work[k] = [x / value for x in work[k]]
        for i in range(k + 1, n):
            factor = work[i][k]
            work[i] = [x - factor*y for x, y in zip(work[i], work[k])]
    assert result.denominator == 1
    return int(result)


def integer_coordinates(basis, vectors):
    """Return whether every supplied vector has integer coordinates in a square basis."""
    n = len(basis)
    work = [
        list(map(Fraction, [v[i] for v in basis] + [v[i] for v in vectors]))
        for i in range(n)
    ]
    for k in range(n):
        pivot = next((i for i in range(k, n) if work[i][k]), None)
        assert pivot is not None, "singular basis in independent coordinate oracle"
        work[k], work[pivot] = work[pivot], work[k]
        value = work[k][k]
        work[k] = [x / value for x in work[k]]
        for i in range(n):
            if i != k:
                factor = work[i][k]
                work[i] = [x - factor*y for x, y in zip(work[i], work[k])]
    return all(x.denominator == 1 for row in work for x in row[n:])


def audit_trapdoor_kernel():
    """MP12 Lemma 5.3, local PDF p.23, specialized to H=I.

    A[R;I]=G, GW=-Abar, and S is a complete basis of ker_q(G).
    The paper's U[[I,0],[W,S]], U=[[I,R],[0,I]], is
    [[I+RW,RS],[W,S]]. The implementation swaps the two column blocks.
    U is unimodular, so the absolute determinant remains |det S|=q^n.
    Membership plus this index establishes the complete kernel; the norm bound
    and Gaussian sampling claims of the paper are outside this linear audit.
    Only synthetic public integer matrices are used and no R is serialized.
    """
    from unittest.mock import patch

    start = time.monotonic()
    counts = {"exhaustive": 0, "random": 0, "block_formula": 0,
              "complete_raw_and_reduced": 0, "bidirectional_integer_coordinates": 0,
              "invalid_relation_rejected": 0}
    def check(a_bar, r, q, kind, reject_invalid=False):
        n, prefix = len(a_bar), len(r)
        k = (q-1).bit_length()
        width, dim = n*k, prefix+n*k
        g = [[(1 << (j % k)) if j // k == i else 0 for j in range(width)]
             for i in range(n)]
        a = [
            list(a_bar[i]) + [
                (g[i][j] - sum(a_bar[i][t]*r[t][j] for t in range(prefix))) % q
                for j in range(width)
            ] for i in range(n)
        ]
        original_a, original_r = [v[:] for v in a], [v[:] for v in r]
        captured = []
        original_lll = w.lll_reduce
        def capture(columns, *args, **kwargs):
            captured.append([v[:] for v in columns])
            return original_lll(columns, *args, **kwargs)
        with patch.object(w, "lll_reduce", capture):
            basis = w._trapdoor_kernel_basis(a, r, q)
        raw = captured[-1]
        assert len(raw) == len(basis) == dim
        assert all(len(v) == dim for v in raw + basis)
        s = [v[prefix:] for v in raw[:width]]
        wc = [v[prefix:] for v in raw[width:]]
        assert len(s) == width and abs(determinant_fraction(s)) == q**n
        for j, vector in enumerate(raw):
            bottom = vector[prefix:]
            expected_top = [
                sum(x*y for x, y in zip(row, bottom)) + int(j >= width and i == j-width)
                for i, row in enumerate(r)
            ]
            assert vector[:prefix] == expected_top
        for i, row in enumerate(g):
            assert all(sum(x*y for x, y in zip(row, v)) % q == 0 for v in s)
            assert all((sum(x*y for x, y in zip(row, v)) + a_bar[i][j]) % q == 0
                       for j, v in enumerate(wc))
        counts["block_formula"] += 1
        for candidate in (raw, basis):
            assert all(sum(x*y for x, y in zip(row, v)) % q == 0
                       for row in a for v in candidate)
            assert abs(determinant_fraction(candidate)) == q**n
            assert w.verify_kernel_basis_is_complete(candidate, a, q) is True
        counts["complete_raw_and_reduced"] += 1
        assert integer_coordinates(raw, basis) and integer_coordinates(basis, raw)
        counts["bidirectional_integer_coordinates"] += 1
        reduced(basis)
        assert a == original_a and r == original_r
        counts[kind] += 1
        if reject_invalid:
            changed = [row[:] for row in a]
            changed[0][prefix] = (changed[0][prefix] + 1) % q
            try:
                w._trapdoor_kernel_basis(changed, r, q)
            except w.InvalidParameterError:
                counts["invalid_relation_rejected"] += 1
            else:
                raise AssertionError("accepted an invalid G-trapdoor relation")
    for q, prefix in ((2, 1), (3, 1), (3, 2), (5, 1)):
        width = (q-1).bit_length()
        for flat_r in itertools.product((-1, 0, 1), repeat=prefix*width):
            r = [list(flat_r[i*width:(i+1)*width]) for i in range(prefix)]
            for a_bar in itertools.product(range(q), repeat=prefix):
                check([list(a_bar)], r, q, "exhaustive")
    rng = random.Random(20261013)
    for q in (3, 5, 7):
        for n in (1, 2):
            for prefix in (1, 2, 3):
                width = n*(q-1).bit_length()
                for _ in range(10):
                    a_bar = [[rng.randrange(-q, 2*q) for _ in range(prefix)] for _ in range(n)]
                    r = [[rng.randint(-3, 3) for _ in range(width)] for _ in range(prefix)]
                    check(a_bar, r, q, "random", reject_invalid=True)
    return {"counts": counts, "elapsed_seconds": time.monotonic()-start,
            "counterexamples": {}}


def load_scoped_module(source, expected_hash, label):
    """Compile the hash-checked bytes directly; no old/current module-name reuse."""
    source = source.resolve()
    data = source.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_hash.lower():
        raise ValueError(f"{label} SHA mismatch: expected {expected_hash}, got {actual}")
    name = f"_wang_pw_linear_{label}_{actual}"
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(source), "exec"), module.__dict__)
    return module, actual


def audit_source(source, expected_hash, label, *, trapdoor=False):
    global w
    w, actual = load_scoped_module(source, expected_hash, label)
    started_at = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    results = {
        "gf": audit_gf(),
        "bareiss": audit_bareiss(),
        "integer_kernel": audit_integer_kernel(),
        "lll": audit_lll(),
        "completeness": audit_completeness(),
    }
    if trapdoor:
        results["trapdoor_kernel"] = audit_trapdoor_kernel()
    examples = minimal_examples()
    if hashlib.sha256(source.read_bytes()).hexdigest() != actual:
        raise RuntimeError(f"{label} source changed during its diagnostic run")
    return {
        "source_sha256": actual,
        "started_at_utc": started_at,
        "elapsed_seconds": time.monotonic()-start,
        "exit_code": 0,
        "diagnostics": results,
        "counterexamples": examples,
    }


def run_regressions(expected_hash):
    """Run only the owned regression file, without pytest or bytecode caches."""
    tests = ROOT / "tests" / "test_wang_pw_linear_regressions.py"
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--tb=short", str(tests)],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    sys.stderr.write(result.stdout)
    sys.stderr.write(result.stderr)
    counts = {}
    for status in ("passed", "failed", "skipped", "error", "xfailed", "xpassed"):
        matches = re.findall(r"(\d+) " + status + r"\b", result.stdout)
        counts[status] = int(matches[-1]) if matches else 0
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != expected_hash:
        raise RuntimeError("Current source changed during regression run")
    return {"source_sha256": expected_hash,
            "test_script_sha256": hashlib.sha256(tests.read_bytes()).hexdigest(),
            "elapsed_seconds": time.monotonic()-start,
            "counts": counts, "exit_code": result.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--baseline-source", type=Path)
    parser.add_argument("--regressions", action="store_true")
    parser.add_argument("--output", type=Path, help="Write JSON here; otherwise use stdout.")
    args = parser.parse_args()
    if not __debug__:
        parser.error("Assertions are diagnostic checks; do not run with -O.")
    source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if source_hash != args.expected_sha256.lower():
        parser.error(f"Source SHA mismatch: expected {args.expected_sha256}, got {source_hash}")
    sys.path.insert(0, str(ROOT / "src"))
    started_at = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    runs = {}
    if args.baseline_source is not None:
        runs["baseline"] = audit_source(args.baseline_source, BASELINE_SHA256, "baseline")
    runs["current"] = audit_source(SOURCE, source_hash, "current", trapdoor=True)
    regression = run_regressions(source_hash) if args.regressions else None
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != source_hash:
        raise RuntimeError("Source changed during this run; refusing to emit a receipt.")
    if args.baseline_source is not None:
        if hashlib.sha256(args.baseline_source.read_bytes()).hexdigest() != BASELINE_SHA256:
            raise RuntimeError("Baseline source changed; refusing to emit a receipt.")
    exit_code = regression["exit_code"] if regression is not None else 0
    report = {
        "audit_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "lemma_source_sha256": hashlib.sha256(
            (ROOT / "papers" / "2011_lattice_trapdoors_micciancio.pdf").read_bytes()
        ).hexdigest(),
        "started_at_utc": started_at,
        "elapsed_seconds": time.monotonic()-start,
        "exit_code": exit_code,
        "runs": runs,
    }
    if regression is not None:
        report["regressions"] = regression
    payload = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.output is None:
        sys.stdout.write(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
        print(payload, end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
