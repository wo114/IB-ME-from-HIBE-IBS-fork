"""Local exact arithmetic evidence; does not construct a cryptographic instance."""
import hashlib
import json
from itertools import product
from math import isqrt
from pathlib import Path
import platform
import sys

from sage.all import GF, PolynomialRing, matrix, power_mod
from experiments.research.candidates.srgg.quotient_challenge import recover


def planning(w):
    n, d, r2, p = 2048, 3, 128, 53615
    m = n // 2
    M = (2 + w) * d
    root = 1 + 2*d*d*w*n*n
    master = 9*r2*root + r2 + 1
    raw = 16*M*n*master
    user = 2*raw + 2*d*n*(p-1)**2
    sig = 2*r2*(n*user + 1) + r2 + 1
    B = (M+1)*n*sig
    G, J = isqrt(4*B), (M-1)*n + 1
    T, q0 = isqrt(4*B*J), 3**w
    ratio_num = (3*G*(2*T + 1))**2
    def below(bits):
        return G < q0 and ratio_num**m * 3**m * 2**bits < q0**m*(3**m - 1)
    return dict(w=w, p=p, Q=p*q0, Q_bits=(p*q0).bit_length(),
        B=B, G=G, J=J, T=T, qfactor=q0,
        qfactor_bits=q0.bit_length(), G_bits=G.bit_length(), T_bits=T.bit_length(),
        ratio_numerator_bits=ratio_num.bit_length(),
        qfactor_gt_G=q0 > G, bound_below_2_minus_211=below(211),
        bound_below_2_minus_212=below(212),
        signature_dimension=(M+1)*n,
        beyond_frozen_digits_resource_guard=w > 32)


def rank_cases():
    output = []
    for n in (4, 8, 16, 32, 64):
        ring = PolynomialRing(GF(3), 'x')
        x = ring.gen()
        mod = x**n + 1
        factors = mod.factor()
        degrees = [int(f.degree()) for f,e in factors for _ in range(int(e))]
        assert degrees == [n//2, n//2]
        polys = [ring(coeffs) for coeffs in product((-1, 0, 1), repeat=n)] if n == 4 else [
            ring(1), x, factors[0][0], factors[1][0], mod - 1,
            sum(x**i for i in range(n)), sum((-1)**i*x**i for i in range(n))]
        checked, minimum = 0, n
        for f in polys:
            if not f:
                continue
            # Independent coefficient multiplication in F3, not SRGG ring helpers.
            cols = []
            for j in range(n):
                value = (f*x**j) % mod
                cols.append([value[i] for i in range(n)])
            rank = int(matrix(GF(3), cols).transpose().rank())
            assert rank >= n//2
            checked += 1
            minimum = min(minimum, rank)
        output.append(dict(n=n, factor_degrees=degrees,
            multiplication_matrices=checked, minimum_rank=minimum))
    assert power_mod(3, 1024, 4096) == 1
    assert power_mod(3, 512, 4096) != 1
    return output


def toy():
    z = (0, 0, 0, 0)
    one, two = (1, 0, 0, 0), (2, 0, 0, 0)
    A = ((one,z,z,z,z,z,z,z), (z,one,z,z,z,z,z,z))
    h = (one, two)
    first = (z,)*9
    second = ((9,0,0,0), (18,0,0,0)) + (z,)*6 + ((9,0,0,0),)
    assert recover(A, h, first, z, 45) == (z,z)
    assert recover(A, h, second, one, 45) == (z,z)
    squared = sum(t*t for poly in second for t in poly)
    assert squared == 486
    return dict(degree=4, Q=45, modulus_factor=9,
        first_challenge=[0,0], second_challenge=[1,0],
        both_recover_zero=True, second_squared_response_norm=squared,
        response_last_difference_mod9=0,
        fixture_only_not_current_crypto_attack=True)


base = Path(__file__).resolve().parent
source = Path('docs/research/team-b-delivery/2026-10-16-srgg-hardness/finite-search.json')
report = dict(schema='IBME/SRGG-LOSSY-ROUTE-CHECK/1',
    source_receipt_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    environment=dict(python=sys.version.split()[0],platform=platform.platform()),
    actual_entropy_bytes=0, cryptographic_lifecycle_executed=False,
    rows=[planning(w) for w in (22,32,64,96,128,160)],
    rank_checks=rank_cases(),
    degree2048_order_check=dict(modulus=4096, base=3, order=1024,
        half_power_not_one=True), unit_inference_counterexample=toy(),
    security_claim='none', backend_admitted=False,
    parameters_are_formal=False, nist_security_category=None)
current = next(r for r in json.loads(source.read_text(encoding='utf-8'))['selected_candidates']
    if r['name']=='search-n2048-d3-b3-w22-r2128-p53615')
assert report['rows'][0]['B'] == current['parameters']['signature_norm_squared_cap']
assert report['rows'][0]['Q'] == current['Q']
(base/'checks.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
