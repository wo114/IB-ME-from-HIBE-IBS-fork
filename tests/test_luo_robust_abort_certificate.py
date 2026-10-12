"""Finite exhaustive checks of the robust/CRT argument, not a formal proof."""
from collections import Counter
from fractions import Fraction as Q
from itertools import product
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments/research"))
from luo_robust_abort_certificate import (certificate, profile, power_interval,
                                         scalar_abort, read_bound, challenge_abort)
from ibme.ibs.luo_module_math import Rounding


@pytest.mark.parametrize("bits", [16, 64, 1024])
def test_directed_power_including_zero_one_and_underflow(bits):
    for den in range(1, 10):
        for num in range(den + 1):
            for exponent in (0, 1, 2, 3, 7, 16):
                lo, hi = power_interval(Q(num, den), exponent, bits)
                assert lo <= Q(num, den) ** exponent <= hi
    lo, hi = power_interval(Q(1, 1000), 4096, bits)
    assert lo == 0 and 0 < hi <= Q(1, 2**bits)


@pytest.mark.parametrize("gamma", range(3, 21))
def test_lowbits_exact_count_and_all_shift_erosion(gamma):
    for h in (2, 3, 5, 9):
        q = 2 * gamma * h + 1
        rnd = Rounding(q, 2 * gamma, 1)
        for beta in range(1, (gamma - 1) // 2 + 1):
            core = [r for r in range(q) if abs(rnd.low_bits(r)) < gamma - 2 * beta]
            assert len(core) == h * (2 * gamma - 4 * beta - 1)
            eroded = [r for r in range(q) if all(abs(rnd.low_bits(r - t)) < gamma - beta
                                                for t in range(-beta, beta + 1))]
            assert core == eroded


def test_crt_second_moment_complete_tiny_public_matrix_space():
    q, n, columns, box = 5, 2, 2, 3
    ys = list(product((-1, 0, 1), repeat=4))
    def evals(y, w):
        return ((y[0] + w * y[1]) % q, (y[2] + w * y[3]) % q)
    zero = sum(any(evals(y, w) == (0, 0) for w in (2, 3)) for y in ys)
    bad_pairs = 0
    for y, z in product(ys, repeat=2):
        if any((evals(y, w)[0] * evals(z, w)[1] - evals(y, w)[1] * evals(z, w)[0]) % q == 0
               for w in (2, 3)):
            bad_pairs += 1
    d0, d2 = Q(n, box**columns), Q(n, box**columns) + Q(n, box**(columns - 1))
    assert Q(zero, len(ys)) <= d0
    assert Q(bad_pairs, len(ys)**2) <= d2
    # A is one row with two ring elements, exhaustive 5^4 choices.
    counts = []
    for a in product(range(q), repeat=4):
        count = 0
        for y in ys:
            output = ((a[0]*y[0]-a[1]*y[1]+a[2]*y[2]-a[3]*y[3]) % q,
                      (a[0]*y[1]+a[1]*y[0]+a[2]*y[3]+a[3]*y[2]) % q)
            count += all(x in (0, 1) for x in output)
        counts.append(Q(count, len(ys)))
    f = Q(2, q)**n
    mean = sum(counts)/len(counts)
    second = sum(x*x for x in counts)/len(counts)
    assert mean >= (1-d0)*f
    assert second <= f*f+d2
    assert sum((x-f)**2 for x in counts)/len(counts) <= d2+2*d0*f*f
    # Marginal concentration uses only one coefficient, not independent NTT roots.
    for w in (2, 3):
        freq = Counter((a+w*b) % q for a,b in product((-1,0,1),repeat=2))
        assert max(freq.values())/9 <= 1/box


@pytest.mark.parametrize("name", ["current", "k49-cap4096", "availability-candidate", "availability-k64"])
def test_certificate_roles_and_finite_budget_monotonicity(name):
    p = profile(name)
    one = certificate(p)
    many = certificate(p, extracts=64, signs=1000000)
    assert not one['backend_admitted'] and not one['parameters_are_formal']
    assert one['security_claim'] == 'none'
    assert read_bound(one['bounds']['finite_lifecycle_abort']) <= read_bound(many['bounds']['finite_lifecycle_abort'])
    assert read_bound(one['bounds']['sign_per_attempt_success_given_good_matrix']) > 0
    assert read_bound(one['bounds']['matrix_bad_event']) < Q(1, 2**200)


def test_scalar_and_hash_abort_endpoints():
    assert scalar_abort(256,128) == scalar_abort(2,128) == 0
    assert scalar_abort(255,128) == Q(1,256)**128
    assert 0 < challenge_abort(profile('current')) < Q(1,2**250)


@pytest.mark.parametrize("kwargs", [{"extracts":-1},{"signs":-1},{"epsilon":Q(0)},{"epsilon":Q(1)},
                                   {"extracts":65},{"oracle_queries":-1},{"signs":True},{"epsilon":0.01}])
def test_invalid_contract_rejected(kwargs):
    with pytest.raises(ValueError):
        certificate(profile('current'), **kwargs)


def test_optimized_mode_produces_identical_certificate():
    root = Path(__file__).resolve().parents[1]
    script = root/'experiments/research/luo_robust_abort_certificate.py'
    normal = subprocess.check_output([sys.executable,'-B',str(script)],cwd=root)
    optimized = subprocess.check_output([sys.executable,'-O','-B',str(script)],cwd=root)
    assert normal == optimized


def test_adaptive_external_hash_queries_are_charged_separately():
    p = profile('availability-candidate')
    no = certificate(p, extracts=0, signs=0)
    yes = certificate(p, extracts=0, signs=0, oracle_queries=2**100)
    h = read_bound(yes['bounds']['challenge_decode_abort_per_fresh_query'])
    assert read_bound(yes['bounds']['external_oracle_decode_abort']) >= 2**100*h
    assert read_bound(yes['bounds']['finite_lifecycle_abort']) > read_bound(no['bounds']['finite_lifecycle_abort'])


def test_hash_capacity_is_checked_not_assumed_for_all_constructor_profiles():
    from dataclasses import replace
    p = replace(profile('current'), max_uniform_attempts=256)
    with pytest.raises(ValueError, match='XOF capacity'):
        certificate(p)


def test_k64_finite_lifetime_is_availability_not_security():
    c = certificate(profile('availability-k64'), extracts=64, signs=65536, oracle_queries=2**64)
    assert read_bound(c['bounds']['finite_lifecycle_abort']) < Q(1, 2**153)
    assert c['security_claim'] == 'none' and not c['parameters_are_formal']
