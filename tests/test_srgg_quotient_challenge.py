"""Independent integer/coset identities and nonvacuous accepted-domain checks."""
from collections import Counter
from copy import deepcopy
from fractions import Fraction
from itertools import product
import json
from pathlib import Path

import pytest

from experiments.research.candidates.srgg import quotient_challenge as qc


def schoolbook(first, second):
    result = [0]*len(first)
    for i, x in enumerate(first):
        for j, y in enumerate(second):
            k = i+j
            result[k % len(first)] += x*y if k < len(first) else -x*y
    return tuple(result)


@pytest.mark.parametrize("n", [2, 4, 8])
def test_all_binary_challenges_split_bijectively_into_independent_uniform_halves(n):
    counts = Counter(qc.split_challenge(c) for c in product(range(2), repeat=n))
    halves = tuple(product(range(2), repeat=n//2))
    assert set(counts) == set(product(halves, repeat=2))
    assert set(counts.values()) == {1}
    for e, high in counts:
        assert qc.split_challenge(qc.join_challenge(e, high)) == (e, high)


@pytest.mark.parametrize("n", [2, 4])
def test_exact_signed_integer_image_lattice_and_orthogonal_scale(n):
    zeta = (1,)+(0,)*(n//2-1)+(1,)+(0,)*(n//2-1)
    adjoint = (1,)+(0,)*(n//2-1)+(-1,)+(0,)*(n//2-1)
    for u in product(range(-2, 3), repeat=n):
        actual = schoolbook(zeta, u)
        assert qc.zeta_action(u) == actual
        assert qc.coset_class(actual) == (0,)*(n//2)
        assert qc.coset_inverse(actual, (0,)*n) == u
        assert schoolbook(adjoint, actual) == tuple(2*x for x in u)
        assert sum(x*x for x in actual) == 2*sum(x*x for x in u)


@pytest.mark.parametrize("n", [2, 4])
def test_every_finite_coset_translates_to_canonical_lift_with_identical_gaussian_exponent(n):
    for c in product(range(2), repeat=n):
        e = qc.split_challenge(c)[0]
        c0 = qc.canonical_challenge(e)
        for u in product(range(-1, 2), repeat=n):
            v = tuple(x+y for x, y in zip(qc.zeta_action(u), c))
            u0 = qc.coset_inverse(v, c0)
            assert u0 is not None
            assert tuple(x+y for x, y in zip(qc.zeta_action(u0), c0)) == v
            expected = Fraction(sum(x*x for x in v), 2)
            assert qc.centered_exponent_squared(u, c) == expected
            assert qc.centered_exponent_squared(u0, c0) == expected


def test_nonmatching_coset_has_no_integer_preimage():
    assert qc.coset_inverse((1, 0), (0, 0)) is None
    assert qc.coset_inverse((-3, 0, 2, 0), (0, 0, 0, 0)) is None


@pytest.mark.parametrize("n", [2, 4])
def test_one_query_linear_output_relabeling_is_equal_on_every_oracle_basis_state(n):
    def g(value):
        e, high = qc.split_challenge(value)
        return e+high
    def xor(a, b):
        return tuple(x ^ y for x, y in zip(a, b))
    for value in product(range(2), repeat=n):
        for target in product(range(2), repeat=n):
            assert g(g(target)) == target
            assert g(xor(g(target), value)) == xor(target, g(value))


def test_frozen_finite_u_integer_translation_keeps_bytes_and_bottom():
    pytest.importorskip("sage.all", reason="specified WSL Sage for actual finite-u test")
    from ibme.core.randomness import DeterministicRandom
    from experiments.research.gaussian_reference import SamplingAbort
    from experiments.research.candidates.srgg.aggregate_budget import sample_batch
    from experiments.research.candidates.srgg.reduction_samplers import deep_scalar_options
    from experiments.research.candidates.srgg.wide_scalar import WideScalarGaussian

    class TracedSource:
        def __init__(self, *, fail=False):
            self.source = DeterministicRandom(b"quotient-finite-integer-translation")
            self.reads = []
            self.fail = fail
        def read(self, size):
            self.reads.append(size)
            return b"\xff"*size if self.fail else self.source.read(size)

    scalar = WideScalarGaussian(64, 64, options=deep_scalar_options())
    for c in product(range(2), repeat=4):
        canonical = qc.canonical_challenge(qc.split_challenge(c)[0])
        centers = [tuple(Fraction(-x, 2) for x in qc.zeta_action(challenge, adjoint=True))
            for challenge in (c, canonical)]
        sources = [TracedSource(), TracedSource()]
        draws = [sample_batch(scalar, 64, center, rng=source, error_bits=192)
            for center, source in zip(centers, sources)]
        values = [tuple(x+y for x, y in zip(qc.zeta_action(u), challenge))
            for u, challenge in zip(draws, (c, canonical))]
        assert values[0] == values[1] and sources[0].reads == sources[1].reads
    sources = [TracedSource(fail=True), TracedSource(fail=True)]
    for challenge, source in zip(((0,)*4, (1,)*4), sources):
        center = tuple(Fraction(-x, 2) for x in qc.zeta_action(challenge, adjoint=True))
        with pytest.raises(SamplingAbort):
            sample_batch(scalar, 64, center, rng=source, error_bits=192)
    assert sources[0].reads == sources[1].reads == [1]*256


def independent_recover(a, target, response, challenge, q):
    n = len(challenge)
    j = (1,)+(0,)*(n//2-1)+(-1,)+(0,)*(n//2-1)
    result = []
    for i, row in enumerate(a):
        last = tuple(q*x-2*h for x, h in zip(j if i == 0 else (0,)*n, target[i]))
        matrix_row = tuple(tuple(2*x for x in poly) for poly in row)+(last,)
        columns = [schoolbook(poly, z) for poly, z in zip(matrix_row, response)]
        correction = schoolbook(j, challenge) if i == 0 else (0,)*n
        result.append(tuple((sum(col[k] for col in columns)-q*correction[k]) % (2*q)
            for k in range(n)))
    return tuple(result)


@pytest.mark.parametrize("n", [2, 4, 8])
def test_recover_only_reads_quotient_even_for_correlated_signed_responses(n):
    one = (1,)+(0,)*(n-1)
    a = ((one, tuple(i-2 for i in range(n))), (tuple(2-i for i in range(n)), one))
    target = (tuple(i+1 for i in range(n)), (3,)*n)
    z = (tuple(1-i for i in range(n)), (1,)*n, (-1,)*n)
    for c in product(range(2), repeat=n):
        w = qc.recover(a, target, z, c, 5)
        assert w == independent_recover(a, target, z, c, 5)
        assert w == qc.recover(a, target, z, qc.canonical_challenge(qc.split_challenge(c)[0]), 5)


@pytest.mark.parametrize("challenge", list(product(range(2), repeat=2)))
def test_nonempty_full_response_enumeration_and_arbitrary_constant_hash_table_bijection(challenge):
    responses = tuple(tuple(tuple(flat[i:i+2]) for i in range(0,6,2))
        for flat in product(range(-1, 2), repeat=6))
    result = qc.accepted_signature_bijection((((1, 0), (2, 0)),), ((1, 1),),
        responses, lambda _w: challenge, modulus=5, norm_cap=2)
    assert result["full_accepted"] > 0
    assert result["full_accepted"] == result["quotient_accepted"]
    assert result["exact_signature_novelty_preserved"]


def test_same_coset_different_full_c_is_not_a_second_accepted_signature_of_fixed_hash():
    a, target, z = (((1, 0), (2, 0)),), ((1, 1),), ((0, 0),)*3
    c, other = (0, 0), (1, 1)
    w = qc.recover(a, target, z, c, 5)
    assert w == qc.recover(a, target, z, other, 5)
    assert qc.split_challenge(c)[0] == qc.split_challenge(other)[0]
    fixed_oracle = {w: c}
    assert fixed_oracle[w] == c and fixed_oracle[w] != other
    # There is one acceptable high half, even though strip on all untrusted
    # candidate signatures would not be injective.


def test_exact_returned_signature_novelty_is_preserved_by_strip_and_lift():
    a, target = (((1, 0), (2, 0)),), ((1, 1),)
    oracle = lambda w: (w[0][0] % 2, w[0][1] % 2)
    accepted = []
    for flat in product(range(-1, 2), repeat=6):
        if sum(x*x for x in flat) > 2:
            continue
        z = tuple(tuple(flat[i:i+2]) for i in range(0,6,2))
        for c in product(range(2), repeat=2):
            if oracle(qc.recover(a, target, z, c, 5)) == c:
                accepted.append((z, c))
    assert len(accepted) > 1
    strip = lambda sig: (sig[0], qc.split_challenge(sig[1])[0])
    for logged in accepted:
        for forged in accepted:
            assert (forged != logged) == (strip(forged) != strip(logged))


def test_frozen_receipt_finite_u_budget_is_charged_without_new_entropy():
    report = qc.build_report()
    cost = report["finite_u_cost"]
    assert cost["degree"] == 512 and cost["max_norm_attempts"] == 16
    assert cost["per_attempt_finite_u_hard_byte_cap"] == 642980
    assert Fraction(cost["full_transcript_finite_u_replacement_upper_exact"]) == 2**44*Fraction(cost["u_batch_tv_including_bottom_exact"])
    assert cost["below_2_minus_138_for_this_u_term_only"]
    assert not cost["P_sampler_replacement_required_for_quotient_equivalence"]
    assert not cost["ideal_P_entropy_automatically_inherited"]
    assert report["actual_entropy_bytes"] == 0
    assert report["coset_exponent_cases"] == 828
    assert sum(row["full_accepted"] for row in report["finite_signature_cases"]) > 0
    assert report["security_claim"] == "none" and report["nist_security_category"] is None
    assert not report["backend_admitted"] and not report["parameters_are_formal"]


@pytest.mark.parametrize("change", ["profile", "count", "width", "admission", "negative_tv", "schema"])
def test_mismatched_or_corrupt_finite_u_receipts_are_rejected(tmp_path, change):
    source = Path(qc.__file__).parents[4]/"docs/research/team-b-delivery/2026-10-16-srgg-bridge/structured-execution-n512-d2w8.json"
    record = deepcopy(json.loads(source.read_text(encoding="utf-8")))
    if change == "profile": record["numerical_profile"] = "default"
    elif change == "count": record["u_batch"]["count"] = 511
    elif change == "width": record["u_batch"]["squared_width_class"] = ["1", "1"]
    elif change == "admission": record["u_batch"]["admitted"] = False
    elif change == "negative_tv": record["u_batch"]["scalar_kernel_tv_including_aggregate_exact"] = "-1/2"
    else: record["schema"] = "other"
    path = tmp_path/"receipt.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError): qc.finite_u_cost(path)


@pytest.mark.parametrize("bad", [(0, 2), (True, 0), (0,), (0,)*3, [0, 0]])
def test_noncanonical_binary_tuples_are_rejected(bad):
    with pytest.raises(ValueError): qc.split_challenge(bad)


def test_accepted_signature_enumeration_is_explicitly_bounded():
    with pytest.raises(ValueError, match="resource limit"):
        qc.accepted_signature_bijection((((0,)*16,),), ((0,)*16,),
            (((0,)*16, (0,)*16),), lambda _w: (0,)*16, modulus=5, norm_cap=1)


def test_recover_rejects_even_modulus_and_shape_errors():
    with pytest.raises(ValueError, match="odd"):
        qc.recover((((1, 0),),), ((1, 1),), ((0, 0),)*2, (0, 0), 4)
    with pytest.raises(ValueError, match="dimension"):
        qc.recover((((1, 0),),), ((1, 1),), ((0, 0, 0, 0),)*2, (0, 0), 5)
