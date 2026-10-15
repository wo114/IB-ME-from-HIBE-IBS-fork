"""Yu exact finite qualification; mandatory Sage, no security-admission claim."""
from fractions import Fraction
from itertools import product
import random

import pytest
from sage.all import AA, ZZ, matrix

from experiments.research.candidates.yu import bpr, evaluation as e
from experiments.research.candidates.yu.circuits import Circuit, Builder, CircuitBudgetExceeded
from experiments.research.candidates.yu import qualification as q


LEGACY = {
    2: ("66e4e4110bbc54f282b86c0c2730dfece8017f0f7c37c6e7b2759a7628089a36",
        "c0f7557a492eddbec26d3628e4cf0197093f17a4d7b6678995ac557a5bb88ace",
        "8ba200e6ac7b3199a256c66e4793d0bdb4e5781088d51e134897434f0dd9d452"),
    8: ("6f8f63dc591c779b8dc20593ab5158f84db77fe5fb064f3bf9d7955536410b7b",
        "0ded10581a9985bb5e021c88b04bb87189038b166491a5e89b5e4264d61aec82",
        "65ec7d47901dc9c5cdfb89df4dcad7f6875e78c62483656126dad776d52e2e37"),
}


@pytest.mark.parametrize("k", [2, 8])
def test_legacy_circuits_identical_to_pre_change_baseline(k):
    # Measured at baseline 8ba7ebf BEFORE the sole 64->128 limit change.
    spec = bpr.make_spec(bpr.Params(k))
    patterns = ((0,)*k, (1,)*k, tuple(i % 2 for i in range(k)))
    for pos, x in enumerate(patterns):
        c = bpr.compile_key_circuit(spec, x)
        assert q.circuit_digest(c) == LEGACY[k][pos]
        for key in ((0,)*spec.params.key_bits, (1,)*spec.params.key_bits,
                    tuple(i % 2 for i in range(spec.params.key_bits))):
            assert c.evaluate(key) == bpr.evaluate(spec, key, x)


@pytest.mark.parametrize("k", [40, 65, 84, 128])
def test_expanded_input_domain_compiles_with_original_budgets(k):
    spec = bpr.make_spec(bpr.Params(k, dimension=1, columns=1))
    c = bpr.compile_key_circuit(spec, (1,)*k)
    assert spec.params.key_bits == 5+32*k
    r = q.circuit_resources(c)
    assert r["gates"] <= 500_000 and r["depth"] <= 4096
    assert r["caps"] == dict(inputs=8192, gates=500_000, depth=4096)
    assert not r["nc1_family_verified"]
    for key in ((1,)*spec.params.key_bits, tuple(i % 2 for i in range(spec.params.key_bits))):
        assert c.evaluate(key) == bpr.evaluate(spec, key, (1,)*k)


@pytest.mark.parametrize("kwargs", [dict(input_bits=129, dimension=1),
    dict(input_bits=128, dimension=2), dict(input_bits=True), dict(input_bits=0),
    dict(input_bits=128, dimension=1, ticket_bits=64)])
def test_expansion_preserves_input_and_key_budget_rejections(kwargs):
    with pytest.raises(ValueError):
        bpr.Params(**kwargs)


def test_new_large_profile_still_propagates_gate_budget_abort(monkeypatch):
    spec = bpr.make_spec(bpr.Params(84, dimension=1, columns=1))
    monkeypatch.setattr(bpr, "Builder", lambda count: Builder(count, max_gates=20))
    with pytest.raises(CircuitBudgetExceeded):
        bpr.compile_key_circuit(spec, (1,)*84)


def test_measured_depth_and_live_counts_include_dead_gates_and_duplicate_edges():
    c = Circuit(2, ((0, 0), (2, 2), (3, 3), (-1, -2)), (1,))
    r = q.circuit_resources(c)
    assert r["depth"] == 3 and r["gates"] == 4
    assert r["peak_live_wire_slots"] == 3 and r["final_live_wire_slots"] == 3
    assert q.circuit_resources(Circuit(0, (), (-1, -2)))["peak_live_wire_slots"] == 0


@pytest.mark.parametrize("rows", [((0, 0),), ((3, 0), (0, 4)), ((1, 1), (1, -1)),
    ((1, 1, 1), (1, 1, 1)), ((-3, 5), (7, -2), (0, 4)), ((1 << 300, -1),)])
def test_spectral_bounds_against_exact_real_algebraic_eigenvalues(rows):
    cert = q.spectral_bounds_squared(rows)
    b = matrix(ZZ, rows)
    exact = max((b*b.transpose()).charpoly().roots(AA, multiplicities=False))
    assert cert["lower"] <= exact <= cert["upper"]
    assert cert["upper"] == min(cert["frobenius"], cert["one_times_infinity"])


def test_random_integer_spectral_cases_against_exact_eigenvalues():
    rng = random.Random(2415)  # Public test fixture, not cryptographic entropy.
    for _ in range(20):
        rows = tuple(tuple(rng.randrange(-9, 10) for _ in range(4)) for _ in range(3))
        c = q.spectral_bounds_squared(rows)
        b = matrix(ZZ, rows)
        exact = max((b*b.transpose()).charpoly().roots(AA, multiplicities=False))
        assert c["lower"] <= exact <= c["upper"]


def test_nonzero_full_prf_witness_auxiliary_algebra_without_changing_ibs_profile():
    from ibme.ibs.yu.params import YuParams
    from ibme.ibs.yu.codec import input_bits
    spec = YuParams().raw().identity_prf
    row = q.algebra_case(spec, input_bits(b"\xff", 1, identity=True), homomorphic=True,
                         evaluation_params=e.EvalParams(1, 15, 257))
    assert row["homomorphism_checks"] == 2
    assert all(b["nonzero_witness"] for b in row["norm_bounds"])
    assert all(b["lower"] <= b["upper"] <= b["coarse_squared"] for b in row["norm_bounds"])
    assert YuParams().q == 3  # Auxiliary diagnostic does not mutate the backend.


@pytest.mark.parametrize("bad", [(), ((),), ((1,), (2, 3)), ((True,),),
    ((1.0,),), ((1 << e.MAX_WITNESS_BITS,),), (("1",),), "matrix"])
def test_spectral_rejects_malformed_or_unbounded_inputs(bad):
    with pytest.raises(ValueError):
        q.spectral_bounds_squared(bad)


def test_exact_gpv_width_gate_and_boundary():
    r = q.finite_width_check(32768, 368, 17, 16)
    assert r["required_squared"] == "32384" and r["sufficient_gate"]
    assert q.finite_width_check(32384, 368, 17, 16)["sufficient_gate"]
    assert not q.finite_width_check(32383, 368, 17, 16)["sufficient_gate"]
    assert q.finite_width_check(Fraction(32384, 7), Fraction(368, 7), 17, 16)["sufficient_gate"]
    assert not r["full_sampler_admission"]


@pytest.mark.parametrize("width", [True, 0, -1, 1.0, "1e500000", 1 << 1025])
def test_width_gate_requires_bounded_exact_positive_rationals(width):
    with pytest.raises(ValueError):
        q.finite_width_check(width, 1, 17, 16)


def test_append_match_preserves_constants_outputs_semantics_and_homomorphism():
    c = Circuit(2, ((0, 1), (2, 2)), (-1, -2, 3, 0))
    p, a = e.EvalParams(1, 3, 17), ((1, 2, 3),)
    witnesses = ((((1,)*p.w, (-1,)*p.w, (1,)*p.w)),)*2
    for key in product((0, 1), repeat=2):
        direct = c.evaluate(key)
        for pattern in product((0, 1), repeat=4):
            composed = q.compose_match(c, pattern)
            assert composed.evaluate(key) == (int(pattern == direct),)
            pub_input = e.encode_inputs(p, a, key, witnesses)
            private = e.eval_private(p, composed, a, key, witnesses)
            public = e.eval_public(p, composed, a, pub_input)
            assert e.homomorphism_holds(p, a, public, private)
            norm = q.spectral_bounds_squared(e.join(private.witnesses))
            assert norm["upper"] <= q.coarse_spectral_squared(composed, p)


def test_public_byte_snapshot_and_parameter_conditions():
    from ibme.ibs.yu.params import YuParams
    from experiments.research.candidates.yu.profiles import tiny_profile
    p = YuParams()
    assert (p.prf_dimension, p.prf_columns) == (1, 1)
    assert (p.identity_bits, p.message_bits, p.signing_input_bits) == (40, 40, 84)
    assert (p.key_bits(40), p.key_bits(84), p.output_bits) == (1285, 2693, 1)
    old = tiny_profile()
    assert old.identity_bits == 2 and old.identity_prf.params.dimension == 2
    for raw in (p.raw(), old):
        c = q.parameter_conditions(raw)
        assert c["signature_dimension"] == 19
        assert c["public_qe1_forgery"]["status"] == "failed"
        assert c["verifier_norm_squared_limit"] == 1275068416
        assert c["gamma_C1_exec"]["sufficient_gate"]
        assert c["delta_C1_exec_using_raw_randbasis_bound"]["sufficient_gate"]
        assert c["beta"]["status"] == c["lemma7"]["status"] == "pending"
        assert not c["ap09"]["near_uniform_bound_nonvacuous"]
        assert c["security_claim"] == "none" and not c["parameters_are_formal"]


def test_byte_domain_is_injective_including_zero_payload_and_empty_message():
    from ibme.core.errors import EncodingError
    from ibme.ibs.yu.codec import input_bits
    messages = [b""] + [bytes([i]) for i in range(256)]
    encoded = [input_bits(m, 1) for m in messages]
    assert len(set(encoded)) == 257 and set(map(len, encoded)) == {40}
    for data, bits in zip(messages, encoded):
        packed = bytes(sum(bits[i+j] << (7-j) for j in range(8)) for i in range(0, 40, 8))
        assert int.from_bytes(packed[:4], "big") == len(data)
        assert packed[4:4+len(data)] == data
        assert packed[4+len(data):] == bytes(1-len(data))
    with pytest.raises(EncodingError):
        input_bits(b"", 1, identity=True)


@pytest.mark.parametrize("id_max,msg_max", tuple(product(range(1, 5), repeat=2)))
def test_byte_profile_lengths_obey_joint_bit_and_key_budget(id_max, msg_max):
    from ibme.ibs.yu.params import YuParams
    length = 64 + 8*(id_max+msg_max) + 4
    if length > 128:
        with pytest.raises(ValueError):
            YuParams(identity_max_bytes=id_max, message_max_bytes=msg_max)
    else:
        p = YuParams(identity_max_bytes=id_max, message_max_bytes=msg_max)
        assert p.raw().signing_prf.params.input_bits == length
        assert p.key_bits(length) <= 8192
