"""Exact interactive-law implications and the frozen SRGG numerical point.

These are mathematical/arithmetic checks. No large key is generated, and no
Fiat--Shamir, random-oracle programming, or QROM security test is performed.
"""
from fractions import Fraction as F
from itertools import product
import json

import pytest

from experiments.research.candidates.srgg.native_sig import (
    DEFAULT_INPUT, build_report, commitment_entropy_certificate, conditional_statistical_ledger,
    interactive_certificate, profile_certificate, zeta_coset_smoothing,
)


@pytest.mark.parametrize("n,c", [(2, F(5, 2)), (4, F(7)), (8, F(19, 2))])
def test_theta_certificate_contains_the_zeta_dual_scale_and_finite_majorant(n, c):
    row = zeta_coset_smoothing(degree=n, c_minimum=c)
    assert F(row["normalized_minimum_on_Zn_exact"]) == c/2
    assert int(row["lattice_index"]) == 2**(n//2)
    a = F(row["theta_q_upper_exact"])
    # Exact finite prefix of the upper theta series, independently summed.
    finite = (1+2*sum(a**(k*k) for k in range(1, 4)))**n-1
    assert finite <= F(row["normalizer_relative_error_upper_exact"])
    assert row["all_centers_and_challenge_cosets"] is True


def test_small_shape_is_reported_vacuous_instead_of_claiming_hvzk():
    row = zeta_coset_smoothing(degree=512, c_minimum=F(1, 100))
    assert row["nontrivial"] is False
    assert F(row["interactive_joint_tv_upper_exact"]) == 1
    assert row["normalizer_relative_error_upper_exact"] is None


def test_relative_normalizer_bound_above_one_is_not_capped_as_a_probability():
    # For n=2 and t=.5 the sufficient product bound exists but exceeds one.
    row = zeta_coset_smoothing(degree=2, c_minimum=1)
    assert F(row["normalizer_relative_error_upper_exact"]) > 1
    assert row["nontrivial"] is False
    assert F(row["interactive_joint_tv_upper_exact"]) == 1


@pytest.mark.parametrize("n,c", [(True, 2), (3, 2), (0, 2), (2, 0), (2, -1), (2, 1.5)])
def test_shape_and_degree_inputs_are_exact_and_bounded(n, c):
    with pytest.raises(ValueError):
        zeta_coset_smoothing(degree=n, c_minimum=c)


def test_perturbation_positivity_cannot_be_inferred_from_an_invalid_cap():
    # n=2, ||y||^2<=3 => beta<=4; nu=2.  Equality leaves a singular shape.
    with pytest.raises(ValueError, match="s>nu"):
        interactive_certificate(degree=2, r_squared=1, signature_squared=8, user_squared_cap=3)
    good = interactive_certificate(degree=2, r_squared=1, signature_squared=9, user_squared_cap=3)
    assert F(good["smoothing"]["C_minimum_lower_exact"]) == F(2, 9)


def test_conditional_head_entropy_integer_bound_contains_the_exact_coset_bound():
    row = commitment_entropy_certificate(degree=2, rank=1, r_squared=1,
        signature_squared=1024, user_squared_cap=1, modulus=17)
    ell = F(row["S_minimum_lower_exact"])
    eps = F(row["head_theta_normalizer_relative_error_upper_exact"])
    assert ell == 1020
    assert row["ceil_sqrt_s_integer"] == 32
    assert row["floor_log2_ell"] == 9
    assert row["ceil_log2_head_growth"] == 2
    assert row["ideal_commitment_min_entropy_bits_lower"] == 4
    coset_bound = (1+F(32, 17))**2/((1-eps)*ell)
    assert coset_bound <= F(1, 2**4)
    assert row["keygen_exception_probability_within_full_cap_class"] == "0"
    assert row["real_finite_commitment_entropy_established"] is False


def test_conditional_head_schur_bound_does_not_require_independent_coordinates():
    # This correlated positive definite S has eigenvalues 16,22,22.
    # Fixing its third coordinate gives this exact 2-by-2 Schur shape.
    schur = ((F(99, 5), F(-11, 5)), (F(-11, 5), F(99, 5)))
    for sign, bound in ((1, 16), (-1, 22)):
        a = sign*(schur[0][0]-bound)
        b = sign*schur[0][1]
        c = sign*(schur[1][1]-bound)
        assert a >= 0 and c >= 0 and a*c-b*b >= 0


def test_commitment_entropy_is_unavailable_without_a_nontrivial_head_normalizer():
    row = commitment_entropy_certificate(degree=2, rank=1, r_squared=1,
        signature_squared=F(401, 100), user_squared_cap=1, modulus=17)
    assert row["head_theta_normalizer_relative_error_upper_exact"] is None
    assert row["entropy_certificate_available"] is False
    assert row["ideal_commitment_min_entropy_bits_lower"] == 0


@pytest.mark.parametrize("q", [2, 4, True, 3.5])
def test_commitment_bound_rejects_invalid_modulus(q):
    with pytest.raises(ValueError):
        commitment_entropy_certificate(degree=2, rank=1, r_squared=1,
            signature_squared=1024, user_squared_cap=1, modulus=q)


def test_normalized_theta_tilt_controls_joint_law_and_complete_abort_atom():
    # Finite model of D(z)*Theta(c,z)/E_D[Theta(c,Z)].  Coset normalizers
    # may vary with c; the normalization is performed separately per challenge.
    base = {0: F(1, 6), 1: F(1, 3), 2: F(1, 2)}
    eps = F(1, 7)
    simulator = {(c, z): F(1, 2)*p for c in (0, 1) for z, p in base.items()}
    gate = lambda law: {
        **{k: p for k, p in law.items() if k[1] != 2},
        None: sum(p for k, p in law.items() if k[1] == 2),
    }
    for signs in product((-1, 1), repeat=6):
        theta = {(c, z): 1+eps*signs[3*c+z] for c in (0, 1) for z in base}
        normalizers = {c: sum(p*theta[c, z] for z, p in base.items()) for c in (0, 1)}
        real = {(c, z): F(1, 2)*p*theta[c, z]/normalizers[c]
                for c in (0, 1) for z, p in base.items()}
        tv = sum(abs(real[k]-simulator[k]) for k in real)/2
        assert tv <= eps/(1-eps)
        gated_real, gated_sim = gate(real), gate(simulator)
        assert sum(gated_real.values()) == sum(gated_sim.values()) == 1
        gated_tv = sum(abs(gated_real[k]-gated_sim[k]) for k in gated_real)/2
        assert gated_tv <= tv
        # In the simulator a z-only gate leaves the successful c uniform.
        success = 1-gated_sim[None]
        assert sum(p for k, p in gated_sim.items() if k is not None and k[0] == 0)/success == F(1, 2)


def test_issuance_terms_count_once_per_key_and_abort_is_not_success_conditioned():
    row = conditional_statistical_ledger(counted_issuances=3, signing_queries=7,
        max_sign_attempts=2, issuance_tv=F(1, 10000), ideal_bad_key=F(1, 20000),
        finite_sign_tv=F(1, 30000), interactive_hvzk_tv=F(1, 40000), norm_reject=F(1, 50000))
    expected = 3*(F(1, 10000)+F(1, 20000))+14*(F(1, 30000)+F(1, 40000)+F(1, 50000))
    bound = F(row["total_upper_exact"])
    assert expected <= bound < expected+F(3, 2**256)
    assert row["FS_or_QROM_simulation_proved"] is False
    zero = conditional_statistical_ledger(counted_issuances=0, signing_queries=0,
        max_sign_attempts=16, issuance_tv=1, ideal_bad_key=1,
        finite_sign_tv=1, interactive_hvzk_tv=1, norm_reject=1)
    assert F(zero["total_upper_exact"]) == 0


@pytest.mark.parametrize("count", [-1, True, 1.5, 2**65])
def test_ledger_rejects_unbounded_or_inexact_query_counts(count):
    with pytest.raises(ValueError):
        conditional_statistical_ledger(counted_issuances=count, signing_queries=1,
            max_sign_attempts=1, issuance_tv=0, ideal_bad_key=0,
            finite_sign_tv=0, interactive_hvzk_tv=0, norm_reject=0)


def test_frozen_n512_full_cap_fails_long_ledger_but_high_probability_analysis_closes_arithmetic():
    report = build_report()
    row = next(p for p in report["profiles"] if p["profile"] == "query-bounded-deep")
    full, good = row["full_cap_interactive"], row["good_key_interactive"]
    s = row["parameters"]["signature_squared"]
    assert F(full["smoothing"]["normalized_minimum_on_Zn_exact"]) == 32-F(2016, s)
    assert F(good["user_squared_cap_exact"]) == F(row["parameters"]["user_norm_cap"], 4)
    assert F(row["raw_threshold_exact"]) == 42265023385474048
    assert F(row["ideal_bad_issued_key_upper_exact"]) == F(1, 2**256)
    assert F(good["smoothing"]["normalizer_relative_error_upper_exact"]) <= F(4666, 2**256)
    assert F(good["smoothing"]["interactive_joint_tv_upper_exact"]) <= F(4667, 2**256)
    last = row["conditional_statistical_ledgers"][-1]
    assert last["counted_issuances"] == last["signing_queries"] == 2**40
    assert F(last["full_cap_interactive_hvzk_term_alone_upper_exact"]) > F(1, 2**128)
    assert F(last["total_upper_exact"]) <= F(1, 2**128)
    assert row["runtime_key_filter_changed"] is False
    assert row["input_certificate_hypotheses_reproved_by_this_tool"] is False
    assert row["security_claim"] == "none"
    assert row["backend_admitted"] is row["parameters_are_formal"] is False
    assert report["actual_entropy_bytes"] == 0
    entropy = row["full_cap_ideal_commitment_entropy"]
    assert entropy["ideal_commitment_min_entropy_bits_lower"] == 36351
    assert entropy["ideal_commitment_max_atom_upper_dyadic_exponent"] == -36351
    assert entropy["real_finite_commitment_entropy_established"] is False
    assert all(len(digest) == 64 for digest in report["source_sha256"].values())
    json.dumps(report)


def test_incorrect_schema_is_not_silently_imported_as_prior_evidence(tmp_path):
    path = tmp_path/"bad.json"
    path.write_text('{"schema":"wrong","profiles":[]}', encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        build_report(path)


def test_good_key_event_with_nonpositive_hnf_threshold_remains_vacuous():
    source = json.loads(DEFAULT_INPUT.read_text(encoding="utf-8"))
    profile = source["profiles"][0]
    profile["parameters"]["user_norm_cap"] = 1
    row = profile_certificate(profile, queries=(1,))
    assert F(row["ideal_bad_issued_key_upper_exact"]) == 1
    assert row["conditional_statistical_ledgers"][0]["at_most_2_minus_128"] is False
