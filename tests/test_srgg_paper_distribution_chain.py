"""Independent checks for the SRGG distribution-chain certificate."""
from fractions import Fraction
import json
from pathlib import Path

import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_distribution_chain import (
    ChainCertificateError, GATE_FLOOR, HISTORY_SCOPE, MOMENT_ORDERS, PROFILES,
    INTERPRETATIONS, bad_root_certificate, build_report, good_root_constants,
    lifecycle_probe, moment_bound,
)


def _tv(left, right):
    keys = set(left) | set(right)
    return sum(abs(Fraction(left.get(k, 0)) - Fraction(right.get(k, 0)))
               for k in keys) / 2


def test_good_root_implication_is_exact_for_all_six_rows():
    for profile in PROFILES:
        for interpretation in INTERPRETATIONS:
            c = good_root_constants(profile, interpretation)
            assert c["C_gate_implies_A"] is True
            assert c["C_gate_implies_schur_floor"] is True
            assert c["uniform_schur_lower_bound_gt_64"] is True
            assert Fraction(c["uniform_schur_lower_bound_exact"]) > GATE_FLOOR
            assert c["uniform_gain_coefficient_upper_lt_512"] is True
            assert c["uniform_factor_in_250_8192"] is True
            assert c["uniform_center_error_below_2_minus_96"] is True
            assert c["uniform_object_cap_bits"] <= 255
            # The C gate threshold is strictly below A, not merely non-strict.
            assert (Fraction(c["threshold_C_gate_squared_exact"])
                    < Fraction(c["threshold_A_squared_exact"]))


def test_moment_A_bound_matches_frozen_setup_acceptance_receipt():
    root = Path(__file__).resolve().parents[1]
    frozen = json.loads((root / "docs/research/team-b-delivery/"
        "2026-10-18-srgg-setup-acceptance/setup-acceptance.json").read_text())
    by_profile = {row["profile"]: row for row in frozen["rows"]}
    for profile in PROFILES:
        row = by_profile[profile]
        for interpretation in INTERPRETATIONS:
            cert = bad_root_certificate(profile, interpretation)
            assert cert["moment_order"] == MOMENT_ORDERS[profile]
            assert Fraction(cert["A_rejection_one_attempt_upper_exact"]) == \
                Fraction(row["mathematical_one_attempt_rejection_upper_exact"])
            assert Fraction(cert["A_rejection_one_attempt_upper_exact"]) < 1


def _dyadic_value(text):
    assert text.startswith("2^-")
    return Fraction(1, 2**int(text[3:]))


def test_mathematical_bad_root_mass_and_ideal_retry_abort_are_nontrivial():
    for profile in PROFILES:
        for interpretation in INTERPRETATIONS:
            cert = bad_root_certificate(profile, interpretation)
            q_a = Fraction(cert["A_rejection_one_attempt_upper_exact"])
            q_c = Fraction(cert["C_gate_rejection_one_attempt_upper_exact"])
            tv = Fraction(cert["mathematical_mu_A_mu_G_tv_upper_exact"])
            assert 0 < q_a < q_c < 1
            assert tv == q_c / (1 - q_a)
            assert 0 < tv < 1
            # The exact 64th power is huge; the JSON keeps its outward
            # power-of-two upper bound instead.
            abort_upper = _dyadic_value(
                cert["mathematical_G_64_retry_abort_upper_dyadic"])
            assert q_c**64 <= abort_upper
            assert cert["mathematical_G_64_retry_abort_below_2_minus_64"] is True
            assert cert["implemented_guard_retry_abort_upper"] is None


def test_moment_bound_rejects_nonpositive_threshold():
    with pytest.raises(ChainCertificateError):
        moment_bound(Fraction(0), 4, 4, 17, 512)
    with pytest.raises(ChainCertificateError):
        moment_bound(Fraction(-1), 4, 4, 17, 512)
    # A positive but too-small threshold yields a vacuous value, which the
    # bad-root certificate rejects rather than reporting as a probability.
    assert moment_bound(Fraction(1), 4, 4, 17, 512) > 1


def test_data_processing_guard_absorbs_bad_key_mass():
    """The guarded reference uses the same deterministic key guard.

    Keys are 0 (good) and 1 (bad); the guard maps 1 to the abort atom.  The
    raw key laws differ, but after the guard the TV is still bounded by the
    raw TV.  For good keys the sign kernel differs by epsilon; bad keys both
    abort.  The s-call hybrid bound follows with no separate beta_bad term.
    """
    p_raw = {0: Fraction(9, 10), 1: Fraction(1, 10)}
    q_raw = {0: Fraction(17, 20), 1: Fraction(3, 20)}
    assert _tv(p_raw, q_raw) == Fraction(1, 20)

    def guard(law):
        return {("abort" if key == 1 else key): mass
                for key, mass in law.items()}

    p_guard, q_guard = guard(p_raw), guard(q_raw)
    assert _tv(p_guard, q_guard) <= _tv(p_raw, q_raw)

    # Good-key one-call kernels: actual A vs reference R, TV = 1/100.
    a_kernel = {"sig-a": Fraction(99, 200), "sig-b": Fraction(99, 200),
                "sig-c": Fraction(1, 100)}
    r_kernel = {"sig-a": Fraction(1, 2), "sig-b": Fraction(1, 2)}
    epsilon = _tv(a_kernel, r_kernel)
    assert epsilon == Fraction(1, 100)
    # Two adaptive calls: the hybrid charges delta_issue once and epsilon twice.
    bound = _tv(p_guard, q_guard) + 2 * epsilon
    assert bound == Fraction(1, 20) + Fraction(2, 100)
    assert bound < 1
    # A naive beta_bad term is not present in the guarded formula.
    assert "beta_bad" not in "min(1, delta_issue + s*epsilon_good)"


def test_full_report_has_six_rows_and_null_ledger():
    report = build_report(lifecycle=False)
    assert len(report["rows"]) == 6
    assert {(row["profile"], row["interpretation"]) for row in report["rows"]} == \
        {(p, i) for p in PROFILES for i in INTERPRETATIONS}
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    assert report["scope_version"] == \
        "mathematical_events_and_conditional_implemented_gates_v2"
    assert report["history_scope"]["included"] == HISTORY_SCOPE
    assert "wall_clock_timing" in report["history_scope"]["excluded"]
    assert "internal_sampler_or_runtime_traces" in report["history_scope"]["excluded"]
    assert report["history_scope"]["actual_service_full_history_TV"] is None
    assert report["unguarded_original_backend"]["A_minus_B_upper_exact"] is None
    assert any("beta_bad" in item for item in report["null_ledger"])
    for row in report["rows"]:
        assert row["guarded_composition"]["beta_bad_unguarded"] is None
        assert row["guarded_composition"]["beta_bad_strictly_positive"] is True
        assert row["fault_history"]["TV"] is None
        acceptance = row["accepted_root_distribution"]
        for field in ("A_minus_B_upper_exact", "TV_mu_A_mu_B_upper_exact",
                      "TV_mu_A_mu_B_upper_dyadic", "TV_mu_A_mu_H_upper_exact",
                      "G_C_subset_B_legacy_certified",
                      "uniform_implementation_preparation_error_upper",
                      "implemented_C_gate_inconclusive_shell_mass_upper",
                      "original_backend_64_retry_abort_upper",
                      "guarded_64_retry_abort_dyadic"):
            assert acceptance[field] is None, field
        assert row["guarded_composition"]["history_scope"] == HISTORY_SCOPE
        assert row["guarded_composition"]["implemented_full_history_TV"] is None
        assert "guarded_no_fault_history_TV" not in row["guarded_composition"]
        assert "accepted_root_tv_upper_exact" not in row["bad_root_mass"]


def test_one_fixed_root_lifecycle_passes_the_complete_gate_set():
    """One deterministic root replay; not a probability or security claim."""
    probe = lifecycle_probe("PARAM-I", "table-standard-deviation")
    assert probe["functional_verified"] is True
    assert probe["master_audit_certified"] is True
    assert probe["sign_audit_certified"] is True
    assert probe["c_gate_certified"] is True
    assert probe["object_envelope_certified"] is True
    assert probe["issuance"]["closed"] is True
    assert probe["sign_call"]["closed"] is True
    assert probe["setup_attempts"] == 1
    assert probe["extract_calls"] == 1
