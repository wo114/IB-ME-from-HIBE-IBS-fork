"""Exact scope and executable-object checks for random-key signing law."""
from fractions import Fraction
import json
from pathlib import Path

import pytest

from experiments.research.candidates.srgg import paper_random_key_sign_law as law
from experiments.research.candidates.srgg.paper_parameters import PaperParams


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/random-key-sign-law.json"


def test_bad_key_charged_once_in_exact_mixture_coupling():
    # On matching issuance, mass beta may enter a key with arbitrary signing
    # behavior. On good keys the conditional sign law pays epsilon per call.
    # This is a generic lemma test, not an SRGG beta estimate.
    assert law.conditional_random_key_bound(
        issuance_tv=Fraction(1, 16), bad_key_mass=Fraction(1, 4),
        good_key_sign_call_tv=Fraction(1, 8), sign_calls=2) == Fraction(9, 16)
    assert law.conditional_random_key_bound(
        issuance_tv=0, bad_key_mass=Fraction(1, 4),
        good_key_sign_call_tv=0, sign_calls=2) == Fraction(1, 4)
    assert law.conditional_random_key_bound(
        issuance_tv=1, bad_key_mass=1, good_key_sign_call_tv=1,
        sign_calls=2) == 1
    assert law.conditional_random_key_bound(
        issuance_tv=Fraction(1, 16), bad_key_mass=None,
        good_key_sign_call_tv=None, sign_calls=0) == Fraction(1, 16)


@pytest.mark.parametrize("missing", ["issuance_tv", "bad_key_mass", "good_key_sign_call_tv"])
def test_missing_premise_never_becomes_fixture_key_bound(missing):
    values = {"issuance_tv": Fraction(1, 100),
              "bad_key_mass": Fraction(1, 100),
              "good_key_sign_call_tv": Fraction(1, 100)}
    values[missing] = None
    assert law.conditional_random_key_bound(**values, sign_calls=2) is None


@pytest.mark.parametrize("kwargs", [
    {"issuance_tv": -1, "bad_key_mass": 0, "good_key_sign_call_tv": 0, "sign_calls": 1},
    {"issuance_tv": 0, "bad_key_mass": Fraction(3, 2), "good_key_sign_call_tv": 0, "sign_calls": 1},
    {"issuance_tv": 0, "bad_key_mass": 0, "good_key_sign_call_tv": 0.1, "sign_calls": 1},
    {"issuance_tv": 0, "bad_key_mass": 0, "good_key_sign_call_tv": 0, "sign_calls": True},
    {"issuance_tv": 0, "bad_key_mass": 0, "good_key_sign_call_tv": 0, "sign_calls": 1025},
])
def test_invalid_probability_or_unbounded_calls_rejected(kwargs):
    with pytest.raises(ValueError):
        law.conditional_random_key_bound(**kwargs)


@pytest.mark.parametrize("profile", law.PROFILES)
@pytest.mark.parametrize("interpretation", law.INTERPRETATIONS)
def test_exact_minimal_rank_one_threshold_on_six_original_rows(profile, interpretation):
    params = PaperParams(profile, interpretation)
    obstruction = law.tail_obstruction(params)
    t = obstruction["constant_coefficient"]
    beta = Fraction(obstruction["conditional_rank_one_beta_exact"])
    diagonal = Fraction(obstruction["diagonal_at_threshold_exact"])
    lower = law.exact_fraction(params.signature_second_squared)
    assert obstruction["full_row_index"] == 2 * params.rank
    assert obstruction["tail_row_index"] == params.rank
    assert lower - beta * t*t == diagonal < 0
    assert lower - beta * (t-1)**2 >= 0
    assert t.bit_length() <= 256


def test_original_backend_rejects_canonical_synthetic_reference_support_key():
    params = PaperParams("PARAM-I", "table-standard-deviation")
    replay = law.replay_canonical_obstruction(params, law.tail_obstruction(params))
    assert replay["canonical_synthetic_key_roundtrip"] is True
    assert replay["unchanged_source_sign_plan_rejects"] is True
    assert replay["synthetic_key_probability_estimated"] is False
    assert replay["synthetic_key_bytes_exported"] is False


def test_frozen_report_keeps_both_unproved_inputs_null():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["schema"] == law.SCHEMA
    assert report["full_random_issuance_signing_history_tv"] is None
    assert report["security_claim"] == "none"
    assert report["rom_used"] is True
    assert report["teaching_parameters"] is False
    assert len(report["rows"]) == 6
    for row in report["rows"]:
        assert row["bad_key_mass_under_mathematical_issuance_reference"] is None
        assert row["uniform_good_key_sign_call_tv"] is None
        assert row["one_random_issued_key_then_two_sign_calls_tv"] is None
        assert row["uniform_all_reference_signing_keys_schur_certificate_possible"] is False
        assert row["canonical_replay"]["unchanged_source_sign_plan_rejects"] is True
        assert row["actual_finite_issuance_mass_of_this_tail"] is None
        assert row["rom_used"] is True
        assert row["teaching_parameters"] is False
        assert row["backend_admitted"] is False
        assert row["parameters_are_formal"] is False
        assert row["nist_security_category"] is None
