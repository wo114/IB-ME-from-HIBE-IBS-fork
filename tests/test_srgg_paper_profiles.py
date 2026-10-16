"""Literal source and non-admission checks for the SRGG reproduction baseline."""

from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path

import pytest

from experiments.research.candidates.srgg.paper_profiles import (
    SOURCE_PDF, SOURCE_SHA256, profile, profiles,
)


@pytest.mark.parametrize("name,rank,widths,target,sizes,cycles", [
    ("PARAM-I", 2, ("2843.9", "1023.0", "843088.2", "310891.6", "42086491.7"),
     100, (12320, 2048, 4900, 12148), (1520313, 5004676, 5203248, 1218478)),
    ("PARAM-II", 3, ("3399.4", "1065.3", "1046714.2", "384614.5", "63653172.0"),
     180, (27680, 4608, 7396, 17786), (3445003, 5490761, 7007089, 1762221)),
    ("PARAM-III", 4, ("3867.7", "1089.9", "1238066.0", "448859.2", "86573930.5"),
     256, (49184, 8192, 9892, 23516), (7294250, 9556676, 11521424, 2544205)),
])
def test_literal_table4_values_keep_every_published_digit(name, rank, widths, target,
                                                       sizes, cycles):
    item = profile(name)
    assert item.rank == rank
    fields = ("master_first_stddev", "master_second_stddev",
              "signature_first_stddev", "signature_second_stddev", "gamma")
    assert tuple(str(getattr(item, field)) for field in fields) == widths
    assert item.reported_target_bits == target
    report = item.author_report
    assert (report.master_public_bytes, report.master_secret_bytes,
            report.user_secret_bytes, report.signature_bytes) == sizes
    assert (report.setup_cycles, report.extract_cycles,
            report.sign_cycles, report.verify_cycles) == cycles
    record = json.loads(json.dumps(item.record()))
    assert tuple(record[field] for field in fields) == widths
    assert record["reported_results_reproduced"] is False
    assert record["security_claim"] == "none"
    assert record["backend_admitted"] is False
    assert record["parameters_are_formal"] is False
    assert record["nist_security_category"] is None


def test_shared_original_parameters_and_one_frozen_primary_source():
    source = Path(__file__).resolve().parents[1] / SOURCE_PDF
    assert sha256(source.read_bytes()).hexdigest() == SOURCE_SHA256
    assert isinstance(profiles, tuple)
    assert len({item.name for item in profiles}) == len(profiles) == 3
    assert {item.source_sha256 for item in profiles} == {SOURCE_SHA256}
    assert {item.source_pdf for item in profiles} == {SOURCE_PDF}
    for item in profiles:
        assert (item.degree, item.p, item.base, item.digits) == (512, 16383, 31, 2)
        assert item.q == 961
        assert item.Q == 15744063
        assert item.r_stddev == Fraction(29, 25)
        assert item.extraction_query_bound == 1 << 40
        # Prior sufficient inequalities do not veto the literal source inputs.
        assert item.Q < 2 * item.gamma
        assert not hasattr(item, "user_norm_cap")
    with pytest.raises(FrozenInstanceError):
        profiles[0].rank = 3


def test_author_security_estimates_do_not_become_nist_levels():
    reports = [item.author_report for item in profiles]
    assert [(r.key_recovery_bkz, r.key_recovery_classical_bits,
             r.key_recovery_quantum_bits) for r in reports] == [
                 (358, 105, 95), (608, 178, 161), (874, 255, 232)]
    assert [(r.forgery_bkz, r.forgery_classical_bits,
             r.forgery_quantum_bits) for r in reports] == [
                 (352, 103, 93), (586, 171, 155), (828, 242, 219)]


@pytest.mark.parametrize("name", [None, 1, True, b"PARAM-I"])
def test_lookup_rejects_non_text_names(name):
    with pytest.raises(TypeError):
        profile(name)


@pytest.mark.parametrize("name", ["", "param-i", "PARAM-IV", "NIST-I", "PARAM-I "])
def test_lookup_rejects_aliases_and_unknown_profiles(name):
    with pytest.raises(ValueError):
        profile(name)


@pytest.mark.parametrize("field,value", [
    ("degree", True), ("degree", 256), ("rank", 1), ("rank", True),
    ("p", 0), ("base", 2), ("digits", 8), ("extraction_query_bound", 1),
    ("r_stddev", 1.16), ("r_stddev", Fraction(8)),
    ("gamma", 42086491.7), ("gamma", Decimal("NaN")),
    ("gamma", Decimal("Infinity")), ("gamma", Decimal(0)),
    ("master_first_stddev", Decimal(-1)), ("name", ""),
])
def test_invalid_profile_input_cannot_silently_replace_paper_parameters(field, value):
    with pytest.raises(ValueError):
        replace(profiles[0], **{field: value})


def test_reported_values_are_typed_and_positive():
    with pytest.raises(TypeError):
        replace(profiles[0], author_report={})
    for invalid in (True, 0, -1, 100.0):
        with pytest.raises(ValueError):
            replace(profiles[0].author_report, target_bits=invalid)
