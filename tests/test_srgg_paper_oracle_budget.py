"""Independent boundary checks for Table 4 finite XOF rejection accounting."""
import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.candidates.srgg.paper_oracle_budget import row_budget, report
from experiments.research.candidates.srgg.paper_profiles import profiles
from experiments.research.candidates.wang_pw.hashing import uniform_values


class CandidateStream:
    def __init__(self, values):
        self.values = iter(values)
        self.reads = 0

    def read(self, size):
        assert size == 3
        self.reads += 1
        return next(self.values).to_bytes(size, "big")


def test_actual_rejection_boundary_and_hard_trial_cap():
    modulus = profiles[0].Q
    stream = CandidateStream([modulus, modulus - 1])
    assert uniform_values(stream, modulus, 1) == (modulus - 1,)
    assert stream.reads == 2
    exhausted = CandidateStream([modulus] * 256)
    with pytest.raises(ValueError, match="rejection budget exhausted"):
        uniform_values(exhausted, modulus, 1)
    assert exhausted.reads == 256


@pytest.mark.parametrize("source,strict_bits", tuple(zip(profiles, (1012, 1011, 1010))))
def test_original_row_exact_union_envelope(source, strict_bits):
    row = row_budget(degree=source.degree, rank=source.rank, modulus=source.Q)
    assert row["candidate_width_bytes"] == 3
    assert row["accepted_range_size"] == source.Q
    assert row["rejected_range_size"] == 2**24 - source.Q
    assert row["rejected_range_size"] * 16 < 2**24
    assert row["max_bytes_used_before_trial_cap_per_coefficient"] == 768
    assert row["stream_budget_bytes_per_coefficient"] == 4096
    assert row["joint_exhaustion_probability_strictly_below_2_negative"] == strict_bits
    assert row["matrix_coefficients"] == source.rank**2 * source.degree
    assert row["identity_coefficients_per_distinct_address"] == source.rank * source.degree


def test_multiple_distinct_identity_addresses_charge_each_once():
    source = profiles[2]
    one = row_budget(degree=source.degree, rank=source.rank, modulus=source.Q)
    many = row_budget(degree=source.degree, rank=source.rank, modulus=source.Q,
                      identity_addresses=2**40)
    assert many["union_coefficient_calls"] > one["union_coefficient_calls"]
    assert many["joint_exhaustion_probability_strictly_below_2_negative"] < 1010
    assert many["concrete_SHAKE_random_oracle_security_proved"] is False


def test_report_keeps_ideal_byte_scope_and_paper_hash():
    result = report()
    assert result["paper"]["sha256"] == profiles[0].source_sha256
    assert [row["profile"] for row in result["rows"]] == [p.name for p in profiles]
    assert result["actual_SHAKE_distribution_to_ideal_RO_TV_upper"] is None
    assert result["full_RO_or_QROM_game_bound"] is None
    assert result["security_claim"] == "none"


@pytest.mark.parametrize("kwargs", [
    {"degree": 256, "rank": 2, "modulus": 15744063},
    {"degree": 512, "rank": 1, "modulus": 15744063},
    {"degree": 512, "rank": 2, "modulus": 961},
    {"degree": 512, "rank": 2, "modulus": 15744063, "identity_addresses": 2**40+1},
])
def test_only_frozen_original_domain(kwargs):
    with pytest.raises(ValueError):
        row_budget(**kwargs)
