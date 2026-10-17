"""The audit's global cap must not silently shorten a certified lifecycle."""
import pytest

pytest.importorskip("sage.all", reason="specified WSL Sage required")

from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.srgg_structured_service_audit import (
    AuditEntropy, CHILD_ENTROPY_CAP, PARENT_ENTROPY_CAP,
)


class Source:
    def __init__(self):
        self.calls = []

    def read(self, size):
        self.calls.append(size)
        return b"x"*size


def test_global_cap_rejects_before_consuming_source_and_counts_exact_bytes():
    source = Source()
    counter = AuditEntropy(source, 8)
    assert counter.read(3) == b"xxx"
    with pytest.raises(SamplingAbort):
        counter.read(6)
    assert source.calls == [3] and counter.used == 3
    assert counter.read(5) == b"xxxxx"
    assert counter.read(0) == b""
    assert counter.used == 8
    with pytest.raises(SamplingAbort):
        counter.read(1)
    assert source.calls == [3, 5, 0]


@pytest.mark.parametrize("size", [True, -1, 1.0, CHILD_ENTROPY_CAP+1])
def test_invalid_or_overlarge_request_does_not_touch_source(size):
    source = Source()
    counter = AuditEntropy(source, PARENT_ENTROPY_CAP)
    with pytest.raises(ValueError):
        counter.read(size)
    assert source.calls == [] and counter.used == 0


@pytest.mark.parametrize("maximum", [True, 0, -1, 1.0, PARENT_ENTROPY_CAP+1])
def test_global_limit_is_bounded_before_any_allocation(maximum):
    source = Source()
    with pytest.raises(ValueError):
        AuditEntropy(source, maximum)
    assert source.calls == []


@pytest.mark.parametrize("value", [b"", b"xx", bytearray(b"x"), None])
def test_malformed_entropy_is_never_returned(value):
    class Broken:
        def read(self, size):
            return value
    counter = AuditEntropy(Broken(), 8)
    with pytest.raises(ValueError):
        counter.read(1)
    assert counter.used == 0


def test_n512_worst_case_parent_and_child_fit_without_sampling():
    # Frozen per-operation envelopes, independently derived in service_budget.
    setup = 32800
    extract = 18155707
    sign_attempt = 11663274
    negative_checks = 22528
    assert setup+2*extract+2*16*sign_attempt+negative_checks == 409591510
    assert CHILD_ENTROPY_CAP < 409591510 < PARENT_ENTROPY_CAP
    assert 16*sign_attempt == 186612384 < CHILD_ENTROPY_CAP
