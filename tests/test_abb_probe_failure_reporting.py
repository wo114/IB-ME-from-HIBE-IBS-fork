"""Error observations must explain failed gates without exposing values."""
import pytest
pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from experiments.research.abb_rom.hibe_probe import safe_failure_chain,paths


def test_static_gate_and_wrapping_are_retained():
    inner=ArithmeticError('LLL public GS bound failed')
    outer=ValueError('arbitrary private coefficients 123456789')
    outer.__cause__=inner
    result=safe_failure_chain(outer)
    assert [(item['type'],item['code']) for item in result]==[
        ('ValueError','nonliteral error text omitted'),('ArithmeticError','LLL public GS bound failed')]
    assert '123456789' not in str(result)


def test_distinct_fresh_address_keeps_full_identity_width():
    bob,alice=paths();carol,other_alice=paths(b'Carol',b'Alice')
    assert len(bob)==len(carol)==len(alice)==86
    assert carol!=bob and alice==other_alice
