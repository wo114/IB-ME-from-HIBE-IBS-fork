"""Reject misleading experiment receipts without running lattice generation."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from experiments.research import report_experiment_probe as probe

ROOT = Path(__file__).resolve().parents[1]
SUITES = ROOT / 'docs/deliveries/2026-10-19-report-three-selection/suites'


def test_cli_selection_preserves_explicit_sageloli_and_hybrid_parameters():
    suite = json.loads((SUITES / 'C-lai-c2-sageloli-I.json').read_bytes())
    args = probe.setup_arguments(suite, Path('/private/state'))
    assert json.loads(args[args.index('--hybrid-limits') + 1]) == suite['hybrid_limits']
    assert json.loads(args[args.index('--hibe-params') + 1])['n'] == 2048
    assert json.loads(args[args.index('--ibs-params') + 1])['signature_width_squared'] == 270116709797628319132317
    invalid = deepcopy(suite)
    invalid['security_claim'] = '128-bit'
    with pytest.raises(ValueError):
        probe.setup_arguments(invalid, Path('/private/state'))


@pytest.mark.parametrize('lengths,capacity', [([0, 1025], 1024), ([True], 1024), ([-1], 1024), ([0, 0], 1024)])
def test_length_plan_rejects_invalid_or_duplicate_observations(lengths, capacity):
    with pytest.raises(ValueError):
        probe.validate_lengths(lengths, capacity)


@pytest.mark.parametrize('change', [
    {'code': 99, 'exception': 'AssertionError'},
    {'code': 1}, {'entropy_bytes': 1}, {'entropy_reads': 1},
])
def test_zero_entropy_acceptance_rejects_failures_and_entropy(change):
    row = dict(code=0, exception=None, entropy_reads=0, entropy_bytes=0)
    row.update(change)
    with pytest.raises(ValueError):
        probe.validate_command(row, expected=0, zero=True)


def test_expected_application_rejection_is_not_an_interpreter_failure():
    row = dict(code=2, exception=None, entropy_reads=0, entropy_bytes=0)
    probe.validate_command(row, expected=2, zero=True)
    with pytest.raises(ValueError):
        probe.validate_command(dict(row, exception='ValueError'), expected=2, zero=True)


def test_provider_binding_rejects_mixed_or_changed_installation(tmp_path):
    prefix = tmp_path / 'installed'
    path = prefix / 'ibme/core/randomness.py'
    entries = {'ibme.core.randomness': {'path': str(path), 'sha256': 'abc'}}
    merged = {}
    probe.merge_providers(merged, entries, prefix=prefix)
    with pytest.raises(ValueError, match='changed'):
        probe.merge_providers(merged, {'alias': {'path': str(path), 'sha256': 'def'}}, prefix=prefix)
    with pytest.raises(ValueError, match='outside'):
        probe.merge_providers({}, {'ibme.core.randomness': {'path': str(tmp_path / 'repo/src/ibme/core/randomness.py'), 'sha256': 'abc'}}, prefix=prefix)
