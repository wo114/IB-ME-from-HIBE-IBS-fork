"""Prevent an installation receipt from inheriting a different frozen budget.

These are CLI selection and fail-closed harness checks, not cryptographic runs.
"""
import json

import pytest

from ibme.assembly import make_suite
from ibme.cli import _suite_from_args, build_parser
from ibme.core.errors import InvalidParameterError
from experiments.research import srgg_paper_cli_probe as probe


def suite():
    return make_suite(hibe='latte', hibe_params='seed32', ibs='srgg2025-paper',
                      ibs_params='PARAM-I', transport='hybrid', signature_format='compact',
                      hybrid_limits=dict(backend_id='latte3-cosac-fix-v1', identity_max_bytes=64,
                                         max_capsule_bytes=4194304, max_payload_bytes=131072))


def write_suite(tmp_path, raw):
    path = tmp_path/'suite.json'
    path.write_text(json.dumps(raw), encoding='utf-8')
    return path


def test_complete_report_b_selection_roundtrips_through_actual_cli_parser(tmp_path):
    expected = suite()
    args, selected = probe.setup_arguments(tmp_path/'state', write_suite(tmp_path, expected.to_dict()))
    actual = _suite_from_args(build_parser().parse_args(list(map(str, args))))
    assert actual.to_dict() == selected.to_dict() == expected.to_dict()
    assert selected.digest == '37a0d413d5daed2c407c03b4b4f1a1fe4b6454e786e9cea3dfe8676a60ce9c97'


def test_historical_no_file_probe_keeps_original_budget(tmp_path):
    args, expected = probe.setup_arguments(tmp_path/'state')
    actual = _suite_from_args(build_parser().parse_args(list(map(str, args))))
    assert expected is None
    assert actual.to_dict()['hybrid_limits']['max_payload_bytes'] == 65536
    assert actual.digest != suite().digest


def test_duplicate_json_fields_are_rejected(tmp_path):
    path = tmp_path/'duplicate.json'
    path.write_text('{"transport":"hybrid",' + suite().to_json()[1:], encoding='utf-8')
    with pytest.raises(InvalidParameterError):
        probe.setup_arguments(tmp_path/'state', path)


@pytest.mark.parametrize('field,value', [('hibe_version', 'different'),
    ('signature_format', 'reference'), ('protocol', 'baseline-v1'),
    ('hibe_params', dict(identity_bytes=86, max_children=1, max_receivers=2,
                         message_mode='seed32', native_timeout_seconds=60)),
    ('ibs_params', dict(profile_name='PARAM-II', interpretation='table-standard-deviation'))])
def test_unsupported_frozen_scope_fails_before_creating_output(tmp_path, monkeypatch, field, value):
    raw = suite().to_dict()
    raw[field] = value
    path = write_suite(tmp_path, raw)
    calls = []
    monkeypatch.setattr(probe, 'command', lambda *args, **kwargs: calls.append(args))
    output = tmp_path/'private'
    with pytest.raises(ValueError):
        probe.generate(output, 'test-only', suite_file=path)
    assert not output.exists() and calls == []


def test_actual_setup_budget_mismatch_stops_before_issuance(tmp_path, monkeypatch):
    expected = suite()
    wrong_args, _ = probe.setup_arguments(tmp_path/'state')
    wrong = _suite_from_args(build_parser().parse_args(list(map(str, wrong_args))))
    names = []

    def setup(directory, name, args, **kwargs):
        names.append(name)
        state = directory/'state'
        state.mkdir()
        (state/'state.json').write_text(json.dumps(dict(suite=wrong.to_dict(), suite_digest=wrong.digest)))
        return {'name': name}

    monkeypatch.setattr(probe, 'command', setup)
    output = tmp_path/'private'
    with pytest.raises(ValueError, match='did not produce'):
        probe.generate(output, 'test-only', suite_file=write_suite(tmp_path, expected.to_dict()))
    assert names == ['setup']
    failure = json.loads((output/'failure.json').read_bytes())
    assert failure['stage'] == 'frozen-suite-binding'
