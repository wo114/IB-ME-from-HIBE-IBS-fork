"""Check source bindings that the original Word/Markdown table check missed."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / 'docs/reports/2026-10-19-research-draft'


@pytest.fixture
def inputs():
    spec = importlib.util.spec_from_file_location('fooli_report_check', HERE / 'check_report.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (module, (HERE / '研究报告初稿.md').read_text(encoding='utf-8'),
            json.loads((HERE / 'report-facts.json').read_bytes()))


def test_report_fooli_rows_match_public_source(inputs):
    checker, text, facts = inputs
    checker.check_fooli_source(text, facts)


def test_report_fooli_rejects_old_wrong_dimension(inputs):
    checker, text, facts = inputs
    changed = text.replace('| 1024 | 390,160 |', '| 1024 | 390,208 |')
    assert changed != text
    with pytest.raises(AssertionError, match='FooLi report row'):
        checker.check_fooli_source(changed, facts)


def test_report_fooli_rejects_wrong_selected_source_row(inputs):
    checker, text, facts = inputs
    changed = copy.deepcopy(facts)
    changed['fooli']['selected'][0]['d'] = 390208
    with pytest.raises(AssertionError, match='FooLi selected source row'):
        checker.check_fooli_source(text, changed)


def test_report_fooli_rejects_empty_selected_rows(inputs):
    checker, text, facts = inputs
    changed = copy.deepcopy(facts)
    changed['fooli']['selected'] = []
    with pytest.raises(AssertionError, match='FooLi three selected points'):
        checker.check_fooli_source(text, changed)


def test_report_fooli_rejects_exhaustive_refutation_claim(inputs):
    checker, text, facts = inputs
    with pytest.raises(AssertionError, match='bounded FooLi wording'):
        checker.check_fooli_source(text + '\n门内穷举否定\n', facts)
