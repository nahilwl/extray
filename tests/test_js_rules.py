from pathlib import Path

import pytest

from extray.js.parser import JSFile
from extray.rules import load_rules

JS_FIXTURES = Path(__file__).parent / "fixtures" / "js"
RULE_DIRS = sorted(p for p in JS_FIXTURES.iterdir() if p.is_dir())
RULES = {r.id: r for r in load_rules()}


def run(rule_id, path):
    return list(RULES[rule_id].check_js(JSFile(path.name, path.read_bytes())))


def test_every_js_rule_has_fixtures():
    assert {p.name for p in RULE_DIRS} == {i for i in RULES if i.startswith("js.")}


@pytest.mark.parametrize("rule_dir", RULE_DIRS, ids=lambda p: p.name)
def test_vulnerable_fixture(rule_dir):
    # fixture convention: every line that must be reported contains "VULN"
    path = rule_dir / "vuln.js"
    expected = [n for n, line in enumerate(path.read_text().splitlines(), 1) if "VULN" in line]
    assert expected
    assert [f.line for f in run(rule_dir.name, path)] == expected


@pytest.mark.parametrize("rule_dir", RULE_DIRS, ids=lambda p: p.name)
def test_fixed_fixture(rule_dir):
    assert run(rule_dir.name, rule_dir / "fixed.js") == []
