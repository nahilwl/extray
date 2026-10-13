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


def test_minified_bundle_positions():
    from extray.scan import scan

    lines = [
        '/*! bundle — ©2026 */var a="é";function x(){return a}',
        'var b="ü→";window.addEventListener("message",function(n){document.body.innerHTML=n.data}),'
        'chrome.runtime.onMessageExternal.addListener(function(n){eval(n.c)});',
    ]
    files = {"manifest.json": b'{"manifest_version": 3}', "dist/bundle.min.js": "\n".join(lines).encode()}
    findings = scan(files)

    def at(needle):
        return 2, lines[1].index(needle) + 1  # 1-based character column, independent of the parser

    assert {(f.rule, f.line, f.column) for f in findings} == {
        ("js.message-no-origin-check", *at("window.addEventListener")),
        ("js.html-sink", *at("document.body.innerHTML")),
        ("js.external-message-no-sender-check", *at("chrome.runtime.onMessageExternal")),
        ("js.code-exec", *at("eval(n.c)")),
    }
    assert all(f.file == "dist/bundle.min.js" for f in findings)
    listener = next(f for f in findings if f.rule == "js.message-no-origin-check")
    assert listener.evidence.splitlines()[1].strip() == "document.body.innerHTML = n.data"  # beautified excerpt
