import json

import pytest

from extray import manifest
from extray.rules import load_rules
from extray.rules.base import SEVERITIES


def test_rules_are_loaded_once_with_unique_ids():
    rules = load_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    assert {i for i in ids if i.startswith("manifest.")} == {
        "manifest.mv2", "manifest.dangerous-permission", "manifest.all-hosts",
        "manifest.externally-connectable", "manifest.web-accessible-html",
        "manifest.csp-unsafe-eval", "manifest.csp-remote-script", "manifest.content-script-all-urls",
    }
    assert all(r.description and r.severity in SEVERITIES for r in rules)


def test_manifest_must_be_an_object():
    with pytest.raises(ValueError, match="not a JSON object"):
        manifest.analyze("[]")


def test_non_string_permissions_are_ignored():
    text = json.dumps({"manifest_version": 2, "permissions": [{"socket": ["tcp-connect"]}, "cookies"]})
    assert [f.rule for f in manifest.analyze(text) if f.rule != "manifest.mv2"] == ["manifest.dangerous-permission"]
