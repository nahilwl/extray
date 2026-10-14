import io

from rich.console import Console

from extray.report.terminal import render
from extray.rules.base import Finding

FINDINGS = [Finding(f"r.{s}", s, "msg", "a.js", 1, "") for s in ("high", "low", "info", "info")]


def output(findings, min_severity):
    console = Console(file=io.StringIO(), width=200)
    render("ext", findings, min_severity, console)
    return console.file.getvalue()


def test_default_hides_info_and_counts_it():
    out = output(FINDINGS, "low")
    assert "r.high" in out and "r.low" in out and "r.info" not in out
    assert out.splitlines()[-1] == "1 high, 0 medium, 1 low, 2 info (2 hidden, -v to show)"


def test_info_shows_everything():
    out = output(FINDINGS, "info")
    assert "r.info" in out and out.splitlines()[-1] == "1 high, 0 medium, 1 low, 2 info"


def test_everything_hidden():
    assert output(FINDINGS[2:], "low").splitlines() == ["ext — no findings at or above low",
                                                         "0 high, 0 medium, 0 low, 2 info (2 hidden, -v to show)"]


def test_no_findings():
    assert output([], "low").splitlines() == ["ext — no findings"]


def test_sorted_by_severity_then_file_and_line():
    findings = [Finding("r.4", "low", "m", "b.js", 1, ""), Finding("r.2", "high", "m", "b.js", 9, ""),
                Finding("r.5", "info", "m", "a.js", 1, ""), Finding("r.3", "low", "m", "a.js", 7, ""),
                Finding("r.1", "high", "m", "a.js", 20, "")]
    out = output(findings, "info")
    assert sorted(["r.1", "r.2", "r.3", "r.4", "r.5"], key=out.index) == ["r.1", "r.2", "r.3", "r.4", "r.5"]
