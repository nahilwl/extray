import pytest

from extray.js.dataflow import flows
from extray.js.parser import JSFile


def run(src):
    js = JSFile("a.js", src.encode())
    return [(f.source.label, f.sink.name, js.position(f.source.node)[0], js.position(f.node)[0]) for f in flows(js)]


def sink_names(src):
    return [name for _, name, _, _ in run(src)]


MSG = 'window.addEventListener("message", (e) => {{\n{}\n}});'


@pytest.mark.parametrize("body", [
    "el.innerHTML = e.data;",                                   # property access
    "el.innerHTML = e.data.html;",                              # deeper property
    'el.innerHTML = e["data"]["html"];',                        # subscript with string
    "const d = e.data; el.innerHTML = d;",                      # declaration
    "let d; d = e.data; el.innerHTML = d;",                     # assignment
    'el.innerHTML = "<b>" + e.data + "</b>";',                  # concatenation
    "el.innerHTML = `<b>${e.data.title}</b>`;",                 # template literal
    "const { html } = e.data; el.innerHTML = html;",            # destructuring
    "const { data: { html: h } } = e; el.innerHTML = h;",       # nested destructuring from the event
    "const [a, b] = e.data; el.innerHTML = b;",                 # array destructuring
    "el.innerHTML = e.data || 'none';",                         # logical operators
    "el.innerHTML = ok ? e.data : '';",                         # ternary
    "el.innerHTML = e.data.trim().toUpperCase();",              # methods of a tainted value
    "el.innerHTML = decodeURIComponent(e.data);",               # propagating functions
    "const o = {}; o.x = e.data; el.innerHTML = o.x;",          # property paths
    "let s = ''; s += e.data; el.innerHTML = s;",               # +=
    "fetch(u).then((r) => { el.innerHTML = e.data; });",        # closure sees the outer taint
])
def test_propagation(body):
    assert sink_names(MSG.format(body)) == ["innerHTML"]


@pytest.mark.parametrize("body", [
    "el.innerHTML = e.origin;",                                 # not the data
    "el.innerHTML = DOMPurify.sanitize(e.data);",               # unknown call stops the taint
    "el.innerHTML = encodeURIComponent(e.data);",
    "let d = e.data; d = 'x'; el.innerHTML = d;",               # clean reassignment
    "el.innerHTML = e.data === 'x' ? 'a' : 'b';",               # comparison: boolean, not data
    "[1].forEach((e) => { el.innerHTML = e.data; });",          # parameter shadows the event
    "el.textContent = e.data;",                                 # not a sink
])
def test_no_propagation(body):
    assert run(MSG.format(body)) == []


def test_origin_check_means_no_source():
    assert run(MSG.format("if (e.origin !== O) return; el.innerHTML = e.data;")) == []


def test_flow_reports_source_and_sink_lines():
    assert run(MSG.format("const d = e.data;\n\nel.innerHTML = d;")) == [("e.data", "innerHTML", 1, 4)]


def test_destructured_event_parameter():
    assert sink_names('addEventListener("message", ({ data }) => eval(data));') == ["eval"]


def test_named_handler():
    src = 'function onMsg(ev) { document.write(ev.data); }\nwindow.addEventListener("message", onMsg);'
    assert run(src) == [("ev.data", "document.write", 1, 1)]


def test_runtime_message_sources():
    src = """
chrome.runtime.onMessage.addListener((msg, sender, reply) => { eval(msg.code); });
chrome.runtime.onMessageExternal.addListener(({ url }) => { chrome.tabs.create({ url }); });
chrome.runtime.onMessageExternal.addListener((m, s) => { if (s.id === ID) eval(m); });
"""
    assert [(label, name) for label, name, _, _ in run(src)] == [
        ("onMessage message", "eval"), ("onMessageExternal message", "chrome.tabs.create url")]


def test_page_sources():
    src = """
el.innerHTML = location.hash;
document.write(new URLSearchParams(window.location.search).get("q"));
eval(document.referrer);
el.insertAdjacentHTML("beforeend", window.name);
el.innerHTML = document.location.href.split("#")[1];
"""
    assert [label for label, *_ in run(src)] == [
        "location.hash", "window.location.search", "document.referrer", "window.name", "document.location.href"]


@pytest.mark.parametrize("sink, name", [
    ("eval(D)", "eval"),
    ("new Function('a', D)", "Function"),
    ("setTimeout(D, 10)", "setTimeout"),
    ("setInterval('x' + D)", "setInterval"),
    ("chrome.scripting.executeScript({ target, code: D })", "chrome.scripting.executeScript code"),
    ("chrome.scripting.executeScript({ target, func, args: [D] })", "chrome.scripting.executeScript args"),
    ("chrome.tabs.executeScript(1, { file: 'x.js', code: D })", "chrome.tabs.executeScript code"),
    ("el.outerHTML = D", "outerHTML"),
    ("document.writeln(D)", "document.writeln"),
    ("el.insertAdjacentHTML('afterend', D)", "insertAdjacentHTML"),
    ("chrome.tabs.create({ url: D })", "chrome.tabs.create url"),
    ("chrome.tabs.update(id, { url: D })", "chrome.tabs.update url"),
    ("const o = { url: D }; chrome.tabs.create(o)", "chrome.tabs.create url"),
    ("fetch(D)", "fetch"),
    ("location.href = D", "location.href"),
    ("window.location = D", "window.location"),
    ("location.assign(D)", "location.assign"),
    ("window.location.replace(D)", "window.location.replace"),
    ("window.open(D)", "window.open"),
])
def test_sinks(sink, name):
    assert sink_names(MSG.format(sink.replace("D", "e.data"))) == [name]


def test_static_values_in_sinks_are_not_flows():
    assert run(MSG.format("fetch('https://api.example.com'); chrome.tabs.create({ url: 'https://x' }); location.href = '/';")) == []


def test_deep_minified_expression_does_not_crash():
    deep = "+".join(["a"] * 20000)
    assert run(f"el.innerHTML = {deep} + location.hash;") == [("location.hash", "innerHTML", 1, 1)]
    nested = "(" * 3000 + "location.hash" + ")" * 3000  # beyond the recursion limit: skipped, not a crash
    assert run(f"el.innerHTML = {nested};") == []
