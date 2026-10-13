import json

import pytest

from extray.scan import scan

LISTENER = 'window.addEventListener("message", (e) => {{ {} }});'
FLOW_HTML = LISTENER.format("el.innerHTML = e.data;")
NO_FLOW = LISTENER.format("el.textContent = e.data;")


def extension(js, manifest_extra=None, **files):
    manifest = {"manifest_version": 3, **(manifest_extra or {})}
    return {"manifest.json": json.dumps(manifest).encode(), "a.js": js.encode(),
            **{k.replace("_", "."): v.encode() for k, v in files.items()}}


def content_script(matches, **extra):
    return {"content_scripts": [{"matches": matches, "js": ["a.js"]}], **extra}


def severities(files):
    return {(f.rule, f.severity) for f in scan(files) if f.file == "a.js"}


ALL_SITES = content_script(["<all_urls>"])
ONE_SITE = content_script(["https://mail.example.com/*"])
POPUP = {"action": {"default_popup": "popup.html"}}


@pytest.mark.parametrize("js, manifest, expected", [
    # the example of the spec: open listener in a content script on every site, data reaching innerHTML
    (FLOW_HTML, ALL_SITES, {("js.message-no-origin-check", "medium"), ("js.flow-html", "high")}),
    (FLOW_HTML, ONE_SITE, {("js.message-no-origin-check", "low"), ("js.flow-html", "medium")}),
    (FLOW_HTML, POPUP, {("js.message-no-origin-check", "low"), ("js.flow-html", "low")}),
    # same listener in an internal page without any flow
    (NO_FLOW, POPUP, {("js.message-no-origin-check", "low")}),
    (NO_FLOW, ALL_SITES, {("js.message-no-origin-check", "medium")}),
    # page sources depend on whose page it is
    ("eval(location.hash.slice(1));", ALL_SITES, {("js.flow-code-exec", "high")}),
    ("eval(location.hash.slice(1));", {"background": {"service_worker": "a.js"}}, {("js.flow-code-exec", "low")}),
    ("location.href = document.referrer;", ALL_SITES, {("js.flow-url", "medium")}),
    # sinks without a controllable source
    ("function f(c) { eval(c); el.innerHTML = c; }", ALL_SITES, {("js.code-exec", "low"), ("js.html-sink", "info")}),
])
def test_severity_from_context_and_flow(js, manifest, expected):
    files = extension(js, manifest, popup_html='<script src="a.js"></script>')
    assert severities(files) == expected


def test_web_accessible_page():
    def war(**entry):
        return {"web_accessible_resources": [{"resources": ["page.html"], "matches": ["<all_urls>"], **entry}]}

    page = {"page_html": '<script src="a.js"></script>'}
    assert ("js.flow-html", "high") in severities(extension(FLOW_HTML, war(), **page))
    assert ("js.flow-html", "medium") in severities(extension(FLOW_HTML, war(use_dynamic_url=True), **page))


EXTERNAL = 'chrome.runtime.onMessageExternal.addListener((m) => {{ {} }});'
BACKGROUND = {"background": {"service_worker": "a.js"}}


@pytest.mark.parametrize("connectable, listener, code, url", [
    ({"matches": ["<all_urls>"]}, "medium", "high", "medium"),
    ({"matches": ["https://app.example.com/*"]}, "low", "medium", "low"),
    (None, "low", "medium", "low"),  # not declared: any extension can send
    ({"ids": ["abcdefghijklmnopabcdefghijklmnop"]}, "low", "low", "low"),  # one trusted extension
])
def test_external_messages(connectable, listener, code, url):
    manifest = {**BACKGROUND, **({"externally_connectable": connectable} if connectable else {})}
    files = extension(EXTERNAL.format("eval(m.code); chrome.tabs.create({ url: m.url });"), manifest)
    assert severities(files) == {("js.external-message-no-sender-check", listener),
                                 ("js.flow-code-exec", code), ("js.flow-url", url)}


def test_internal_runtime_messages_are_low():
    files = extension("chrome.runtime.onMessage.addListener((m) => { el.innerHTML = m.html; });", ALL_SITES)
    assert severities(files) == {("js.flow-html", "low")}


def test_flow_message_shows_path_and_exposure():
    finding = next(f for f in scan(extension(FLOW_HTML, ALL_SITES)) if f.rule == "js.flow-html")
    assert finding.message == "e.data (L1) → innerHTML (L1), source reachable from any website"
