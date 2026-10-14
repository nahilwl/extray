# extray

[![tests](https://github.com/nahilwl/extray/actions/workflows/tests.yml/badge.svg)](https://github.com/nahilwl/extray/actions/workflows/tests.yml)

**ext**ension + **x-ray**: put Chrome extensions under X-ray to find malicious behavior and exploitable vulnerabilities.

## Install

```sh
pip install -e '.[dev]'
```

## Usage

```sh
extray scan <chrome-web-store-id>   # downloads the latest .crx
extray scan path/to/extension.crx   # or a .zip
```

Findings below `--min-severity` (`info`, `low`, `medium`, `high`; default `low`) are hidden, `-v`
shows them all. The last line counts findings per severity and how many are hidden.

Options: `--max-js-size BYTES` skips bigger JS files (default 5 MB), reported as an `info` finding.
`--js-timeout SECONDS` gives up on a JS file after that time (default 30). Each JS file is parsed in a
worker process: a file that crashes the parser or times out is reported as an `info` finding and the
scan goes on.

What is checked:

- **manifest.json**: dangerous permissions, all-hosts access, broad `externally_connectable`,
  HTML exposed in `web_accessible_resources`, weakened CSP, `<all_urls>` content scripts, Manifest V2.
- **Where each JS file runs**, deduced from the manifest, the `<script>` tags of the HTML pages and
  imports: content script (on which sites), background, extension page, web-accessible page.
- **Data flow** inside each function (and its callbacks), from attacker-controlled sources
  (`event.data` of unchecked `message` listeners, `onMessage`/`onMessageExternal` messages,
  `location.*`, `document.referrer`, `window.name`) to code execution (`eval`, `Function`, string
  timers, `executeScript`), HTML (`innerHTML`, `document.write`...) and URLs (`tabs.create/update`,
  `fetch`, `location`, `window.open`). A finding shows the path: `e.data (L3) → innerHTML (L5)`.
- **Patterns**: `message` listeners that never read `event.origin`, `onMessageExternal` listeners that
  never check the sender, dynamic code or HTML without a known source.

Severity combines the sink and who can feed the source:

| Source reachable from | code / HTML sink | URL sink | listener without check |
|---|---|---|---|
| any website (content script or web-accessible page on all sites, `externally_connectable` on all sites) | high | medium | medium |
| some websites or other extensions | medium | low | low |
| the extension only | low | low | low |

Dynamic code without a known source is `low`, dynamic HTML without one is `info`. Handlers that cannot
be resolved statically, JS files above `--max-js-size` and JS files the parser crashed or timed out on
are reported as `info`, not skipped silently.

Each finding gives the file, line, column, context and a readable excerpt. The analysis stays inside a
function: data passed to an unknown function is not followed. A finding is a place to review, not a
proven vulnerability.

## Rules

One rule per file in `extray/rules/vulns/` or `extray/rules/malware/`, loaded automatically: a `Rule`
subclass with `id`, `severity`, `description` and `check_manifest` and/or `check_js`. Each JS rule ships
`tests/fixtures/js/<rule id>/vuln.js` (reported lines marked `VULN`) and `fixed.js` (nothing reported).

## Responsible disclosure

If extray finds a real vulnerability in a public extension, contact the developer (or its bug bounty
program) before publishing anything.
