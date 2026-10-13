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

Options: `--max-js-size BYTES` skips bigger JS files (default 5 MB), reported as an `info` finding.

What is checked:

- **manifest.json**: dangerous permissions, all-hosts access, broad `externally_connectable`,
  HTML exposed in `web_accessible_resources`, weakened CSP, `<all_urls>` content scripts, Manifest V2.
- **JavaScript** (parsed with tree-sitter, minified or not): `message` listeners that never read
  `event.origin`, `onMessageExternal` listeners that never check the sender, dynamic code execution
  (`eval`, `Function`, string timers) and dynamic HTML sinks (`innerHTML`, `document.write`...).

Each finding gives the file, line, column and a readable excerpt. JS checks are patterns, not data flow
yet: a finding is a place to review, not a proven vulnerability.

## Rules

One rule per file in `extray/rules/vulns/` or `extray/rules/malware/`, loaded automatically: a `Rule`
subclass with `id`, `severity`, `description` and `check_manifest` and/or `check_js`. Each JS rule ships
`tests/fixtures/js/<rule id>/vuln.js` (reported lines marked `VULN`) and `fixed.js` (nothing reported).

## Responsible disclosure

If extray finds a real vulnerability in a public extension, contact the developer (or its bug bounty
program) before publishing anything.
