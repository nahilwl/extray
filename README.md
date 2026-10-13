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

v0.1 analyzes `manifest.json`: dangerous permissions, all-hosts access, broad `externally_connectable`,
exposed HTML in `web_accessible_resources`, weakened CSP, `<all_urls>` content scripts, Manifest V2.
Each finding gives file, line and the offending line.

## Responsible disclosure

If extray finds a real vulnerability in a public extension, contact the developer (or its bug bounty
program) before publishing anything.
