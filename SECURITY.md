# Security policy

## Reporting a vulnerability in extray

extray reads untrusted archives and JavaScript, so a bug can be a security issue: a crafted extension
that gets past the archive limits, exhausts memory, crashes or hangs the scan, or hides code from the
analysis.

Do not open a public issue. Report it privately through GitHub:
**Security** tab → **Report a vulnerability**
([private vulnerability reporting](https://github.com/nahilwl/extray/security/advisories/new)).

Include the extray version (`pip show extray`), the steps or the sample that triggers it, and its impact.
Once a fix is released, the advisory is published with credit, unless you prefer to stay anonymous.

Only the latest release is supported.

## Vulnerabilities found with extray

A finding is a place to review, not a proven vulnerability: confirm it by hand before reporting it.

If you confirm a real vulnerability in a public extension:

- report it privately to the developer (the contact or support address on the Chrome Web Store page)
  or to its bug bounty program, and give them reasonable time to ship a fix (90 days is common);
- if the developer does not answer, or the extension is actively exploited or malicious, report it to
  Google through the Chrome Web Store "Report abuse" link;
- do not publish details, proofs of concept or affected user data before a fix is available;
- do not test against other people's browsers or accounts.
