# Security

## Threat model

CyberShield Triage is a static website. It has no server, database, user accounts, API or secrets. The only input is a file the visitor chooses to load into their own browser tab, and that file is never sent anywhere.

What an attacker could try, and why it fails:

| Attack | Why it fails |
| --- | --- |
| Steal API keys or credentials from the repo or site | There are none. CI scans for secret-like strings on every push |
| Hack the backend or database | There isn't one. GitHub Pages serves static files only |
| Script injection (XSS) through a crafted alert file | All uploaded text is set with `textContent`. The page enforces Trusted Types (`require-trusted-types-for 'script'`, `trusted-types 'none'`), so the browser itself rejects HTML string injection. CI fails if HTML sinks appear in `site/js` |
| Load a malicious script from elsewhere | CSP `script-src 'self'` only. No CDNs, fonts or third-party code |
| Exfiltrate data from the page | CSP `connect-src 'none'`, `form-action 'none'`, `img-src 'self' data:` |
| Prototype pollution through JSON | Only known fields are copied into fresh objects. `__proto__` and unknown keys are dropped |
| Crash or freeze the tab with a huge file | 5 MB size limit, 5,000-row limit, per-field length cap |
| Formula injection when exported CSV is opened in Excel | Cells starting with `=`, `+`, `-` or `@` are prefixed with `'` |
| Prompt injection aimed at the triage engine | Instruction-like text in logs is detected, raises risk, and blocks a benign verdict |
| Compromised GitHub Action in CI | Actions are pinned to full commit SHAs, `persist-credentials: false`, minimum permissions, Dependabot updates pins |

## Known limits

- GitHub Pages does not allow custom response headers, so the policy is delivered as a `<meta>` tag. The `frame-ancestors` directive is not supported in meta tags, so other sites could frame the page. The page holds no secrets or session, so clickjacking has nothing to gain.
- Tests cover the engine and parser. The UI is checked manually in a browser.

## Reporting a vulnerability

Please open a private security advisory on this repository (**Security → Report a vulnerability**) rather than a public issue.
