# WebHunter — P-02

OWASP Top 10 web vulnerability scanner for authorized pentesting.

Part of [jmsDev](https://www.linkedin.com/in/jmsilva83)'s cybersecurity portfolio — Project P-02 of 9.

---

## Quick Start

```bash
pip install -e .
webhunter --help
webhunter checkers
webhunter scan http://10.10.11.21
webhunter scan https://target.htb:8443 --no-ai
webhunter scan http://target.htb --output results.json
```

## Requirements

- Python 3.11+
- `GEMINI_API_KEY` in `.env` for AI-assisted analysis (optional)

## Scope

By default, only these targets are allowed (no `--force-scope` needed):

- HTB machines: `10.10.10.x`, `10.10.11.x`
- THM machines: `10.10.x.x`, `10.8.x.x`
- RFC1918 private ranges
- `*.htb`, `*.thm`, `*.local`, `localhost`

For any other target, pass `--force-scope` and ensure you have written authorization.

## OWASP Coverage (Phase 2+)

| OWASP ID | Category | Checker | Status |
|---|---|---|---|
| A01:2021 | Broken Access Control | `access_control.py` | Pending |
| A02:2021 | Cryptographic Failures | `crypto_failures.py` | Pending |
| A03:2021 | Injection | `injection.py` | Pending |
| A05:2021 | Security Misconfiguration | `misconfig.py` | Pending |
| A06:2021 | Vulnerable Components | `vuln_components.py` | Pending |
| A07:2021 | Auth Failures | `auth_failures.py` | Pending |
| A10:2021 | SSRF | `ssrf.py` | Pending |

---

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por @jmsDev All rights reserved
