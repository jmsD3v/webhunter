# 🕷️ WebHunter — OWASP Top 10 AI Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-Top_10-000000?style=for-the-badge&logo=owasp&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Portfolio](https://img.shields.io/badge/Portfolio-P--02_Offensive-critical?style=for-the-badge)

**Automated web vulnerability scanner covering all OWASP Top 10 categories with AI-powered exploit suggestions**

*P-02 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

WebHunter runs a full OWASP Top 10 assessment against a target web application — injection testing, authentication probing, misconfiguration detection, XSS fuzzing, SSRF probing — then feeds results to **Google Gemini** for exploitation narrative and remediation guidance.

```bash
webhunter scan http://10.10.11.21
```

---

## Features

- **Full OWASP Top 10 coverage** — A01 through A10, active probing
- **Injection testing** — SQLi (error-based, boolean, time-based), command injection, SSTI
- **XSS fuzzing** — reflected, stored, DOM-based pattern detection
- **Authentication analysis** — default creds, JWT weaknesses, session fixation
- **Misconfiguration detection** — exposed admin panels, directory listing, debug endpoints
- **SSRF probing** — internal interaction detection via URL parameters
- **Component fingerprinting** — server/framework versions matched against known CVEs
- **AI-powered analysis** — Gemini generates PoC context, CVSS rationale, and remediation steps
- **Dark-theme HTML report** — professional report with CVSS-style severity cards

---

## OWASP Top 10 Coverage

| ID | Category | Active Checks |
|---|---|---|
| **A01** | Broken Access Control | IDOR testing, forced browsing, horizontal/vertical privilege escalation |
| **A02** | Cryptographic Failures | HTTP redirect, weak TLS detection, cleartext sensitive data |
| **A03** | Injection | SQLi (3 techniques), CMDi, SSTI, LDAP injection |
| **A04** | Insecure Design | Rate limiting absence, logic flaw indicators |
| **A05** | Security Misconfiguration | Default creds, exposed admin panels, debug mode, open CORS |
| **A06** | Vulnerable Components | Version banner → CVE correlation |
| **A07** | Auth & Session Failures | Brute force exposure, JWT `alg:none`, session fixation |
| **A08** | Software Integrity Failures | Missing SRI on CDN assets |
| **A09** | Logging & Monitoring Failures | Verbose error responses, stack traces |
| **A10** | Server-Side Request Forgery | Internal service reach via URL params |

---

## Installation

```bash
git clone https://github.com/jmsdev83/webhunter
cd webhunter
pip install -e .

cp .env.example .env
# Add GEMINI_API_KEY to .env
```

### Requirements

- Python 3.11+
- Gemini API key: [aistudio.google.com](https://aistudio.google.com) (free tier, optional)

---

## Usage

```bash
# Full OWASP Top 10 scan with AI
webhunter scan http://target.htb

# Target specific check categories
webhunter scan http://target.htb --checks injection,auth,misconfig

# Authenticated scan (pass session cookie)
webhunter scan http://target.htb --cookie "session=abc123"

# Export HTML report
webhunter scan http://target.htb --output report.html --format html

# Fast mode — skip AI analysis
webhunter scan http://target.htb --no-ai

# List all available check modules
webhunter checks
```

---

## Architecture

```
webhunter scan <url>
      │
      ▼
  TargetAnalyzer       ← fingerprint stack, crawl endpoints, map parameters
      │
      ▼
  asyncio.gather()     ← all OWASP checkers run concurrently
  ┌───┴──────────────────────────────────────────────────────┐
  │  InjectionChecker   AuthChecker      MisconfigChecker    │
  │  XSSChecker         SSRFChecker      ComponentChecker    │
  │  CryptoChecker      IntegrityChecker LoggingChecker      │
  └───┬──────────────────────────────────────────────────────┘
      │
      ▼
  GeminiAnalyzer       ← CVSS scoring + exploit context + remediation
      │
      ▼
  Rich terminal table + HTML/JSON report
```

---

## Severity Classification

| Level | CVSS Range | Example Finding |
|---|---|---|
| 🔴 **CRITICAL** | 9.0–10.0 | SQLi with DB extraction, RCE via SSTI |
| 🟠 **HIGH** | 7.0–8.9 | Auth bypass, stored XSS, SSRF to internal |
| 🟡 **MEDIUM** | 4.0–6.9 | Reflected XSS, CORS wildcard, missing CSP |
| 🔵 **LOW** | 0.1–3.9 | Version disclosure, verbose errors |
| ⚪ **INFO** | 0.0 | Tech stack fingerprint, open endpoints |

---

## Project Structure

```
webhunter/
├── webhunter/
│   ├── checkers/
│   │   ├── base.py              # BaseChecker ABC
│   │   ├── injection.py         # SQLi, CMDi, SSTI
│   │   ├── auth.py              # Auth/session analysis
│   │   ├── misconfig.py         # Security misconfiguration
│   │   ├── xss.py               # XSS fuzzer
│   │   ├── ssrf.py              # SSRF prober
│   │   └── components.py        # Version → CVE
│   ├── core/
│   │   ├── crawler.py           # Target crawling + param discovery
│   │   ├── orchestrator.py      # Async checker pipeline
│   │   └── ai_analyzer.py       # Gemini integration
│   ├── types/
│   │   └── findings.py          # Vulnerability, ScanResult, Severity
│   ├── report/
│   │   ├── generator.py
│   │   └── template.html
│   └── cli/
│       └── main.py
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=your-key-here      # Google AI Studio (free tier)
```

---

## Portfolio

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | ReconAI — Recon Orchestrator | ✅ |
| P-02 | Offensive | **WebHunter** ← you are here | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing | ✅ |
| D-01 | Defensive | SOC-Lite — AI SIEM | ✅ |
| D-02 | Defensive | ThreatFeed — CTI Aggregator | ✅ |
| D-03 | Defensive | HoneyGrid — SSH/HTTP Honeypot | ✅ |
| F-01 | Forensics | DFIR-Auto — Forensic Triage | ✅ |
| F-02 | Forensics | MalwareScope — Malware Analyzer | ✅ |
| F-03 | Forensics | PCAPForge — Network Forensics | ✅ |

---

> ⚠️ **Legal Notice** — Only scan applications you own or have explicit written authorization to test.

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
