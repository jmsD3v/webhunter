# CLAUDE.md — WebHunter

Este archivo es el contexto completo para Claude Code.
Leelo antes de tocar cualquier archivo del proyecto.

---

## Qué es este proyecto

**WebHunter** es un scanner de vulnerabilidades web basado en OWASP Top 10 para pentesting autorizado.
Es el proyecto **P-02** de un portfolio de ciberseguridad de 9 proyectos.
El objetivo final es conseguir el primer trabajo en ciberseguridad.

El autor es **Juanma** (Juan Manuel Silva), Full Stack Developer TypeScript/Python en Las Breñas, Chaco, Argentina.
Está estudiando Tecnicatura en Seguridad Informática (TECLAB) + Licenciatura en Ciberdefensa (UNDEF-FADENA).

---

## Relación con P-01 ReconAI

WebHunter sigue el mismo patrón arquitectónico que ReconAI:

| Concepto ReconAI | Equivalente WebHunter |
|---|---|
| `BaseAgent` | `BaseChecker` |
| `Finding` | `Vulnerability` |
| `ReconResult` | `ScanResult` |
| `Target` | `TargetURL` |
| `orchestrator.py` → `run_recon()` | `orchestrator.py` → `run_scan()` |
| `ANTHROPIC_API_KEY` (Claude) | `GEMINI_API_KEY` (Gemini) |
| `reconai agents` | `webhunter checkers` |

Si ya entendés cómo funciona ReconAI, entendés WebHunter.

---

## Estado actual del proyecto

### Fase 1 — COMPLETA (scaffold)

```
webhunter/
├── pyproject.toml
├── .env.example
├── README.md
├── CLAUDE.md
└── webhunter/
    ├── __init__.py
    ├── types/
    │   ├── __init__.py
    │   └── findings.py        ← Vulnerability, ScanResult, Severity, VulnCategory
    ├── core/
    │   ├── __init__.py
    │   ├── target.py          ← TargetURL parse + scope validate
    │   └── orchestrator.py    ← async orchestrator (CHECKERS vacío por ahora)
    ├── checkers/
    │   ├── __init__.py
    │   └── base.py            ← BaseChecker ABC
    └── cli/
        ├── __init__.py
        └── main.py            ← CLI: `webhunter scan` + `webhunter checkers`
```

### Lo que funciona ahora mismo

```bash
pip install -e .
webhunter --help
webhunter checkers              # lista checkers (vacío en Fase 1)
webhunter scan http://127.0.0.1 --no-ai    # scan sin checkers todavía
webhunter scan http://10.10.11.21 --no-ai  # contra HTB (in-scope)
```

### Lo que falta — por orden de prioridad

#### Fase 2 — Checkers OWASP (hacer acá en Claude Code)

Cada checker va en `webhunter/checkers/` y se registra en `CHECKERS` en `orchestrator.py`.

| Archivo | Checker | OWASP | Técnicas | Estado |
|---|---|---|---|---|
| `headers.py` | `SecurityHeadersChecker` | A05:2021 | Detecta ausencia de CSP, HSTS, X-Frame-Options, X-Content-Type | **PENDIENTE** |
| `ssl_tls.py` | `SSLTLSChecker` | A02:2021 | TLS version, cipher suites débiles, cert expirado | **PENDIENTE** |
| `cors.py` | `CORSChecker` | A01:2021 | CORS wildcard, credentials + wildcard, origin reflection | **PENDIENTE** |
| `auth_failures.py` | `AuthFailuresChecker` | A07:2021 | Login sin lockout, default creds, JWT weak signing | **PENDIENTE** |
| `injection.py` | `InjectionChecker` | A03:2021 | SQL injection básico, XSS reflected, SSTI | **PENDIENTE** |
| `misconfig.py` | `MisconfigChecker` | A05:2021 | Dir listing, backup files (.bak, .old), debug endpoints | **PENDIENTE** |
| `ssrf.py` | `SSRFChecker` | A10:2021 | SSRF en params, headers, redirect chains | **PENDIENTE** |
| `vuln_components.py` | `VulnComponentsChecker` | A06:2021 | Server header version disclosure, X-Powered-By | **PENDIENTE** |
| `access_control.py` | `AccessControlChecker` | A01:2021 | IDOR básico, path traversal, forced browsing | **PENDIENTE** |
| `crypto_failures.py` | `CryptoFailuresChecker` | A02:2021 | HTTP sin redirect a HTTPS, cookies sin Secure/HttpOnly | **PENDIENTE** |

#### Fase 3 — Report Generator

- `webhunter/report/generator.py` — Jinja2 → HTML → PDF
- `webhunter/report/template.html` — template profesional estilo pentest report
- Activar `--report <file.html>` en el CLI

#### Fase 4 — Integración con ReconAI

- ReconAI descubre targets → WebHunter los escanea
- Supabase compartido entre ambos proyectos
- Dashboard Next.js unificado (ver P-01 Fase 4)

---

## Arquitectura del pipeline

```
URL (string)
  → TargetURL.parse()         # scheme, host, port, base_url
  → target.validate_scope()   # scope gate — lanza ScopeError si no autorizado
  → run_scan()                # orchestrator async
      → asyncio.gather([checkers])  # todos corren en paralelo
          → SecurityHeadersChecker.execute()
          → SSLTLSChecker.execute()
          → CORSChecker.execute()
          → ... (todos los checkers registrados)
      → analyze_with_gemini()  # Gemini API (si GEMINI_API_KEY está seteada)
  → print_summary()            # Rich table en terminal
  → HTML/PDF report            # Fase 3
```

---

## Cómo agregar un nuevo checker

```python
# webhunter/checkers/headers.py
from __future__ import annotations

from webhunter.checkers.base import BaseChecker
from webhunter.core.target import TargetURL
from webhunter.types.findings import Severity, ScanResult, VulnCategory, Vulnerability


class SecurityHeadersChecker(BaseChecker):
    name = "security_headers"
    category = VulnCategory.A05_MISCONFIG
    description = "Checks for missing or misconfigured HTTP security headers"

    async def run(self, target: TargetURL, result: ScanResult) -> None:
        # tu lógica acá usando httpx
        # agregar vulnerabilidades con result.add(Vulnerability(...))
        pass
```

Luego en `webhunter/core/orchestrator.py`, agregar en `CHECKERS`:

```python
from webhunter.checkers.headers import SecurityHeadersChecker

CHECKERS: list[BaseChecker] = [
    SecurityHeadersChecker(),  # agregar acá
]
```

---

## Reglas del proyecto

### Ética / scope
- El `ScopeValidator` en `core/target.py` es la puerta ética. **Nunca bypassearlo silenciosamente.**
- In-scope por default: HTB (10.10.10-11.x), THM (10.10.x.x, 10.8.x.x), RFC1918, *.htb, *.thm, *.local, localhost
- Externos: necesitan `--force-scope` + autorización escrita del usuario

### Código
- Python 3.11+, type hints en todo, `from __future__ import annotations`
- Sin docstrings en métodos
- Checkers: async, tolerantes a fallos (no crashear el orchestrator)
- Si algo falla en un checker, agregar `Vulnerability` de tipo ERROR y continuar
- `Vulnerability` es inmutable después de `result.add()` — no modificar vulns ajenas
- Usar `httpx.AsyncClient` (no requests, no urllib)

### Severidades de vulnerabilidades
```
CRITICAL → RCE, auth bypass directo, data exfiltration sin credenciales
HIGH     → SQLi, XSS stored, SSRF en servicios internos, IDOR crítico
MEDIUM   → XSS reflected, CORS misconfigured, missing HSTS
LOW      → Server version disclosure, dir listing sin datos sensibles
INFO     → Datos útiles para el atacante (headers, tecnologías)
```

### MITRE ATT&CK — técnicas por checker

| Checker | Técnicas principales |
|---|---|
| security_headers | T1190 (Exploit Public-Facing Application) |
| ssl_tls | T1557 (Adversary-in-the-Middle) |
| cors | T1185 (Browser Session Hijacking) |
| auth_failures | T1110 (Brute Force), T1078 (Valid Accounts) |
| injection | T1190, T1059 (Command and Scripting Interpreter) |
| misconfig | T1083 (File and Directory Discovery) |
| ssrf | T1090 (Proxy), T1005 (Data from Local System) |
| vuln_components | T1592.002 (Software Discovery) |
| access_control | T1083, T1548 (Abuse Elevation Control Mechanism) |
| crypto_failures | T1557, T1040 (Network Sniffing) |

---

## Variables de entorno (.env)

```bash
GEMINI_API_KEY=          # gratis en aistudio.google.com/app/apikey
AUTHORIZED_SCOPE=        # targets adicionales (comma-separated)
```

---

## Setup desde cero

```bash
# Windows PowerShell
pip install -e .

# Verificar
webhunter --help
webhunter checkers

# Primer scan (sin checkers todavía en Fase 1)
webhunter scan http://127.0.0.1 --no-ai

# Con AI (necesita GEMINI_API_KEY en .env)
cp .env.example .env
# editar .env con tu key
webhunter scan http://10.10.11.21
```

---

## Comandos útiles para Claude Code

```bash
# Scan de prueba contra localhost
webhunter scan http://127.0.0.1 --no-ai

# Ver output JSON
webhunter scan http://127.0.0.1 --no-ai --output /tmp/test.json

# Ver checkers disponibles
webhunter checkers

# Tests
python -m pytest tests/ -v

# Estructura del proyecto
find . -name "*.py" | grep -v __pycache__ | sort
```

---

## Footer obligatorio en todo output del proyecto

```
Copyright © {año actual, calculado dinámicamente — nunca hardcodear} Desarrollado desde Las Breñas con 💜 por @jmsDev All rights reserved
```

`@jmsDev` → https://www.linkedin.com/in/jmsilva83
