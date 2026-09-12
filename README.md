# WebHunter

Scanner de vulnerabilidades web basado en OWASP Top 10, con sugerencias de explotación asistidas por IA — proyecto **P-02** del portfolio de ciberseguridad de [@jmsDev](https://www.linkedin.com/in/jmsilva83).

## Qué hace

WebHunter lanza 10 checkers asíncronos contra una URL objetivo — uno por cada categoría del OWASP Top 10 2021 (A01 a A10) — haciendo peticiones HTTP reales con `httpx` contra el target, no análisis estático de código. Cada checker agrega sus hallazgos (`Vulnerability`) a un resultado común con severidad (CRITICAL/HIGH/MEDIUM/LOW/INFO), evidencia y remediación sugerida. Si se define alguna de `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` u `OPENAI_API_KEY` (`webhunter/core/ai_provider.py` detecta automáticamente cuál está seteada, con esa prioridad), el resultado del escaneo se envía al proveedor de IA correspondiente (Claude, Gemini `gemini-1.5-flash`, u OpenAI) para generar una evaluación de riesgo en texto libre; sin ninguna key, el escaneo corre igual y esa sección simplemente se omite. Antes de escanear, valida que el target esté en scope autorizado (HTB, THM, rangos RFC1918, `*.htb/.thm/.local`, localhost) y corta con un error claro si no lo está, salvo que se use `--force-scope`.

## Características

- **Cobertura real de las 10 categorías OWASP Top 10 2021**, un checker por categoría (ver tabla abajo) — no son todos igual de profundos: varios (headers, endpoints de debug, SSRF, SQLi/XSS básico) hacen pruebas activas concretas; otros son más livianos (fingerprint de versión, detección pasiva de superficie de ataque).
- **Checkers 100% asíncronos** (`asyncio.gather`) sobre `httpx.AsyncClient` — corren en paralelo contra el mismo target.
- **Tolerante a fallos**: si un checker se cae (timeout, conexión rechazada, excepción), el orquestador lo captura y lo reporta como finding INFO en vez de tirar abajo todo el scan.
- **Scope gate obligatorio** (`webhunter/core/target.py`): por defecto solo permite escanear rangos de laboratorio (HTB, THM, RFC1918, `.htb/.thm/.local`, localhost) o hosts agregados manualmente vía `AUTHORIZED_SCOPE`. `--force-scope` lo saltea, con advertencia en pantalla.
- **Análisis con IA opcional y configurable** — cualquiera de estas API keys (`ANTHROPIC_API_KEY` > `GEMINI_API_KEY` > `OPENAI_API_KEY`, en ese orden de prioridad si hay más de una seteada); no bloquea el escaneo si falta la API key.
- **Salida a JSON** (`--output`) para integrarlo en otras herramientas o pipelines.
- **Exit code útil**: devuelve `1` si hubo hallazgos CRITICAL o HIGH, pensado para CI/CD.

### Cobertura OWASP Top 10 (checkers reales, verificado en código)

| Categoría | Checker | Qué prueba |
|---|---|---|
| A01 — Broken Access Control | `access_control` | Directory traversal, exposición de paths admin, acceso a archivos sensibles |
| A02 — Cryptographic Failures | `crypto` | Config TLS/SSL, redirect HTTP→HTTPS, cookies inseguras |
| A03 — Injection | `injection` | SQLi por detección de errores en respuesta, reflected XSS |
| A04 — Insecure Design | `insecure_design` | Misconfiguración de CORS, open redirects, path traversal en parámetros |
| A05 — Security Misconfiguration | `misconfiguration` | Headers de seguridad ausentes, endpoints de debug expuestos, verbosidad de errores |
| A06 — Vulnerable Components | `vulnerable_components` | Versiones de software desactualizadas en headers y comentarios HTML |
| A07 — Auth Failures | `auth_failures` | Detección de formularios de login, política de lockout, credenciales por defecto |
| A08 — Software/Data Integrity | `integrity_failures` | SRI ausente en recursos CDN, JWT `alg:none`, patrones de deserialización insegura |
| A09 — Logging Failures | `logging_failures` | Archivos de log expuestos, endpoints de debug, interfaces de monitoreo |
| A10 — SSRF | `ssrf` | SSRF vía parámetros URL, endpoints proxy, prueba contra metadata de nube (AWS/GCP/DO) |

> Nota honesta: `webhunter checkers` lista estos 10 módulos en el momento de escribir esto — es la fuente de verdad más confiable, correlo si querés confirmar el estado actual.

## Requisitos

- **Python 3.11+** (declarado en `pyproject.toml`, probado localmente con 3.14)
- Una API key de IA — opcional, y configurable entre cualquiera de estas: `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` u `OPENAI_API_KEY`. Necesaria solo para el análisis con IA. Si hay más de una seteada, `webhunter/core/ai_provider.py` usa la primera que encuentre en ese orden de prioridad exacto: Anthropic > Gemini > OpenAI. Gemini se consigue gratis en [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey). Sin ninguna key, el scan corre normal y solo se omite esa sección.
- `AUTHORIZED_SCOPE` — opcional. Lista separada por comas de IPs/CIDRs/hostnames adicionales autorizados para escanear, más allá del scope de laboratorio incluido por defecto.

(Estas son las únicas variables de entorno que el código realmente lee — confirmado buscando `os.getenv`/`os.environ` en todo `webhunter/`.)

## Instalación

Probado en Windows con Git Bash / PowerShell:

```bash
git clone https://github.com/jmsDev/webhunter
cd webhunter

python -m venv .venv

# Activar el entorno virtual
# PowerShell:
.venv\Scripts\Activate.ps1
# Git Bash:
source .venv/Scripts/activate

# Instalar el paquete
pip install -e .

# Opcional: dependencias de desarrollo (pytest, mypy, ruff)
pip install -e ".[dev]"

# Variables de entorno (opcional, solo si vas a usar análisis con IA)
cp .env.example .env
# editar .env y agregar UNA de: ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY
```

La instalación con `pip install -e .` se verificó limpia, sin conflictos de versiones.

## Uso

```bash
# Ver comandos y opciones
webhunter --help

# Listar los checkers disponibles y a qué categoría OWASP corresponde cada uno
webhunter checkers

# Scan completo con IA (requiere una API key de IA en .env)
webhunter scan http://10.10.11.21

# Scan rápido sin análisis de IA
webhunter scan http://127.0.0.1 --no-ai

# Guardar resultados en JSON
webhunter scan http://10.10.11.21 --no-ai --output resultado.json

# Escanear un target fuera del scope por defecto (requiere autorización escrita)
webhunter scan https://midominio-autorizado.com --force-scope
```

Flags reales de `webhunter scan` (`webhunter/cli/main.py`):

| Flag | Qué hace |
|---|---|
| `url` (posicional) | Target a escanear, ej. `http://10.10.11.21` |
| `--force-scope` | Saltea la validación de scope. Solo con autorización escrita. |
| `--no-ai` | Se salta el análisis con IA. |
| `--output` / `-o` | Guarda el resultado completo en un JSON. |
| `--report` / `-r` | Pensado para generar reporte HTML/PDF (Fase 3). **No verificado**: el código lo invoca pero `jinja2`/`weasyprint` no están declarados como dependencias del proyecto, así que puede fallar al usarlo tal cual está el repo hoy. |

Si el target no está en scope (no es HTB/THM/RFC1918/`.htb`/`.thm`/`.local`/localhost ni fue agregado en `AUTHORIZED_SCOPE`), el comando corta con un `SCOPE ERROR` claro y exit code `1` — no hace falta API key para llegar a ese punto.

## Estructura del proyecto

```
webhunter/
├── pyproject.toml
├── .env.example
├── CLAUDE.md
├── README.md
└── webhunter/
    ├── cli/
    │   └── main.py                   # Comandos Typer: scan, checkers
    ├── core/
    │   ├── target.py                 # Parseo de URL + scope gate
    │   ├── ai_provider.py            # Selección de proveedor de IA (Anthropic/Gemini/OpenAI)
    │   └── orchestrator.py           # Orquestador async + análisis con IA
    ├── checkers/                     # 10 checkers, uno por categoría OWASP A01–A10
    │   ├── base.py                   # BaseChecker (ABC), tolerante a fallos
    │   ├── access_control.py
    │   ├── auth_failures.py
    │   ├── crypto.py
    │   ├── injection.py
    │   ├── insecure_design.py
    │   ├── integrity_failures.py
    │   ├── logging_failures.py
    │   ├── misconfiguration.py
    │   ├── ssrf.py
    │   └── vulnerable_components.py
    ├── report/
    │   ├── generator.py              # HTML/PDF (dependencias no declaradas, ver Uso)
    │   └── template.html
    └── types/
        └── findings.py               # Vulnerability, ScanResult, Severity, VulnCategory
```

## Aviso legal

WebHunter está pensado exclusivamente para pentesting autorizado y fines educativos (labs propios, HackTheBox, TryHackMe, o targets con autorización escrita explícita). Escanear sistemas que no son tuyos y sobre los que no tenés autorización es ilegal en la mayoría de las jurisdicciones. El scope gate por defecto es una ayuda, no una garantía legal — la responsabilidad de usar esta herramienta dentro de la ley es de quien la ejecuta.

---

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved
