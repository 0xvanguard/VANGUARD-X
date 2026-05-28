<!-- markdownlint-disable MD033 MD041 -->
<p align="center">
  <strong>VANGUARD-X</strong><br/>
  <em>Autonomous agentic pentesting & continuous security monitoring</em>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-informational"></a>
  <img alt="Python 3.12" src="https://img.shields.io/badge/python-3.12-blue">
  <img alt="Status" src="https://img.shields.io/badge/status-alpha%20%7C%20Phase%201-orange">
</p>

> **Mission.** Democratise continuous pentesting for SMBs that cannot afford
> €15K-€90K/year manual engagements — without compromising on the ethical
> guardrails of professional offensive security.
>
> **Misión.** Democratizar el pentesting continuo para PYMEs que no pueden
> afrontar auditorías manuales de €15K-€90K/año, sin renunciar a las
> salvaguardas éticas del pentesting profesional.

---

## Table of contents / Índice

- [What VANGUARD-X is](#what-vanguard-x-is) · [Qué es](#qué-es-vanguard-x)
- [Architecture (Phase 1)](#architecture-phase-1)
- [Quick start](#quick-start) · [Inicio rápido](#inicio-rápido)
- [Configuration](#configuration) · [Configuración](#configuración)
- [Development](#development)
- [Roadmap](#roadmap)
- [Legal & ethical disclaimer](#legal--ethical-disclaimer) · [Aviso legal y ético](#aviso-legal-y-ético)

---

## What VANGUARD-X is

VANGUARD-X is an open-source platform built around four specialised AI agents
— **RECON**, **ATTACK**, **ANALYZE**, **REPORT** — coordinated by a Python
core. The reasoning engine is Claude Opus (with Ollama / Mistral as offline
fallback) and every external tool runs in an isolated, hardened container.

The platform is designed for **continuous** monitoring: it does not stop at a
one-shot scan but tracks asset, surface and finding drift across runs, and
escalates only what a human analyst really needs to look at.

### Qué es VANGUARD-X

Plataforma open-source con cuatro agentes IA especializados — RECON, ATTACK,
ANALYZE, REPORT — orquestados por un núcleo Python. El motor de razonamiento
es Claude Opus (con Ollama / Mistral como fallback offline) y cada
herramienta externa corre en un contenedor aislado y endurecido.

---

## Architecture (Phase 1)

```text
                  ┌──────────────────────────────────────────────┐
                  │  CLI: vanguard-x scan --target example.com   │
                  └──────────────────────┬───────────────────────┘
                                         ▼
                            ┌───────────────────────┐
                            │   ScopeEnforcer       │  ← default-deny
                            │   (safety boundary)   │
                            └──────────┬────────────┘
                                       ▼
                            ┌───────────────────────┐
                            │     ReconAgent        │
                            │ (parallel via gather) │
                            └──────────┬────────────┘
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
      ┌───────────┐             ┌──────────────┐           ┌──────────────┐
      │  Nmap     │             │ theHarvester │           │  Subfinder   │
      │ wrapper   │             │   wrapper    │           │   wrapper    │
      └─────┬─────┘             └──────┬───────┘           └──────┬───────┘
            │                          │                          │
            ▼                          ▼                          ▼
      ┌───────────┐             ┌──────────────┐           ┌──────────────┐
      │  WhatWeb  │             │   wafw00f    │           │ (Phase 2:    │
      │ wrapper   │             │   wrapper    │           │  attack)     │
      └─────┬─────┘             └──────┬───────┘           └──────────────┘
            │     CommandRunner        │
            │  ┌─────────────────────┐ │
            └──┤ LocalRunner (dev)   │─┘
               │ DockerExecRunner    │
               │  → vanguardx-nmap   │
               │  → vanguardx-harv.  │
               └─────────────────────┘
                          │
                          ▼
                   ┌─────────────┐       ┌──────────────────┐
                   │  SQLite     │──────▶│ TelegramNotifier │
                   │ scans /     │       │ (alerts, summary,│
                   │ assets /    │       │ change detection,│
                   │ findings    │       │   PDF reports)   │
                   └─────────────┘       └──────────────────┘
```

**Hard architectural rules** (enforced in code, see `.kiro/steering`):

1. The `ScopeEnforcer` is **default-deny**: an empty authorised list rejects
   every target.
2. Every tool wrapper is `CommandRunner`-agnostic — same code runs locally
   and inside hardened Docker containers.
3. No agent ever passes raw tool output to an LLM (Phase 3 onwards): a
   structuring step is mandatory.
4. Every container runs as a non-root user with `cap_drop: ALL` + only the
   capabilities its tool truly needs.

---

## Quick start

> **You will need:** Docker 24+, Docker Compose v2, and a target you are
> *legally authorised* to scan.

```bash
git clone https://github.com/0xvanguard/VANGUARD-X.git
cd VANGUARD-X
cp .env.example .env

# Fill in at minimum:
#   VANGUARDX_AUTHORIZED_TARGETS=your-target.example.com
# Optionally:
#   VANGUARDX_TELEGRAM_BOT_TOKEN=...
#   VANGUARDX_TELEGRAM_CHAT_ID=...

docker compose build
# One-shot scan (RECON: nmap, theHarvester, subfinder, whatweb, wafw00f in parallel):
docker compose run --rm core scan --target your-target.example.com --scope external

# Continuous monitoring (re-scans every 24h, alerts on new/removed assets):
docker compose run --rm core monitor -t your-target.example.com -i 24
```

The first run will create `./data/vanguard.db` (SQLite) and emit a summary on
the configured Telegram channel.

### Inicio rápido

Mismos pasos que arriba; rellena `VANGUARDX_AUTHORIZED_TARGETS` con los
dominios o redes para los que tienes autorización por escrito.

### Local development (no Docker)

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# Make sure nmap and theHarvester are on your PATH for live scans.
vanguard-x version
vanguard-x init-db
vanguard-x scan --target your-target.example.com
```

---

## Configuration

All configuration lives in environment variables (`.env` is auto-loaded). See
[`.env.example`](.env.example) for the full reference. Highlights:

| Variable                          | Purpose                                                      |
| --------------------------------- | ------------------------------------------------------------ |
| `VANGUARDX_AUTHORIZED_TARGETS`    | Comma-separated allow-list of domains / IPs / CIDRs (**required**) |
| `VANGUARDX_TOOL_RUNNER`           | `local` (default) or `docker_exec` (production)              |
| `VANGUARDX_DATABASE_URL`          | `sqlite+aiosqlite://...` (dev) or `postgresql+asyncpg://...` |
| `VANGUARDX_TELEGRAM_BOT_TOKEN`    | Optional — leave blank to disable notifications              |
| `VANGUARDX_TELEGRAM_CHAT_ID`      | Optional — paired with the token                             |
| `VANGUARDX_TOOL_TIMEOUT_SECONDS`  | Per-tool execution timeout (default 600)                     |

### Configuración

Los secretos se cargan exclusivamente desde `.env`. **Nunca** se admiten
valores hardcodeados. Si `VANGUARDX_AUTHORIZED_TARGETS` está vacío, todo
escaneo será denegado por defecto.

---

## Development

```bash
pip install -e '.[dev]'
pytest -q              # unit + integration tests, coverage gate at 80%
ruff check .           # lint
mypy src/              # strict type-checking
```

Repository layout:

```text
src/vanguard_x/
├── agents/        # ReconAgent (Phase 2-4 add Attack/Analyze/Report)
├── core/          # ScopeEnforcer, CommandRunner abstractions
├── db/            # SQLAlchemy 2.0 schema + async repository
├── notifications/ # Telegram notifier
├── tools/         # Nmap & theHarvester wrappers
├── config.py
├── logging_setup.py
├── models.py
└── __main__.py    # Typer CLI
docker/            # Hardened tool images (nmap, theHarvester)
tests/             # Pytest suite + fixtures (≥80% coverage gate)
```

---

## Roadmap

| Phase | Months | Theme                            |
| ----- | ------ | -------------------------------- |
| 1     | 1-2    | RECON foundation **(complete: 5 tools, parallel exec, change detection, continuous monitoring)** |
| 2     | 3-4    | ATTACK engine (Nuclei, Gobuster, scope-aware exploitation) |
| 3     | 5-7    | ANALYZE — Claude Opus reasoning loop, false-positive memory |
| 4     | 8      | REPORT — Jinja2 + WeasyPrint, NIS2 control mapping |
| 5     | 9-10   | Orchestrator + production hardening, FastAPI control plane |
| 6     | 11-12  | Dashboard UI, demo mode, monetisation prep |

---

## Legal & ethical disclaimer

> **VANGUARD-X is an offensive security tool.** Running it against systems
> you are not explicitly authorised to test is illegal in most jurisdictions
> (Spain: LO 10/1995 art. 197bis; Colombia: Ley 1273 de 2009;
> EU NIS2 / GDPR violations may also apply).
>
> By using VANGUARD-X you confirm that:
>
> 1. You have **written authorisation** from the legal owner of every target
>    listed in `VANGUARDX_AUTHORIZED_TARGETS`.
> 2. You understand that the platform's scope enforcement is a defensive
>    control, **not** a substitute for that authorisation.
> 3. You will not store credentials, session tokens or personal data in
>    plaintext in the VANGUARD-X database or logs.
>
> The maintainers accept no liability for misuse.

### Aviso legal y ético

VANGUARD-X es una herramienta de seguridad ofensiva. Usarla contra sistemas
para los que no tienes autorización explícita es ilegal (Colombia: Ley 1273
de 2009; España: LO 10/1995 art. 197bis; UE: NIS2 / RGPD). Al utilizarla
confirmas tener autorización por escrito del propietario legal de cada
objetivo declarado en `VANGUARDX_AUTHORIZED_TARGETS`.

---

## License

[MIT](LICENSE) — © 2026 John Sebastian Camargo (`@0xvanguard`).
