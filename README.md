# RecconSuite — Agentic Reconnaissance & Vulnerability Assessment

Multi-agent security assessment framework using [CrewAI](https://crewai.com) and local LLMs via [Ollama](https://ollama.com). Automates reconnaissance, active scanning, CVE analysis, and risk scoring across six specialized teams.

**Purpose:** Information gathering and vulnerability identification for penetration testing engagements. Provides structured, evidence-grounded findings for exploit development.

---

## Overview

RecconSuite orchestrates six teams sequentially to perform reconnaissance through vulnerability assessment:

```
Passive Recon  →  Active Scan  →  CVE Analysis  →  NVD Enrichment
     ↓
Threat Intel  →  Compliance Mapping  →  Risk Scoring  →  Final Report
```

Each phase operates as an independent CrewAI Flow or deterministic process. An LLM planner selects relevant phases based on scope and objectives. Post-scan routing determines which enrichment teams execute.

---

## Architecture

### Six-Team System

| Team | Package | Role | Technology |
|------|---------|------|-----------|
| 1 | `agentscanit/` | Passive OSINT + Active Scan + CVE Finding | CrewAI Crew (5 Agents, 19 Tools) |
| 2 | `interpret_agent/` | CVE enrichment (CVSS, severity, references) | CrewAI Flow + NVD API v2 |
| 3 | `reporting/` | Report synthesis and formatting | CrewAI Flow |
| 4 | `threatintel_agent/` | In-the-wild status (OTX, Shodan, VirusTotal) | CrewAI Flow (deterministic) |
| 5 | `compliance_agent/` | OWASP/CIS framework mapping | CrewAI Crew + LLM |
| 6 | `risk_scorer/` | Deterministic risk scoring | CrewAI Flow (deterministic) |

### Team 1: Active Scanning & Reconnaissance

**Passive Reconnaissance (`research_agent`):**
- `subfinder` — Subdomain enumeration (Certificate Transparency, passive DNS)
- `dnsrecon` — Full DNS analysis, zone transfer attempts
- `katana` — Web crawling (URLs, API endpoints, forms, JavaScript links)
- `dnsx`, `dig`, `whois` — DNS queries and domain registration data
- `searchsploit`, `ddgs`, NVD API — Exploit and CVE search

**Active Scanning (`blue_agent`):**
- `nmap` — Port discovery and service version detection
- `httpx` — HTTP probing, technology detection, API path discovery
- `whatweb` — Web technology fingerprinting (CMS, frameworks, servers)
- `wafw00f` — WAF/CDN detection (Cloudflare, Akamai, AWS WAF, ModSecurity)
- `nikto` — Web server vulnerability scanning (7000+ checks)
- `nuclei` — Template-based vulnerability scanning (CVEs, misconfigurations)
- `sslscan` — TLS/SSL configuration analysis
- `curl` — HTTP header examination

**Analysis (`red_agent`):**
- PoC validation via searchsploit, nuclei matches, NVD correlation
- Attack surface extraction from confirmed findings

### Flow Routing

Post-scan routing determines the enrichment pipeline:

```
No CVEs found       → CLEAN route        → Team 3 only
CVEs, unexploitable → CVE_ANALYSIS route → Teams 2 → 5 → 6 → 3
CVEs + exploitable  → FULL_ANALYSIS route → Teams 2 → 4 → 5 → 6 → 3
```

### Inter-Team Communication

Teams communicate through `ScanState` (Pydantic model):

```
Team 1  → scan_json_path, has_cve_findings, has_exploitable
Team 2  → nvd_results (CVSS, severity, CWE)
Team 4  → threat_intel_output (in-the-wild summary)
Team 5  → compliance_output (OWASP mapping)
Team 6  → risk_score_output (score + level)
Team 3  → final_report_path
```

Within Team 1, agents communicate via CrewAI task context (Pydantic output as context for the next task).

---

## Scoping Strategy

Reconnaissance follows [PTES](http://www.pentest-standard.org/) phases 2–7:

| PTES Phase | Covered | Implementation |
|---|---|---|
| 2. Intelligence Gathering | ✅ | Team 1 passive reconnaissance |
| 3. Threat Modeling | ✅ | Team 4 threat intelligence |
| 4. Vulnerability Analysis | ✅ | Team 1 active scanning + CVE analysis + Team 6 risk scoring |
| 5. Exploitation | ⚠️ Out of scope | Findings prepared for external exploit tools |
| 6. Post-Exploitation | — | Out of scope |
| 7. Reporting | ✅ | Team 3 synthesis + Team 5 mapping |

Reports are designed as handoff artifacts for exploitation:

- `final_report_*.md` — Executive summary and technical findings
- `risk_score_*.json` — Structured risk data for triage
- `scan_*.py` — Executable automation script from scanning steps
- Trace logs — Evidence trail for each finding

### Report Philosophy

- **Exploit-oriented:** Data is structured for exploit development, including exact versions, attack vectors, and accessible services.
- **Evidence-based findings only:** Versionless generic CVEs are excluded unless an active scan confirms the finding against the target.
- **No hallucinated findings:** Assertions are grounded in actual tool output through validation guardrails.

---

## Prerequisites

- Python 3.11+
- Ollama with a local or remote API-compatible endpoint
- **External scan tools** (system binaries, not Python packages):
  - **Debian/Ubuntu/Kali:** `nmap`, `nikto`, `whatweb`, `sslscan`, `dnsrecon`, `whois`, `dig`, `curl`, `ping`
  - **ProjectDiscovery tools:** `nuclei`, `httpx`, `dnsx`, `katana`, `subfinder`
  - **ExploitDB:** `searchsploit`

## Installation

```bash
# 1. Python dependencies
pip install -r requirements.txt

# 2. Install external tools (idempotent; only missing tools are installed)
sudo bash setup_tools.sh

# Check what's missing without installing:
bash setup_tools.sh --check

# 3. Configure models
cp agentscanit/models.json.example agentscanit/models.json
```

Scan tools are compiled/system binaries, not Python packages. `setup_tools.sh` installs them from the appropriate sources. `httpx` refers to the ProjectDiscovery Go binary, not the Python package with the same name.

---

## LLM Requirements

The framework uses Ollama native function calling. Suitable models must:

1. Support native tool/function calling.
2. Remain stable through deep multi-turn chains (at least 10 messages).
3. Be non-reasoning models or support `think:False` reliably.

| Role | Tested candidates |
|------|-------------------|
| Remote workers | `qwen3-coder`, `nemotron-3` family |
| Local workers | `qwen2.5:7b-instruct`, `llama3-groq-tool-use:8b` |
| Planner | `qwen2.5:7b-instruct` |

The Gemma family and reasoning models without reliable `think:False` support are not suitable for the current workflow.

```bash
RECON_LLM_DEBUG=1 python3 main.py <target> osint
# Logs: logs/llm_debug_<pid>.jsonl
```

---

## Quick Start

```bash
# Interactive mode
python3 main.py

# Direct execution
python3 main.py example.com web

# With objective and scope
python3 main.py example.com "Web application assessment" web

# List and resume saved runs
python3 main.py --list
python3 main.py --resume <flow-id>

# Team 1 only, without enrichment
cd agentscanit && python3 main.py example.com
```

### Scopes

Scope controls the depth and focus of Team 1 tasks:

| Scope | Tasks | Route |
|-------|-------|-------|
| `osint` | research → report | Team 3 directly |
| `ssl` | research → blue(ssl) → report | Team 3 directly |
| `quick` | research → blue(top-ports) → findings → report | Router |
| `web` | research → blue(web) → findings → red → report | Router |
| `network` | research → blue(all-ports) → findings → red → report | Router |
| `full` | research → blue → findings → red_scan → red → coding → report | Router |

---

## Outputs

All outputs are saved to `logs/`:

| File | Contents |
|------|----------|
| `recon_report_*.md` | Reconnaissance findings, open ports, services, and CVEs |
| `crew_*.json` | Structured task output, CVE references, and ports |
| `trace_*.json` | Tool calls with raw output and timings |
| `scan_*.py` | Executable script generated from scan steps |
| `interpret_*.md` | NVD enrichment data: CVSS, CWE, and references |
| `final_report_*.md` | Merged final report |
| `threatintel_*.md` | OTX, Shodan, and VirusTotal results |
| `compliance_*.md` | OWASP Top 10 mapping |
| `risk_score_*.md` / `.json` | Risk score, level, top findings, and next steps |
| `workflow_last.json` | Latest scan metadata used by Teams 2–6 |
| `flow_state.db` | SQLite persistence for resuming runs |

---

## Configuration

Environment variables can be set in `.env` or in the system environment:

| Variable | Purpose | Default |
|----------|---------|---------|
| `OLLAMA_BASE_URL` | Ollama endpoint | `http://localhost:11434` |
| `OLLAMA_API_KEY` | API key for remote Ollama | — |
| `MODEL_ANALYSIS` | Model for analysis agents | `models.json` |
| `MODEL_RESEARCH` | Model for research agent | `models.json` |
| `MODEL_CODE` | Model for coding agent | `models.json` |
| `EMBED_MODEL` | Embedding model | `models.json` |
| `NVD_API_KEY` | NVD API key | — |
| `OTX_API_KEY` | AlienVault OTX API key | — |
| `SHODAN_API_KEY` | Shodan API key | — |
| `VT_API_KEY` | VirusTotal API key | — |

Teams 4–6 degrade gracefully without API keys and report a `no_key` status instead of failing.

---

## Guardrails & Validation

RecconSuite includes evidence-grounding controls intended to reduce unsupported LLM output:

- **Value grounding:** Findings must be supported by raw tool output.
- **Tool validation:** Reported tools must have executed during the scan.
- **CVE validation:** CVEs are checked against detected service versions.
- **Source attribution:** Findings retain their tool source and scan context.

Validation errors trigger task rejection and diagnostic feedback.

---

## Documentation

| File | Contents |
|------|----------|
| [`agentscanit/toolinfo.md`](./agentscanit/toolinfo.md) | Tool reference: binaries, versions, and parameters |
| [`debugging/README.md`](./debugging/README.md) | Diagnostic workflow for models, tools, and agents |
| `CLAUDE.md` | Development notes and architecture decisions |

---

## Operational Notes

- Use the framework only against targets for which you have explicit authorization.
- Passive reconnaissance is used where possible; active scans can generate traffic and alerts.
- The framework performs no exploitation or post-exploitation activity.
- Findings are intended to support subsequent manual analysis and exploit development.
- A scan result is not a substitute for manual verification by a security professional.

---

## License

MIT

---

## Acknowledgments

- [CrewAI](https://crewai.com) — Multi-agent orchestration
- [Ollama](https://ollama.com) — Local LLM inference
- [ProjectDiscovery](https://projectdiscovery.io) — Security tools including nuclei, httpx, katana, subfinder, and dnsx
- [PTES](http://www.pentest-standard.org/) — Penetration testing standard
