# AgentScanIT — Agentic Vulnerability Assessment Framework

Multi-agent security recon suite auf Basis von [CrewAI](https://crewai.com) und lokalen LLMs via [Ollama](https://ollama.com).

---

## Was es macht

Führt einen vollständigen Recon- und Vulnerability-Assessment-Workflow durch:

```
Passive Recon  →  Active Scan  →  CVE-Analyse  →  Exploitability  →  Report
```

Jede Phase ist ein spezialisierter CrewAI-Agent. Ein LLM-Planner wählt anhand von Scope und Objective nur die relevanten Phasen aus.

---

## Architektur

```
agentscanit/   — Team 1: Scanner (Haupt-Package)
interpret_agent/ — Team 2: NVD-Enrichment (CVE-Details via NVD API v2)
reporting/     — Team 3: Final Report (Merge scan + NVD → Markdown)
flow.py        — Orchestrierung aller 3 Teams
```

### Agents

| Agent | Aufgabe |
|---|---|
| `research_agent` | Passive OSINT: Subdomains, DNS, WHOIS, theHarvester |
| `blue_agent` | Active Scanning: nmap, nikto, nuclei, sslscan, httpx |
| `research_agent` | CVE-Analyse: searchsploit + DuckDuckGo (findings_task) |
| `blue_agent` | Targeted Follow-up: nuclei/nikto mit CVE-Tags (red_scan_task) |
| `red_agent` | Exploitability-Analyse: searchsploit + DDG PoC-Check |
| `coding_agent` | Python-Automatisierungs-Skript aus den Scan-Schritten |
| `reporter_agent` | Finaler Markdown-Recon-Report |

---

## Voraussetzungen

- Python 3.11+
- Ollama lokal oder remote (API-kompatibler Endpunkt)
- System-Tools: `nmap`, `nikto`, `whatweb`, `sslscan`, `subfinder`, `nuclei`, `httpx`, `ffuf`, u.a.

```bash
cd agentscanit
pip install -r requirements.txt
cp models.json.example models.json   # Modelle konfigurieren
```

---

## Schnellstart

```bash
cd agentscanit

# Interaktiv
python3 main.py

# Mit Argumenten
python3 main.py example.com
python3 main.py example.com "CVE-Suche" full
python3 main.py example.com "SSL/TLS prüfen" ssl
```

### Scopes

| Scope | Was läuft |
|---|---|
| `osint` | Nur passive Recon (kein aktiver Scan) |
| `ssl` | sslscan + testssl |
| `quick` | ping + nmap Top-100 + httpx |
| `web` | httpx, whatweb, nikto, nuclei |
| `network` | nmap + naabu + httpx |
| `full` | Alle Tools + CVE-Analyse + Exploitability |

---

## Outputs

Alle Outputs landen in `logs/`:

| Datei | Inhalt |
|---|---|
| `recon_report_<target>_<ts>.md` | Markdown-Recon-Report |
| `crew_<target>_<ts>.json` | Strukturierter JSON-Log (Ports, CVEs, Phasen) |
| `trace_<target>_<ts>.json` | Tool-Calls mit Raw-Output + Timings |
| `final_report_<target>_<ts>.md` | Merged Report mit NVD-CVE-Details (via reporting_flow) |

---

## Konfiguration

Umgebungsvariablen (oder `.env`):

| Variable | Bedeutung |
|---|---|
| `OLLAMA_BASE_URL` | Ollama-Endpunkt (default: `http://localhost:11434`) |
| `OLLAMA_API_KEY` | API-Key für remote Ollama |
| `NVD_API_KEY` | NVD API-Key (optional, erhöht Rate-Limit) |

Modell-Auswahl über `agentscanit/models.json`.

---

## Bekannte Einschränkungen

- **CVE-Erkennung**: Die Pipeline findet aktuell keine CVEs für Cloud-Infrastruktur (Cloudflare, CDNs) da searchsploit keine generischen Dienste trifft. `tools/nvd.py` (NVD API v2) ist implementiert aber noch nicht in die Agent-Pipeline integriert.
- **EyeWitness**: Entfernt (Selenium-Abhängigkeit fehlt auf Server-Systemen ohne Display).
- **Thinking-Modelle (Qwen3)**: `think: False` via `extra_body` verhindert Reasoning-Text in strukturierten JSON-Responses.

---

## Tool-Dokumentation

Detaillierte Übersicht aller 26 Tools (Binaries, Versionen, Status): [`agentscanit/toolinfo.md`](agentscanit/toolinfo.md)
