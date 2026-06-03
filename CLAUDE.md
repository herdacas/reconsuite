# CLAUDE.md — AgentScanIT / Recon-Suite

## Was ist das?

Agentic Vulnerability Assessment Framework auf Basis von CrewAI + lokalen Ollama-Modellen.
Mehrere spezialisierte Agents arbeiten sequenziell: Passive Recon → Aktiver Scan → CVE-Analyse → Exploitability → Report.

---

## Projekt-Struktur

```
recon-suite/
├── agentscanit/          ← Haupt-Package (Team 1: Scanner)
│   ├── main.py           ← CLI-Einstiegspunkt
│   ├── crew.py           ← AgentScanITCrew, Planner, Pipeline-Logik
│   ├── agents.py         ← CrewAI Agent-Definitionen (5 Agents)
│   ├── tasks.py          ← Task-Definitionen + Pydantic Output-Schemas
│   ├── config.py         ← Env-basierte Konfiguration (Modelle, Pfade, API-Keys)
│   ├── tools/            ← Tool-Implementierungen
│   │   ├── _base.py      ← Subprocess-Helper + run_trace-Integration
│   │   ├── active_scanning.py   ← nmap, nikto, nuclei, sslscan, etc.
│   │   ├── passive_recon.py     ← subfinder, dnsrecon, whois, ddg, etc.
│   │   ├── nvd.py               ← NVD API v2 Client (eigenständig, noch nicht in Pipeline)
│   │   └── trace.py             ← Tool-Call-Trace für JSON-Logs
│   ├── scan_summary.py   ← Hilfsskript für Report-Ausgabe
│   └── toolinfo.md       ← Detaillierte Tool-Dokumentation (26 Tools)
├── interpret_agent/      ← Team 2: NVD-Enrichment
│   ├── interpret_flow.py ← CrewAI Flow für CVE-Lookup + Interpretation
│   └── nvd.py            ← NVD API v2 Client (standalone)
├── reporting/            ← Team 3: Final Report
│   └── reporting_flow.py ← Merge scan-report + NVD data → final_report_*.md
├── flow.py               ← Top-Level: orchestriert alle 3 Teams
├── main.py               ← Root-Wrapper (ruft agentscanit/main.py auf)
├── logs/                 ← Scan-Outputs (gitignored)
└── requirements.txt      ← Python-Abhängigkeiten
```

---

## Agents & Pipeline

| Agent | Rolle | Tools |
|---|---|---|
| `research_agent` | Passive OSINT / Recon | 14 (subfinder, dnsrecon, dig, whois, ...) |
| `blue_agent` | Active Scanning | 12 (nmap, nikto, nuclei, sslscan, ...) |
| `research_agent` | CVE-Analyse (findings_task) | searchsploit, ddg |
| `blue_agent` | Targeted Follow-up (red_scan_task) | nuclei, nikto |
| `red_agent` | Exploitability-Analyse | searchsploit, ddg |
| `coding_agent` | Script-Generierung | keine Tools |
| `reporter_agent` | Report-Erstellung | keine Tools |

Pipeline-Reihenfolge: `research → blue → findings → red_scan → red → coding → report`

Der LLM-Planner wählt anhand von Scope + Objective eine Teilmenge aus.

---

## Scopes

| Scope | Pipeline |
|---|---|
| `osint` | research → report |
| `ssl` | research → blue (sslscan/testssl only) → report |
| `quick` | research → blue → findings → report |
| `web` | research → blue → findings → red → report |
| `network` | research → blue → findings → red → report |
| `full` | alle Phasen |

---

## Ausführen

```bash
cd agentscanit
python3 main.py example.com
python3 main.py example.com "SSL/TLS prüfen" ssl
python3 main.py example.com "CVE-Suche" full
python3 main.py          # interaktiv
```

Outputs in `logs/`:
- `recon_report_<target>_<ts>.md` — Markdown-Report
- `crew_<target>_<ts>.json` — strukturierter JSON-Log
- `trace_<target>_<ts>.json` — Tool-Calls mit Raw-Output + Timings
- `workflow_last.json` — letzter Run (überschrieben)

---

## Konfiguration (config.py / .env)

| Variable | Bedeutung |
|---|---|
| `OLLAMA_BASE_URL` | Ollama API-URL (default: http://localhost:11434) |
| `OLLAMA_API_KEY` | API-Key für remote Ollama (aktiviert auch `think: False` für Qwen3) |
| `MODEL_ANALYSIS` | Modell für Analyse-Agents (default aus models.json) |
| `MODEL_RESEARCH` | Modell für Research-Agent |
| `MODEL_CODE` | Modell für Coding-Agent |
| `EMBED_MODEL` | Embedding-Modell für LanceDB Memory |
| `NVD_API_KEY` | NVD API-Key (optionaler Env-Var, erhöht Rate-Limit von 5 auf 50 req/30s) |

Modell-Auswahl via `models.json` (aus `models.json.example` ableiten).

---

## Bekannte Probleme / Offene Punkte

### CVEs werden nicht mehr gefunden (Stand: 2026-06-03)
- **Ursache:** `findings_task` nutzt nur `searchsploit` + DuckDuckGo; bei Cloud-Infrastruktur (Cloudflare, CDNs) oder gut gepatchten Systemen gibt searchsploit bei generischen Diensten keine Treffer zurück — die strikte "nur tool-bestätigte CVEs"-Regel verhindert dann jeden Eintrag.
- **Nebenproblem:** `agentscanit/tools/nvd.py` ist implementiert aber **nicht in die Agent-Pipeline integriert** (kein CrewAI-Tool-Wrapper, nicht in tools/__init__.py, nicht in agents.py).
- **Fix-Optionen:**
  1. `NvdSearchTool` als CrewAI BaseTool wrappen und `research_agent`/`red_agent` hinzufügen, damit Agents direkt NVD-Keyword-Suche durchführen können.
  2. `findings_task`-Prompt anpassen: bei leerer searchsploit-Ausgabe explizit auf NVD-Keyword-Suche ausweichen.
  3. Kurzfristig: `reporting_flow.py` direkt aufrufen und manuell CVE-IDs aus Logs mitgeben.

### think: False (agents.py)
- Für Ollama-Modelle mit Chain-of-Thought (`extra_body={"think": False}`) — verhindert dass Reasoning-Text in JSON-Responses fließt.
- Nur aktiv wenn `OLLAMA_API_KEY` gesetzt ist (Remote-Modelle).

### JSON-Retry-Logik (main.py)
- Bei `json_invalid`-Fehlern des LLM wird die Crew bis zu 3× neu gestartet.
- Die Crew-Instanz wird jedesmal neu erstellt (inkl. Planner-Aufruf).

### Memory-Patching (main.py)
- CrewAI's Memory-Analyse-LLM-Calls werden monkey-gepatcht (keine LLM-Calls bei save/recall).
- Grund: Pydantic-Validation-Errors + Rate-Limit-Probleme bei gleichzeitigen async-Requests.

---

## Tool-Hinzufügen

1. Klasse in `tools/active_scanning.py` oder `tools/passive_recon.py` anlegen (Basisklasse: `BaseTool`)
2. Instanz in `tools/__init__.py` exportieren
3. In `agents.py` dem passenden Agent hinzufügen
4. In `toolinfo.md` dokumentieren

---

## Wichtige Patterns

- **`_run()` in tools/_base.py** ist der Subprocess-Helper (mit Trace-Integration) — nicht `self._run()` (das ist CrewAI's BaseTool-Interface).
- **Strict factual outputs**: Task-Prompts verlangen explizit "nur tool-bestätigte Fakten" — kein Halluzinations-Output. CVEs nur wenn tool-bestätigt.
- **Planner-Fallback**: Wenn LLM-Planner kein valides JSON liefert, wird die scope-ceiling als Fallback genutzt (alle erlaubten Tasks für den Scope).
- **Memory**: LanceDB vector storage, shallow recall erzwungen (`_ShallowMemory`). Warme Runs (gleicher Target) nutzen Prior-Run-Daten.
