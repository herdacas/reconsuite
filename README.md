# AgentScanIT — Agentic Vulnerability Assessment Framework

Multi-Agent Security Assessment auf Basis von [CrewAI](https://crewai.com) und lokalen LLMs via [Ollama](https://ollama.com). Sechs spezialisierte Teams arbeiten sequenziell: vom passiven OSINT-Scan bis zum priorisierten Risk-Score mit OWASP-Compliance-Mapping.

---

## Was es macht

```
Passive Recon  →  Active Scan  →  CVE-Analyse  →  NVD-Enrichment
      ↓
Threat Intel  →  Compliance-Mapping  →  Risk-Scoring  →  Final Report
```

Jede Phase ist ein eigenständiger CrewAI-Flow oder deterministischer Prozess. Ein LLM-Planner wählt anhand von Scope und Objective die relevanten Phasen aus. Das Routing nach dem Scan entscheidet dynamisch welche Teams aktiv werden.

---

## Architektur

### 6-Team-System

| Team | Package | Technologie | Aufgabe |
|---|---|---|---|
| 1 | `agentscanit/` | CrewAI Crew · 5 Agents · 26 Tools | Passive Recon + Active Scan + CVE-Analyse |
| 2 | `interpret_agent/` | CrewAI Flow | NVD API v2 — CVE-Details, CVSS, Severity |
| 3 | `reporting/` | CrewAI Flow | Merge aller Reports → `final_report_*.md` |
| 4 | `threatintel_agent/` | CrewAI Flow (kein LLM) | OTX · Shodan · VirusTotal — In-the-Wild-Status |
| 5 | `compliance_agent/` | CrewAI Crew · LLM · OWASP Knowledge | OWASP Top 10 Mapping |
| 6 | `risk_scorer/` | CrewAI Flow (kein LLM) | Deterministisches Risk-Scoring |

### Flow-Routing

Nach dem Scan entscheidet der Router welche Teams laufen:

```
Kein CVE gefunden   →  CLEAN         →  Team 3 (direkt)
CVEs, kein Exploit  →  CVA_ANALYSIS  →  Teams 2 → 5 → 6 → 3
CVEs + Exploit      →  FULL_ANALYSIS →  Teams 2 → 4 → 5 → 6 → 3
```

### Kommunikation zwischen Teams

Teams kommunizieren **nicht direkt**. Alle Übergaben laufen über `ScanState` — ein Pydantic-Modell im CrewAI Flow:

```
Team 1  →  scan_json_path, has_cve_findings, has_exploitable
Team 2  →  nvd_results (CVSS, Severity pro CVE)
Team 4  →  threat_intel_output (In-the-Wild-Summary)
Team 5  →  compliance_output (OWASP-Mapping-Text)
Team 6  →  risk_score_output ("Score: 7.8 / 10 — HIGH")
Team 3  →  final_report_path
```

Innerhalb von Team 1 kommunizieren die 5 Agents über den CrewAI Task-Kontext (Pydantic-Output einer Task als Kontext der nächsten).

### Agents in Team 1

| Agent | Aufgabe | Tools |
|---|---|---|
| `research_agent` | Passive OSINT: Subdomains, DNS, WHOIS, theHarvester | 15 |
| `blue_agent` | Active Scanning: nmap, nikto, nuclei, sslscan, httpx | 12 |
| `research_agent` | CVE-Analyse (findings_task) | searchsploit, DDG, nvd_tool |
| `blue_agent` | Targeted Follow-up (red_scan_task) | nuclei, nikto |
| `red_agent` | Exploitability-Analyse: PoC-Check, Attack-Surface | searchsploit, DDG, nvd_tool |
| `coding_agent` | Automatisierungs-Skript aus Scan-Schritten | — |
| `reporter_agent` | Markdown-Report aus allen Phasen | — |

---

## Voraussetzungen

- Python 3.11+
- Ollama lokal oder remote (API-kompatibler Endpunkt)
- System-Tools: `nmap`, `nikto`, `whatweb`, `sslscan`, `subfinder`, `nuclei`, `httpx`, `ffuf`, `dnsrecon`, u.a.

```bash
pip install -r requirements.txt
cp models.json.example models.json   # Modelle konfigurieren
```

---

## Schnellstart

```bash
# Top-Level-Flow (empfohlen — alle 6 Teams)
python3 main.py example.com
python3 main.py example.com web                  # Scope als Argument
python3 main.py example.com "CVE-Suche" web      # Objective + Scope
python3 main.py                                  # interaktiv

# Flow-Resume nach Unterbrechung
python3 main.py --list                           # gespeicherte Runs anzeigen
python3 main.py --resume <flow-id>               # fortsetzen

# Nur Team 1 (Scanner ohne NVD + Reporting)
cd agentscanit && python3 main.py example.com
```

### Scopes

| Scope | Was läuft | Teams aktiv |
|---|---|---|
| `osint` | Passive Recon (kein aktiver Scan) | 1 → 3 |
| `ssl` | sslscan + testssl | 1 → 3 |
| `quick` | nmap Top-100 + httpx + CVE-Analyse | 1 → routing → 3 |
| `web` | httpx · whatweb · nikto · nuclei + CVE + Exploit | 1 → routing → 2–6 → 3 |
| `network` | nmap · naabu · httpx + CVE + Exploit | 1 → routing → 2–6 → 3 |
| `full` | Alle Tools + alle Phasen | 1 → routing → 2–6 → 3 |

> **Hinweis zum `full`-Scope:** Der LLM-AgentPlanner (Ausführungs-Optimierung vor den Phasen) ist bei `full` **deaktiviert** — bei 7 Phasen wird der Planner-Prompt so groß (~32k Tokens), dass er das Kontextfenster des lokalen Planner-Modells (qwen2.5:7b, num_ctx 4096) überläuft. Die Pipeline läuft unverändert (alle Phasen/Tools), nur ohne diese Optimierung. `web`/`network`/`quick` nutzen den Planner weiterhin. (Tracking: BUG-18.)
>
> **Empfohlenes Remote-Worker-Modell:** `qwen3-coder:480b` (Non-Reasoning, agentic Tool-Calling). Das frühere `gpt-oss:120b` (Reasoning-Modell) lieferte bei tiefen Tool-Call-Ketten sporadisch leere Antworten und ließ `full`-Scans abbrechen. Mit `qwen3-coder` läuft `full` stabil durch (verifiziert: alle 7 Phasen, 0 Retries). Konfiguration in `models.json` (`models.analysis/research/code`). (Tracking: BUG-19.)

---

## Outputs

Alle Outputs landen in `logs/`:

| Datei | Erzeugt von | Inhalt |
|---|---|---|
| `recon_report_*.md` | Team 1 | Recon-Report mit Ports, Services, CVEs |
| `crew_*.json` | Team 1 | Strukturierter JSON-Log (Tasks, CVE-Refs, Ports) |
| `trace_*.json` | Team 1 | Tool-Calls mit Raw-Output + Timings |
| `interpret_*.md` | Team 2 | NVD-Detaildaten pro CVE (CVSS, CWE, References) |
| `final_report_*.md` | Team 3 | Merged Final Report |
| `threatintel_*.md` | Team 4 | OTX/Shodan/VT — In-the-Wild-Status pro CVE + IP-Reputation |
| `risk_score_*.md` | Team 6 | Risk Score + Level + Top-Findings + Next Steps |
| `risk_score_*.json` | Team 6 | Maschinenlesbarer Risk-Score (für Weiterverarbeitung) |
| `compliance_*.md` | Team 5 | OWASP Top 10 Mapping der Findings |
| `workflow_last.json` | Team 1 | Letzter Scan (überschrieben) — Eingabe für Teams 2–6 |
| `flow_state.db` | Flow | SQLite — Flow-State pro Run (für `--resume`) |
| `checkpoints/*/` | Team 1 | Per-Task Checkpoint-Files (max 3 behalten) |

---

## Konfiguration

`.env` oder Umgebungsvariablen:

| Variable | Bedeutung | Default |
|---|---|---|
| `OLLAMA_BASE_URL` | Ollama-Endpunkt | `http://localhost:11434` |
| `OLLAMA_API_KEY` | API-Key für remote Ollama | — |
| `MODEL_ANALYSIS` | Modell für Analyse-Agents | aus `models.json` |
| `MODEL_RESEARCH` | Modell für Research-Agent | aus `models.json` |
| `MODEL_CODE` | Modell für Coding-Agent | aus `models.json` |
| `EMBED_MODEL` | Embedding-Modell (LanceDB + ChromaDB) | aus `models.json` |
| `NVD_API_KEY` | NVD API-Key (erhöht Rate-Limit 5→50 req/30s) | — |
| `OTX_API_KEY` | AlienVault OTX (kostenlos) | — |
| `SHODAN_API_KEY` | Shodan (paid-tier) | — |
| `VT_API_KEY` | VirusTotal (free-tier verfügbar) | — |

Teams 4–6 degradieren **graceful** ohne API-Keys — kein Crash, kein Timeout, nur `"no_key"`-Status im Output.

Modell-Auswahl über `models.json` (von `models.json.example` ableiten).

---

## Einschränkungen

**Erkennungsrate:**
- Targets hinter **Cloudflare / CDN / WAF** liefern keine CVEs — Banner-Informationen sind generisch. Kein Bug, korrektes Verhalten.
- CVE-Erkennung ist **banner-basiert** (HTTP-Header, Service-Fingerprint) — keine aktive Exploitation, keine Authentifizierung.

**Laufzeiten:**
- `quick`-Scan: 20–60 Minuten je nach Modell
- `full`-Scan (FULL_ANALYSIS-Route): 90–180 Minuten
- Teams 4+6 (ohne LLM): +2–5 Minuten pro CVA/FULL-Route
- Team 5 (LLM): +5–15 Minuten

**Modell-Abhängigkeiten:**
- Planning-LLM läuft immer lokal via Ollama — remote Modelle unterstützen Ollama's native FC-API nicht
- `allow_delegation=False` auf allen Agents — Delegation triggert native Function-Calling auf lokalen Modellen die das Schema nicht zuverlässig ausführen

**Bekannte CrewAI-Eigenheiten (dokumentiert in CLAUDE.md):**
- `@listen` Stacking überschreibt Trigger — `or_()` verwenden wenn eine Methode auf mehrere Quellen hören soll
- `Knowledge.__init__` überschreibt immer `source.storage` — Embedder muss über `Crew(embedder=...)` gesetzt werden
- Flow-State-DB-Einträge sind nach Breaking Changes am Flow-Graphen nicht mehr resumable

---

## Tool-Dokumentation

Detaillierte Übersicht aller 26 Tools (Binaries, Versionen, Status): [`agentscanit/toolinfo.md`](agentscanit/toolinfo.md)
