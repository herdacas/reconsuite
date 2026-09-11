# Analyse: recon-suite

## Übersicht

**recon-suite** ist ein **agentisches Vulnerability-Assessment-Framework** zur automatisierten Sicherheitsanalyse von Webdomains und IP-Adressen. Es basiert auf [CrewAI](https://crewai.com) und nutzt lokale LLMs via [Ollama](https://ollama.com) (wahlweise auch remote).

Sechs spezialisierte Teams arbeiten **sequenziell** zusammen, orchestriert durch einen CrewAI Flow mit persistiertem State (SQLite). Der gesamte Scan-Durchlauf ist auf **Penetrationtesting** ausgerichtet, nicht auf defensives Auditing.

---

## Architektur

```
                    ┌─────────────────────────────────────────────────────┐
                    │                 main.py / flow.py                    │
                    │        (Top-Level CLI + Master-Flow)                │
                    └─────────────────────────────────────────────────────┘
                                         │
                    ┌─────────────────────┴─────────────────────┐
                    │         ReconSuiteFlow (CrewAI Flow)       │
                    │         State: ScanState (Pydantic)        │
                    │         Persist: SQLiteFlowPersistence     │
                    │         Resume-fähig (--resume)            │
                    └─────────────────────────────────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         │                               │                               │
         ▼                               ▼                               ▼
   ┌──────────────┐              ┌──────────────┐              ┌──────────────┐
   │   TEAM 1     │              │   Router      │              │   TEAMS 2-6  │
   │  agentscanit │─────────────►│ (after scan)  │◄────────────►│  (post-scan) │
   │  5 Agents    │              │               │              │              │
   │  26 Tools    │              │  3 Routen:    │              │  interpret   │
   └──────────────┘              │  clean        │              │  threatintel │
                                 │  cve_analysis │              │  compliance  │
                                 │  full_analysis│              │  risk_scorer │
                                 └──────────────┘              │  reporting   │
                                                               └──────────────┘
```

### Flow-Routing

| Bedingung | Route | Aktive Teams |
|---|---|---|
| Keine CVEs gefunden | `clean` → Team 3 direkt | 1 → 3 |
| CVEs gefunden, kein Exploit | `cve_analysis` | 1 → 2 → 5 → 6 → 3 |
| CVEs + Exploit | `full_analysis` | 1 → 2 → 4 → 5 → 6 → 3 |

---

## Die 6 Teams im Detail

### Team 1: `agentscanit/` — Active Recon & Enumeration

**Technologie:** CrewAI Crew mit 5 Agents, 26 Tools, `Process.sequential` (außer `hierarchical`-Scope)

**Agents:**

| Agent | Rolle | Tools |
|---|---|---|
| `research_agent` | OSINT & Recon Specialist | subfinder, dig, dnsrecon, whois, dnsx, katana, ddg_search, searchsploit, nvd_tool, nvd_cpe_tool |
| `blue_agent` | Blue Team Security Analyst | nmap, nikto, whatweb, sslscan, curl, ping, nuclei, httpx |
| `red_agent` | Attack Surface Analyst | searchsploit, ddg_search, nvd_tool |
| `coding_agent` | Security Automation Developer | — (generiert Python-Code aus Kontext) |
| `reporter_agent` | Pentest Recon Report Writer | — (erstellt Markdown-Report) |

**Prozess (7 Phasen):**
1. **research** — Passive Reconnaissance: Subdomains, DNS, WHOIS, Technologie-Erkennung
2. **blue** — Active Scanning: Ports, Dienste, Versionen, Schwachstellen
3. **findings** — CVE-Analyse: searchsploit + NVD-Lookup für erkannte Services
4. **red_scan** — Gezielte Nachscans: nuclei + nikto für bestätigte Findings
5. **red** — Exploitability-Analyse: PoC-Prüfung, Angriffsflächen-Bewertung
6. **coding** — Generierung reproduzierbarer Python-Skripte
7. **report** — Markdown-Bericht aus allen Phasen

**Guardrails:**
- `_tool_call_guardrail` — Erzwingt echten Tool-Einsatz (keine halluzinierten Antworten)
- `_scope_coverage_guardrail` — Stellt sicher dass Scope-Pflicht-Tools aufgerufen wurden
- `_cve_trace_guardrail` — Validiert CVE-IDs gegen Tool-Outputs (Halluzinations-Prävention)
- `_cve_tool_used_guardrail` — Erzwingt CVE-Recherche-Tool vor Urteil
- `_subdomain_fanout_guardrail` — Reichert research-Output mit per httpx verifizierten Live-Hosts an

**Scopes (steuern welche Phasen aktiv sind):**

| Scope | Phasen |
|---|---|
| `osint` | research + report |
| `ssl` | research + blue (sslscan) + report |
| `quick` | research + blue (nmap Top-100, httpx) + findings + report |
| `web` | research + blue + findings + red + report |
| `network` | research + blue + findings + red + report |
| `full` | Alle 7 Phasen |
| `hierarchical` | research + blue + findings + red + report (Manager-Agent koordiniert) |

### Team 2: `interpret_agent/` — CVE Enrichment (NVD API v2)

**Technologie:** CrewAI Flow, **kein LLM**

- Liest CVE-IDs aus dem Scan-JSON
- Fragt NVD API v2 ab (CVSS-Score, Severity, CWE, References)
- Schreibt `interpret_<target>_<ts>.md`
- Arbeitet rein deterministisch — keine Halluzination

### Team 3: `reporting/` — Final Report

**Technologie:** CrewAI Flow, **kein LLM**

- Merged Scan-Report und NVD-Daten zu einem finalen Markdown-Report
- `final_report_<target>_<ts>.md`

### Team 4: `threatintel_agent/` — Threat Intelligence

**Technologie:** CrewAI Flow, **kein LLM**

- Prüft CVEs und IPs gegen AlienVault OTX, Shodan, VirusTotal
- In-the-Wild-Status pro CVE, IP-Reputation
- Degradiert graceful ohne API-Keys (kein Crash)

### Team 5: `compliance_agent/` — Compliance Mapper

**Technologie:** CrewAI Crew mit LLM + OWASP Knowledge Source

- Mapped Scan-Findings auf OWASP Top 10 (2021)
- Nutzt eine lokale eingebettete Wissensdatenbank (Knowledge Source)
- Remediation-Empfehlungen nur bei nachgewiesener Ausnutzbarkeit (nuclei-Treffer)
- Schreibt `compliance_<target>_<ts>.md`

### Team 6: `risk_scorer/` — Risk Scoring

**Technologie:** CrewAI Flow, **kein LLM**

- Deterministisches Risk-Scoring basierend auf:
  - Anzahl und Severity der CVEs (NVD)
  - Threat-Intel-Daten (OTX/Shodan/VT)
  - Compliance-Mapping (OWASP)
  - Exploitability (red-Phase-Findings)
- Ausgabe: Score (1–10) + Risk Level + `risk_score_*.md` + `risk_score_*.json`

---

## Kommunikation zwischen Teams

Teams kommunizieren **nicht direkt**. Alle Übergaben laufen über `ScanState` (Pydantic-Modell im CrewAI Flow):

```
Team 1  →  scan_json_path, has_cve_findings, has_exploitable
Team 2  →  nvd_results (CVSS, Severity pro CVE)
Team 4  →  threat_intel_output (In-the-Wild-Summary)
Team 5  →  compliance_output (OWASP-Mapping-Text)
Team 6  →  risk_score_output ("Score: 7.8 / 10 — HIGH")
Team 3  →  final_report_path
```

Innerhalb von Team 1 kommunizieren Agents über CrewAI Task-Kontext (Pydantic-Output einer Task als Input der nächsten).

---

## Technische Details

### LLM-Integration

- **Lokaler Modus** (Default): Alle LLMs laufen via Ollama localhost (qwen2.5-coder:14b, qwen2.5:7b)
- **Remote-Modus**: Über `OLLAMA_API_KEY` in models.json — Haupt-LLMs remote, Planner bleibt lokal
- **4 LLM-Profile**: Analysis (Temp 0.3), Code (Temp 0.2), Research (Temp 0.1), Planner (Temp 0.1)
- **Planner läuft immer lokal** — remote Modelle unterstützen Ollamas native FC-API nicht zuverlässig
- **AgentPlanner** ist bei >5 Tasks (full-Scope) deaktiviert — der Plan-Prompt würde 32k Tokens überschreiten und das Kontextfenster überlaufen (BUG-18)

### Resume-Mechanismus

- Flow-State wird per `@persist(SQLiteFlowPersistence)` in `flow_state.db` gespeichert
- `main.py --resume <flow-id>` stellt den letzten persistenten State wieder her
- Abgeschlossene Schritte werden via `completed_steps` übersprungen
- **Intra-Crew-Checkpointing wurde entfernt** (Phase 7) — Resume läuft nur auf Flow-Ebene

### Qualitätssicherung

- `trace_*.json` — protokolliert jeden Tool-Call mit Raw-Output, Timings
- `main.py --score` — berechnet Scan-Qualitäts-Scorecard
- `RECON_LLM_DEBUG=1` — protokolliert jeden LLM-Call (Prompt-Größe, Status, Dauer)
- 5 Retries für LLM-Fehler, 3 für strukturelle Fehler, Backoff bei 500ern
- `workflow_last.json` — BUG-6-Detection: wird nach Scan nicht aktualisiert, gilt Scan als fehlgeschlagen

---

## Laufzeiten (empirisch)

| Scan-Typ | Dauer |
|---|---|
| `quick` | 20–60 min |
| `full` (FULL_ANALYSIS-Route) | 90–180 min |
| Teams 4+6 (kein LLM) | +2–5 min |
| Team 5 (LLM) | +5–15 min |

---

## Outputs (alle in `logs/`)

| Datei | Team | Inhalt |
|---|---|---|
| `recon_report_*.md` | 1 | Recon-Report: Ports, Services, CVEs |
| `crew_*.json` | 1 | Strukturierter JSON-Log (Tasks, CVEs, Ports) |
| `trace_*.json` | 1 | Tool-Calls mit Raw-Output + Timings |
| `interpret_*.md` | 2 | NVD-Detaildaten pro CVE (CVSS, CWE, References) |
| `threatintel_*.md` | 4 | OTX/Shodan/VT — In-the-Wild-Status |
| `compliance_*.md` | 5 | OWASP Top 10 Mapping |
| `risk_score_*.md` | 6 | Risk Score + Level + Top Findings |
| `risk_score_*.json` | 6 | Maschinenlesbarer Risk-Score |
| `final_report_*.md` | 3 | Gemergter Final Report |
| `workflow_last.json` | 1 | Letzter Scan (Eingabe für Teams 2–6) |
| `flow_state.db` | Flow | SQLite — State pro Run (--resume) |
| `scan_*.py` | 1 | Generiertes Automatisierungs-Skript |

---

## Wichtige Design-Entscheidungen

1. **Pentest-Scope statt Audit**: Berichte fokussieren auf Ausnutzung, nicht auf Härtung. Remediation-Empfehlungen nur bei nachgewiesenem PoC (nuclei-Treffer).
2. **Deterministisch wo möglich**: Teams 2, 3, 4, 6 nutzen kein LLM — reine Datenabfragen und Berechnungen.
3. **Halluzinations-Prävention**: Guardrails prüfen CVE-IDs gegen Tool-Outputs, verhindern generische versionslose CVEs.
4. **Subdomain-Fanout**: Deterministische httpx-Liveness-Prüfung nach research, keine LLM-Entscheidung welche Subdomains gescannt werden.
5. **Resilienz**: Retry-Logik mit Backoff, Vollneustart bei LLM-Fehlern, graceful Degradation ohne API-Keys.
6. **Planer-Deaktivierung**: Der LLM-AgentPlanner wird bei full-Scope automatisch deaktiviert, da der Plan-Prompt zu groß für lokale Modelle wird.