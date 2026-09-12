# Field Inventory — recon-suite Analyzer-Suite

Erzeugt: 2026-09-12. Erfasst jedes Ausgabefeld aller Pydantic-Output-Modelle
(Team 1: `agentscanit/tasks.py`) sowie die wichtigsten strukturierten Felder
der Downstream-Teams (5/6/4: `compliance_agent/`, `risk_scorer/`,
`threatintel_agent/`). Reine Markdown-Freitext-Reports (Team 3 `reporting_flow.py`)
werden über ihre strukturierte Quelle (Team 1/2/6-Felder) abgedeckt, nicht
separat — der Report ist reine Darstellung.

**Oracle-Strategien** (Definition siehe VALIDATION_SPEC.md Phase 0):
`CONTROLLED` (Soll-Wert von uns gesetzt) · `ORACLE` (unabhängige Zweitquelle) ·
`CROSSCHECK` (nur Konsistenz gegen andere Felder/den Trace) · `UNVERIFIABLE`.

## Team 1 — Scanner (`agentscanit/tasks.py`)

### ResearchOutput (research-Task, `research_agent`)

| Feld | Typ | Quelle (Code-Pfad) | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `target_type` | str | LLM-Klassifikation ("domain"/"ip") | CROSSCHECK | Deterministisch aus dem Target-String selbst ableitbar (IP-Regex vs. Domain-Regex) — kein externes Oracle nötig, aber verifizierbar |
| `summary` | str | LLM-Freitext | UNVERIFIABLE | Prosa, kein Soll-Wert definierbar |
| `subdomains` | List[str] | LLM aus subfinder/dnsrecon-Output | ORACLE | Jede behauptete Subdomain muss unabhängig auflösbar sein (DNS-Oracle, mehrere Resolver) |
| `technologies` | List[str] | LLM aus whatweb/httpx-Output | CROSSCHECK | Zweiter unabhängiger Fingerprinter (siehe Phase 2) |
| `osint_notes` | List[str] | LLM-Freitext | UNVERIFIABLE | Prosa-Liste, kein Soll-Wert |
| `reverse_dns` | Optional[str] | LLM aus dig-Output | ORACLE | Unabhängiger PTR-Lookup |
| `asn_info` | Optional[str] | LLM aus whois-Output | ORACLE | RDAP/Routing-Registry als Zweitquelle |
| `memory_hit` | bool | LLM-Selbstauskunft | CROSSCHECK | Deterministisch prüfbar: existiert `recon_report_<target>_*.md` vor diesem Lauf? (`main.py`-Logik) |

### BlueOutput (blue-Task, `blue_agent`)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `tools_executed` | List[str] | LLM-Selbstauskunft | ORACLE | `run_trace`-Log (deterministisch von Subprocess-Aufrufen geführt, unabhängig vom LLM) — **live bestätigter Fabrikationsvektor**, siehe `_tools_executed_guardrail` (2026-09-12) |
| `open_ports` | List[int] | LLM aus nmap-Output | ORACLE | Trace-Rawoutput-Parsing (deterministisch, unabhängig vom LLM-Textverständnis) |
| `services` | Dict | LLM aus nmap/httpx-Output | CROSSCHECK | Gegen Trace-Rawoutput |
| `vulnerabilities` | List[str] | LLM-Freitext-Liste | CROSSCHECK | Falls CVE-ID enthalten → NVD-Oracle; sonst UNVERIFIABLE (Freitext) |
| `analysis` | str | LLM-Freitext | UNVERIFIABLE | Bare-required-Feld-Historie: BUG-26 (2026-09-12) |

### FindingsOutput (findings-Task)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `service_versions` | List[str] | LLM aus Bannern | CROSSCHECK | Gegen Trace-Rawoutput (Banner-String muss wörtlich vorkommen) |
| `cve_references` | List[str] | LLM aus searchsploit/NVD-Tools | ORACLE | NVD-API: CVE-ID muss auflösbar sein, sonst `FABRICATED` |
| `risk_summary` | str | LLM-Freitext | UNVERIFIABLE | Bare-required-Feld-Historie: BUG-26 |

### RedScanOutput (red_scan-Task, `blue_agent`)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `targeted_findings` | List[str] | LLM-Freitext | CROSSCHECK | Gegen Trace (nuclei/nikto-Rawoutput) |
| `tools_executed` | List[str] | LLM-Selbstauskunft | ORACLE | Wie BlueOutput.tools_executed |
| `open_ports` | List[int] | LLM aus Rescans | CROSSCHECK | Gegen Trace |
| `vulnerabilities` | List[str] | LLM-Freitext | CROSSCHECK | Wie BlueOutput.vulnerabilities |
| `analysis` | str | LLM-Freitext | UNVERIFIABLE | — |

### RedOutput (red-Task, `red_agent`)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `confirmed_attack_surface` | List[str] | LLM aus searchsploit/DDG | CROSSCHECK | Gegen Trace-Rawoutput |
| `exploitable_findings` | List[str] | LLM aus searchsploit/DDG | CROSSCHECK | Gegen Trace-Rawoutput |
| `exploitable_findings_count` | int | `model_validator` (Code, kein LLM) | CROSSCHECK | Rein deterministisch (`len(exploitable_findings)`) — Selbstkonsistenz-Check auf Code-Bugs |
| `cve_references` | List[str] | LLM aus searchsploit/DDG | ORACLE | NVD-API |

### CodingOutput (coding-Task, keine Guardrails, kein Tool-Zugriff)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `filename` | str | LLM | UNVERIFIABLE | Kein Soll-Wert |
| `code` | str | LLM | UNVERIFIABLE | Inhaltlich keine externe Referenz — aber `syntax_valid` (s.u.) ist real prüfbar |
| `code_plan` | List[str] | LLM-Freitext | UNVERIFIABLE | Prosa |
| `syntax_valid` | bool | LLM-Selbstauskunft | ORACLE | Real via `py_compile`/`ast.parse` gegen `code` verifizierbar — **Blocker identifiziert:** aktuell KEIN Guardrail prüft das, das Modell behauptet nur |

### ReportOutput (report-Task, `reporter_agent`)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `path` | str | LLM | CROSSCHECK | Datei muss real existieren |
| `executive_summary` | str | LLM-Markdown (enthält Confirmed-Findings-Tabelle etc.) | CROSSCHECK | Bereits durch `_confirmed_findings_tool_guardrail`/`_value_grounding_guardrail` teilweise abgedeckt; Rest der Prosa UNVERIFIABLE |

## Team 5 — Compliance (`compliance_agent/compliance_flow.py`)

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `mapping_result` | str | LLM-Freitext (OWASP-Mapping) | CROSSCHECK | Falls CVE-ID zitiert → NVD-Oracle; OWASP-Kategorie selbst nicht unabhängig prüfbar |
| `has_poc` / `exploitable_items` / `poc_hits` | bool/list | **Deterministisch** aus nuclei-Trace (`_extract_nuclei_poc`, kein LLM) | CROSSCHECK | Code-Pfad, kein LLM-Risiko — Selbstkonsistenz-Check |

## Team 6 — Risk Scorer (`risk_scorer/risk_flow.py`) — komplett deterministisch, kein LLM

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `risk_score` / `risk_level` / `critical_count` / `high_count` | float/str/int | `cve_filters.*` (Code) | CROSSCHECK | Rein deterministisch berechnet — Oracle = Re-Implementierung der Formel unabhängig im Scoring-Skript, deckt Code-Bugs auf (z.B. der Backlog-Fix vom 2026-09-11) |
| `top_findings` | list[dict] | Code, aus `nvd_results` | CROSSCHECK | — |

## Team 4 — Threat Intel (`threatintel_agent/threatintel_flow.py`) — kein LLM, reine API-Calls

| Feld | Typ | Quelle | Oracle-Strategie | Begründung |
|---|---|---|---|---|
| `otx_cve_data` / `otx_ip_data` / `shodan_data` / `vt_cve_data` / `vt_ip_data` | list[dict] | Direkte API-Responses (OTX/Shodan/VT) | CONTROLLED | Die Rohantwort IST die Oracle-Antwort — Prüfpunkt ist nur ob der Request wirklich stattfand (Cache/Log) und die Response nicht editiert wurde |
| `threat_summary` | str | LLM-Freitext über obige Daten | CROSSCHECK | Muss zu den strukturierten Feldern konsistent sein |

## Blocker / ohne Oracle-Zuordnung

Keine — jedes Feld hat eine Zuordnung (ggf. `UNVERIFIABLE`, siehe Tabellen).
Freitext-Felder (`summary`, `analysis`, `risk_summary`, `osint_notes`, `code`,
`code_plan`) sind bewusst `UNVERIFIABLE` — sie fließen NICHT in die
Korrektheitsquote ein, wie in Phase 3 (`score.py`) umgesetzt.

## Zusammenfassung nach Strategie

| Strategie | Felder (Anzahl) |
|---|---|
| ORACLE | 8 (`subdomains`, `reverse_dns`, `asn_info`, `tools_executed`×2, `open_ports`, `cve_references`×2, `syntax_valid`) |
| CROSSCHECK | 15 |
| CONTROLLED | 1 (Threat-Intel-Rohdaten) |
| UNVERIFIABLE | 10 |
