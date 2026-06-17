# CLAUDE.md — AgentScanIT / Recon-Suite

## Arbeitsweise / Entwicklungsprozess

Wir arbeiten die Roadmap (`roadmap.md`) phasenweise ab. Im Ablauf wird entschieden:
- Schritte zu verschieben wenn sie ein höheres Risiko für die Hauptfunktionalität darstellen
- Arbeitsschritte zusammenzufassen wenn sie logisch zusammengehören
- Schritte vorübergehend zu überspringen um die Kernfunktion nicht zu beeinträchtigen

**WICHTIG — Keine pauschalen Antworten. Faktenbasierte Responses auf jede Frage.**

### Architektur-Entscheidung (2026-06-14) — Phase 9

Nach systematischer Analyse (24 Scans, pentest-ground.com-Auswertung) wurde erkannt:
**LLM-basiertes CVE-Keyword-Matching ist strukturell falsch und wird in Phase 9 ersetzt.**

Kern-Problem: NVD Keyword-Search (`nvd_cve_search`) gibt `pubDate:asc` zurück → älteste CVEs zuerst.
Bei 309 WebLogic-CVEs erscheinen die 5 neuesten nie im Top-5-Ergebnis.
CVE-2023-21839 (CVSS 7.5, aktiv ausgenutzt) wurde auf pentest-ground.com nicht gefunden.

**Umgesetzte Lösung (Phase 9 — 2026-06-14, Commit ff9beb3):**
- `tools/cpe_map.py` — deterministisches Banner→CPE-Mapping (50+ Einträge, kein LLM)
- `NvdCpeTool` (`nvd_cpe_lookup`) in `tools/nvd.py` — CPE-API statt Keyword-Search
- `cpe_search_nvd()`: paginiert zum Ende der pubDate:asc-Liste (Pool=100), sortiert CVSS desc
- Tool-Bereinigung: research 15→10, blue 11→8 (tote/nicht-installierte Tools raus)
- `_scope_coverage_guardrail` auf blue-Task: Kern-Tools-Garantie pro Scope
- findings-Task: nvd_cpe_lookup als Primär-Schritt, nvd_cve_search als Fallback

**Tool-Status (Stand 2026-06-14, nach Phase 9.1):**
- ✅ 18 Tools aktiv: nmap, httpx, whatweb, nikto, nuclei, sslscan, dig, whois, dnsrecon, subfinder, dnsx, katana, searchsploit, ddg_search, curl, ping, nvd_cve_search, **nvd_cpe_lookup** (neu)
- ❌ 3 nicht installiert (testssl.sh, enum4linux-ng, theHarvester) — Klassen bleiben, aus Agent-Listen entfernt
- 🗑 9 aus Tool-Listen entfernt: ffuf, gau, waybackurls, amass, assetfinder, sublist3r, naabu, testssl, enum4linux (Klassen bleiben für Reversibilität)

---

### Phase 8 — Verifikation (2026-06-16/17)

**Verifikationsziel:** pentest-ground.com (intentionell verwundbar, bekannte CVEs pro Service)

| Test | Status | Commit | Befund |
|---|---|---|---|
| V-1: `quick` Scan durchläuft, Scorecard auto | ✅ Bestätigt | — | Grade A, 5 Phasen, Scorecard sichtbar |
| V-2: `--score` zeigt neuesten Trace | ✅ Bestätigt | — | Korrekte mtime-Sortierung |
| V-3: `--plot` erzeugt 3 Dateien mit Timestamp | ✅ Bestätigt | `3a91884` | HTML/CSS/JS in logs/ mit `_<ts>`-Suffix |
| V-4: Ports 4280/5013/6379/7001 gefunden | ✅ Bestätigt | `a7ec771` | BUG-10 gefixt: `-p 1-65535` statt top-1000 |
| V-5: CVE-2022-0543 (Redis) im Final Report | ✅ Bestätigt | `c422e71`+`fc5b25a` | BUG-11+12b gefixt: Notable-Pinning + [:5]-Limit entfernt |
| V-6: CVE-2023-21839 (WebLogic) im Final Report | ✅ Bestätigt | `0327478`+`972fe5a`+`c4510e4` | Direkte NOTABLE_CVES-Injection aus blue-Output — 39 CVEs, 20 Critical, Grade A |

**Bugs gefixt in Phase 8 (2026-06-16/17):**

| Bug | Beschreibung | Fix | Commit |
|---|---|---|---|
| BUG-8 | `has_exploitable` immer True (nutzte `attack_surface_count` statt exploitable findings) | `flow.py` + `main.py`: `exploitable_findings_count > 0 OR red_cves non-empty` | `a7ec771` |
| BUG-9 | Scorecard 20/100 wenn Agent CVEs korrekt verwirft (kein Version-Match) | `quality.py`: neutral 50/100 statt Malus | `a7ec771` |
| BUG-10 | `full`/`network` scope: nmap top-1000 → Ports 4280/5013/6379 verpasst | `tasks.py`: `-p 1-65535` in full-scope-Prompt explizit | `a7ec771` |
| BUG-11 | `nvd_cpe_lookup` schnitt CVE-2023-21839 ab (Rang #34, max_results=10) | `nvd.py`+`cpe_map.py`: NOTABLE_CVES Pinning — bekannte CVEs garantiert im Output | `7e1cf26` |
| BUG-12 | findings-Prompt ließ nvd_cpe_lookup-CVEs raus (nur searchsploit als "Bestätigung") | `tasks.py`: REGEL erweitert — alle 3 NVD-Tools zählen als Bestätigung | `fc5b25a` |
| BUG-12b | `main.py`: `pd.cve_references[:5]` schnitt alle CVEs ab Position 6 ab | `main.py` Zeile 341: `[:5]` entfernt | `c422e71` |

**Bugfixes für V-6 (2026-06-17, commits `0327478` + `972fe5a` + `c4510e4`):**
- **Auto-Pin** (`0327478`): `_cve_trace_guardrail` pinnt NOTABLE_CVES deterministisch wenn sie im Tool-Output stehen aber nicht in `cve_references` — auch wenn `cve_references` leer ist.
- **NVD-Tool-Guarantee** (`972fe5a`): wenn blue-Phase CPE_MAP-bekannte Services erkannt hat (weblogic, redis, openssh) aber findings kein nvd_cpe_lookup/nvd_cve_search aufruft, wird beim ersten Guardrail-Fehler abgelehnt mit explizitem Feedback.
- **Direkte NOTABLE_CVES-Injection** (`c4510e4`): Guardrail erkennt bekannte Services im blue-Output (z.B. `"oracle weblogic admin httpd"`) und holt NOTABLE_CVES direkt per `lookup_cve()` aus NVD — unabhängig davon ob Agent-Input an nvd_cpe_lookup korrekt war. Auch: `banner_to_cpe()` robuster gegen LLM-mangled Input (Whitespace-Normalisierung, Token-Fallback, exakter nmap-Banner-Alias).
- **V-6 E2E-Bestätigt** (2026-06-17, network scan): CVE-2023-21839 (WebLogic CVSS 7.5, CISA KEV), 39 CVEs total, 20 Critical, Grade A 100/100.

**Offen:**
- Remote-Ollama-API Instabilität: HTTP 429 Session-Limit nach mehreren Scans, HTTP 500 bei full-Scope (großer Kontext findings-Phase).

### Teilschritte in Phasen

Wenn eine Phase in Teilschritte zerlegt wird, werden diese hier notiert.
Abgeschlossene Teilschritte werden sofort als erledigt markiert.

### Nach jeder Phase

Check ob der aktuelle Stand noch der Planung in `roadmap.md` entspricht.
Abweichungen werden begründet dokumentiert.

---

### Phase 5 — True Multi-Agent (Branch: phase/5-multi-agent)

| Schritt | Beschreibung | Status |
|---|---|---|
| 5.1 | `allow_delegation=True` auf research_agent + red_agent | Reverted — inkompatibel mit Sequential Process + lokalen Ollama-Modellen (Delegation-Tools triggern native FC auf Regular-Agents). Manager-Delegation (5.3) ist der korrekte Weg. |
| 5.2 | `_arun()` auf `NvdSearchTool` (async NVD-Lookup) | ✅ Erledigt |
| 5.3 | Hierarchical Process Option (`scope=hierarchical`) | ✅ Erledigt |
| 5.4 | `context=[]` Review auf `findings_task` + `red_scan_task` | ✅ Erledigt |

---

### Phase 6 — Knowledge Sources (Branch: phase/6-knowledge)

| Schritt | Beschreibung | Status |
|---|---|---|
| 6.1 | Service Normalization Knowledge (`agentscanit/knowledge/service_normalization.py`) | ✅ Erledigt |
| 6.2 | OWASP Top 10 Knowledge | ✅ Erledigt (aktiviert in Phase 7.2) |
| 6.3 | Knowledge auf Agents setzen (`research_agent`, `red_agent`) | ✅ Erledigt |
| 6.4 | `Crew(embedder=...)` für Ollama-Embedding + `KNOWLEDGE_DIR` in `config.py` | ✅ Erledigt |
| 6.5 | Task-Prompt in `findings_task` auf Knowledge Source umgestellt | ✅ Erledigt |

**Technische Anmerkung:** `KnowledgeStorage` darf nicht direkt auf `StringKnowledgeSource` gesetzt werden — `Knowledge.__init__` überschreibt `source.storage` immer mit einer neuen Instanz. Embedder muss über `Crew(embedder=...)` gesetzt werden, wird via `setup_agents()` → `agent.set_knowledge(crew_embedder=...)` korrekt weitergereicht.

---

### Phase 7 — Neue Teams (Branch: phase/7-new-teams)

| Schritt | Beschreibung | Status |
|---|---|---|
| 7.4a | `ScanState` erweitern + 3-Wege-Router + Stub-Kette in `flow.py` | ✅ Erledigt |
| 7.1 | Team 4: `threatintel_agent/` — OTX + Shodan + VT, graceful degradation | ✅ Erledigt |
| 7.2 | Team 5: `compliance_agent/` — OWASP-Mapping via LLM + Knowledge Source | ✅ Erledigt |
| 7.3 | Team 6: `risk_scorer/` — deterministisches Risk-Scoring, kein LLM | ✅ Erledigt |
| 7.4b | Master-Flow vollständig verdrahtet (Stubs durch echte Calls ersetzt) | ✅ Erledigt |
| — | Verifikationsscan | ✅ Erledigt (CLEAN-Route + or_()-Fix verifiziert) |

**Technische Anmerkungen:**
- `threatintel_agent/tools/` darf nicht via `sys.path.insert(0, _TEAM_DIR)` importiert werden — schattet `agentscanit/tools/` — stattdessen absolute Package-Imports: `from threatintel_agent.tools import ...`
- `compliance_agent` nutzt `Crew(embedder=ollama)` analog Team 1 — gleiches Pattern wie Phase 6
- Risk Scorer: `_has_in_the_wild` nutzt Keyword-Matching auf `threat_summary` — Keyword `"aktiv"` war zu breit (matched "aktiven"), ersetzt durch `"aktiv ausgenutzt"`
- `run_threat_intel` ist no-op auf `cva_analysis`-Route (`has_exploitable=False`) — Team 4 läuft nur bei `full_analysis`
- **`@listen` stacking ist broken** — `@listen(A)` + `@listen(B)` auf derselben Methode registriert nur den äußersten Trigger (A). Grund: jeder `@listen`-Aufruf erstellt einen neuen `ListenMethod`-Wrapper und setzt `__trigger_methods__` neu — der innere Wrapper wird überschrieben. Fix: `@listen(or_(A, B))` aus `crewai.flow.flow`. Gilt für alle Flow-Methoden mit mehr als einem Trigger.

---

## Was ist das?

Agentic Vulnerability Assessment Framework auf Basis von CrewAI + lokalen Ollama-Modellen.
Mehrere spezialisierte Agents arbeiten sequenziell: Passive Recon → Aktiver Scan → CVE-Analyse → Exploitability → Report.

---

## Projekt-Struktur

```
recon-suite/
├── agentscanit/          ← Haupt-Package (Team 1: Scanner)
│   ├── main.py           ← CLI-Einstiegspunkt + Retry-Logik + Prior-Scan-Erkennung (logs)
│   ├── crew.py           ← AgentScanITCrew, Planner, Pipeline-Logik
│   ├── agents.py         ← CrewAI Agent-Definitionen (5 Agents)
│   ├── tasks.py          ← Task-Definitionen + Pydantic Output-Schemas + CVE-Validator
│   ├── config.py         ← Env-basierte Konfiguration (Modelle, Pfade, API-Keys)
│   ├── tools/            ← Tool-Implementierungen
│   │   ├── _base.py      ← Subprocess-Helper + run_trace-Integration
│   │   ├── active_scanning.py   ← nmap, nikto, nuclei, sslscan, etc.
│   │   ├── passive_recon.py     ← subfinder, dnsrecon, whois, ddg, etc.
│   │   ├── nvd.py               ← NVD API v2 Client + NvdSearchTool (CrewAI BaseTool) — Single Source of Truth
│   │   └── trace.py             ← Tool-Call-Trace für JSON-Logs + get_all_raw_outputs()
│   ├── scan_summary.py   ← Hilfsskript für Report-Ausgabe
│   └── toolinfo.md       ← Detaillierte Tool-Dokumentation (26 Tools)
├── interpret_agent/      ← Team 2: NVD-Enrichment
│   ├── interpret_flow.py ← CrewAI Flow für CVE-Lookup + Interpretation
│   └── nvd.py            ← Thin shim → agentscanit.tools.nvd
├── reporting/            ← Team 3: Final Report
│   └── reporting_flow.py ← Merge scan-report + NVD data → final_report_*.md
├── threatintel_agent/    ← Team 4: Threat Intelligence (OTX + Shodan + VT)
│   ├── threatintel_flow.py ← OTX/Shodan/VT Lookup, graceful ohne API-Key
│   └── tools/            ← otx_tool.py, shodan_tool.py, virustotal_tool.py
├── compliance_agent/     ← Team 5: Compliance Mapping (OWASP)
│   └── compliance_flow.py ← OWASP Top 10 Mapping via LLM + Knowledge Source
├── risk_scorer/          ← Team 6: Asset Risk Scorer
│   └── risk_flow.py      ← Deterministisches Risk-Scoring, kein LLM
├── flow.py               ← Top-Level: orchestriert alle 6 Teams
├── main.py               ← Root-Wrapper (ruft flow.py auf)
├── logs/                 ← Scan-Outputs (gitignored)
└── requirements.txt      ← Python-Abhängigkeiten
```

---

## Agents & Pipeline

| Agent | Rolle | Tools |
|---|---|---|
| `research_agent` | Passive OSINT / Recon | 15 (subfinder, dnsrecon, dig, whois, ..., nvd_tool) |
| `blue_agent` | Active Scanning | 11 (nmap, nikto, nuclei, sslscan, ...; naabu ausgeklammert) |
| `research_agent` | CVE-Analyse (findings_task) | searchsploit, ddg, nvd_tool — max_iter=20 (erhöht von 12: 5-10 Services × 2-3 Calls = bis 30 Iterations) |
| `blue_agent` | Targeted Follow-up (red_scan_task) | nuclei, nikto |
| `red_agent` | Exploitability-Analyse | searchsploit, ddg, nvd_tool |
| `coding_agent` | Script-Generierung | keine Tools |
| `reporter_agent` | Report-Erstellung | keine Tools, max_iter=3 |

Pipeline-Reihenfolge: `research → blue → findings → red_scan → red → coding → report`

`_SCOPE_CEILING` bestimmt welche Tasks verfügbar sind. `Crew(planning=True)` optimiert wie diese Tasks ausgeführt werden (AgentPlanner).

---

## CVE-Validierungs-Architektur

CVE-IDs durchlaufen zwei Ebenen bevor sie in den Report eingehen:

**1. Pydantic-Validator auf `FindingsOutput` + `RedOutput` (`tasks.py`)**
- Format-Check only: `CVE-YYYY-NNNNN`, Jahr 1999–2030. Kein Trace/NVD hier.

**2. Task-Guardrail `_cve_trace_guardrail` auf `findings_task` + `red_task` (`tasks.py`)**
- **Trace-Kreuzvalidierung (primär):** ID muss im Raw-Output eines Tool-Calls dieser Session vorkommen.
- NVD-Fallback: wenn Trace inaktiv (Unit-Tests), NVD-Existenz-Check.
- Bei Failure: Agent bekommt explizites Feedback (`"Halluzinierte CVE-IDs: [...]"`) und kann die Task korrigiert wiederholen (`guardrail_max_retries=2`). Unterschied zum alten Pydantic-Validator: keine stille Verwerfung mehr — der Agent lernt warum IDs abgelehnt werden.

**3. `interpret_flow.py`**
- Liest ausschließlich strukturierte `cve_references`-Felder aus `findings`- und `red`-Task.
- Kein Regex-Fallback auf Preview-Text (war Halluzinations-Vektor via reporter_agent-Markdown).

**CVE-Suche-Reihenfolge in `findings_task`:**
1. Service-Normalisierung: `Apache-Coyote` → `Apache Tomcat`, `Jetty` → `Eclipse Jetty`
2. `searchsploit '<service> <version>'`
3. `nvd_cve_search '<service> <version>'` (Fallback / Ergänzung)
4. `nvd_cve_search '<service>'` (wenn keine Version bekannt)
5. DDG `'<CVE-ID> PoC'` zur Bestätigung

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
# Über den Top-Level-Flow (empfohlen — startet alle 3 Teams)
python3 main.py example.com
python3 main.py example.com web               # Scope als 2. Arg (ohne Objective)
python3 main.py example.com "CVE-Suche" web   # Objective + Scope
python3 main.py example.com "SSL/TLS prüfen" ssl
python3 main.py          # interaktiv

# Flow-Persistence (Phase 4b)
python3 main.py --list                        # gespeicherte Flow-Runs auflisten
python3 main.py --resume <flow-id>            # unterbrochenen Run fortsetzen

# Nur Team 1 (Scanner ohne NVD-Enrichment)
cd agentscanit && python3 main.py example.com
```

Outputs in `logs/`:
- `recon_report_<target>_<ts>.md` — Markdown-Report (Team 1)
- `crew_<target>_<ts>.json` — strukturierter JSON-Log
- `trace_<target>_<ts>.json` — Tool-Calls mit Raw-Output + Timings
- `interpret_<target>_<ts>.md` — NVD-Enrichment-Report (Team 2)
- `final_report_<target>_<ts>.md` — Merged Final Report (Team 3)
- `workflow_last.json` — letzter Run (überschrieben)
- `flow_state.db` — SQLite-DB mit persistierten Flow-States (alle Runs, `--list`/`--resume`)

---

## Konfiguration (config.py / .env)

| Variable | Bedeutung |
|---|---|
| `OLLAMA_BASE_URL` | Ollama API-URL (default: http://localhost:11434) |
| `OLLAMA_API_KEY` | API-Key für remote Ollama |
| `MODEL_ANALYSIS` | Modell für Analyse-Agents (default aus models.json) |
| `MODEL_RESEARCH` | Modell für Research-Agent |
| `MODEL_CODE` | Modell für Coding-Agent |
| `EMBED_MODEL` | Embedding-Modell für LanceDB Memory |
| `NVD_API_KEY` | NVD API-Key (optionaler Env-Var, erhöht Rate-Limit von 5 auf 50 req/30s) |

Modell-Auswahl via `models.json` (aus `models.json.example` ableiten).

---

## Bekannte Probleme / Offene Punkte

### ⚠️ Stiller Flow-Failure bei transientem 500er (BUG-6, 2026-06-14) — offen
Wenn der Remote-Ollama-Server während der Blue-Phase einen 500er zurückgibt, endet der Flow mit `exit 0`,
aber Blue/Findings/Red wurden nicht ausgeführt. Kein neuer Trace, kein neues `recon_report_*.md`.
**Root Cause:** `AgentExecutor.call_llm_native_tools()` wirft Exception die vom CrewAI-Flow-Layer
(`_execute_single_listener`) geloggt aber nicht nach außen propagiert wird → `run_scan()` in `flow.py`
sieht keinen Fehler → `_mark_step("run_scan")` wird aufgerufen → stiller Totalausfall.
Erkannt: futuremultiverse.com full (2026-06-14, erster Versuch) — Research 118s erfolgreich, dann Stop.
**Geplanter Fix:** `workflow_last.json`-Alters-Check in `run_scan()` (Phase 8.5 in `roadmap.md`).

### 📋 Scan-Qualitäts-Findings (westerstede.de full, 2026-06-11) — für später, nicht gefixt
Beobachtet bei einem sauberen `full`-Scan (4m13s, CLEAN, 20 Tool-Calls). Quelle: `trace_*.json`.
Verortet im Workflow-Schritt (Pipeline: research → blue → findings → red_scan → red → coding → report):

- **#1 — LLM verstümmelt das Target-Argument (research + blue):** gpt-oss übergibt vereinzelt
  kaputte Domain-/URL-Werte: `dnsrecon -d wenum?` (research), `theHarvester -d westernde?` (research),
  `whatweb https://://?` (blue). Betrifft jeweils das Target-Arg. dnsrecon wurde danach korrekt
  wiederholt (1 Call verschwendet); whatweb-Call nutzlos. Diagnose offen: systematisch vs. sporadisch.
- **#2 — theHarvester (research):** ✅ Gefixt (2026-06-14) — `shutil.which("theHarvester")` gibt
  `"[theHarvester] nicht installiert — Tool nicht verfügbar."` zurück statt zu crashen. theHarvester
  ist in der recon-suite nicht installiert; Tool graceful disabled.
- **#3 — findings-Phase dünn (findings):** nur 2 generische `nvd_cve_search Apache`/`Joomla` (ohne
  Version), **kein `searchsploit`** obwohl der Task-Prompt es als Schritt A fordert. Banner ohne
  Version → generische Suche → 0 CVEs. Teils CVE-Erkennungs-Limit, teils Agent nutzt searchsploit nicht.
- **#4 — Redundanz/Coverage:** `whatweb` 3× auf verwandte Hosts (blue+red_scan). „full" nutzte nur
  ~6/15 research-Tools + ~7/11 blue-Tools (amass, assetfinder, dnsx, katana, waybackurls, gau,
  sublist3r, ffuf, testssl, enum4linux ungenutzt — teils bewusst konditional).

Detail-Notiz + Priorisierung: `phase7.md` (Abschnitt „Scan-Qualitäts-Findings").

### 🛠️ Attack-Surface-Coverage Fix (2026-06-11) — Subdomains werden jetzt gescannt
Befund (futuremultiverse.com full): research fand 12 Subdomains (`auth`, `api.auth`, `backoffice`,
`cockpit`, `sandbox`, …), aber blue scannte NUR die Apex-Domain → Angriffsfläche komplett verfehlt,
„nichts gefunden" trotz vorhandener CVEs/Dienste. Umgesetzt:
- **Deterministischer Subdomain-Fanout** (`tasks.py:_subdomain_fanout_guardrail` auf research-Task):
  prüft entdeckte Subdomains via httpx auf Liveness (Code, kein LLM), hängt einen Block
  `=== VERIFIED LIVE HOSTS ===` an den research-Output → fließt via `context=[research]` in blue.
  Cap `_FANOUT_MAX_SUBS=40` gegen Fake-Subdomain-Fluten. Liest Subdomains aus Pydantic ODER Raw-Fallback.
- **blue-Prompt geschärft:** MUSS jeden VERIFIED-LIVE-HOST scannen (nicht nur Apex); nmap-Default-Portnamen
  (`EtherNetIP-1`/`snet-sensor-mgmt`) sind Rate-Namen, nicht Dienste (10000→Webmin, 2222→SSH prüfen).
- **blue `max_iter` 10→20** (mehr Hosts × Tools). **nmap `TIMEOUT_NMAP_SCAN` 180→600** + `--host-timeout 540s`
  (langsame `-sV` auf Webmin/odd-Ports lieferte vorher `[TOOL_ERROR]` ohne Daten).
- **Folge-Design (Backlog, vom User):** bei Domains mit vielen Fake-Subdomains ist „LLM wählt relevante →
  ggf. durch zusätzliche Einheit bestätigen → nur relevante scannen" der bessere Weg. Aktuell: httpx-Liveness
  aller (gecappten) Subdomains. Nach Test-Scans nachschärfen.
- Verifiziert (Unit): httpx-Liveness filtert korrekt live-only; Guardrail hängt Block an; verify_phase7 14/14.
  **E2E-Test (Subdomains tauchen in blue/red-Trace auf) steht aus — vom User.**

---

### ⭐ Phase-7-Verifikation (2026-06-10) — Pipeline-Crash gefixt + naabu ausgeklammert
Vollständiger Beweis-Trail: `debugging/DIAGNOSIS.md`. Kurzfassung für die nächste Session:

**ROOT CAUSE (gefixt): Checkpoint-Write korrumpiert die findings-Task.**
- Symptom war: Pipeline crasht nach blue in `findings` mit `Agent execution ended without reaching a final answer` (3× Retry → exit 1). KEIN Hang zwischen research/blue — das war eine Fehlannahme.
- Ursache (A/B-Test bewiesen): `CheckpointConfig` schreibt nach `task_completed` im **Hintergrund-Thread** (`event_bus.emit` submittet an ThreadPoolExecutor ohne zu warten). `RuntimeState._serialize` serialisiert die `self.root`-Entities (crew/agent/task) WÄHREND der Main-Thread sie in der findings-Phase mutiert → Pydantic-Rust-Serializer → PyO3-Panic „dict changed size during iteration" → Thread-Local-Korruption → nächster findings-LLM-Call schlägt fehl.
- Der ältere Fix (`EventRecord.model_dump` mit `r_locked()` in crew.py) schützt nur das `event_record`, **NICHT die Entities** → wirkt nicht. Patch ist aktiv, RWLock korrekt — verifiziert.
- **Fix (Phase 7, Stufe 1 — strukturell entfernt):** Intra-Crew-Checkpointing (`CheckpointConfig`) komplett entfernt — kein dokumentierter CrewAI-Resume-Mechanismus (Docs: Resume = Flow-`@persist`). Mitentfernt: die drei checkpoint-bezogenen Monkey-Patches (`JsonProvider.checkpoint`, `EventRecord.model_dump`-RWLock, `_do_checkpoint`-Wrapper) und der Checkpoint-Resume-Zweig in `main.py` (Retry = Vollneustart). Zwischen-Team-Resume bleibt über `@persist(SQLiteFlowPersistence)`. Verifiziert: quick-Pipeline läuft durch, keine Checkpoint-Dateien mehr.
- **Verifiziert E2E:** quick-Scope läuft research→blue→findings→report→reporting komplett durch, 0 Fehler-Marker.

**naabu ausgeklammert (agents.py).**
- `naabu_tool` ist aus der `blue_agent`-Tool-Liste entfernt (jetzt 11 statt 12 Tools). Grund: naabu macht `-p 1-65535` (Full-Port-Scan), läuft mehrere Minuten ohne Output → das vom User als „Hängen nach Research" wahrgenommene Verhalten. Port-Discovery läuft weiter über nmap.
- Auswirkung verifiziert: Active-Scanning-Phase von ~293s auf ~19s.
- Prompt-Erwähnungen in `tasks.py` (4 Stellen) + Docstring in `main.py` auf nmap/httpx umgestellt.
- **Reversibel:** `NaabuTool`-Klasse, Import, `NAABU_BIN` bleiben. Wieder einschalten = `naabu_tool` zurück in die `tools=[]`-Liste des blue_agent.

**Verworfene Hypothese (NICHT erneut verfolgen): „gpt-oss liefert leere Antworten".**
- Ein Retry-on-empty-Fix (`OpenAICompletion.call`-Patch) wurde gebaut, unit-getestet UND End-to-End widerlegt: das Retry feuerte nie, findings crashte trotzdem. Komplett zurückgenommen. Die leere Antwort ist real (kommt vereinzelt vor), aber NICHT der Crash-Pfad.

**Noch offen (nicht angefasst):**
- „Strg+C wirkt nicht" während langer Tool-Scans = Subprozess-/asyncio-Signalhandling. Prozess ist via `kill` beendbar. Separater Punkt.
- (ERLEDIGT in Phase 7, Stufe 1) Intra-Crew-Checkpoint entfernt statt repariert — Resume läuft über Flow-`@persist`.
- Gegentest auf Ziel mit vielen offenen Ports + echten CVEs steht aus (bisher CLEAN-Route verifiziert).

### allow_delegation=False (agents.py)
- Alle Agents haben `allow_delegation=False`. `allow_delegation=True` würde Delegation-Tools injizieren, was mit lokalen Ollama-Modellen nicht zuverlässig funktioniert (keine Garantie dass das Modell das Delegation-Schema korrekt ausführt).

### think: False (agents.py)
- `extra_body={"think": False}` wird bedingungslos gesetzt — lokales Ollama ignoriert es für nicht-thinking-Modelle, remote-Modelle (Qwen3, gpt-oss) benötigen es.

### `_tool_call_guardrail` No-Tool-Fallback (tasks.py / trace.py)
- Wenn ein Agent ein Ergebnis liefert ohne ein Tool aufzurufen → `_tool_call_guardrail` lehnt ab (korrekt). (Seit Phase 7, Stufe 3b nicht mehr durch LanceDB-Memory ausgelöst — Memory ist entfernt; tritt z. B. bei Modell-Halluzination auf.)
- Im Guardrail-Retry kann das Modell `None` oder leeren String zurückgeben → Crash oder ConverterError.
- **Fix**: `run_trace._guardrail_reject_count` — wird beim ersten Reject hochgezählt, beim zweiten Aufruf (count≥1) wird der Output akzeptiert (No-Tool-Fallback). Reset in `close_phase()`. Verhindert endlose Retry-Schleifen; CVE-Guardrail bleibt der entscheidende Fakten-Check.
- `_EXECUTOR_CLASS` ist einheitlich `AgentExecutor` (experimental, native FC) für alle Modi — kein OLLAMA_API_KEY-bedingtes Umschalten auf `CrewAgentExecutor` mehr.

### Retry-Logik (main.py) — kein Intra-Crew-Checkpointing mehr
- **Intra-Crew-Checkpointing (`CheckpointConfig`) ist seit Phase 7, Stufe 1 entfernt.** Grund: kein dokumentierter CrewAI-Resume-Mechanismus (Docs: Resume = Flow-`@persist`) + war race-behaftet (Entity-Serialisierung im Hintergrund-Thread vs. findings-Mutation) + Resume kaputt (`BaseKnowledgeSource`). Beweis: `debugging/DIAGNOSIS.md`.
- Retryable Errors (lösen Vollneustart aus, max 3): `json_invalid`, pydantic `ValidationError` (Klassen- UND String-Check), `ConverterError`, `Failed to convert`, `Agent must be provided`, `Field required`, `ended without reaching a final answer`, `Invalid response from LLM call`, `guardrail validation after`.
- Bei retrybarem Fehler: **Vollneustart** mit frischer Crew-Instanz (`scanner.crew(task_callback=...)`). Kein Phasen-Überspringen mehr.
- Zwischen-Team-Resume läuft weiterhin über `@persist(SQLiteFlowPersistence)` auf Flow-Ebene (`--list`/`--resume`).

### Memory-Subsystem entfernt (Phase 7, Stufe 3b)
- **Das LanceDB-Memory-Subsystem (`_crew_memory`, `_ShallowMemory`) + die drei Memory-Analyse-Monkey-Patches (`analyze_for_save/_consolidation/_query`) wurden entfernt.** Grund: Alle Crews laufen `memory=False` → CrewAI nutzt Memory während eines Scans gar nicht; es gab keinen `save()`-Pfad mehr; die Patches schützten nur einen toten Recall-Pfad.
- Prior-Scan-Erkennung läuft jetzt **logs-basiert** in `main.py` (existiert `recon_report_<target>_*.md`?) — kein Memory, kein LLM, kein Patch. Banner-Label: „History: prior scan on disk / first run".
- Verbleibender CrewAI-Patch: nur die Event-Bus-Console-Stille in `crew.py:_apply_crewai_patches()` (kosmetisch).

### Flow-Persistence (`@persist`, flow.py)
- `ReconSuiteFlow` trägt `@persist(SQLiteFlowPersistence(_FLOW_DB), verbose=False)` — nach jedem abgeschlossenen Flow-Schritt wird der State in `logs/flow_state.db` gespeichert.
- `ScanState.id` (uuid4) ist der `flow_uuid`-Key in der DB. Wird beim Flow-Start angezeigt und am Ende erneut gedruckt.
- `--resume <flow-id>`: erstellt neue `ReconSuiteFlow`-Instanz, ruft `flow.kickoff(restore_from_state_id=...)` — Flow lädt State aus DB.
- **Resume-Skip-Guards (Phase 7, Stufe 3 Vorstufe):** `@persist` hydratisiert bei Resume zwar den State, **führt die `@listen`-Methoden aber von vorn aus** — ohne Guard würde `run_scan` (der gesamte Team-1-Scan, ~Minuten) erneut laufen. Beweis: Resume eines abgeschlossenen Flows scannte komplett neu. **Fix:** `ScanState.completed_steps: list[str]` + `_step_done()`/`_mark_step()` in `flow.py`. Jede Team-Methode markiert sich bei Abschluss und überspringt sich bei Resume, wenn schon erledigt. Verifiziert: Resume eines fertigen quick-Runs → 5s statt ~60s, `run_scan`/`run_reporting` übersprungen, 0 Scan-Tools. Granularität = Flow-/Team-Ebene (run_scan ist atomar; Abbruch mitten im Scan → run_scan läuft neu; Abbruch zwischen Teams → erledigte Teams werden übersprungen).
- `--list`: liest `flow_states`-Tabelle direkt per `sqlite3` — zeigt letzten Snapshot pro `flow_uuid` sortiert nach Zeitstempel.
- **Limitation**: Nur Flow-/Team-Level-Persistence. Intra-Crew-Persistence (zwischen Tasks innerhalb von Team 1) gibt es nicht — `CheckpointConfig` wurde in Phase 7, Stufe 1 entfernt.

### CVE-Trefferquote bei Cloudflare/CDN-Targets
- Bremen.de etc. liefern keine CVEs weil Dienste hinter Cloudflare versteckt sind — kein Bug.

---

## Tool-Hinzufügen

1. Klasse in `tools/active_scanning.py` oder `tools/passive_recon.py` anlegen (Basisklasse: `BaseTool`)
2. Instanz in `tools/__init__.py` exportieren
3. In `agents.py` dem passenden Agent hinzufügen
4. In `toolinfo.md` dokumentieren

---

## Wichtige Patterns

- **`_run()` in tools/_base.py** — Subprocess-Helper mit Trace-Integration. Nicht `self._run()` (das ist CrewAI's BaseTool-Interface).
- **CVE-Validator** — `FindingsOutput.validate_cve_references` und `RedOutput.validate_cve_references` nutzen Trace-Kreuzvalidierung. Kein CVE ohne Tool-Bestätigung im Raw-Output.
- **`run_trace.get_all_raw_outputs()`** — gibt alle Tool-Raw-Outputs der laufenden Session zurück (closed phases + pending). Genutzt vom CVE-Validator während Pydantic-Parsing.
- **`interpret_agent/nvd.py`** — Thin Shim, re-exportiert aus `agentscanit.tools.nvd`. Nie direkt editieren.
- **Strict factual outputs** — Task-Prompts verlangen "nur tool-bestätigte Fakten". CVEs nur wenn Tool-Bestätigung im Trace vorhanden.
- **`Crew(planning=True, planning_llm=llm_planner)`** — AgentPlanner erstellt vor der ersten Task einen Ausführungsplan. `planning_llm` (`llm_planner`) läuft IMMER lokal (`localhost:11434`, z.B. `qwen2.5:7b-instruct`) — remote Modelle unterstützen Ollama's native function-calling API nicht zuverlässig. `_SCOPE_CEILING` bleibt der Gate-Keeper für welche Tasks überhaupt laufen. **`max_tokens=2000` auf `llm_planner`** — begrenzt Plan-Output auf ~2000 Tokens, damit combined input+output im 4096-Token-Kontext des lokalen Servers bleibt. Ohne diese Begrenzung kann `--context-shift` im Server eine endlose Generierung auslösen (>20 Minuten für 7-Phasen-Plan).
- **Memory** — entfernt (Phase 7, Stufe 3b). Crews laufen `memory=False`; Prior-Scan-Erkennung ist logs-basiert in `main.py`.
- **reporter_agent max_iter=3** — bewusst niedrig gehalten; der Reporter nutzt keine Tools und soll den Report in einem Durchgang schreiben. Höhere Werte führen zu 400s+ Laufzeiten bei großem Kontext.
- **Resume** — ausschließlich auf Flow-Ebene über `@persist(SQLiteFlowPersistence)` (`--list`/`--resume`). Intra-Crew-Checkpoint-Resume (`Crew.from_checkpoint()`) wurde in Phase 7, Stufe 1 entfernt.
- **Flow-Persistence** — `@persist(SQLiteFlowPersistence(_FLOW_DB))` als Klassen-Dekorator auf `ReconSuiteFlow` speichert nach jedem Schritt in `logs/flow_state.db`. `ScanState` braucht `id: str = Field(default_factory=lambda: str(uuid4()))`. Resume via `flow.kickoff(restore_from_state_id=state_id)` — lädt State aus DB und überspringt fertige Schritte. `_FLOW_DB` muss vor der Klassendefinition stehen (Dekorator evaluiert bei Import).
- **`@listen` Stacking — BROKEN** — `@listen(A)` + `@listen(B)` auf derselben Methode registriert NUR den äußersten Trigger. Jeder `@listen`-Aufruf erstellt einen neuen `ListenMethod`-Wrapper und setzt `__trigger_methods__` neu — die innere Registration wird überschrieben. Immer `@listen(or_(A, B))` verwenden wenn eine Methode auf mehrere Quellen hören soll. Import: `from crewai.flow.flow import or_`.
- **`_tool_call_guardrail` — Halluzinations-Blocker** — `research` und `blue` Tasks haben `guardrails=[_tool_call_guardrail]`. Prüft `run_trace._pending` bei Task-Abschluss: wenn leer (kein Subprocess aufgerufen), lehnt der Guardrail beim ERSTEN Auftreten ab (Agent bekommt Feedback). Beim ZWEITEN Auftreten (count≥1 in `run_trace._guardrail_reject_count`) wird der Output akzeptiert — No-Tool-Fallback um endlose Retry-Schleifen zu verhindern. `close_phase()` setzt den Counter zurück. Timing: Guardrail läuft VOR `task_callback`/`close_phase()` — `_pending` enthält exakt die Calls der aktuellen Task. Fallback-safe: wenn `run_trace.is_active == False` (Unit-Tests, Standalone), gibt der Guardrail immer `True` zurück.
