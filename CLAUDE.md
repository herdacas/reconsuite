# CLAUDE.md — AgentScanIT / Recon-Suite

## Arbeitsweise / Entwicklungsprozess

Wir arbeiten die Roadmap (`roadmap.md`) phasenweise ab. Im Ablauf wird entschieden:
- Schritte zu verschieben wenn sie ein höheres Risiko für die Hauptfunktionalität darstellen
- Arbeitsschritte zusammenzufassen wenn sie logisch zusammengehören
- Schritte vorübergehend zu überspringen um die Kernfunktion nicht zu beeinträchtigen

**WICHTIG — Keine pauschalen Antworten. Faktenbasierte Responses auf jede Frage.**

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
| 5.3 | Hierarchical Process Option (`scope=hierarchical`) | 🔄 In Arbeit |
| 5.4 | `context=[]` Review auf `findings_task` + `red_scan_task` | ✅ Erledigt |

---

## Was ist das?

Agentic Vulnerability Assessment Framework auf Basis von CrewAI + lokalen Ollama-Modellen.
Mehrere spezialisierte Agents arbeiten sequenziell: Passive Recon → Aktiver Scan → CVE-Analyse → Exploitability → Report.

---

## Projekt-Struktur

```
recon-suite/
├── agentscanit/          ← Haupt-Package (Team 1: Scanner)
│   ├── main.py           ← CLI-Einstiegspunkt + Memory-Patching + Retry-Logik
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
├── flow.py               ← Top-Level: orchestriert alle 3 Teams
├── main.py               ← Root-Wrapper (ruft flow.py auf)
├── logs/                 ← Scan-Outputs (gitignored)
└── requirements.txt      ← Python-Abhängigkeiten
```

---

## Agents & Pipeline

| Agent | Rolle | Tools |
|---|---|---|
| `research_agent` | Passive OSINT / Recon | 15 (subfinder, dnsrecon, dig, whois, ..., nvd_tool) |
| `blue_agent` | Active Scanning | 12 (nmap, nikto, nuclei, sslscan, ...) |
| `research_agent` | CVE-Analyse (findings_task) | searchsploit, ddg, nvd_tool |
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
- `checkpoints/<target>_<ts>/main/*.json` — Checkpoint-Files pro Task (max 3 kept)
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

### allow_delegation=False (agents.py)
- Alle Agents haben `allow_delegation=False`. `allow_delegation=True` würde Delegation-Tools injizieren, was mit lokalen Ollama-Modellen nicht zuverlässig funktioniert (keine Garantie dass das Modell das Delegation-Schema korrekt ausführt).

### think: False (agents.py)
- `extra_body={"think": False}` wird bedingungslos gesetzt — lokales Ollama ignoriert es für nicht-thinking-Modelle, remote-Modelle (Qwen3, gpt-oss) benötigen es.

### Checkpoint + Retry-Logik (main.py / crew.py)
- `Crew(checkpoint=CheckpointConfig(...))` speichert nach jeder abgeschlossenen Task einen Snapshot unter `logs/checkpoints/<target>_<ts>/main/*.json` (max 3 behalten).
- Bei `json_invalid`, `ValidationError`, `Field required` oder `ended without reaching a final answer`-Fehlern: bis zu 3 Retries.
  - Wenn ≥1 Phase abgeschlossen: Checkpoint-Resume via `Crew.from_checkpoint()` — überspringt bereits erledigte Phasen.
  - Callables (guardrails, task_callback) werden beim Checkpoint-Serialisieren gedroppt und nach dem Restore manuell re-attached.
  - Fallback bei fehlgeschlagenem Restore: Vollneustart mit frischer Crew-Instanz.
- **CrewAI-Checkpoint-Limitation**: Checkpoint-Writes schlagen silently fehl wenn die event_record-Serialisierung in eine PyO3 Race-Condition läuft (concurrent Dict-Mutation während der Serializer iteriert → `PanicException(BaseException)`). Der Panic wird von unserem Patch in `_apply_memory_patches()` abgefangen — Scan läuft weiter, Checkpoint wird für diese Task übersprungen. Phasen mit wenigen Tool-Calls (z.B. Report) schreiben trotzdem zuverlässig Checkpoints.

### Memory-Patching (crew.py)
- CrewAI's Memory-Analyse-LLM-Calls werden monkey-gepatcht (keine LLM-Calls bei save/recall).
- Grund: Pydantic-Validation-Errors + Rate-Limit-Probleme bei gleichzeitigen async-Requests.
- Patch sitzt in `crew.py:_apply_memory_patches()` — co-located mit der Memory-Konfiguration.
- Patch-Targets nach CrewAI-Update immer prüfen: `crewai.memory.analyze`, `encoding_flow`, `recall_flow`.

### Flow-Persistence (`@persist`, flow.py)
- `ReconSuiteFlow` trägt `@persist(SQLiteFlowPersistence(_FLOW_DB), verbose=False)` — nach jedem abgeschlossenen Flow-Schritt wird der State in `logs/flow_state.db` gespeichert.
- `ScanState.id` (uuid4) ist der `flow_uuid`-Key in der DB. Wird beim Flow-Start angezeigt und am Ende erneut gedruckt.
- `--resume <flow-id>`: erstellt neue `ReconSuiteFlow`-Instanz, ruft `flow.kickoff(restore_from_state_id=...)` — Flow lädt State aus DB und überspringt bereits abgeschlossene Schritte.
- `--list`: liest `flow_states`-Tabelle direkt per `sqlite3` — zeigt letzten Snapshot pro `flow_uuid` sortiert nach Zeitstempel.
- **Limitation**: Nur Flow-Level-Persistence (zwischen den drei Teams). Intra-Crew-Persistence (zwischen Tasks) läuft weiterhin über `CheckpointConfig` in `crew.py`.

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
- **`Crew(planning=True, planning_llm=llm_planner)`** — AgentPlanner erstellt vor der ersten Task einen Ausführungsplan. `planning_llm` (`llm_planner`) läuft IMMER lokal (`localhost:11434`, z.B. `qwen2.5:7b-instruct`) — remote Modelle unterstützen Ollama's native function-calling API nicht zuverlässig. `_SCOPE_CEILING` bleibt der Gate-Keeper für welche Tasks überhaupt laufen.
- **Memory** — LanceDB vector storage, shallow recall erzwungen (`_ShallowMemory`). Warme Runs nutzen Prior-Run-Daten.
- **reporter_agent max_iter=3** — bewusst niedrig gehalten; der Reporter nutzt keine Tools und soll den Report in einem Durchgang schreiben. Höhere Werte führen zu 400s+ Laufzeiten bei großem Kontext.
- **Checkpoint-Resume** — Nach `Crew.from_checkpoint()`: `_guardrails` (PrivateAttr) werden via `object.__setattr__()` re-attached, weil Pydantic validators bei direktem Field-Setzen nicht erneut laufen. `task_callback` wird sowohl auf Crew als auch auf jedem Task gesetzt.
- **Flow-Persistence** — `@persist(SQLiteFlowPersistence(_FLOW_DB))` als Klassen-Dekorator auf `ReconSuiteFlow` speichert nach jedem Schritt in `logs/flow_state.db`. `ScanState` braucht `id: str = Field(default_factory=lambda: str(uuid4()))`. Resume via `flow.kickoff(restore_from_state_id=state_id)` — lädt State aus DB und überspringt fertige Schritte. `_FLOW_DB` muss vor der Klassendefinition stehen (Dekorator evaluiert bei Import).
