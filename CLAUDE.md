# CLAUDE.md — AgentScanIT / Recon-Suite

## Arbeitsweise / Entwicklungsprozess

Wir arbeiten die Roadmap (`roadmap.md`) phasenweise ab. Im Ablauf wird entschieden:
- Schritte zu verschieben wenn sie ein höheres Risiko für die Hauptfunktionalität darstellen
- Arbeitsschritte zusammenzufassen wenn sie logisch zusammengehören
- Schritte vorübergehend zu überspringen um die Kernfunktion nicht zu beeinträchtigen

**WICHTIG — Keine pauschalen Antworten. Faktenbasierte Responses auf jede Frage.**

### Aktueller Stand (2026-06-25)
- **BUG-21 (2026-06-25) — findings-Guardrail-Lücke: 0 CVE-Tools → stilles falsches „keine Vulns"** (Lokal-Achsen-Befund): Lokaler Test (llama3-groq-tool-use:8b, web-Scope) zeigte: das schwache 8B-Modell schloss die findings-Phase mit validem JSON („No vulnerabilities found") ab, OHNE ein einziges CVE-Tool (searchsploit/nvd_*) aufzurufen — es urteilte direkt aus dem Banner. Der vorhandene `_cve_trace_guardrail` fängt das NICHT (prüft nur EINGETRAGENE CVEs gegen Trace; bei leerer `cve_references` nichts zu prüfen). **Wichtig: NICHT scope-spezifisch** — der findings-Task ist für web/network IDENTISCH (kein scope-Parameter in `make_tasks()`); Ursache ist 8B-Modell-Schwäche (mal 0 Tools, mal halluzinierte Fake-CVEs `CVE-2021-12345`). Fix: neuer `_cve_tool_used_guardrail` auf findings — erzwingt mind. 1 CVE-Recherche-Tool-Aufruf, sonst Reject (No-Tool-Fallback nach 1 Reject). Wirkung: schwaches Modell bricht jetzt EHRLICH ab statt still „keine Vulns" zu lügen (sicherer). Verifiziert: feuert NICHT bei gesunden Remote-findings (qwen3-coder nutzt Tools), red-Task unberührt. **Lokal-Achsen-Fazit: 8B läuft E2E durch (network ✅, 0 Leerantworten, ~37min), aber findings-CVE-Phase für 8B zu schwach (Tool-Calling unzuverlässig) — für verlässliche CVE-Analyse stärkeres lokales Modell nötig (qwen3-coder:30b Kandidat).**
- **BUG-20 (2026-06-25) — versionslose generische CVEs werden NICHT mehr gelistet** (User-Entscheidung, deterministisch): Befund bei zib.niedersachsen.de — Server sendet nur `Server: Apache` (gehärtet, `ServerTokens Prod`), trotzdem 16 CVEs / 14 Critical gelistet. Alle waren produkt-generische Keyword-Treffer ("alle Apache-Critical-CVEs 2017–2023") ohne Versions-Bezug → wertloses Rauschen. **WICHTIG: reine Prompt-Anweisung (tasks.py) reichte NICHT** — das LLM trug trotzdem 13 generische CVEs ein. Durchsetzungsstarker Fix ist DETERMINISTISCH im reporting: das vorhandene BUG-17-Gate (`_version_confirmed_in_scan`) **entfernt** jetzt versionslose CVEs (statt sie nur als UNBESTÄTIGT zu markieren). AUSNAHME: aktiv ausgenutzte (CISA-KEV-Heuristik: "exploited in the wild" in NVD-Desc) bleiben als expliziter Hinweis. Kopfzeile + Completion-Panel zählen nur noch gelistete CVEs. Verifiziert: zib 16→1 (nur KEV CVE-2021-41773), 14 ausgeblendet; Tomcat 8.5.19 (Version bekannt) behält CVE-2017-12615/12617 unverändert. Lehre: CVE-Kontrolle braucht Guardrail, nicht Prompt-Bitte.
- **Aktives Remote-Worker-Modell: `qwen3-coder:480b`** (ollama.com, Non-Reasoning, agentic Tool-Calling). Ersetzt `gpt-oss:120b` wegen Leerantworten bei tiefen FC-Ketten — siehe BUG-19. Planner läuft weiterhin lokal (qwen2.5:7b).
- **`full`-Scope läuft stabil durch** (alle 7 Phasen, 6 Teams, 0 Retries) — nach BUG-18 (Planner bei >5 Tasks aus) + BUG-19 (Modellwechsel). Verifiziert demo.testfire.net Grade A 99.8.
- **Diagnose-Werkzeug:** `RECON_LLM_DEBUG=1 python3 main.py …` schreibt `logs/llm_debug_<pid>.jsonl` (jeder LLM-Call: Agent, Prompt-Größe, Status, Leerantworten). Env-gated, null Overhead ohne die Var.
- Phasen 1–9 + Finale Abnahme abgeschlossen; offene Punkte siehe „Offen"-Block weiter unten.

### ➡️ AKTIVER ARBEITSPLAN — Testkonzept-Harness (Schritte 1–8 UMGESETZT, Stand 2026-06-23)

**ERGEBNIS-STAND (2026-06-23):** Harness vollständig gebaut + verifiziert (lokal committet `e11209e`).
Alle 6 Bausteine mit Positiv/Negativ-Kontrolle bestanden. Volle Matrix gelaufen (3 Container-Targets
× N=4 = 12 Scans, REMOTE qwen3-coder, Container-Lifecycle auto). Auswertung:

| Target | Dim 1 Input | Dim 2 Halluz | Dim 3 Recall | Port-Konsistenz |
|---|---|---|---|---|
| Tomcat 8.5.19 (TP) | ✅ 100% | ✅ 0 | ✅ **4/4 Recall 1.0** (CVE-2017-12615/12617) | ✅ 1.0 |
| WebLogic 12.2.1.3 (TP) | ✅ 100% | ✅ 0 | ✅ **3/4 Recall 1.0** (CVE-2023-21839) | ✅ 1.0 |
| nginx:alpine (TN) | ✅ 100% | ✅ 0 | ⚠️ echtes nuclei-CVE gefunden (s.u.) | ✅ 1.0 |

**Kern-Erkenntnisse:**
1. **Tool-Input + Output-Handling makellos** (deine 2 Kernpunkte): 100% saubere Tool-Inputs, 0 Halluzinationen über ALLE Läufe. qwen3-coder erfindet nichts, verstümmelt keine Targets.
2. **Ziel-CVE-Findung robust** → schließt qwen3-coder-Gründlichkeits-Vorbehalt POSITIV. Designierte CVEs zuverlässig gefunden (Tomcat 4/4, WebLogic 3/4).
3. **Konsistenz: Ports deterministisch (1.0), CVE-GESAMT-Menge stochastisch** (Jaccard 0.09–0.44). Grund: variierende Begleit-CVEs (großer CPE-Pool + NVD-Ranking-Schwankung), NICHT die Ziel-CVE. Ehrliche Erkenntnis: konsistent bei Kern-CVE, stochastisch bei Vollständigkeit.
4. **nginx war NICHT 100% clean:** nuclei fand `CVE-2026-42530` (echtes HTTP/3-UAF in nginx 1.31.2) — kein Framework-Fehler, reale tool-bestätigte Schwachstelle. TN-Annahme war zu optimistisch. Framework verarbeitete korrekt (mal verifiziert, mal UNBESTÄTIGT je nach NVD-Status).

**Offene Harness-Schwachpunkte (run_matrix, NICHT Framework — TODO nächste Session):**
- `run_matrix.py` sollte `exit≠0`-Läufe aus der Auswertung nehmen (sonst greift `_newest` einen alten Report → 2 verfälschte Dim3-Ergebnisse: Tomcat Lauf 4, nginx Lauf 4).
- CVE-Jaccard auf GESAMT-Menge ist zu streng als Pass-Kriterium. Besser: Jaccard auf **versions-verifizierte** CVEs ODER separater „Ziel-CVE-Konsistenz"-Wert (Recall über N Läufe).
- TN-Target: nginx:alpine hat ein echtes CVE → entweder akzeptieren (forbid_cves nutzen) oder älteres gehärtetes Image als echtes TN.

**Noch ausstehend:** scanme.nmap.org bewusst NICHT in Matrix (12-Scans/Tag-Limit) → separat mit kleinem N.
Lokal-Achse (llama3-groq) steht aus (User entfernt Key bei Bedarf). `dnsx`/`katana` weiterhin nicht provoziert.

**GIT-STAND (Entscheidung User, 2026-06-23): ALLES LOKAL — NICHTS GEPUSHT.**
- `origin/main` ist bei `b9d2edb` (letzter gepushter Stand: Modell-Anforderungen).
- Lokal voraus (NICHT pushen ohne neue Freigabe): `874873d` (Arbeitsplan), `9ff72b7` (Testkonzept),
  `e11209e` (Harness-Code), `560b6ce` (Matrix-Ergebnisse), + dieser Doku-Commit.
- Das gesamte `testing/`-Harness + Testkonzept bleibt vorerst lokal (User-Wunsch). CLAUDE.md-Doku
  ebenfalls lokal belassen, damit Harness + Doku zusammen bleiben (Commits bauen aufeinander auf).
- Nächste Session: hier weitermachen. Erst klären ob gepusht werden soll, sonst lokal weiterarbeiten.

**NÄCHSTE SESSION — konkrete nächste Schritte (Priorität):**
1. Harness-Schwachpunkte fixen (run_matrix exit≠0-Filter + Jaccard-Metrik auf versions-verifizierte CVEs/Ziel-CVE-Recall).
2. TN-Target sauber machen (nginx forbid_cves ODER anderes Image).
3. scanme.nmap.org separat (kleines N, Rate-Limit) + Lokal-Achse (llama3-groq, Key entfernen).
4. Optional: dnsx/katana mit Subdomain-reichem Target provozieren.

---

#### Ursprünglicher Plan (Referenz):

**Kontext:** Roadmap (Phasen 1–9 + Finale Abnahme) vollständig durch. Post-Roadmap-Phase: Aufbau des
Test-Harness zum Konzept [`testing/TESTKONZEPT.md`](testing/TESTKONZEPT.md) (4 Dimensionen, Remote/Lokal-Matrix,
methodisch fundiert BFCL/ReliabilityBench/Trajectory-Eval). Messbar aus `trace_*.json`
(`command`/`agent_params`/`raw_output`/`is_error`) + `RECON_LLM_DEBUG`-Logger. Wiederverwendbar:
`tools/trace.py::cve_in_raw_outputs`, `quality.py::score_scan`, `cpe_map.py`.

**Geklärte Designentscheidungen (User, 2026-06-18):**
1. models.json remote↔lokal: **bleibt manuell** — User entfernt Key bei Bedarf für Lokal-Test. (Harness zunächst Remote-only.)
2. CLEAN/TN-Target: **lokaler `nginx:alpine`-Container** (aktuell/gehärtet → 0 kritische CVEs erwartet, reproduzierbar). Live-Hosts taugen nicht (scanme „sauber"-Annahme war falsch: OpenSSH 6.6.1 verwundbar).
3. N-Wiederholungen: **4**
4. LLM-Judge für Dim-2-Versions-Treue: **jetzt** (Schritt 6)
5. VulHub-Container: **automatisch** starten/stoppen (snap-Docker braucht `/root`-Pfad!)

**Targets:** TP-1 VulHub Tomcat 8.5.19 (→CVE-2017-12615/12617) · TP-2 VulHub WebLogic 12.2.1.3
(→CVE-2023-21839, CVE-2018-2628) · TP-3 scanme.nmap.org (→CVE-2018-15473 u.a., ⚠️ max 12 Scans/Tag)
· CLEAN nginx:alpine-Container (→0 kritische CVEs).

**Arbeitsschritte (autonom, User bestätigt nur Endergebnis):**
| # | Schritt | Verifikation (Pos+Neg-Kontrolle) | Erwartung |
|---|---|---|---|
| 1 | `testing/targets.yaml` — Ground-Truth (Ports/Services/Soll-CVEs/TP-TN/Container-Cmds) | YAML lädt + Schema; Soll-CVEs gegen VulHub-README | 4 Targets sauber, jede Soll-CVE belegt |
| 2 | `eval_tool_input.py` (Dim 1) — Target-Integrität, Scope-Konformität, Flag-Plausibilität | echte qwen3-Traces (8com/scanme) → ≥0.95; künstl. `https://://?` → erkannt | sauber ~1.0, manipuliert <1.0 |
| 3 | `eval_tool_output.py` (Dim 2) — Halluzination (`cve_in_raw_outputs`) + Port-Auslassung | 8com-Trace 7/7 CVEs=0 Halluz; injizierte Fake-CVE → erkannt | echte Scans 0 Halluz |
| 4 | `eval_groundtruth.py` (Dim 3) — Recall/Precision-Proxy/TN gegen targets.yaml | Tomcat-Trace (alt) → Recall 1.0; CLEAN → 0 CVEs | TP Recall 1.0, TN 0 FP |
| 5 | `eval_consistency.py` (Dim 4, N=4) — cve_jaccard, port_consistency, grade_stddev | synth. 4 identische→1.0; 4 verschiedene→<1.0 | Ports 1.0, CVE-Jaccard ≥0.8 |
| 6 | LLM-Judge Versions-Treue (Dim 2, nutzt Remote-Modell) | gegen 5 BUG-17-Fälle (OpenSSH verif / Coyote spekulativ) | Judge ≥80% Konsens mit BUG-17-Gate |
| 7 | `run_matrix.py` — VulHub-Lifecycle auto + {Targets}×{N=4} + ruft eval_*.py | Smoke 1×1; Container start/stop sauber | E2E ohne manuelle Eingriffe, Matrix-Report |
| 8 | Ausgiebiger Test: volle Matrix 4 Targets × N=4 (=16 Scans) + Scope-Variation | Matrix-Report = Verifikation; schließt qwen3-CVE-Gründlichkeits-Vorbehalt | TP Recall 1.0, CLEAN 0 FP, Konsistenz ≥0.8, 0 Halluz |

**Verifikations-Philosophie:** Jedes `eval_*.py` mit Positiv- UND Negativ-Kontrolle (misst es wirklich, oder
immer „grün"?). Eval-Skripte sind **read-only** → keine Auswirkung auf Framework-Output. Nur `run_matrix.py`
löst echte Scans aus → dort zusätzlich Scorecard prüfen.

**Schließt nebenbei:** offenen Vorbehalt „qwen3-coder CVE-Gründlichkeit dünn" (N=4 gegen VulHub) +
`dnsx`/`katana` mit qwen3-coder erstmals provozieren.

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

**Tool-Status (Stand 2026-06-17, nach Phase 9 E2E-Verifikation):**
- ✅ 18 Tools aktiv: nmap, httpx, whatweb, nikto, nuclei, sslscan, dig, whois, dnsrecon, subfinder, dnsx, katana, searchsploit, ddg_search, curl, ping, nvd_cve_search, **nvd_cpe_lookup**
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

**Nachgelagerte Analyse (2026-06-17) — nach Phase-8-Abschluss:**

**CrewAI-Update:** 1.14.6 → 1.14.7 (keine Breaking Changes, alle Imports stabil).
Neu: `Agent.planning=True` (Agent-Level Reflection) — nicht aktiviert, da `think: False` via `extra_body` gesetzt ist.

**Bugs gefixt im Zuge der Framework-Konformitätsprüfung:**

| Bug | Beschreibung | Fix |
|---|---|---|
| `current_ids` NameError | `_cve_trace_guardrail`: `current_ids` in Direct-Injection-Loop (Zeile 185) undefiniert — im `try/except` still geschluckt → Direct-Injection nie aktiv | `current_ids` direkt nach `cves = list(...)` definiert (`tasks.py:147`) |
| `exploitable_findings_count` fehlt | `RedOutput` hatte kein `exploitable_findings_count`-Feld → `flow.py:157` las immer 0 → `has_exploitable` nur via `red_cves` gesetzt, nie via Exploitability-Count | `model_validator` in `RedOutput`: `count = len(exploitable_findings)` deterministisch; `flow.py` mit Fallback auf `len(exploitable_findings)` für alte JSONs |
| `planning=True` nicht aktiv | `llm_planner` in `agents.py` konfiguriert aber `planning=True`/`planning_llm=` fehlten in `crew_kwargs` → AgentPlanner wurde nie genutzt | `planning=True, planning_llm=llm_planner` in beiden `crew_kwargs`-Blöcken (sequential + hierarchical) |

**Interoperabilitäts-Status (2026-06-17):**
- Suite → externes Framework: ✅ `AgentScanITCrew.crew()` gibt echtes `crewai.Crew`-Objekt zurück — direkt in externe Flows einhängbar.
- Externes Team → Suite: ✅ Alle Team-Flows sind `Flow[State]`-Subklassen mit stabilen `run_*()`-Entry-Points — direkt als `@listen`-Methoden integrierbar.
- Einschränkung: Team 1 kommuniziert über `workflow_last.json` (Filesystem) statt State-Objekt — hemmt vollständige programmatische Integration von außen.

**Phase 9 — E2E-Verifikation (2026-06-17):**

| Test | Status | Befund |
|---|---|---|
| pentest-ground.com network | ✅ Bestätigt | CVE-2023-21839 (WebLogic CVSS 7.5) + CVE-2022-0543 (Redis CVSS 10.0) — 39 CVEs, Grade A 99.7/100 |
| futuremultiverse.com network (1. Scan) | ⚠️ Bug | CVE-2023-38408 (OpenSSH) fehlt — BUG-13 |
| futuremultiverse.com network (nach Fix) | ✅ Bestätigt | CVE-2023-38408 (OpenSSH CVSS 9.8) im Report — 33 CVEs, Grade A 93.4/100 |

**BUG-13 (2026-06-17):** OpenSSH fehlte in `NOTABLE_CVES` → kein deterministisches Pinning. `NvdCpeTool._run/_arun` hatte `max_results=5` als Hard-Default (statt 10 aus Schema) → CVE-2023-38408 (Rang 6) abgeschnitten.
Fix: `cpe_map.py` — `("openbsd","openssh"): ["CVE-2023-38408"]` + `nvd.py` — `_run/_arun` Default auf 10.
**Phase 9 vollständig abgeschlossen (2026-06-17).**

### Finale Abnahme (2026-06-17)

| Test | Status | Befund |
|---|---|---|
| `--plot` Flow-Visualisierung | ✅ Bestätigt | 3 Dateien (HTML/JS/CSS) mit Timestamp-Suffix, alte Plots bleiben erhalten |
| Web-Scan zero.webappsecurity.com (6 Teams) | ✅ Bestätigt | Alle 6 Teams liefen (interpret/threatintel/compliance/risk/reporting). Re-Scan 19:08 verifiziert BUG-14-Fixes E2E (6 bestätigte + 8 UNBESTÄTIGTE CVEs, Scorecard korrekt). `--list` zeigt persistierte Flows. |
| Resume-Test (Flow `85d064d9`, abgeschlossen) | ✅ Bestätigt | `--resume` überspringt alle 6 Team-Schritte via Skip-Guards (`↻ ... übersprungen (Resume — bereits abgeschlossen)`), 0 Scan-Tools, Exit 0 in Sekunden statt Minuten. `@persist`/`completed_steps` funktioniert. |
| Full-Scope futuremultiverse.com (7 Phasen) | ❌ Server-blockiert | Remote-Ollama (`ollama.com`) **reproduzierbar** HTTP 500 in Blue-Phase (2×: 14:xx + 19:25). Retry-Logik nutzte alle 5 Versuche (Research je ~300s + Backoff), dann sauberes `raise` (kein stiller BUG-6-Failure → Phase-8.5-Absicherung positiv verifiziert). `web`/`network`-Scope laufen durch, nur `full` (größerer Kontext, 7 Phasen) triggert die 500er. |

**BUG-14 (2026-06-17) — NVD-Ausfall wurde als bestätigte CVEs / Grade A gewertet (Commit `5ca67fa`):**
- Root Cause: `nvd_cpe_lookup`/`nvd_cve_search` → 503/timeout. findings nutzte `searchsploit "Apache Tomcat"` (ohne Version) → CVE-IDs aus dem `Codes`-Feld der Exploit-DB bestehen die Trace-Kreuzvalidierung, sind aber versionslos/spekulativ. Server-Banner war nur `Apache-Coyote/1.1` (keine Version).
- **14a** (`nvd.py`): zentraler `_nvd_get()`-Helper — Retry/Backoff bei 503/502/504/429 + Read-Timeout, Timeout 15/20→30s. Alle drei NVD-Funktionen nutzen ihn.
- **14b** (`reporting/reporting_flow.py`): NVD-Transient-Fehler werden als „⚠️ UNBESTÄTIGT — NVD nicht erreichbar" statt „Not found in NVD" dargestellt — explizit als spekulativ markiert.
- **14c** (`quality.py`): CVE-Qualität deckelt auf 40/100 wenn ALLE NVD-Lookups scheiterten. CPE-first-Bonus nur bei echten CVE-Daten. Verifiziert: alter zero-Trace 94.6 A → 82.6 B; gesunde Scans (pentest-ground/futuremultiverse) bleiben 100/A.
- **E2E-Re-Scan ✅ bestätigt** (2026-06-17 19:08, zero.webappsecurity.com web): NVD kam intermittierend durch (`nvd_cve_search Apache HTTP Server 2.2.6` → 7 echte versions-bezogene CVEs; 2/3 andere Calls 503/timeout). Ergebnis: Report listet **6 bestätigte CVEs mit echtem CVSS** + **8 explizit als „⚠️ UNBESTÄTIGT — NVD nicht erreichbar" markiert** (14b ✅). Scorecard NICHT gedeckelt (Grade A 91.4 berechtigt, da echte NVD-Treffer vorhanden → `len(failed)≠len(nvd_calls)`, 14c ✅). Timeouts in raw_output zeigen `read timeout=30` (14a ✅). Vorher (174609, NVD komplett tot): 0 bestätigte CVEs, 7 versionslose searchsploit-CVEs getarnt als Grade A 94.6.
- **Wichtig (historisch, gpt-oss):** `gpt-oss:120b` ist ein Reasoning-Modell — Health-Checks MÜSSEN `extra_body={"think": False}` + ausreichend `max_tokens` (≥50) setzen, sonst landet die Antwort im verworfenen thinking-Kanal und wirkt fälschlich „leer" (führte zu Fehldiagnose „Ollama tot"). Die Suite setzt beides korrekt. **Seit BUG-19 ist das aktive Worker-Modell `qwen3-coder:480b` (Non-Reasoning) — dieses Problem entfällt dort.**

**Finale Abnahme — Status:** `--plot` ✅, Web-Scan 6 Teams ✅, Resume-Test ✅, BUG-14 E2E ✅. **Einziger offener Punkt: Full-Scope-Run** — reproduzierbar durch Remote-Ollama HTTP 500 blockiert (server-seitig, nicht Code). Die 6-Teams-Funktionalität ist über den `web`-Scope vollständig verifiziert (alle Teams laufen, Dateien entstehen); `full` fügt nur red_scan + coding hinzu, die einzeln bereits in Phase 7 getestet wurden.

### Ground-Truth-Verifikation mit VulHub-Containern (2026-06-18)

Ziel: Wahrheitsgehalt prüfen mit Targets, deren CVEs **exakt vorab bekannt** sind. VulHub-Docker-Container (`/root/vulhub`, snap-Docker sieht `/opt` nicht → nach `/root` kopiert), lokal gescannt.

| Target | Erwartete CVE | Status | Befund |
|---|---|---|---|
| Tomcat 8.5.19 (`tomcat/CVE-2017-12615`, :8080) | CVE-2017-12615 | ✅ TP | CVE-2017-12615 **+** CVE-2017-12617 gefunden (beide korrekt für 8.5.19, CVSS 8.1). NVD-findings-Calls scheiterten (503), CVEs via searchsploit (Banner trug Version 8.5.19 → korrekte versionsspezifische Treffer), final via interpret NVD-bestätigt |
| WebLogic 12.2.1.3 (`weblogic/CVE-2023-21839`, :7001) | CVE-2023-21839 | ✅ TP | CVE-2023-21839 (CVSS 7.5, CISA KEV) via NOTABLE_CVES-Pin gefunden, **+** CVE-2018-2628 (T3 RCE 9.8), CVE-2023-22089, CVE-2025-21535 u.a. NVD-bestätigt. BUG-14b sichtbar: CVE-2020-14882/CVE-2019-2725 als „UNBESTÄTIGT" markiert (lookup_cve 503). Deckte BUG-16 auf |
| `testphp.vulnweb.com` (web) | OWASP (SQLi/XSS) | ⚠️ ungültig | Target war während des Scans **down** (HTTP 000, nikto: „No web server found"). Retry-Durchlauf ging in CLEAN-Route → 0 CVEs. Kein Framework-Fehler, Target nicht erreichbar. Ganze vulnweb.com-Familie down. |
| `demo.testfire.net` (web, Ersatz) | Apache/Tomcat-Stack | ⚠️ Grenzfall | Alle 6 Teams liefen (OWASP-Mapping ✅, Risk-Score 10.0 ✅, interpret 7/16 ✅) — Funktionsbandbreite bestätigt. ABER: Banner `Apache-Coyote/1.1` **version unknown** → 7 „NVD-bestätigte" CVEs sind versionslose Keyword-Treffer (potenzielle FALSE-POSITIVES), CVE-Qual 100/100 überzeichnet. **Strukturelle Grenze:** bei versionslosem Banner kann das Framework verwundbar/nicht-verwundbar nicht unterscheiden (vgl. BUG-14, dort NVD tot → 14c griff; hier NVD ok → 14c greift nicht). |
| `scanme.nmap.org` (network) | „sauber" (TN-Annahme) | ✅ TP | Annahme „sauber" war FALSCH: läuft **OpenSSH 6.6.1p1** + **Apache httpd 2.4.7** (Ubuntu, 2014). Version **präzise erkannt** → CVE-2018-15473 (User-Enum, <7.7), CVE-2016-10009/10010 (Privesc, <7.4) — alle KORREKT versionsspezifisch, NVD-bestätigt mit echtem CVSS. KEIN erfundenes CVE. Grade A 100 berechtigt. (Hinweis: nmap-only-Policy 12/Tag beachtet — 1 Scan) |

**Kern-Erkenntnis der Ground-Truth-Verifikation (2026-06-18):**
Das Framework ist **so gut wie der erkannte Banner**. Bei **präziser Version** (Tomcat 8.5.19, OpenSSH 6.6.1p1, WebLogic 12.2.1.3) findet es die **korrekten versionsspezifischen CVEs** — verifizierte True-Positives gegen vorab bekannte Ground Truth. Bei **versionslosem Banner** (`Apache-Coyote/1.1`) erzeugt der searchsploit/keyword-Fallback potenzielle False-Positives, die NVD zwar mit CVSS anreichern kann, deren Versions-Match aber unbestätigt bleibt. Das ist die fundamentale, nicht vollständig schließbare Grenze; BUG-14b (UNBESTÄTIGT-Markierung bei NVD-Ausfall) + 14c (Scorecard-Deckelung) + **BUG-17 (Banner-Versions-Gate)** mildern sie: versionslose CVEs werden im Report jetzt explizit als „⚠️ OHNE Versions-Bestätigung / potenzielle False-Positives" getrennt dargestellt, auch wenn NVD CVSS liefert. Vollständig lösbar wäre nur durch zuverlässige Versions-Erkennung im Banner (oft serverseitig unterdrückt).

**BUG-15 (2026-06-18) — Scorecard deckelte fälschlich bei final NVD-bestätigten CVEs (Commit `4ffa158`):**
- Befund beim Tomcat-Scan: findings-NVD tot (503) → BUG-14c deckelte CVE-Qualität auf 40/B, OBWOHL CVE-2017-12615/12617 final mit echtem CVSS 8.1 im Report standen (interpret-`lookup_cve` kam durch).
- Unterschied zu BUG-14: Tomcat-Banner trug **konkrete Version** (8.5.19) → searchsploit fand die KORREKTEN versionsspezifischen CVEs (kein versionsloser Müll wie bei zero/Apache-Coyote).
- Fix: `score_scan(trace_path, nvd_results=...)` — `_score_cve_quality` deckelt nur noch wenn die CVEs NIRGENDS NVD-bestätigt wurden (weder findings-Phase noch finales interpret-Enrichment). `flow.py` reicht `self.state.nvd_results` durch.
- Verifiziert: Tomcat 40→60/B; BUG-14-Fall (zero, versionslos) bleibt 40/B; gesunde Scans (pentest-ground) bleiben 100/A.

**BUG-16 (2026-06-18) — NOTABLE_CVES-Pinning hing von NVD-Erreichbarkeit ab (Commit `0c95e84`):**
- Befund beim WebLogic-Scan: 2/3 NOTABLE_CVES gepinnt, aber CVE-2020-14882 fiel raus — die Direct-Injection in `_cve_trace_guardrail` rief `lookup_cve()` und pinnte nur bei `"error" not in result`. Bei NVD-503 fällt eine hardcoded-bekannte NOTABLE-CVE raus.
- Fix (`tasks.py`): bei transientem NVD-Fehler (503/502/504/429/timeout/connection) wird trotzdem gepinnt (Enrichment markiert via BUG-14b als UNBESTÄTIGT). Nur eindeutiges „not found in NVD" verwirft die ID.
- Ziel-CVE CVE-2023-21839 wurde unabhängig davon gefunden (Kerntest bestanden); Fix härtet die zusätzlichen NOTABLE-Pins.

**BUG-17 (2026-06-18) — Banner-Versions-Gate gegen False-Positives (Commit `a22151a`):**
- Befund beim demo.testfire.net-Scan: Banner `Apache-Coyote/1.1` (version unknown), trotzdem 7 NVD-CVSS-CVEs (inkl. CVE-2025-24813 Tomcat RCE) als bestätigte Findings dargestellt. NVD-CVSS belegt nur dass die CVE EXISTIERT, nicht dass die laufende Version betroffen ist → potenzielle False-Positives.
- Fix (`reporting/reporting_flow.py`): `_version_confirmed_in_scan()` prüft pro CVE ob der Scan für das betroffene Produkt eine konkrete Version (`\d+\.\d+`) erkannt hat (Produkt-Keywords aus `affected_cpe` + Alias-Tabelle http_server→httpd). CVEs ohne Versions-Bestätigung → eigene Sektion „⚠️ CVEs OHNE Versions-Bestätigung" mit FP-Hinweis, getrennt von versions-verifizierten. Generische Tokens (server/http/…) als Solo-Keyword ausgeschlossen; `Apache-Coyote/1.1` wird NICHT als Tomcat-Version fehlgedeutet.
- Verifiziert 5/5 gegen reale Scans (OpenSSH 6.6.1p1 / httpd 2.4.7 / Tomcat 8.5.19 / WebLogic 12.2 → verifiziert; Apache-Coyote/1.1 → unbestätigt) + E2E-Render. Adressiert die zuvor als „nicht vollständig schließbar" dokumentierte Grenze: das schlimmste FP-Risiko (versionslos als confirmed getarnt) ist jetzt im Report sichtbar getrennt.

**BUG-18 (2026-06-18) — full-Scope-Abbruch: URSACHE WAR DER LOKALE PLANNER, NICHT Remote-Ollama (Commit folgt):**
- **Frühere Fehldiagnose korrigiert:** Der full-Scope-Abbruch wurde monatelang als „Remote-Ollama HTTP 500 in Blue-Phase / Kontextgröße" dokumentiert. Das war FALSCH. Bewiesen durch ein neues Roh-Request-Logging (`RECON_LLM_DEBUG=1`, Patch in `crew.py`, env-gated):
  - Der **CrewAI AgentPlanner**-Call (lokal, qwen2.5:7b) war der einzige problematische: **prompt_chars=129302 (~32k Tokens), dur=237s**. Alle anderen Calls 5k–20k chars, <20s.
  - Der Planner baut EINEN Prompt mit ALLEN Tasks + Tools + Backstories. Bei `full` (7 Tasks) = 32k Tokens. Planner-`num_ctx`=4096 → **8-facher Overflow** → lokaler Server generiert minutenlang und kippt intermittierend in „Invalid response from LLM call - None or empty". Die danach im Log sichtbaren `gpt-oss`-500er waren Folgefehler der Retry-Vollneustarts.
  - `web`/`network` (5 Tasks) bleiben unter der Schwelle → liefen IMMER durch. Genau das Muster.
  - Erklärt auch „anfangs ungewöhnlich langwierig" = die 237s Planner-Zeit ganz am Anfang.
- **Fix (`crew.py`):** AgentPlanner nur bei **≤5 Tasks** aktiv (`_use_planning = len(tasks) <= 5`). Bei `full` (7) deaktiviert. `_SCOPE_CEILING` legt die Pipeline ohnehin fest — Planner optimiert nur Ausführung, nicht Task-Auswahl → Verlust bei full gering. Verifiziert 6/6: full→planning=False, network/web/quick/ssl/osint→planning=True.
- **Echte Lösung (TODO, damit Planner auch bei full wieder läuft):** Planner-Prompt für große Scopes verkleinern (Task-Beschreibungen kürzen / Tools aus dem Plan-Prompt nehmen) ODER Planner-`num_ctx` an Prompt-Größe koppeln ODER lokales Planner-Modell mit größerem nativem Kontext (verfügbar: `qwen3-coder:30b`, `qwen2.5-coder:14b`). Diagnose-Werkzeug bleibt: `RECON_LLM_DEBUG=1` schreibt `logs/llm_debug_<pid>.jsonl`.

**BUG-19 (2026-06-18) — gpt-oss:120b Leerantworten bei tiefen FC-Ketten → Modellwechsel auf qwen3-coder:480b:**
- Nach dem BUG-18-Fix kam `full` viel weiter, brach aber weiter sporadisch ab. Debug-Log (`RECON_LLM_DEBUG`) zeigte: **9/135 Calls (6.7%) lieferten LEERE Antworten** (`status=ok, resp_chars=0`) — NICHT kontextabhängig (kleine Prompts ~8-13k chars, dur 0.8s = sofort leer), gehäuft bei **Blue (max_iter=20) + Attack Surface/red (max_iter=8)**. Diskriminator: leere Calls hatten Ø10.1 messages (tiefe Multi-Turn-FC-Ketten) vs. Ø6.4 bei Erfolg.
- Ursache: `gpt-oss:120b` ist ein **Reasoning-Modell** — bei tiefen Tool-Call-Konversationen landet die Antwort sporadisch im (verworfenen) thinking-Kanal → leerer `content`. `think:False`/`max_tokens` widerlegt als Ursache (isolierte Tests 0/N leer; Problem nur im echten Multi-Turn-Kontext). Retry-Vollneustarts würfeln nur neu, senken die 6.7%-Grundrate nicht → bei vielen Calls in `full` scheitern alle 5 Versuche statistisch.
- **Lösung:** Worker-LLMs (analysis/research/code) in `models.json` von `gpt-oss:120b` auf **`qwen3-coder:480b`** umgestellt — ein **Non-Reasoning** Instruct-Modell auf ollama.com (kein thinking-Kanal). Isoliert verifiziert (0/12 leer bei tiefen FC-Ketten), dann E2E: **full-Scan demo.testfire.net komplett durch, alle 7 Phasen, 0 Retries, 0 Leerantworten (0/35 Calls), Grade A 99.8** (vs. gpt-oss 93.8, Tool-Coverage 100 statt 75). Planner bleibt lokal/unberührt.
- **Hinweis:** Modellwechsel ändert auch Agent-Verhalten (Tool-Auswahl/JSON). Erste Beobachtung positiv (bessere Tool-Coverage). Bei breiterem Einsatz weitere Scans gegen Ground-Truth-Targets empfohlen.

### Modell-Anforderungen — was ein verwendbares LLM können MUSS (Stand 2026-06-18)

Empirisch belegt in dieser Session (gpt-oss / qwen3-coder / gemma4:e2b / div. lokale getestet).
Diese Sammlung ist Vorarbeit für später formal zu definierende **Mindestanforderungen**.

**Harte Voraussetzungen (sonst läuft das Framework GAR NICHT zuverlässig):**
1. **Natives Ollama Tool-Calling / Function-Calling.** Der `AgentExecutor` nutzt `call_llm_native_tools`.
   Modelle ohne sauberes FC liefern „Invalid response from LLM call - None or empty". Belegt:
   reine Chat-Modelle scheitern; Coder-/Tool-Use-trainierte Modelle bestehen.
2. **Stabilität bei TIEFEN Multi-Turn-FC-Ketten (≥10 messages).** Das ist der eigentliche Lackmustest,
   NICHT der Einzel-Call. Diskriminator aus `RECON_LLM_DEBUG`: leere Antworten traten bei Ø10.1 messages
   auf vs. Ø6.4 bei Erfolg. **Isolierte Einzel-Call-Tests sind NICHT aussagekräftig** — gemma4:e2b und
   gpt-oss bestehen Einzel-Calls (5/5), scheitern aber im echten Scan-Kontext. Immer im Multi-Turn testen
   (Test-Pattern: System-Prompt + 6 Tool-Call/Result-Paare + abschließender Turn → muss nicht-leer + korrekt
   Tool-Call/Content liefern).
3. **Non-Reasoning ODER `think:False`-konform.** Reasoning-Modelle (gpt-oss, Qwen3-thinking) verlieren bei
   tiefen FC-Ketten sporadisch die Antwort in den (verworfenen) thinking-Kanal → 6.7% Leerantworten (BUG-19).
   Non-Reasoning Instruct-/Coder-Modelle (qwen3-coder, qwen2.5-coder, llama3-groq-tool-use) haben diesen
   Kanal nicht → 0% Leerantworten gemessen. `extra_body={"think": False}` wird bedingungslos gesendet;
   ein Reasoning-Modell das das ignoriert, ist ungeeignet.

**Quantitative Soll-Werte (gemessen, nicht geraten):**
| Eigenschaft | Anforderung | Beleg |
|---|---|---|
| Leerantwort-Rate (Multi-Turn) | **0%** (Toleranz <1%) | qwen3-coder 0/35 full, 0/21 quick; gpt-oss 9/135 (6.7%) → untauglich |
| Kontextfenster Worker | ≥ 8k Tokens (Prompts real ~8–18k chars, also ~2–5k Tok; 16k remote / 8k lokal genügt) | größter gemessener Worker-Prompt 31.648 chars |
| Kontextfenster Planner | ⚠️ Sonderfall: bräuchte ~32k bei full (7 Tasks); deshalb bei >5 Tasks AUS (BUG-18) statt großes Planner-Modell zu fordern | Planner-Prompt 129.302 chars |
| Tool-Input-Sauberkeit | keine verstümmelten Targets (`?`, `://://`) | qwen3-coder: 31/31 Calls sauber (8com.de-Scan); gpt-oss: vereinzelt verstümmelt |

**Modell-Rollen + getestete Tauglichkeit:**
- **Remote-Worker (analysis/research/code):** `qwen3-coder:480b` ✅ (aktiv). gpt-oss:120b ❌ (BUG-19).
- **Lokal-Worker:** `llama3-groq-tool-use:8b` ✅ / `qwen2.5:7b-instruct` ✅ / `qwen3-coder:30b` ✅
  (alle 0 Leer, 5/5 Tool-Call im Multi-Turn-Test). `gemma4:e2b` ❌ (Gemma-Familie: schwaches agentic FC,
  scheitert im echten Scan trotz bestandener Einzel-Calls). End-to-End-Lokalscan steht noch aus.
- **Planner (immer lokal):** `qwen2.5:7b-instruct` ✅ (natives Ollama-FC; remote Modelle taugen NICHT als
  Planner — die native FC-API wird remote nicht zuverlässig unterstützt).

**Diagnose-Werkzeug für Modell-Eval:** `RECON_LLM_DEBUG=1` → `logs/llm_debug_<pid>.jsonl` (pro Call:
agent, n_messages, prompt_chars, status, resp_chars, dur_s). `resp_chars=0` bei `status=ok` = Leerantwort.
Das ist die Metrik zur Modell-Bewertung. Gehört methodisch zur **Lokal-Achse des Testkonzepts**
([`testing/TESTKONZEPT.md`](testing/TESTKONZEPT.md), Dim 1+4).

**Offen:**
- **full-Scope mit Planner** (BUG-18 echte Lösung) — siehe oben. Mit dem Gate läuft full ohne Planner stabil; die Planner-Optimierung für full ist temporär deaktiviert.
- NVD-API Instabilität (2026-06-17): intermittierend HTTP 503 + Read-Timeout selbst mit 3×30s-Retry. BUG-14 macht den Ausfall im Report+Scorecard sichtbar statt ihn zu verschleiern.
- Ground-Truth-Befund demo.testfire.net (2026-06-18): AltoroMutual ist eine **Web-App-Vuln-Demo** (SQLi/XSS auf App-Ebene). Die Suite ist ein Infrastruktur-/CVE-Scanner — sie fand korrekt Security-Header-Mängel + Tomcat-Komponente (OWASP A05/A06), aber NICHT die SQLi/XSS (außerhalb des Scopes, kein DAST). **Wichtig: nichts erfunden.** Bestätigt: Suite stark bei versions-CVE-Matching, nicht für Web-App-Discovery gebaut.

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

`_SCOPE_CEILING` bestimmt welche Tasks verfügbar sind. `Crew(planning=…)` optimiert wie diese Tasks ausgeführt werden (AgentPlanner) — **aktiv nur bei ≤5 Tasks** (BUG-18: der Planner-Prompt bei 7 Tasks/`full` ist ~32k Tokens und sprengt das lokale Planner-`num_ctx`=4096 → full läuft ohne Planner).

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

**Verworfene Hypothese (Phase 7, NICHT erneut verfolgen FÜR DEN FINDINGS-CRASH): „gpt-oss liefert leere Antworten".**
- Ein Retry-on-empty-Fix (`OpenAICompletion.call`-Patch) wurde gebaut, unit-getestet UND End-to-End widerlegt: das Retry feuerte nie, findings crashte trotzdem. Komplett zurückgenommen. Die leere Antwort ist real (kommt vereinzelt vor), aber NICHT der damalige findings-Crash-Pfad.
- **UPDATE 2026-06-18 (BUG-19):** Die leeren Antworten SIND später als realer Abbruch-Pfad für den `full`-Scope identifiziert worden (6.7% bei tiefen FC-Ketten, gehäuft Blue/red) — gelöst durch Modellwechsel auf das Non-Reasoning-Modell `qwen3-coder:480b`, NICHT durch Retry-on-empty (die damalige Verwerfung des Retry-Ansatzes bleibt korrekt — neu würfeln senkt die Grundrate nicht). Siehe BUG-19 oben.

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
- **`Crew(planning=_use_planning, planning_llm=llm_planner)`** — AgentPlanner erstellt vor der ersten Task einen Ausführungsplan. `planning_llm` (`llm_planner`) läuft IMMER lokal (`localhost:11434`, z.B. `qwen2.5:7b-instruct`) — remote Modelle unterstützen Ollama's native function-calling API nicht zuverlässig. `_SCOPE_CEILING` bleibt der Gate-Keeper für welche Tasks überhaupt laufen. **`max_tokens=2000` auf `llm_planner`** — begrenzt Plan-Output auf ~2000 Tokens. **BUG-18-Gate: `_use_planning = len(tasks) <= 5`** — der Plan-Prompt skaliert mit der Task-Zahl (alle Task-Beschreibungen + Tools im einen Prompt); bei 7 Tasks (`full`) ~32k Tokens, was das lokale `num_ctx`=4096 um das 8-fache überläuft → minutenlange Generierung + intermittierende Leerantworten (bewiesen via `RECON_LLM_DEBUG`). Deshalb Planner bei `full` aus. Frühere Annahme „`--context-shift` / >20min" war das Symptom desselben Overflows.
- **Memory** — entfernt (Phase 7, Stufe 3b). Crews laufen `memory=False`; Prior-Scan-Erkennung ist logs-basiert in `main.py`.
- **reporter_agent max_iter=3** — bewusst niedrig gehalten; der Reporter nutzt keine Tools und soll den Report in einem Durchgang schreiben. Höhere Werte führen zu 400s+ Laufzeiten bei großem Kontext.
- **Resume** — ausschließlich auf Flow-Ebene über `@persist(SQLiteFlowPersistence)` (`--list`/`--resume`). Intra-Crew-Checkpoint-Resume (`Crew.from_checkpoint()`) wurde in Phase 7, Stufe 1 entfernt.
- **Flow-Persistence** — `@persist(SQLiteFlowPersistence(_FLOW_DB))` als Klassen-Dekorator auf `ReconSuiteFlow` speichert nach jedem Schritt in `logs/flow_state.db`. `ScanState` braucht `id: str = Field(default_factory=lambda: str(uuid4()))`. Resume via `flow.kickoff(restore_from_state_id=state_id)` — lädt State aus DB und überspringt fertige Schritte. `_FLOW_DB` muss vor der Klassendefinition stehen (Dekorator evaluiert bei Import).
- **`@listen` Stacking — BROKEN** — `@listen(A)` + `@listen(B)` auf derselben Methode registriert NUR den äußersten Trigger. Jeder `@listen`-Aufruf erstellt einen neuen `ListenMethod`-Wrapper und setzt `__trigger_methods__` neu — die innere Registration wird überschrieben. Immer `@listen(or_(A, B))` verwenden wenn eine Methode auf mehrere Quellen hören soll. Import: `from crewai.flow.flow import or_`.
- **`_tool_call_guardrail` — Halluzinations-Blocker** — `research` und `blue` Tasks haben `guardrails=[_tool_call_guardrail]`. Prüft `run_trace._pending` bei Task-Abschluss: wenn leer (kein Subprocess aufgerufen), lehnt der Guardrail beim ERSTEN Auftreten ab (Agent bekommt Feedback). Beim ZWEITEN Auftreten (count≥1 in `run_trace._guardrail_reject_count`) wird der Output akzeptiert — No-Tool-Fallback um endlose Retry-Schleifen zu verhindern. `close_phase()` setzt den Counter zurück. Timing: Guardrail läuft VOR `task_callback`/`close_phase()` — `_pending` enthält exakt die Calls der aktuellen Task. Fallback-safe: wenn `run_trace.is_active == False` (Unit-Tests, Standalone), gibt der Guardrail immer `True` zurück.
