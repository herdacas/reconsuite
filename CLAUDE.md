# CLAUDE.md — AgentScanIT / Recon-Suite

## Arbeitsweise / Entwicklungsprozess

Wir arbeiten die Roadmap (`roadmap.md`) phasenweise ab. Im Ablauf wird entschieden:
- Schritte zu verschieben wenn sie ein höheres Risiko für die Hauptfunktionalität darstellen
- Arbeitsschritte zusammenzufassen wenn sie logisch zusammengehören
- Schritte vorübergehend zu überspringen um die Kernfunktion nicht zu beeinträchtigen

**WICHTIG — Keine pauschalen Antworten. Faktenbasierte Responses auf jede Frage.**

### Aktueller Stand (2026-09-12, Abarbeitung offener Punkte — 7 Fixes, alle committet)

Systematisches Abarbeiten der zu diesem Zeitpunkt bekannten offenen Punkte, jeweils Fix → Verifikation → Commit. Alle unten genannten Commit-Hashes sind auf `main`, nichts gepusht.

1. **`is_kev()`-Negation** (`b0c9d8c`): satzweise Prüfung statt Substring-Match, siehe Fix-Historie unten.
2. **Strg+C-Fix** (`235c871`): `subprocess.Popen`-Registry + SIGINT-Handler, siehe „Bekannte Probleme" unten.
3. **BUG-18 echte Lösung** (`2669866`): Planner-`num_ctx` auf native Modellgrenze (32768) statt `≤5`-Tasks-Gate, live verifiziert bei `full`.
4. **BUG-25-Nachtrag: sslscan-Eigenbanner** (`34e9607`): live bestätigt, dass der reine Prompt-Fix unzureichend war — jetzt deterministisch in `_value_grounding_guardrail` gefixt.
5. **Confirmed-Findings-Zeile mit leerer Tool-Spalte** (`efd6a27`): live gefunden bei `www.cloudflare.com` (WAF-Behauptung ohne jede Tool-Angabe) — `_confirmed_findings_tool_guardrail` erkennt das jetzt.
6. **`run_matrix.py` Fehlerausgabe** (`7413166`): Harness gab bei Scan-Fehlschlag bisher keine Fehlermeldung aus — jetzt stdout/stderr-Tail.
7. **Neuer `_tools_executed_guardrail`** (`c8431fb`): live gefunden bei `www.cloudflare.com` — `BlueOutput.tools_executed` nannte `wafw00f`, das nie lief. Gleiche Fabrikationsklasse wie BUG-23/25, jetzt auch im strukturierten Pydantic-Feld (nicht nur im Markdown-Report) gefixt.

Details zu jedem Punkt (Root Cause, Verifikation) stehen in den jeweiligen Sektionen weiter unten bzw. in den Commit-Messages. Nebenbei erledigt: Testing-Harness-Matrix komplettiert (`nginx-clean-baseline` + `waf-cloudflare`, siehe Voll-Matrix-Abschnitt unten), „Gesamt-E2E-Beweis Pentest-Scope" bestätigt.

**Neu gefundener, NICHT gefixter Backlog-Punkt** (eigene Design-Runde nötig): sslscan-Banner-Kontamination erreicht auch Team 5/6 (compliance/risk_scorer) — Details direkt darunter.

### Neuer Backlog-Punkt (2026-09-12, gefunden bei der BUG-25-Nachtrag-Verifikation, NICHT gefixt)

- **sslscan-Banner-Kontamination erreicht auch Team 5/6 (compliance/risk_scorer), nicht nur den Reporter-Task.** Der `_strip_sslscan_self_banner()`-Fix (siehe BUG-25-Nachtrag oben) schützt nur die "Confirmed Findings"/"Detected Technologies"-Sektionen des `report`-Tasks. Im selben `example.com full`-Lauf, der diesen Fix auslöste, übernahm `compliance_example.com_20260912_040914.md` (Team 5) "OpenSSL 3.0.13" ebenfalls unter "A03:2025 – Software Supply Chain Failures" mit Bezug auf `CVE-2011-1468` — die Kontamination sitzt bereits eine Stufe früher (blue/findings-Phase selbst schreibt die Fehlinterpretation in ihren strukturierten Output, den Team 5/6 direkt konsumieren, nicht erst der finale Markdown-Report). Root Cause identisch zu BUG-25: reine Prompt-Anweisung im blue-Task (kein Guardrail) reicht nicht.
  - **Nicht gefixt, bewusst zurückgestellt** — würde einen Guardrail auf dem `blue`/`findings`-Task selbst erfordern (analog `_value_grounding_guardrail`, aber auf Pydantic-Feldern statt Markdown-Text), plus Prüfung ob das bestehende BUG-17-Versions-Gate (`cve_filters.version_confirmed_in_scan`) ebenfalls auf den kontaminierten `scan_body`-Text anspricht (wahrscheinlich ja, da "OpenSSL" + "3.0.13" dort literal nebeneinander stehen). Eigene Design-Runde nötig, nicht spontan mitgefixt.

### Aktueller Stand (2026-09-12, Fortsetzung — BUG-26: drei Scan-Crashes nach BUG-25-Verifikation)

- **BUG-26 (2026-09-12, UMGESETZT, Unit-verifiziert, E2E-Verifikation läuft) — Required-Field-Crashes + BUG-24-Rezidiv, gefunden bei 3 manuellen Scans in Folge (example.com full [Crash], oldenburg.de [durchgelaufen trotz Fehlern], westerstede.de full [Crash]):**
  - **Befund 1 — `BlueOutput.analysis`/`FindingsOutput.risk_summary` fehlten im Modell-Output → harter Crash:** Beim `example.com full`-Lauf (BUG-25-E2E-Versuch) schlug die Pipeline zweimal an genau diesem Muster fehl: `FindingsOutput.risk_summary` fehlte (1. Vollneustart), dann — nach Ausschöpfen des LLM-Fehler-Retry-Budgets (5 Versuche) — `BlueOutput.analysis` fehlte am LETZTEN erlaubten Versuch → `main.py` klassifiziert "Field required" als STRUKTURELL (nur 3 Vollneustarts statt 5 bei reinen LLM-Fehlern), das Budget war an dieser Stelle bereits erschöpft → Flow crashte komplett (`Flow Execution Failed`, uncaught `ValidationError`).
  - **Root Cause:** `analysis`/`risk_summary` waren jeweils das EINZIGE bare-required `str`-Feld (kein Default) in `BlueOutput`, `FindingsOutput`, `RedScanOutput` — jedes andere Feld hat bereits `default_factory`. `nemotron-3-nano:30b` lässt dieses eine Freitext-Feld unter Last (langer Kontext, viele Tool-Calls) gelegentlich weg → Pydantic wirft einen harten `ValidationError` für ein Feld, das nachgelagert (interpret/risk_scorer/reporting) **nirgends strukturell konsumiert wird** (die nutzen `cve_references`/`vulnerabilities`/`confirmed_attack_surface` etc., nie `analysis`/`risk_summary` direkt) — ein reines Anzeige-Feld crasht den ganzen 10-Minuten-Scan.
  - **Fix 1 (`tasks.py`):** `analysis`/`risk_summary` (in `BlueOutput`, `FindingsOutput`, `RedScanOutput`) sowie `target_type`/`summary` (in `ResearchOutput`, gleiches Muster, per Grep verifiziert nirgends im Code referenziert) bekommen `= ""` als Default statt bare `str`. Prompts fordern die Felder weiterhin an — die Änderung wirkt nur, wenn das Modell sich fehlverhält, kein Verhaltensunterschied im Normalfall.
  - **Befund 2 — BUG-24 (max_tokens-Truncation) rezidivierte, mit neuer Präzisions-Diagnose:** Beim `westerstede.de full`-Lauf (User-getriggert, unabhängig von BUG-25) schlug `ReportOutput` erneut fehl — diesmal mit einer EXPLIZITEN LiteLLM-Fehlermeldung statt nur "EOF while parsing": `"Could not parse response content as the length limit was reached - CompletionUsage(completion_tokens=8000, prompt_tokens=3540, total_tokens=11540, ...)"`. Das ist der Beweis: `completion_tokens` traf EXAKT den konfigurierten `max_tokens=8000`-Deckel (BUG-24-Fix von 2026-09-11), während `total_tokens=11540` weit unter `num_ctx=16384` blieb — reines `max_tokens`-Limit, KEIN Context-Overflow. Der BUG-24-Fix (8000) reicht für detailreiche `full`-Scope-Reports nicht.
  - **Root Cause 2:** `reporter_agent` teilte sich `llm_analysis` (und damit dessen `max_tokens=8000`) mit `blue_agent`/`red_agent` — deren finale Turns sind aber strukturell viel kürzer (Tool-Calls + kompakte Listen) als ein vollständiger Markdown-Report als Single-Shot-JSON-Feld.
  - **Fix 2 (`agents.py`):** `_llm()` bekommt einen optionalen `max_tokens`-Parameter. Neue dedizierte Instanz `llm_reporter = _llm(ACTIVE_ANALYSIS, TEMP_ANALYSIS, max_tokens=12000 remote / 6000 lokal)`, NUR an `reporter_agent` gehängt (`llm=`/`function_calling_llm=`) — `blue_agent`/`red_agent` bleiben unverändert bei `llm_analysis`/8000, bewusst NICHT global erhöht (deren Bedarf ist ungeprüft anders, eine unbegründete globale Änderung hätte unnötiges Risiko für Kontext-Überlauf bei langen Multi-Turn-Konversationen). 12000 + der beobachtete Prompt (3540) = 15540, sicher unter `num_ctx=16384`.
  - **Wichtig — Klarstellung zur User-Beobachtung "3 Scans in Folge, kein Scan läuft mehr normal":** Der `oldenburg.de`-Lauf zwischen den beiden Crashes lief tatsächlich VOLLSTÄNDIG durch (`✓ Report`, `Assessment Complete`, Team 2+3 liefen) — die dort sichtbaren Fehler (leere LLM-Antworten, `ReportOutput`-JSON-Fehler) wurden von der BESTEHENDEN Retry-Infrastruktur aufgefangen, ohne Crash. Das "hing" wirkende Ende dieses Laufs war das (bereits vor dieser Session existierende, uncommittete) Phase-9-Safety-Gate (`scope_gate.py`), das bei `has_exploitable=True` eine TTY-Bestätigung erwartet — kein Hang, keine Regression. Weder `_value_grounding_guardrail` (BUG-25) noch die `blue`-Prompt-Ergänzung (sslscan-Banner-Hinweis) sind ursächlich für BUG-26 — beide Crash-Root-Causes liegen strukturell an anderer Stelle (Pydantic-Schema-Fragilität bzw. ein bereits vor BUG-25 bestehendes `max_tokens`-Limit).
  - **Verifiziert (2026-09-12):**
    1. `py_compile` sauber auf `tasks.py` + `agents.py`.
    2. Reale Fehlerpayloads (exakt die beobachteten JSON-Shapes ohne `analysis`/`risk_summary`) gegen `BlueOutput`/`FindingsOutput`/`ResearchOutput`/`RedScanOutput` → alle 4 parsen jetzt erfolgreich mit leerem String statt `ValidationError`.
    3. Konstruktionstest: `llm_analysis.max_tokens == 8000` (unverändert), `llm_reporter.max_tokens == 12000`, `reporter_agent.llm is llm_reporter`, `blue_agent.llm`/`red_agent.llm` weiterhin `is llm_analysis` — alle 4 Scopes bauen weiterhin fehlerfrei.
    4. Regressionscheck BUG-25: `_value_grounding_guardrail` erkennt den echten fabrizierten example.com-Report weiterhin korrekt (unverändert durch diese Änderung).
  - **E2E-Verifikation (2026-09-12, `westerstede.de full`, Log `llm_debug_1201295.jsonl` + `trace_westerstede.de_20260912_025117.json`):** ✅ Bestanden — kompletter Durchlauf, alle Teams bis Team 6 (Risk Scorer) fertig (`recon_report`/`interpret`/`final_report`/`compliance`/`risk_score` vorhanden), kein Crash. `has_exploitable=False` auf dieser Route → Team 4 (Threat-Intel) planmäßig übersprungen, kein Fehler.
    - Ein `ReportOutput`-`ValidationError` (`EOF while parsing an object`, 02:49:03 — gleiches Muster wie Befund 2/BUG-24) trat weiterhin auf, wurde aber diesmal durch einen reinen Task-LLM-Retry (nicht durch einen vollen Flow-Neustart) sofort behoben (Folge-Call 02:50:08 erfolgreich, 1591 Zeichen) — kein Kaskadenausfall wie zuvor. Zeigt: der `llm_reporter`-max_tokens-Fix (12000) reduziert die Trunkierungsrate, schließt sie aber nicht vollständig aus — für dieses Szenario griff die bestehende Retry-Infrastruktur wie vorgesehen.
    - **Nebenbefund (kein neuer Bug, nur notiert):** `risk_score_westerstede.de_20260912_025251.md` zeigt 10 Critical-CVEs, alle Apache-HTTP-Server-CVEs für Versionsbereiche 2.4.49–2.4.55 — nicht im Rahmen dieser Verifikation gegen den tatsächlich erkannten Apache-Versions-Banner geprüft (BUG-17/25-Versions-Gate-Frage bleibt offen, separat zu prüfen falls die Zahl auffällt).
  - **Status: BUG-26 vollständig abgeschlossen** (umgesetzt, Unit- UND E2E-verifiziert). Noch nicht committet.

### Aktueller Stand (2026-09-12 — BUG-25 gefunden, NOCH NICHT gefixt: Content-Fabrikation trotz korrekter Tool-Zuschreibung)

- **BUG-25 (2026-09-12, gefunden beim manuellen Verifikationsscan `example.com full`, NOCH NICHT gefixt):** Review von `recon_report_example.com_20260912_001357.md`/`final_report_example.com_20260912_001733.md` gegen den echten `trace_example.com_20260912_001357.json` zeigt mehrere **inhaltlich erfundene** Einträge in "Confirmed Findings"/"Detected Technologies" — mit korrekt zitiertem, tatsächlich gelaufenem Tool. Das ist eine ANDERE Hallizinations-Klasse als BUG-23 (dort: falscher Tool-*Name*) — hier stimmt der Tool-Name, aber der behauptete WERT (Produkt/Version/Zitat) hat keine Deckung im Raw-Output. Die BUG-23-Guardrails (`_confirmed_findings_tool_guardrail`, `_searchsploit_version_guardrail`) prüfen beide nur Tool-Namen bzw. CVE-Trace-Präsenz — keiner prüft den Wert selbst.
  - **Befunde (alle gegen `trace_*.json` gegengeprüft):**
    1. `"WordPress version 5.9 identified"`, Zitat `<title>Example Site - WordPress 5.9</title>` — zugeschrieben an `whatweb`. Echter whatweb-Output: `Title[Example Domain]`, kein WordPress/PHP irgendwo im gesamten Trace. **Komplett erfunden, inkl. Fake-Zitat.**
    2. `"Detected Technologies: nmap_service_version → Apache 2.4.54"` — echter nmap-Output nennt nirgends "Apache" (nur `nginx`/`Cloudflare http proxy`). **Komplett erfunden.**
    3. `"Subdomain admin.example.com discovered … resolved"` — zugeschrieben an `subfinder`. subfinder fand `admin11/17/20/24.example.com`, nie exakt `admin.example.com`. **Erfunden/verfälscht** (vermutlich "bereinigte" Version einer realen, aber andersnamigen Subdomain).
    4. `"OpenSSL 2.1.2 on port 443"` — zugeschrieben an `sslscan`. Echter sslscan-Rohoutput bestand NUR aus `Version: 2.1.2\nOpenSSL 3.0.13 30 Jan 2024` — das ist sslscans EIGENER Tool-Versions-Banner (kompiliert gegen OpenSSL 3.0.13), kein echtes Scan-Ergebnis gegen das Ziel (sslscan lieferte offenbar keine Cipher-/Zertifikatsdaten, vermutlich wegen Cloudflare-TLS-Terminierung — separates mögliches Tool-Problem). Die findings-Phase interpretierte die Banner-Zeile fälschlich als Ziel-Version und fragte NVD danach ab (`nvd_cpe_lookup OpenSSL 2.1.2` → CVE-2019-0190). **Kaskadeneffekt korrekt abgefangen:** Das BUG-17-Versions-Gate erkannte, dass keine der von NVD zurückgegebenen CPE-Produkte (`apache:http_server`, diverse Oracle) im Scan-Body versions-bestätigt ist, und blendete die CVE zurecht aus dem Final Report aus (0 gelistete CVEs) — dieser Teil der Kette funktioniert wie vorgesehen.
  - **Root Cause (Hypothese, nicht verifiziert):** Die blue-/findings-Phase (Non-Reasoning-Modell `nemotron-3-nano:30b`) generiert die "Confirmed Findings"-Tabelle und "Detected Technologies" als freien Markdown-Text ohne strukturellen Zwang, Werte wörtlich aus dem Tool-Kontext zu übernehmen — ähnlich dem BUG-23-Root-Cause (Reporter-Task hat keine geschützten Pydantic-Felder für diese Tabelle), aber hier schon eine Stufe früher (blue/red-Phase selbst, nicht erst der Reporter).
  - **Möglicher Fix-Ansatz (nicht umgesetzt, Design-Entscheidung ausstehend):** Neuer Guardrail-Typ, der über Tool-Namen-Match hinausgeht — z.B. prüft ob die in einer "Confirmed Findings"-Zeile behauptete Produkt/Versions-Zeichenkette (oder ein signifikanter Teilstring davon) tatsächlich im Raw-Output des zitierten Tool-Calls vorkommt (Substring- oder Fuzzy-Match), sonst Reject mit Feedback. Deutlich aufwändiger als die bestehenden Guardrails (muss pro Zeile den richtigen Trace-Call anhand Trace-Seq# oder Tool-Name auflösen und den Wert extrahieren) — braucht eigene Design-Runde, bewusst nicht spontan mitgefixt.
  - **User-Entscheidung (2026-09-12):** Fund dokumentiert, Fix zurückgestellt. Der unabhängig davon verifizierte Critical/High-Count-Konsistenz-Fix (`cve_filters.py`) wurde committet (Hash `1594400`) — BUG-25 ist NICHT Teil dieses Commits und blockiert ihn nicht.
  - **STATUS: UMGESETZT + Unit-verifiziert (2026-09-12), E2E-Scan noch ausstehend.** Details unten unter "Umsetzung" nach dem ursprünglichen Arbeitsplan.
  - **ARBEITSPLAN (dokumentiert 2026-09-12 vor Umsetzung — Notfall-Referenz falls Session abbricht; Umsetzung erfolgt NACH dieser Doku, mit User-Freigabe):**
    1. **Neuer Guardrail `_value_grounding_guardrail`** (analog `_confirmed_findings_tool_guardrail` aus BUG-23), am `report`-Task zusätzlich zum bestehenden Tool-Namen-Guardrail. Parst dieselbe "## Confirmed Findings"-Tabelle, zusätzlich zur Tool-Spalte jetzt auch die "Beobachtung"-Spalte.
    2. **Prüflogik pro Zeile:** Tool-Name aus Spalte 4 auflösen → zugehörige(n) `raw_output`-Block(e) aus `run_trace` per Tool-Name holen (NICHT per Trace-Seq#, da die Seq#-Spalte selbst teils erfunden war, siehe BUG-23) → prüfen ob ein signifikanter FAKTISCHER ANKER der Beobachtung (Produktname + Versionsnummer als eigenständiges Token, z.B. `"WordPress"` + `"5.9"`, oder ein exakter Hostname wie `"admin.example.com"`) wörtlich im Raw-Output vorkommt. Bewusst KEIN Exact-Match des ganzen Satzes (Paraphrasierung ist erlaubt) — nur die faktischen Anker müssen belegt sein.
    3. **Sonderfall sslscan-Eigenbanner (separater, kleinerer Fix):** Die ersten 1-2 Zeilen von `sslscan`-Output (`Version: X.X.X` / `OpenSSL X.X.X ...`) sind IMMER der Tool-eigene Versions-Banner, nie das Scan-Ergebnis gegen das Ziel — das reine Substring-Vorkommen im Raw-Output würde diesen Fall NICHT fangen (der Wert steht ja wörtlich da, ist nur falsch interpretiert). Deshalb zusätzlich: im `findings`-Task-Prompt explizit kennzeichnen, dass diese beiden Zeilen NICHT die Zielversion sind.
    4. **Abgrenzung:** Kein generisches Fact-Checking der gesamten Report-Prosa — nur die strukturierte "Confirmed Findings"-Tabelle, da sie explizit "bestätigt" beansprucht.
    5. **Verifikationsplan (Positiv- + Negativkontrolle, wie bei BUG-23):**
       - Unit-Reject: Guardrail gegen den echten fabrizierten example.com-Report (bzw. dessen JSON-Rohform mit escapten Newlines, analog dem BUG-23-Folgefund) → muss auf "WordPress"/"Apache 2.4.54"/"admin.example.com" reagieren, mit Feedback welcher Wert nicht im Trace steht.
       - Positivkontrolle: ein bereits verifizierter sauberer Report (z.B. der zweite `oldenburg.de full`-Lauf aus BUG-23) → Accept, kein Fehlalarm.
       - Sonderfall-Test: isolierter `findings`-Phase-Test mit sslscan-Bannerzeile im Kontext → Modell muss die Version danach als "nicht ermittelbar" statt als Zielversion einordnen.
       - Echter E2E-Verifikationsscan (wie BUG-23 gefordert) — erneuter Scan mit aktivem Fix, um zu bestätigen dass ein Reject im echten Agent-Retry-Loop greift, nicht nur in der Unit-Simulation.
       - Regressionscheck: bestehende BUG-23-Guardrail-Verhaltenstests laufen unverändert weiter grün.
  - **Umsetzung (2026-09-12):**
    1. Neu in `tasks.py`: `_extract_report_text()` — Text-Extraktion (pydantic → JSON-Fallback → raw) aus `_confirmed_findings_tool_guardrail` herausgezogen, jetzt von BEIDEN Guardrails geteilt (reiner Refactor, keine Verhaltensänderung, per Regressionstest bestätigt).
    2. Neu `RunTrace.get_raw_outputs_for_tool(tool_name)` (`tools/trace.py`) — liefert alle `raw_output`-Strings für ein exaktes `tool_name` (geschlossene Phasen + `_pending`).
    3. Neu `_value_grounding_guardrail` (`tasks.py`), zweiter Guardrail auf dem `report`-Task (`guardrails=[_confirmed_findings_tool_guardrail, _value_grounding_guardrail]`, teilt sich `guardrail_max_retries=2` + den globalen `_guardrail_reject_count`). Prüft ZWEI Sektionen:
       - **"Confirmed Findings"-Tabelle:** pro Zeile Anker aus der Beobachtung extrahieren (Versionsnummern `\d+(\.\d+){1,3}`, Hostnamen, `<tag>`-Zitate), gegen `get_raw_outputs_for_tool()` der zitierten Tool(s) prüfen.
       - **"Detected Technologies"-Zeilen** (`<label> → <wert>`): zusätzlich abgedeckt, NACHDEM der erste Testlauf zeigte, dass der reale "Apache 2.4.54"-Fabrikationsfall NUR dort steht, nicht in der Tabelle — ohne diese Erweiterung wäre einer der drei bekannten Fälle unentdeckt geblieben. Tool wird über Präfix-Match des Labels gegen `get_all_tool_names()` aufgelöst (z.B. `"nmap_service_version".startswith("nmap")`).
    4. sslscan-Banner-Sonderfall: neuer Absatz im `blue`-Task-Prompt (`tasks.py`, direkt nach dem bestehenden nmap-Rate-Namen-Hinweis) — kennzeichnet die ersten sslscan-Zeilen explizit als Tool-Eigenbanner, nicht als Ziel-Version.
  - **Verifiziert (2026-09-12):**
    1. `py_compile` sauber auf `tasks.py` + `tools/trace.py`.
    2. Echter Konstruktionstest: `AgentScanITCrew(target='example.com', scope='full').crew()` → beide Guardrails korrekt am `report`-Task verdrahtet.
    3. **Unit-Reject gegen den ECHTEN fabrizierten `recon_report_example.com_20260912_001357.md`** (realer Trace aus `trace_example.com_20260912_001357.json` in `run_trace` nachgespielt, keine Synthetik) → **Reject**, erkennt alle 3 bekannten Fabrikationsfälle korrekt: `<title>...WordPress 5.9</title>` (whatweb), `admin.example.com` (subfinder), `Apache 2.4.54` (nmap_service_version, Detected-Technologies-Sektion). Erster Testlauf fing nur 2/3 (Apache-Fall fehlte) → deckte die Sektions-Lücke auf → sofort behoben (Punkt 3 oben) → zweiter Lauf fängt alle 3.
    4. **Positivkontrolle:** synthetischer sauberer Report mit real gegroundeten Werten (OpenSSH 9.6p1, nginx 1.24.0, X-Frame-Options-Hinweis) → **Accept**, kein Fehlalarm.
    5. **Regressionscheck BUG-23:** `_confirmed_findings_tool_guardrail` weiterhin korrekt — (a) fabrizierter Tool-Name (`nuclei_vulnerability_scanner`) → Reject, (b) JSON-escaped-raw-only-Pfad (der zweite BUG-23-Fix) → weiterhin Reject. Beide nach dem `_extract_report_text()`-Refactor unverändert.
  - **E2E-Scan mit aktivem Fix — jetzt durchgeführt (2026-09-12, erneuter `example.com full`-Lauf):** bestätigt GENAU das befürchtete Muster (analog dem BUG-23-Folgefund: Unit-Test allein übersieht einen zweiten, nur live sichtbaren Bug). Der sslscan-Banner-Prompt-Fix (Punkt 3 im ursprünglichen Arbeitsplan, nur code-reviewed) erwies sich live als **unzureichend** — der Report übernahm sslscans Eigenbanner (`Version: 2.1.2`/`OpenSSL 3.0.13`) trotz Prompt-Hinweis erneut als Ziel-TLS-Version, in Confirmed Findings UND Detected Technologies. `_value_grounding_guardrail` fing das strukturell nicht (Wert steht wörtlich im Raw-Output, nur die Interpretation ist falsch). **BUG-25-Nachtrag-Fix:** neues `_strip_sslscan_self_banner()` entfernt die ersten 1-2 Banner-Zeilen deterministisch aus dem Grounding-Haystack für sslscan-Tools, bevor die Anker-Suche läuft — bestätigt die Projekt-Lehre aus BUG-20/23 ("Werte-Kontrolle braucht Guardrail, nicht Prompt-Bitte") ein weiteres Mal. Verifiziert: `testing/test_sslscan_banner_guardrail.py` 3/3 (Reject mit den ECHTEN Daten aus diesem Lauf, Accept bei echten sslscan-Cipher-Daten, Accept bei anderen Tools unverändert) + Regressionscheck (alle 3 originalen BUG-25-Fälle weiterhin erkannt). Committet (`34e9607`). Der ursprüngliche `_value_grounding_guardrail`-Reject-Pfad selbst ist damit ebenfalls erstmals E2E (nicht nur Unit) bestätigt — dieser Lauf hat ihn faktisch ausgelöst/durchlaufen.

### Aktueller Stand (2026-09-11 — BUG-22 NVD-CPE-Truncation-Fix + Threat-Intel-Key-Konsolidierung + Modell-Wechsel-Verifikation)

- **BUG-24 (2026-09-11, gefixt in [`agents.py`](agentscanit/agents.py), Commit nachgeholt 2026-09-12) — Reporter-Output riss bei langen `full`-Scope-Reports mitten im JSON ab:**
  - **Befund:** Bei `oldenburg.de full` schlug das Parsen von `ReportOutput` mit `"EOF while parsing an object"` fehl — das vom LLM zurückgegebene JSON war exakt an einer bestimmten Zeichenzahl abgeschnitten, mitten im `executive_summary`-String.
  - **Root Cause:** `_llm()` setzte kein explizites `max_tokens` — der Remote-Endpoint (`ollama.com`) fällt dann auf einen knappen internen Default zurück, der bei langen Reports (viele Findings, `full`-Scope) nicht ausreicht und die Antwort mitten im JSON-Objekt abschneidet, statt einen Fehler zu werfen.
  - **Fix:** `max_tokens=8000` remote (passend zu `num_ctx=16384`, lässt genug Raum für den Input-Context) / `4000` lokal (passend zu `num_ctx=8192`).
  - **Verifiziert:** `py_compile` sauber; `num_ctx`-Werte im selben Modul gegengeprüft (16384 remote/8192 lokal, Kommentar-Behauptung stimmt mit tatsächlicher Konfiguration überein). Kein dedizierter Regressionsscan nachträglich gefahren (Fix bereits vor dieser Session inhaltlich abgeschlossen) — Verhaltensannahme stützt sich auf die Codeanalyse + die genannte reale Fehlerbeobachtung bei oldenburg.de, nicht auf einen erneuten End-to-End-Beweis in dieser Session.
  - **Hinweis:** Dieser Fix stand im Code (Kommentar referenziert "BUG-24, 2026-09-11"), war aber nirgends in diesem Dokument beschrieben — beim Commit-Aufräumen 2026-09-12 nachgetragen. Die neue, unabhängige Fabrikations-CVE-Klasse vom 2026-09-12-Scan wurde deshalb als **BUG-25** nummeriert (nicht BUG-24, um die Kollision nicht zu wiederholen).

- **BUG-22 (2026-09-11) — `affected_cpe`-Truncation ließ real zutreffende CVEs verschwinden, gefixt in [`tools/nvd.py`](agentscanit/tools/nvd.py):**
  - **Befund:** Review eines `final_report_rastede.de_*.md` (quick-Scope) zeigte: `CVE-2024-6387` ("regreSSHion", CVSS 8.1 HIGH, betrifft OpenSSH 8.5p1–9.7p1) wurde vom Scan gefunden und vom `interpret`-Team korrekt gegen NVD verifiziert (steht mit vollen Daten in `interpret_rastede.de_*.md`), verschwand aber beim Merge in den Final Report spurlos — nur anonym mitgezählt in der Fußnote „N weitere … ausgeblendet". Der erkannte Server läuft **OpenSSH 9.6p1** — die CVE ist also tatsächlich zutreffend, nicht nur theoretisch.
  - **Root Cause:** `_parse_cve()` in `nvd.py` (Zeile 106–113/123, genutzt von ALLEN vier Fetch-Pfaden: `lookup_cve`, `fetch_cves`, `cpe_search_nvd`, `search_nvd`) kappt `affected_cpe` hart auf die ersten 10 von NVD gelieferten CPE-Einträge, in unveränderter API-Reihenfolge. Bei `CVE-2024-6387` listet NVD zuerst diverse Firmware-/OS-Bundling-CPEs (SonicWall SMA, Arista EOS, Ubuntu, AlmaLinux …) — die eigentliche Anwendungs-CPE `cpe:2.3:a:openbsd:openssh:*` fiel dadurch aus den ersten 10 raus. `reporting_flow.py::_cve_product_keywords()` extrahiert Produkt-Keywords AUSSCHLIESSLICH aus `affected_cpe` → "openssh" tauchte nie als Keyword auf → `_version_confirmed_in_scan()` (BUG-17-Gate) schlug fehl → CVE landete in `version_unk` → NVD-Beschreibung enthält keines der KEV-Schlüsselwörter ("exploited in the wild" etc.) → CVE wurde komplett verworfen, ohne jede Markierung im Report. **Strukturell dasselbe Muster wie das historische BUG-11** (Truncation cappt eine relevante CVE weg), aber an einer anderen Code-Stelle (`_parse_cve`'s Feld-Truncation statt `cpe_search_nvd`'s Ergebnis-Truncation) — von der damaligen NOTABLE_CVES-Pinning-Lösung nicht abgedeckt.
  - **Nebenbefund (kein Fix, dokumentierte Grenze):** `CVE-2023-38408` wurde im selben Report als "✅ versions-verifiziert CRITICAL" gelistet, betrifft laut NVD aber nur "OpenSSH before 9.3p2" — die erkannte Version 9.6p1 ist dagegen bereits gepatcht. Das BUG-17-Gate prüft nur *ob* eine Version erkannt wurde, nicht *ob* die erkannte Version im verwundbaren Bereich liegt (semantischer Range-Vergleich fehlt strukturell, siehe bestehende Doku unter "Ground-Truth-Verifikation" oben). Kein neuer Bug, bewusst nicht angefasst — nur hier vermerkt, weil im selben Review aufgefallen.
  - **Fix:** `_parse_cve()` sortiert `affected` vor dem `[:10]`-Cut so um, dass Anwendungs-CPEs (`cpe:2.3:a:...`) vor Betriebssystem-/Firmware-CPEs (`cpe:2.3:o:...`/`h:...`) stehen (`affected.sort(key=lambda c: 0 if _cpe_part(c) == "a" else 1)`, `sort()` ist stabil → Reihenfolge innerhalb einer Gruppe bleibt erhalten, weiterhin max. 10 Einträge).
  - **Verifiziert:**
    1. Isoliert: `lookup_cve('CVE-2024-6387')` → `openbsd:openssh`-CPE jetzt an Position 1 (vorher: gar nicht in den ersten 10).
    2. `_version_confirmed_in_scan()` gegen `"OpenSSH 9.6p1 detected"` → `True` (vorher `False`).
    3. Regressionscheck gegen 3 historisch bekannte Fälle (`CVE-2023-21839` WebLogic, `CVE-2017-12615` Tomcat, `CVE-2023-38408` OpenSSH) — alle weiterhin korrekt `confirmed: True`, keine Verschlechterung durch die Sortierung.
    4. End-to-End: `reporting_flow.merge()` erneut mit den 7 echten rastede.de-CVE-IDs ausgeführt (frisches `fetch_cves()`, Fix aktiv) → `CVE-2024-6387` erscheint jetzt korrekt unter "✅ Versions-verifizierte CVEs", Kopfzeile "Gelistet: 6, Critical: 2, High: 3" (nur noch 1 statt 2 versionslose CVEs ausgeblendet — die verbleibende, `CVE-2021-42013`, ist berechtigt ausgeblendet, da für Apache keine Version erkannt wurde).
  - **Betrifft alle 4 NVD-Fetch-Pfade** (zentrale Stelle `_parse_cve`), nicht nur den Reporting-Merge — z.B. auch `nvd_cpe_lookup`/`nvd_cve_search` während der `findings`-Phase profitieren vom selben Fix.

- **Threat-Intel-API-Key-Konsolidierung** (`threatintel_agent/`, analog `agentscanit/models.json`-Muster): neu `tools/_keys.py` (zentraler Loader: Env-Var > `api_keys.md` > leer) + `api_keys.md.example` (Vorlage, Format `KEY: wert` pro Zeile, Platzhalter werden ignoriert). `otx_tool.py`/`shodan_tool.py`/`virustotal_tool.py` nutzen jetzt `get_key("OTX_API_KEY"|"SHODAN_API_KEY"|"VT_API_KEY")` statt direkt `os.environ`. `.gitignore`: `threatintel_agent/api_keys.md` ergänzt. `README.md` Konfigurationsabschnitt verweist auf die neue Datei. Grund: einzelne, gitignorete Datei statt verstreuter Env-Vars, gleiches Ergonomie-Prinzip wie bei den LLM-Modellen.

- **Remote-Modell-Recherche + -Wechsel-Verifikation über die Ollama-API (`agentscanit/models.json`):**
  - `https://ollama.com/api/tags` abgefragt (20 verfügbare Remote-Modelle) + `/api/show` je Kandidat (Caps/Kontext/Param-Größe). `qwen3-coder:480b` (das frühere Standard-Remote-Modell, siehe BUG-19) ist nicht mehr in der Liste.
  - Testweise auf `deepseek-v4.1-flash` gewechselt (1M Kontext, sehr aktuell) — **Live-Ping (`/api/chat`) zeigte HTTP 402 "requires a subscription or usage credits"**, ebenso bei einem Scan-Versuch gegen rastede.de (13 Calls liefen fehlerfrei, dann Abbruch durch User wegen fehlendem Abo). Kein technischer Bug — reines Zugriffsrechte-Problem.
  - **Alle 20 Remote-Modelle einzeln per Minimal-Chat-Ping auf Abo-Pflicht getestet** (HTTP 200 vs. 402): frei nutzbar mit dem aktuellen Key sind nur `nemotron-3-nano:30b`, `nemotron-3-super`, `gpt-oss:120b`, `gpt-oss:20b`, `gemma4:31b` — alle anderen 14 (u.a. `kimi-k2.7-code`, `deepseek-v4.1-flash`, `qwen3.5:397b`, `glm-5.x`, `kimi-k2.6/k3`, `mistral-large-3:675b`, `minimax-*`) verlangen Abo/Guthaben.
  - Von den 5 freien Modellen: `gpt-oss:120b`/`gpt-oss:20b` strukturell vorbelastet (BUG-19-Reasoning-Familie), `gemma4:31b` strukturell vorbelastet (Gemma-Familie, siehe `gemma4:e2b`-Befund oben). `nemotron-3-super` (120B, gleiche Familie wie aktuelles Modell) wurde dem User als ungetestetes Upgrade vorgeschlagen — **User-Entscheidung: bei `nemotron-3-nano:30b` (30B, bereits bewährt) bleiben**, kein Wechsel.
  - **`models.json` steht damit unverändert bei `nemotron-3-nano:30b`** für analysis/code/research (Planner weiterhin lokal `qwen2.5:7b-instruct`).
  - **Verifikationsscan** `rastede.de quick` mit `nemotron-3-nano:30b` + `RECON_LLM_DEBUG=1` komplett durchgelaufen: 21 LLM-Calls über alle Agents (Planner/Research/Blue/Reporter/Compliance), **0 Leerantworten** — Kriterium aus BUG-19 sauber erfüllt. Alle Teams liefen durch (Recon→Interpret→Compliance→Risk→Final Report). Fund: OpenSSH 9.6p1 + Apache httpd auf rastede.de (führte direkt zum BUG-22-Review oben).
  - **NUR LOKAL:** `models.json` (gitignored, enthält Live-API-Key) — Änderungen dort sind nicht versionierbar/nicht Teil eines Commits.

- **CrewAI-Update 1.14.7 → 1.15.21** (`requirements.txt` + `agentscanit/requirements.txt` gepinnt, Venv aktualisiert via `pip install --upgrade crewai`):
  - **Kompatibilität verifiziert, kein Breaking Change gefunden:**
    - Alle Team-Module importieren weiter fehlerfrei (`flow.py`, `scope_gate.py`).
    - `from crewai.flow.flow import or_, Flow, start, listen, router` — alle Imports vorhanden (kritisch, da `@listen(or_(A,B))` projektweit für Multi-Trigger-Methoden genutzt wird, siehe `@listen`-Stacking-Hinweis unten in diesem Dokument).
    - `Crew.model_fields` bestätigt: `planning`/`planning_llm` weiterhin vorhanden und funktional.
    - **Kern-Empfindlichkeit explizit nachgeprüft (BUG-19-relevant):** Die Empty-Response-Erkennung in `crewai/utilities/agent_utils.py::_validate_and_finalize_llm_response()` wirft weiterhin **exakt denselben Fehlertext** `"Invalid response from LLM call - None or empty."` — die Retry-Klassifikation in `main.py` (die genau auf diesen String matched) bleibt also gültig, keine Anpassung nötig.
    - Echter Konstruktions-Test (kein LLM-Call, keine Kosten): `AgentScanITCrew(...).crew()` baut ein valides `Crew`-Objekt (3 Agents, 4 Tasks bei `quick`-Scope), `planning=True`, `planning_llm` gesetzt — Pydantic-Validierung besteht.
  - **Neue Crew-Felder entdeckt (informativ, aktuell alle auf Default/inaktiv, kein Handlungsbedarf):**
    - `checkpoint` / `checkpoint_inputs` / `checkpoint_train` / `checkpoint_kickoff_event_id` — Intra-Crew-Checkpointing ist als neues, offenbar überarbeitetes natives Feature zurück (Default `None` = inaktiv, muss explizit gesetzt werden). **Wichtig:** Das ist NICHT automatisch das alte `CheckpointConfig`, das in Phase 7 wegen des PyO3-Race-Bugs (Hintergrund-Thread-Serialisierung kollidierte mit Task-Mutation, siehe `debugging/DIAGNOSIS.md`) entfernt wurde — ob der neue Mechanismus dieses Problem behebt, ist **nicht verifiziert**. Bleibt bewusst deaktiviert (`checkpoint: None` bestätigt im Konstruktionstest); eine Reaktivierung wäre ein separates, mit eigener Verifikation zu behandelndes Vorhaben, kein Nebeneffekt dieses Updates.
    - `tool_failure_policy` — neues Feld zur Steuerung, wie Tool-Fehler behandelt werden (Default `None` = "warn"), auf Crew-/Agent-/Task-/Tool-Ebene überschreibbar. Potenziell interessant für die bestehende Guardrail-Landschaft (`_tool_call_guardrail`, No-Tool-Fallback), aber ungenutzt — keine Verhaltensänderung ohne explizites Setzen.
    - `stream` (Default `False`) — Streaming-Output der Crew, für die Suite (Batch-CLI-Scans, kein interaktives UI) nicht relevant.
    - `skills` — neue Möglichkeit, SKILL.md-Dateien/Registry-Refs an alle Agents einer Crew zu hängen. Nicht genutzt, kein Bezug zum aktuellen Knowledge-Source-Ansatz (Phase 6).
  - **Offizielle Changelog-Highlights 1.15.12–1.15.21** (GitHub Releases, ältere 1.15.x-Einträge nicht einsehbar gewesen): "Preserve tool results when the final answer is empty" (v1.15.18 — Detail-Recherche im installierten Package-Code ergab: NICHT im Kern-Pfad `_validate_and_finalize_llm_response`, sondern in der neueren `todos`/Reasoning-Step-Infrastruktur des `experimental/agent_executor.py`, die dieses Projekt über `_EXECUTOR_CLASS = AgentExecutor` nutzt — betrifft vermutlich einen anderen Teilpfad als den BUG-19-Fall, nicht abschließend zurückverfolgt), native Tool-Calls über die OpenAI-Responses-API repariert (v1.15.17), diverse Security-Bumps (pypdf, nltk, v1.15.19), Claude-Sonnet-4.6-Kontextfenster-Mapping (v1.15.18) — für dieses Projekt (Ollama-Remote/-Lokal, kein Anthropic/OpenAI-Provider) ohne direkte Relevanz.
  - **Fazit:** Update ist ein sicherer Drop-in-Replace für dieses Projekt — nichts Kritisches bricht, nichts Kritisches wird automatisch aktiviert. Die einzige Funktion mit echtem Potenzial für die dokumentierte Historie (`checkpoint`, evtl. Lösung für das Phase-7-Resume-Problem) ist bewusst NICHT aktiviert und bräuchte eine eigene Verifikationsrunde, bevor sie in Betracht gezogen wird.
  - **Verifikationsscan `rastede.de full`** (nach dem Update, `RECON_LLM_DEBUG=1`): 37 LLM-Calls über alle Agents, **0 Leerantworten**, tiefste FC-Kette 27 Nachrichten (Research-Agent) — deutlich über der BUG-19-Lackmustest-Schwelle (Ø10.1 messages). Safety-Gate (Phase 9.0) korrekt ausgelöst + im Audit-Log protokolliert. Alle 7 Phasen inkl. Team 4 (Threat-Intel, da `has_exploitable=True`) liefen durch.

- **BUG-23 (2026-09-11, UMGESETZT + verifiziert, User-Freigabe erteilt) — "Confirmed Findings" im Recon Report teilweise fabriziert/fehlzugeordnet:**
  - **Befund:** Review von `final_report_rastede.de_20260911_184953.md` (`full`-Scope): Die Tabelle "## Confirmed Findings" listete 7 Einträge (u.a. "ActiveMQ < 5.14.0 - Web Shell Upload", "Apache 0.8.x/1.0.x … 'test-cgi' Directory Listing", "Apache 1.1 …", "Apache 1.2.5/1.3.1 … MIME Header DoS") als von `nuclei_vulnerability_scanner` bestätigt, mit `Trace-Seq# 1–7`. **Beides ist falsch:** Der einzige echte Nuclei-Call dieser Session (`trace_*.json`, `blue`-Phase, seq 7, `-tags apache,wordpress -severity critical,high`) lieferte **0 Treffer** (57 Zeichen Rohoutput, nur eine Config-Warnung). Die 7 Einträge stammen tatsächlich aus `searchsploit --json Apache` (`red`-Phase, seq 20, 141.307 Zeichen) — einem **ungefilterten, versionslosen Keyword-Dump** der gesamten lokalen ExploitDB (älteste Treffer von 1996). ActiveMQ läuft nachweislich gar nicht auf dem Ziel (taucht nirgends in "Detected Technologies" auf); keine Apache-Version wurde je erkannt.
  - **Root Cause, zwei Ebenen:**
    1. **`red`-Task** ([tasks.py:818-846](agentscanit/tasks.py#L818-L846), Attack Surface Analyst): Prompt verlangt `searchsploit <service> <version>`, der Agent rief real `searchsploit --json Apache` **ohne Version** auf und übernahm alle 7 rohen ExploitDB-Titel unverändert in `RedOutput.confirmed_attack_surface`/`exploitable_findings` — die "OUTPUT-REGELN" im Prompt ("nur Tool-bestätigte Findings") sind **reine Prompt-Vorgabe, kein Guardrail** (anders als bei `cve_references`, geschützt durch `_cve_trace_guardrail`). Exakt das BUG-20-Muster ("versionslose generische Treffer sind Rauschen"), aber für `red` nie umgesetzt — BUG-20 deckt nur die NVD-CVE-Liste in `reporting_flow.py` ab.
    2. **`report`-Task** ([tasks.py:871-920](agentscanit/tasks.py#L871-L920), Reporter, keine eigenen Tools, `ReportOutput` hat nur `path`+`executive_summary` — die "Confirmed Findings"-Tabelle ist **komplett ungeschütztes Markdown-Freitext**): erfand beim Formatieren zusätzlich die Tool-Zuschreibung `nuclei_vulnerability_scanner` und die `Trace-Seq#`-Spalte — beides existiert so nicht im echten Trace. Kein Guardrail prüft diese Tabelle überhaupt.
  - **Kaskadeneffekt:** `RedOutput.exploitable_findings_count: 7` → `flow.py` setzt `has_exploitable=True` → `full_analysis`-Route (Threat-Intel + Safety-Gate liefen deswegen). Die 6 zugehörigen CVE-IDs (`CVE-2016-3088`, `CVE-1999-0070/0045/0926/0925/0107`) bestanden `_cve_trace_guardrail` (stehen ja wirklich im searchsploit-Rohoutput — die Guardrail prüft nur Existenz im Trace, nicht Versions-Relevanz) und landeten im finalen NVD-Abschnitt. Dort fand die BUG-17-Versions-Gate-Regex (`_version_confirmed_in_scan`) die Zahl **"5.14" aus "ActiveMQ < 5.14.0" direkt in der bereits fabrizierten Tabelle selbst** (< 20 Zeichen neben "httpd") und stufte mehrere 1990er-Apache-CVEs fälschlich als "✅ versions-verifiziert" ein —**selbstreferenzielle Kontamination**, die Halluzination bestätigt sich teilweise selbst. Ergebnis: Risk Score **10.0/10 CRITICAL, "Exploitable: ✓ Ja"** — komplett auf fabrizierter Basis berechnet.
  - **Fix (2 neue Guardrails, umgesetzt in [`tasks.py`](agentscanit/tasks.py) + [`tools/trace.py`](agentscanit/tools/trace.py)):**
    1. **`_searchsploit_version_guardrail`** (Modul-Ebene, vor `make_tasks()`, analog aller anderen Guardrails) auf dem `red`-Task: `guardrails=[_cve_trace_guardrail, _searchsploit_version_guardrail]`, teilt sich `guardrail_max_retries=2`. Inspiziert `run_trace._pending` auf `searchsploit`-Aufrufe; enthält der Such-Query (`command`) **kein Versions-Token** (`\d+\.\d+`) UND ist `confirmed_attack_surface` oder `exploitable_findings` nicht leer → Reject mit Feedback (erneut mit `<service> <version>` suchen, oder Listen leer lassen). Teilt sich den globalen `run_trace._guardrail_reject_count` mit `_cve_trace_guardrail` — bewusst dasselbe Muster wie beim `findings`-Task (dort teilen sich `_cve_tool_used_guardrail` + `_cve_trace_guardrail` den Counter bereits) — ein Retry-Budget pro Task-Versuch, nicht pro Guardrail-Typ.
    2. **`RunTrace.get_all_tool_names()`** (neu, `tools/trace.py`, analog `get_all_raw_outputs()`): sammelt `tool_name` aus allen geschlossenen Phasen + `_pending`.
    3. **`_confirmed_findings_tool_guardrail`** (Modul-Ebene, neu) auf dem `report`-Task (**hatte vorher KEINEN Guardrail**): `guardrails=[_confirmed_findings_tool_guardrail]`, neu `guardrail_max_retries=2` (Task hatte vorher keinen gesetzt). Parst die "## Confirmed Findings"-Markdown-Tabelle per Regex (`_CONFIRMED_FINDINGS_SECTION_RE`) aus dem rohen Reporter-Output, prüft jede "Tool"-Spalte (Spalte 4, mehrere Namen via `,`/`/` getrennt möglich) gegen `run_trace.get_all_tool_names()` → Reject bei fabriziertem/nie gelaufenem Tool-Namen, Feedback listet die real gelaufenen Tools zur Selbstkorrektur.
  - **Verifiziert:**
    1. `py_compile` sauber auf beiden geänderten Dateien.
    2. `make_tasks()` real aufgerufen: `red`-Guardrails = `[_cve_trace_guardrail, _searchsploit_version_guardrail]`, `report`-Guardrails = `[_confirmed_findings_tool_guardrail]` mit `guardrail_max_retries=2`.
    3. Verhaltenstests (echte + synthetische Daten): (a) `_searchsploit_version_guardrail` gegen einen echten versionslosen `searchsploit --json Apache`-Call + nicht-leere Findings → **Reject** mit korrektem Feedback; derselbe Call MIT Versions-Token im Query → **Accept**. (b) `_confirmed_findings_tool_guardrail` gegen den ECHTEN fabrizierten `recon_report_rastede.de_20260911_183942.md`-Text → **Reject**, erkennt `nuclei_vulnerability_scanner` korrekt als nie gelaufenes Tool (auch obwohl `nuclei` selbst real lief — der Name muss exakt stimmen). (c) Positivkontrolle: sauberer Report mit korrekt zugeordneten echten Tool-Namen (`nmap`, `nuclei`) → **Accept**, kein Fehlalarm.
    4. Echter Konstruktionstest: `AgentScanITCrew(target='example.com', scope='full').crew()` baut alle 7 Tasks korrekt, neue Guardrails an den richtigen Agents (`Attack Surface Analyst` = red, `Pentest Recon Report Writer` = report) verdrahtet.
  - **Folgefund + zweiter Fix (2026-09-11, echter E2E-Scan `oldenburg.de full`):** Der geplante End-to-End-Test lief — und deckte auf, dass `_confirmed_findings_tool_guardrail` **wirkungslos war**: der finale Report (`final_report_oldenburg.de_20260911_204710.md`) nennt `nikto_scanner`/`sslscan_tls` als Quelle für 3 Findings ("Swagger UI exposed", "Directory listing enabled", "weak cipher suites"), obwohl `nikto`/`sslscan` in dieser Session **nie aufgerufen wurden** (echte Tools laut Trace: `curl, httpx, nmap, nvd_cpe_lookup, searchsploit, subfinder, whatweb, whois`) — kein Reject erfolgte, der Scan lief mit Grade A 87.7/100 sauber durch.
    - **Root Cause:** `output.raw` beim Report-Task ist die **rohe JSON-Antwort** (`{"path":...,"executive_summary":"# Recon Report:...\n\n##..."}`, bestätigt via `crew_oldenburg.de_*.json`-Preview) — die Zeilenumbrüche darin sind JSON-escaped (zwei Zeichen `\`+`n`, kein echtes `\n`). `.splitlines()` und die `_CONFIRMED_FINDINGS_SECTION_RE`-Regex brauchen echte Zeilenumbrüche → fanden dadurch **keine einzige Tabellenzeile**, die Prüfschleife lief leer durch und akzeptierte stillschweigend. Der ursprüngliche Verhaltenstest (Punkt 3b oben) hatte fälschlich die bereits sauber gespeicherte `.md`-Datei (mit echten Newlines) verwendet statt der rohen LLM-JSON-Antwort — deckte den Bug deshalb nicht auf.
    - **Fix:** Guardrail liest jetzt bevorzugt aus `output.pydantic.executive_summary` (bereits von Pydantic geparst → echte Python-Newlines); Fallback: `raw` selbst per `json.loads()` parsen und das Feld entpacken; nur als letzter Fallback `raw` direkt als Text verwenden.
    - **Verifiziert:** gegen eine realistische JSON-escapte Rohform des echten oldenburg.de-Reports (sowohl mit `pydantic=None`/nur-raw-Pfad als auch mit gesetztem `ReportOutput`-Objekt) → **Reject**, erkennt `nikto_scanner`/`sslscan_tls`/`nmap_scanner`/`curl_http_headers` korrekt als fabriziert. Positivkontrolle (sauberer Report, JSON-escaped) → weiterhin **Accept**, kein Fehlalarm.
    - **Wichtig:** `final_report_oldenburg.de_20260911_204710.md` (der Report AUS DIESEM Lauf) enthält also noch die fehlerhaften Tool-Zuordnungen — er wurde VOR dem zweiten Fix erzeugt. Nicht als Beleg für "Guardrail funktioniert" verwenden; ein neuer Scan mit dem jetzt gefixten Code steht noch aus.
  - **Live-Bestätigung (2026-09-11, zweiter `oldenburg.de full`-Lauf mit dem gefixten Guardrail — schließt den zuvor offenen Backlog-Punkt "echter E2E-Scan mit dem gefixten Guardrail steht noch aus"):** Grade A 90.9/100, Exit 0, `RECON_LLM_DEBUG=1` → 33 Calls / 4 Leerantworten (flache Ketten, 2–3 Nachrichten — nicht das BUG-19-Muster, Retries fingen es sauber ab). **"Confirmed Findings"-Tabelle diesmal komplett korrekt:** alle 7 Zeilen (`nmap`, `nikto`×3, `whatweb`, `subfinder`, `dig`) matchen exakt die real gelaufenen Tools laut Trace (`dig, httpx, nikto, nmap, nvd_cpe_lookup, searchsploit, subfinder, whatweb, whois`) — keine Fabrikation, keine Suffix-Mismatches (`nmap` statt `nmap_scanner` etc.). Kein Guardrail-Reject im Log sichtbar — der Reporter hat diesmal von sich aus korrekt zugeordnet; die Guardrail lief im Hintergrund mit (kein Crash, kein Fehlalarm auf dem sauberen Report). Bestätigt zusammen mit der vorherigen Unit-Verifikation (Reject-Pfad gegen reale escaped-JSON-Rohdaten) beide Seiten: Guardrail blockt Fabrikation UND lässt saubere Reports unangetastet durch.
  - **Status:** Umgesetzt (2 Fixes), Unit- UND Live-verifiziert, nicht committet. `_searchsploit_version_guardrail` (red-Task) ist von diesem spezifischen Bug nicht betroffen — der arbeitet auf Pydantic-Listenfeldern, nicht auf raw-Text-Regex.

- **BACKLOG-FIX (2026-09-11, UMGESETZT + verifiziert, noch NICHT committet) — Critical-Count-Inkonsistenz zwischen Team 3 und Team 6:** Beim `rastede.de full`-Verifikationsscan zeigte der Final Report "Critical: 13", der Risk Score für denselben Scan "Critical CVEs: 14". Root Cause: `risk_scorer/risk_flow.py` zählte Severities direkt aus dem ungefilterten `nvd_results` (jede NVD-bestätigte CVE zählt), während `reporting_flow.py` seit BUG-17/BUG-22 nur versions-bestätigte + KEV-CVEs zählt (`_counted = version_ok + version_unk_kev`). Zwei Teams, zwei unterschiedliche Zählbasen auf denselben Rohdaten → für denselben Scan zwei widersprüchliche Zahlen im Report-Set. Kein Scan-Fehler, reine Report-Inkonsistenz.
  - **Fix:** neues gemeinsames Modul [`cve_filters.py`](cve_filters.py) (Root, Single Source of Truth) — extrahiert aus `reporting_flow.py`: `cve_product_keywords()`, `version_confirmed_in_scan()` (BUG-17-Gate), `is_kev()`, `valid_nvd_results()`, `split_by_version_gate()`, `counted_cves()` (version_ok + KEV-Ausnahmen — exakt das was reporting als "Gelistet" zählt), `severity_counts()`, `load_scan_body()` (liest + extrahiert den recon_report-Body für die Versions-Suche, gleiche Logik wie zuvor lokal in `reporting_flow.merge()`).
  - `reporting/reporting_flow.py`: lokale Kopien von `_cve_product_keywords`/`_version_confirmed_in_scan`/`_is_kev` entfernt, nutzt jetzt `cve_filters.*` — Output/Text unverändert (reine Delegation, keine Verhaltensänderung).
  - `risk_scorer/risk_flow.py`: `RiskState` neues Feld `scan_body` (aus `summary["report"]` via `cve_filters.load_scan_body()` in `load_data()`). `calculate_score()`: `critical_count`/`high_count` werden jetzt aus `cve_filters.counted_cves(nvd_data, scan_body)` + `severity_counts()` berechnet statt aus dem ungefilterten `top_findings`/`nvd_results`-Abgleich. Kein Signatur-Change an `run_risk_flow()` nötig (Report-Pfad kam schon vorher aus der geladenen `workflow_last.json`).
  - **Verifiziert:** `py_compile` sauber. Isolierter `cve_filters`-Test (regreSSHion-artiges CPE-Ordering + KEV-Ausnahme ohne Version + Negativkontrolle ohne Scan-Body) — korrekt. Echter End-to-End-Lauf beider Flows (`RiskFlow` + `ReportingFlow`) gegen identische synthetische NVD-Daten (4 CVEs: 2 versions-bestätigt, 1 versionslos+KEV, 1 versionslos+generisch) → **beide Teams liefern jetzt identisch Critical=2/High=1** (vorher hätte Risk Scorer 3 Critical gezählt). Zusätzliche gezielte Negativkontrolle (CRITICAL, versionslos, NICHT KEV) bestätigt: alter Zählweg hätte 2 Critical geliefert, neuer korrekt 1 — schließt die Lücke nachweislich.
  - **Nebenbefund — GEFIXT (2026-09-12):** `is_kev()`-Heuristik (übernommen unverändert aus dem alten `_is_kev`) matchte reine Substrings wie `"known to be exploited"` — eine NVD-Beschreibung mit Verneinung wie `"not known to be exploited"` würde fälschlich als KEV gewertet. Bisher nicht als echtes Problem beobachtet (NVD formuliert Verneinungen so nicht typischerweise). **Fix:** `is_kev()` prüft die Beschreibung jetzt satzweise — ein Satz zählt nur als KEV-Treffer wenn er eine KEV-Phrase enthält UND keinen Verneinungs-Cue (`not/no/n't/without/never/unlikely/no known/not been`) im selben Satz. Verifiziert: `testing/test_cve_filters.py` 10/10 (4 Positiv-, 6 Negativkontrollen inkl. Verneinung in einem ANDEREN Satz, die den Treffer korrekt NICHT unterdrückt), `py_compile` sauber auf `cve_filters.py` + beiden Konsumenten. Committet (`b0c9d8c`).
  - **Folgefund + zweiter Fix (2026-09-12, echter Verifikationsscan `example.com full`):** Der geplante manuelle Scan deckte einen von diesem Fix selbst ausgelösten Folgefehler auf: `risk_score_example.com_*.md` zeigte "Critical CVEs: 0, High CVEs: 0" (korrekt, neuer Fix), aber gleichzeitig "Risk Score: 9.8/10 — CRITICAL" — Selbstwiderspruch. Root Cause: `base_score` (die Score-Berechnungsbasis) kam weiterhin aus dem UNGEFILTERTEN `top_findings`, während `critical_count`/`high_count` bereits auf die neue Versions-Gate-Filterung umgestellt waren — vor dem Fix waren beide (Count UND Score) gleichermaßen ungefiltert, also zumindest intern konsistent; der erste Fix hat diese interne Konsistenz gebrochen, indem er nur die Counts korrigierte.
    - Konkret ausgelöst durch `CVE-2019-0190` (CVSS 7.5 HIGH): `findings`-Phase interpretierte `sslscan`s eigene Versions-Banner-Zeile ("Version: 2.1.2" = sslscan-Tool-Version, nicht Ziel-TLS-Version) fälschlich als "OpenSSL 2.1.2" auf dem Ziel und fragte NVD danach ab — Versions-Gate erkannte zurecht, dass keine der CPE-Produktbezeichnungen der zurückgegebenen CVE (`apache:http_server`, diverse Oracle-Produkte) im Scan-Body versions-bestätigt ist → korrekt aus dem Final Report ausgeblendet, aber `risk_flow` rechnete trotzdem mit ihrem CVSS 7.5 weiter.
    - **Fix:** `base_score` wird jetzt ebenfalls nur aus `cve_filters.counted_cves()` (derselben Versions-Gate-gefilterten Liste) berechnet. `top_findings`-Anzeige (Markdown + JSON) bleibt vollständig (nichts wird versteckt), aber jede nicht-versions-bestätigte CVE bekommt jetzt ein explizites `⚠️ unbestätigt — keine Versions-Bestätigung`-Label (MD) bzw. `"version_confirmed": false` (JSON) — Transparenz statt Löschen, analog zu reporting_flow's KEV-Ausnahme-Darstellung.
    - **Nebenbefund dabei entdeckt + gefixt:** ein Scoping-Bug in derselben Änderung — die erste Fassung des Top-Findings-Labels referenzierte `nvd_data` (eine lokale Variable aus `calculate_score()`) innerhalb von `write_report()`, wo sie nicht existiert (`NameError` beim ersten echten Lauf wäre die Folge gewesen). Vor dem Commit über `self.state.nvd_results` korrigiert und erneut end-to-end verifiziert.
    - **Verifiziert:** `py_compile` sauber. Exakte Reproduktion des example.com-Szenarios (1 CVE, CVSS 7.5, versionslos) → Score jetzt **0.0/NONE** (vorher 9.8/CRITICAL) bei Critical=0/High=0, Top-Findings zeigt die CVE weiterhin mit `unbestätigt`-Label. Bestehender 4-CVE-Konsistenz-Test (Team 3 == Team 6) läuft nach dieser Änderung weiterhin unverändert grün (Critical=2/High=1/9.8-Score, Team 3 und Team 6 identisch).
  - **Status: COMMITTET** (2026-09-12, Commit `1594400`, nur `cve_filters.py` + `reporting/reporting_flow.py` + `risk_scorer/risk_flow.py` — bewusst NICHT das restliche uncommittete Arbeitsverzeichnis, siehe BUG-25 unten). Manueller Verifikationsscan (User, `example.com full`) bestand — deckte dabei den base_score-Folgefehler auf, der im selben Zug gefixt wurde.

### Aktueller Stand (2026-09-10 — Phase 9 Roadmap-Kapitel + Safety-Gate 9.0, NUR LOKAL, NICHTS COMMITTET)

- **Phase 9 "Exploitation & Validation" neu in `roadmap.md`** (roadmap.md ist gitignored — kein Git-Diff verfügbar, Rollback dort nur manuell): nächste Phase nach PTES-Systematik, direkt auf den Findings der Recon-Suite aufgesetzt (`risk_score_*.json`, `RedOutput.confirmed_attack_surface`/`exploitable_findings`). **Architekturentscheidung dokumentiert:** natives Team 7 statt Bridge zum Schwesterprojekt `pentest-agent/` — dessen "Red Agent" (`pentest_agent_red.py`) hat ausschließlich Recon/Scan-Tool-Funktionen registriert (deckungsgleich mit Team 1), `sqlmap`/`metasploit` tauchen dort nur als ungenutzte String-Whitelist auf, keine passende Runner-Funktion. Kapitel enthält: Tool-Liste in 3 Tiers (Tier 1 Safe Validation / Tier 2 Active Injection / Tier 3 Exploitation-Credentials), Router-Diff (`FULL_ANALYSIS: 1→2→4→[7 Validation]→5→6→3`), neues `ValidationOutput`-Pydantic-Modell (Spezifikation, noch nicht implementiert), Verifikationsplan, aktualisierte Zeitplan-Tabelle (12.5→15 Tage).
- **9.0 "Safety-Gate" implementiert und verifiziert** (Code — **NICHT committet**, siehe Rollback-Kommando unten):
  - NEU `scope_gate.py` (Root): `check_scope(target, enable_injection, enable_exploit, flow_id)` prüft 3 Tiers unabhängig gegen `authorized_scopes.json` (gitignored, Vorlage `authorized_scopes.json.example`). Regeln: **Tier 1** = Whitelist-Eintrag ODER interaktive TTY-Bestätigung (getippter Zielname); **Tier 2** = NUR Whitelist-Eintrag mit `"tier2"`, kein interaktiver Bypass; **Tier 3** = Whitelist-Eintrag mit `"tier3"` UND zusätzlich Live-Bestätigung PRO RUN — in nicht-interaktiven Läufen (Cron/CI, kein TTY) IMMER blockiert, unabhängig von der Whitelist. Jede Entscheidung (erlaubt wie verweigert) wird als JSON-Zeile nach `logs/audit_phase9.jsonl` angehängt (Wer/Was/Wann/Ziel/Begründung).
  - NEU `testing/test_scope_gate.py` — 6 deterministische Tests, kein CrewAI/Ollama nötig, alle grün (`python3 testing/test_scope_gate.py` → `PASS: 6/6`): unlisted target ohne TTY → blockiert; whitelisted tier1 → erlaubt; `--enable-injection` ohne tier2-Whitelist-Eintrag → trotzdem blockiert; tier3 ohne TTY selbst mit voller Whitelist → blockiert; abgelaufene `valid_until` → blockiert; jede Entscheidung landet im Audit-Log.
  - GEÄNDERT `flow.py`: Import `scope_gate as _scope_gate`. `ScanState` +4 Felder (`enable_injection: bool = False`, `enable_exploit: bool = False`, `scope_authorized: bool = False`, `scope_gate_reason: str = ""`). Neuer `@listen(run_threat_intel)`-Step `run_validation_gate` (No-op wenn `has_exploitable=False`; sonst `_scope_gate.check_scope()` aufrufen und `scope_authorized`/`scope_gate_reason` setzen). `run_compliance` hört jetzt auf `run_validation_gate` statt direkt auf `run_threat_intel` (Kette bleibt für `cve_analysis`- und `full_analysis`-Route intakt, da `run_validation_gate` bei `has_exploitable=False` durchreicht). `run_flow()`-Signatur um `enable_injection`/`enable_exploit` (Default `False`) erweitert.
  - GEÄNDERT `main.py`: neue CLI-Flags `--enable-injection` / `--enable-exploit` (Default OFF, gleiches Muster wie `--log-llm`), durchgereicht an `run_flow()`.
  - GEÄNDERT `.gitignore`: `authorized_scopes.json` ergänzt (Engagement-Scope, analog `models.json`).
  - **Wichtig — Team 7 führt noch KEINE aktiven Tools aus.** `run_validation_gate` meldet aktuell nur bestanden/nicht bestanden + schreibt den Audit-Trail; die Tier-1-Tool-Wrapper (Phase 9.1, `agentscanit/tools/exploitation.py`) und der `validation_agent` (Phase 9.2) existieren noch nicht. Das ist beabsichtigt — Safety-Gate zuerst, vor jedem aktiven Tool.
  - **Verifiziert:** `py_compile` auf allen geänderten/neuen Dateien sauber; `flow.py` real importiert (State-Defaults korrekt, `run_validation_gate` als Step vorhanden); `main.py`-Flag-Parsing isoliert getestet; alle 6 Scope-Gate-Tests grün.

**Rollback (nichts davon ist committet — `git status` zeigt `.gitignore`/`flow.py`/`main.py` als modified, den Rest als untracked):**
```bash
cd /opt/projects/agentic-ai/recon-suite
git checkout -- .gitignore flow.py main.py
rm -f scope_gate.py authorized_scopes.json.example testing/test_scope_gate.py
```
`roadmap.md` ist gitignored (kein Git-Diff möglich) — das Kapitel `## Phase 9: Exploitation & Validation` (bis vor `## Zusammenfassung Zeitplan`) müsste dort manuell entfernt werden, inkl. der Zeitplan-Zeile `| 9 | Exploitation & Validation ... |` und der Korrektur `~15 Tage` → `~12.5 Tage`.

### Aktueller Stand (2026-06-27 — Finale Matrix 5/7 belegt, 2 offen)
- **FINALE VOLL-MATRIX zu 5/7 Targets durchgeführt (Remote qwen3-coder:480b).** Über mehrere Session-Limit-Resets verteilt (free-tier: Session-Limit ~alle 3h, Weekly bei 91% am Sessionende). Bei jedem Limit **sauber abgebrochen** (exit≠0-Filter verhindert Verfälschung). Volldetails: `testing/TESTKONZEPT.md` §8/§9.
  - ✅ **Tomcat 8.5.19** (TP): CVE-2017-12615 in **4/4** Läufen (Recall 1.0)
  - ✅ **WebLogic 12.2.1.3** (TP): CVE-2023-21839 in **4/4** Läufen (Recall 1.0)
  - ✅ **scanme.nmap.org** (TP): CVE-2018-15473 gefunden (1 valider Lauf; Rest nmap.org 12/Tag-Limit)
  - ✅ **petstore.swagger.io** (feature): PASS — swagger.json [200] via httpx `api_probe`
  - ✅ **proofpoint.com** (feature): PASS — **dnsx + katana ERSTMALS vom Agenten ausgelöst** (tool-bestätigt, katana crawlte 8 Subdomains). LÖST den seit Projektbeginn offenen Punkt „dnsx/katana mit qwen3-coder nie provoziert".
  - ✅ **Nachgeholt (2026-09-12): nginx-TN + waf-cloudflare.** `nginx-clean-baseline`: PASS, alle 3 Dimensionen 1/1. `waf-cloudflare`: erster Lauf `exit=1` nach 1746s (`run_matrix.py` gab dabei keine Fehlermeldung aus — Harness-Gap, siehe unten). Direkte Reproduktion zeigte den echten Fehler: bekannte `ReportOutput`-JSON-Trunkierung (BUG-24/26-Muster) plus zwei NEUE, live gefundene Fabrikationsfälle (Confirmed-Findings-Zeile mit leerer Tool-Spalte + `tools_executed` nannte `wafw00f`, das nie lief) — beide noch am selben Tag gefixt (siehe `efd6a27`/`c8431fb` unten) und der Matrixlauf danach wiederholt: `exit=0`, Dim1 1/1, Dim2 1/1, **Feature 0/1** (ehrliches Ergebnis: `wafw00f` wird vom Modell nicht zuverlässig aufgerufen — agent-ermessensabhängig, gleiche Kategorie wie `dnsx`/`katana`, kein Guardrail erzwingt den Aufruf selbst, nur die Fabrikation bei Nicht-Aufruf ist jetzt verhindert). `run_matrix.py` gibt bei Fehlschlag jetzt stdout/stderr aus (`7413166`).
  - **Kern-Erkenntnis:** CVE-Recall 1.0 + 0 Halluzinationen über alle TP-Läufe → Wahrheitsgehalt für versions-präzise Targets bestätigt. **Methodischer Befund (kein Framework-Fehler):** Tomcat+WebLogic liefen parallel auf 127.0.0.1 (Container-Lifecycle überlappte, beide Ports in allen Traces) → beide CVEs gefunden, aber nicht isoliert getrennt. Backlog: `container_up`/`container_down` strikt sequenziell.
  - **NUR LOKAL:** Matrix-Artefakte + TESTKONZEPT §8/§9 (testing/, nicht gepusht). CLAUDE.md (dieser Block) ist push-bar.

### Aktueller Stand (2026-06-26, Nachmittag — Harness-Fertigstellung)
- **TESTKONZEPT-HARNESS WEITGEHEND FERTIGGESTELLT (2026-06-26, NUR LOKAL in `testing/`, nicht gepusht).** Plan + Details: `docs/harness-fertigstellung-plan.md`. Schritte 1–7 umgesetzt + verifiziert (Pos/Neg-Kontrollen):
  - **Schritt 1 — exit≠0-Filter** (`run_matrix.py`): fehlgeschlagene Läufe (`exit!=0`) werden NICHT mehr ausgewertet (sonst griff `_newest` einen alten Report → verfälschte Dim3). `failed`-Flag, aus Konsistenz-Paaren + Dim-Raten entfernt. Verifiziert synthetisch.
  - **Schritt 2 — Ziel-CVE-Konsistenz** (`eval_consistency.py`): neues PRIMÄRES Pass-Kriterium = Anteil der Läufe, die ALLE `must_find_cves` enthalten (Ziel 1.0). Gesamt-CVE-Jaccard nur noch INFO (war zu streng, da Begleit-CVEs legitim schwanken). Verifiziert: Ziel stabil→PASS trotz Jaccard 0.29; Ziel fehlt→FAIL.
  - **Schritt 3 — TN-Target sauber** (`targets.yaml` + `eval_groundtruth.py`): nginx:alpine hat ein ECHTES nuclei-CVE (CVE-2026-42530) → neues `allow_cves`-Feld toleriert bekannte reale CVEs beim TN-Check (statt Target als unsauber zu werten). Verifiziert Pos/Neg.
  - **Schritt 4 — neue Tools im Harness** (`targets.yaml` `kind=feature` + `run_matrix._eval_feature`): WAF (cloudflare) + API (petstore) als Feature-Targets; deterministischer Signatur-Check (WAF/CDN-Block bzw. swagger.json im Report/Trace) statt CVE-Recall. `run_scan` reicht jetzt `objective` durch (objective-getriggerte Tools). Verifiziert Pos/Neg.
  - **Schritt 5 — scanme E2E** (Remote qwen3-coder, N=2): alle Dimensionen PASS, Recall Ziel-CVE CVE-2018-15473 = 1.0, Ziel-CVE-Konsistenz 1.0, 0 Halluzinationen. Die neuen Metriken (1–3) im echten Lauf bestätigt.
  - **Schritt 6 — Lokal-Achse ABGESCHLOSSEN:** 3 Modelle (qwen3-coder:30b erfolglos; llama3.1:8b @ scanme E2E durch aber Tool-Coverage 0/100 + 71min; llama3-groq:8b @ Tomcat Abbruch/zu langsam). **Befund: Framework lokal-fähig** (0 Leerantworten, Halluzinationen korrekt gefiltert — scanme: WebLogic-Fake-CVEs→Final Report 0 CVEs), **aber lokale Modelle/HW zu schwach** (Speed ~0.6 tok/s effektiv + agentic Tool-Coverage). **Remote qwen3-coder:480b bleibt der verlässliche Pfad.** Eingeschobener Zwischenschritt (extern beim User): LLM-Performance-Benchmark — Spec `docs/bench_req.md`, Mindestanforderungen `docs/modell-mindestanforderungen.md`. Letzter Benchmark-Durchlauf, danach Lokal-Achse endgültig zu.
  - **Schritt 7 — dnsx/katana-Target** (`targets.yaml`): proofpoint.com als Feature-Target (~20 echte Subdomains, Ground-Truth aus externem Framework-Scan). **Wichtiger Befund: dnsx/katana sind rein agenten-ermessensabhängig** (KEINE Prompt-Anweisung im research-Task) — Signatur-Fehlschlag = valider Befund, kein Harness-Fehler.
  - **OFFEN (bewusst pausiert): finale Voll-Matrix** (6 Targets × N=4 ≈ 24 Scans, Remote). **Verschoben auf nach Weekly-Limit-Reset von qwen3-coder:480b (~2 Tage)** — bei 26% Restbudget würde die volle Bandbreite abbrechen. Code/Config dafür steht; nur die Ausführung fehlt.
  - **CrewAI 1.15.0 Upgrade:** ERLEDIGT — siehe "CrewAI-Update 1.14.7 → 1.15.21" oben (Stand 2026-09-11): kompatibilitätsgeprüft, kein Breaking Change, `checkpoint`-Feature bewusst inaktiv gelassen. Details damals geplant unter `docs/harness-fertigstellung-plan.md` §5.

### Aktueller Stand (2026-06-26)
- **TOOL-ERWEITERUNGEN: WAF-Erkennung + API-/Misconfig-Erkennung + venv-Konsolidierung (2026-06-26, Commit `0f23f73`)** — abgeleitet aus `docs/bewertung_recon-suite.md` (Lücken-Katalog; bleibt LOKAL, nicht gepusht). Drei Lücken geschlossen (#1/#4/#7), eine bewusst abgelehnt (#9):
  - **NEU: `Wafw00fTool` (`wafw00f_detect`)** in `tools/active_scanning.py`, am blue_agent, läuft bei web/full **zuerst**. Erkennt WAF/CDN (Cloudflare, Akamai, ModSecurity u.a.) via `wafw00f -a`. Graceful-disable via `shutil.which` (wie theHarvester). `WAFW00F_BIN` in config.py. **Report-Hinweis deterministisch:** `_waf_detection_guardrail` (tasks.py, am blue-Task) liest wafw00f-Output aus dem Session-Trace und hängt bei Treffer `=== WAF/CDN DETECTED ===` an den blue-Output → fließt via context in findings + Final Report. ANSI-Strip + Ausschluss der generischen Fallback-Zeile. Zweck: leeres CVE-Ergebnis hinter WAF ist NICHT „Ziel sicher". Verifiziert Pos/Neg (Cloudflare erkannt, scanme.nmap.org leer). **Wichtig: wafw00f liegt im Root-`venv` (pip), nur bei AKTIVEM venv im PATH** — sonst greift graceful-disable.
  - **API-Service-Erkennung (objective-getriggert):** httpx-Tool neuer `api_probe`-Parameter — probt eine **kuratierte feste Pfadliste** (16 kanonische API-/Doku-Pfade: /api, /graphql, /v2/swagger.json, /openapi.json, /actuator …), meldet Status+Content-Type (`-mc 200,201,401,403 -content-type -no-color`; 401/403 = „existiert"). NUR Erkennung, KEIN Fuzzing/keine Enumeration (Scope-Grenze). nuclei: Tags `exposures,graphql,swagger` dokumentiert (kein Code-Change). blue-Task weist beides NUR an wenn Objective API/REST/GraphQL/Swagger erwähnt. Verifiziert: petstore.swagger.io → `/v2/swagger.json [200] [application/json]`; scanme leer.
  - **CORS/Misconfiguration-Checks (objective-getriggert):** nuclei `tags='misconfiguration,cors,redirect'` — NUR wenn Objective Fehlkonfiguration/CORS/Open-Redirect nennt. Keine separate Phase (bewusst leichtgewichtig). Verifiziert: nuclei lädt real Templates (misconfiguration 9, cors 6, redirect 186), E2E sauber.
  - **venv-Konsolidierung:** doppeltes venv (`recon-suite/venv` 936 MB + `agentscanit/venv` 934 MB) → **ein Root-venv** (`recon-suite/venv`, hat crewai 1.14.7 + wafw00f). `agentscanit/venv` gelöscht (934 MB frei). `VENV_PYTHON` in config.py von `PROJECT_DIR/venv` auf `_SUITE_DIR/venv` umgestellt; `debugging/run_timed.py` + `diagnose_hang.py` auf Root-venv; py-spy nachinstalliert. **Erkenntnis: die Suite greift beim Scan auf System-Binaries AUSSERHALB des Projekts zu** (`/usr/bin/*`, `/snap/bin/httpx`, `/root/go/bin/*`, `/usr/local/bin/searchsploit`) — venv kapselt nur Python-Deps, nicht die 18 Scan-Tools (→ `setup_tools.sh`). Hart kodierte Pfade (`HTTPX_BIN`, `SEARCHSPLOIT_BIN`) sind fragil (Backlog: auf `shutil.which`+Fallback härten, siehe `docs/docker-image-konzept.md`).
  - **#9 OSV/GHSA bewusst ABGELEHNT:** package-/ecosystem-zentriert (npm/PyPI/Maven), passt NICHT zum Infra-/CPE-Scope der Suite (Server-Banner → NVD/CPE ist der richtige Weg). Realer offener Punkt ist NVD-Verfügbarkeit (BUG-14, Single Point of Failure), nicht die fehlende Quelle.
  - **Pattern für künftige Tool-Erweiterungen:** objective-getriggert (Prompt-Regel `NUR wenn Objective X erwähnt`, gleiches Muster wie bestehende Fuzzing-Bedingung) + vorhandene Tools nutzen statt neue Tools, wo möglich. Deterministische Report-Anreicherung über Guardrail (vgl. BUG-20: Kontrolle braucht Guardrail, nicht Prompt-Bitte).
  - **NUR LOKAL (nicht gepusht):** `docs/` (Konzept-/Bewertungs-Docs: bewertung_recon-suite, inkrementelles-scannen, docker-image-konzept) + die `logs copy*`-Ordner.
- **PENTEST-SCOPE-REPORTING-UMBAU (2026-06-25)** — drei Audit-Checks (CrewAI-Konformität, Berichts-Detailtiefe, Pentest-Terminologie) durchgeführt. **Check 1: ✅ Framework-konform** (idiomatischer Flow/Router/Guardrails/output_pydantic, gut dokumentiert). **Check 2 + 3 ergaben Handlungsbedarf, umgebaut:**
  - **compliance_flow.py:** OWASP-Mapping von Audit- auf PENTEST-Terminologie. **Strikte PoC-Schranke deterministisch** (`_extract_nuclei_poc`): nur nuclei-verifizierte Treffer gegen DIESES Target (`[CVE] [http] [critical/high] <url>`) zählen als „nachgewiesen ausnutzbar" — nicht LLM-Einschätzung „PoC existiert irgendwo". Mit PoC → Exploit-Ansatz + Endpunkte/Payloads für Exploit-Entwicklung + Remediation NUR für verifizierte Findings. Ohne PoC → nur Angriffsfläche/Ansatzpunkte, KEINE Härtungsempfehlung, Wortwahl „potenziell" statt „nachgewiesen", Severity max High. Verifiziert: rastede (kein nuclei-PoC) 3→0 „nachgewiesen", Severity≤High; WebLogic (5 nuclei-CVEs) → Exploit-Details mit Endpunkten.
  - **tasks.py reporter-Task:** „KOMPAKT-PFLICHT max 5 Zeilen / im Zweifel weglassen" → **DETAIL-PFLICHT** für pentest-relevante Infos (exakte Versionen inkl. Patch-Level, Angriffsvektoren wie T3 explizit, exponierte Dienste mit Service-Hypothese, interessante Endpunkte). Verifiziert: WebLogic-Scan zeigt jetzt `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16`, T3 als Vektor markiert, Ollama/OpenClaw-Ports identifiziert, OpenSSH-CVEs mit Beschreibung.
  - **risk_flow.py `_next_steps`:** Defender-Empfehlungen („isolieren/patchen/Monitoring") → Angriffs-Priorisierung („Exploit entwickeln", „Verkettbarkeit prüfen"). Deterministisch, 0 Defender-Begriffe verifiziert.
  - **reporting_flow.py:** versionslos-Hinweis von „Server-Härtung" auf Angreifer-Schritt („Version fingerprinten, dann gezielter Re-Scan") umformuliert.
  - **Prinzip (Pentest-Scope):** Empfehlungen zur Security-Verbesserung NUR bei nachgewiesener Ausnutzbarkeit (PoC). Sonst Fokus auf Ausnutzung/Exploit-Entwicklung/Angriffsfläche. LLM-Mehrwert = Tool-Daten für Exploit-Entwicklung aufbereiten.
- **setup_tools.sh (2026-06-25):** installiert die 18 externen Scan-Tools (System-Binaries, KEINE Python-Pakete → nicht in requirements.txt). apt + `go install` (ProjectDiscovery) + Git (exploitdb). Idempotent, `--check`-Modus. Wichtig: httpx = ProjectDiscovery-Go, nicht apt/Python-httpx.
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

**GIT-STAND (Stand 2026-06-25, nach Pentest-Scope-Push):**
- **Gepusht** auf `origin/main`: Programm-Commits (BUG-14 bis BUG-21, Modell-Doku, Pentest-Scope-Umbau,
  setup_tools.sh, README/CLAUDE-Doku). Das ausgelieferte Programm ist aktuell auf dem Remote.
- **NUR LOKAL** (bewusst, NICHT pushen ohne Freigabe): das `testing/`-Harness + Matrix-Ergebnisse
  (Verifikations-Infrastruktur, gehört nicht ins ausgelieferte Programm). Commit-Reihenfolge so umgebaut
  dass die Programm-Commits VOR dem testing/-Commit liegen → Push nimmt das Harness nicht mit.
- roadmap.md + models.json bleiben gitignored.

**NÄCHSTE SESSION — offene Punkte (Priorität):**
1. ~~**Gesamt-E2E-Beweis Pentest-Scope**~~ — **erledigt (2026-09-12)**, durch den BUG-18/BUG-25-Verifikationslauf (`example.com full`) nebenbei mitbestätigt: alle 6 Teams liefen (recon/interpret/threatintel/compliance/risk/final), `compliance_example.com_20260912_040914.md` + `risk_score_example.com_20260912_040914.md` durchgängig Angreifer-Perspektive ("Angriffsvektor", "Exploit entwickeln", "keine Remediation ohne nachgewiesenen Exploit"), 0 Defender-Sprache. (Dabei den neuen Backlog-Fund oben entdeckt — sslscan-Banner-Kontamination erreicht auch Team 5/6.)
2. **Lokal-Achse abschließen:** llama3-groq E2E-Scan (network lief durch; findings-CVE-Phase für 8B zu schwach,
   BUG-21-Guardrail greift → ehrlicher Abbruch). Stärkeres lokales Modell testen (qwen3-coder:30b Kandidat).
3. **Testkonzept-Harness-Schwachpunkte** (testing/, lokal): run_matrix exit≠0-Filter + Jaccard-Metrik auf
   versions-verifizierte/Ziel-CVEs. TN-Target sauber (nginx forbid_cves). scanme separat (Rate-Limit).
4. **Optional:** dnsx/katana mit Subdomain-reichem Target provozieren (mit qwen3-coder noch nie ausgelöst).

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
- **Echte Lösung — UMGESETZT + live verifiziert (2026-09-12):** Ein erster Versuch, `num_ctx` linear an die Task-Zahl zu koppeln, scheiterte an echten historischen Debug-Logs — auch ≤5-Task-Scopes hatten dort schon Plan-Prompts >100.000 Zeichen und liefen trotzdem bei festem `num_ctx=4096` nicht-leer durch (Ollama truncatet intern statt hart zu scheitern); eine lineare Schätzung ist also kein verlässlicher Prädiktor und hätte den Zielfall (full) sogar erneut ausgelöst. Stattdessen: `llm_planner` läuft jetzt durchgängig mit der nativen Kontextgrenze des lokalen Modells (`PLANNER_NUM_CTX=32768`, qwen2.5:7b-instruct laut Ollama-Modellkarte). Ressourcen geprüft (59GB RAM frei, CPU-only) — kein Risiko. Das `≤5-Tasks`-Gate in `crew.py` entfällt komplett, `planning=True` für alle Scopes. **Live-verifiziert** (`example.com full`, `RECON_LLM_DEBUG=1`): Planner-Call für 7 Tasks (prompt_chars=93592) lieferte `status=ok, resp_chars=1371` — exakt der Fall, der vorher abbrach. Gesamter Scan lief durch: Grade A 96.9/100, 0/17 Tool-Fehler. Committet (`2669866`).

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
- ~~full-Scope mit Planner (BUG-18 echte Lösung)~~ — **erledigt, siehe oben** (2026-09-12, `num_ctx` auf native Modellgrenze, live verifiziert).
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
- **GEFIXT (2026-09-12):** „Strg+C wirkt nicht" während langer Tool-Scans. Root Cause: CrewAI's natives Tool-Calling ruft `tools/_base.py::_run()` (blockierender subprocess-Call) nicht im Main-Thread auf — SIGINT feuert in CPython nur im Main-Thread, der Worker-Thread blieb im Subprocess-Wait stecken. Fix: `_run()` nutzt jetzt `subprocess.Popen` + eine modulweite Registry aktiver Subprozesse (`_active_procs`); neuer SIGINT-Handler in `main.py` ruft `kill_all_active_procs()` auf (killt alle registrierten Subprozesse direkt per OS-Signal → lässt den blockierenden Call im Worker-Thread sofort zurückkehren) und beendet den Prozess danach hart (`os._exit(130)`). Verifiziert: `testing/test_sigint_fix.py` 5/5 — Kernfall (`_run(["sleep","30"])` in einem Worker-Thread, extern per `kill_all_active_procs()` beendet) kehrt in ~1s statt 30s zurück; Regressionschecks (Timeout/FileNotFoundError/stdin-Pfad) unverändert korrekt. Bewusste Grenze: verifiziert per treuer Cross-Thread-Simulation, nicht per vollem CLI-Test mit echtem Ollama-Scan. Committet (`235c871`).
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
