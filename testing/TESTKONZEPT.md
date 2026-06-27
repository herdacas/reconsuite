# Testkonzept — Wahrheitsgehalt & Konsistenz erfolgreicher Scans

**Status:** Entwurf zur Abstimmung (2026-06-18)
**Zweck:** Systematisch prüfen, ob das Framework *wahre* und *konsistente* Scan-Ergebnisse liefert — über Remote- (Ollama API) und Lokal-Modelle hinweg.

---

## 1. Warum ein eigenes Testkonzept?

Ein agentisches Scan-Framework hat eine Fehlerquelle, die klassisches Testing nicht erfasst:
**Zwischen "das Tool funktioniert" und "der Report stimmt" sitzt ein LLM**, das

1. Tool-**Inputs formuliert** (z.B. `nmap -p 1-65535 <target>`), und
2. Tool-**Outputs interpretiert** (z.B. "Port 7001 → Oracle WebLogic → CVE-2023-21839").

An beiden Stellen kann das LLM Fehler machen, ohne dass ein einzelnes Tool versagt:
- verstümmeltes Target-Argument (`whatweb https://://?`) → Tool läuft, Ergebnis nutzlos
- halluzinierte CVE, die in keinem Tool-Output stand
- übersehene CVE, die im Tool-Output stand aber nicht in den Report kam

Diese Fehler sind **stochastisch** (mal da, mal nicht) und **modellabhängig** — deshalb braucht
es Wiederholung (Konsistenz) und einen Remote/Lokal-Vergleich.

**Methodische Grundlage** (etablierte Agent-Evaluation, 2025/26):
- **Trajectory-Evaluation** (der *Weg*): Tool-Calls + Inputs + Output-Interpretation → diagnostiziert *warum*.
- **Output-Evaluation** (das *Ergebnis*): finaler Report vs. bekannte Wahrheit → bestätigt *was*.
- **k-trial Consistency**: gleiche Aufgabe N× → Varianz messen (LLMs sind nicht deterministisch).
- Quellen: Berkeley Function-Calling Leaderboard (Tool/Argument Correctness), ReliabilityBench
  (Konsistenz/Robustheit/Fehlertoleranz), T-Eval / AgentBoard (Trajectory vs. Ground-Truth).

---

## 2. Die vier Prüf-Dimensionen

Jede Dimension ist so gewählt, dass sie **möglichst deterministisch** aus vorhandenen Artefakten
(`trace_*.json`, `crew_*.json`, `final_report_*.md`, `llm_debug_*.jsonl`) messbar ist — ohne teuren
LLM-Judge, wo es geht.

### Dimension 1 — Tool-Input-Korrektheit  *(= „Input zu den Tools")*

**Frage:** Bekommt jedes Tool valide, sinnvolle Argumente?

**Datenquelle:** `trace_*.json` → pro Tool-Call die Felder `command` (tatsächlich ausgeführte
Kommandozeile), `agent_params` (was der Agent dem Tool übergab), `tool_name`.

**Checks (deterministisch):**
| Check | Regel | Fehlerbeispiel (real beobachtet) |
|---|---|---|
| Target-Integrität | Das Target-Argument enthält den Scan-Target-Host (oder eine entdeckte Subdomain/IP), nicht verstümmelt | `dnsrecon -d wenum?`, `whatweb https://://?` |
| Kein leeres/Platzhalter-Arg | kein `?`, kein leerer String, kein `<target>`-Literal | `theHarvester -d westernde?` |
| Flag-Plausibilität | tool-spezifisch: nmap hat Ports/`-sV`, nuclei hat `-u`+templates, nikto hat `-h` | nmap ohne Target |
| Scope-Konformität | nur Tools die der Scope erlaubt (`_SCOPE_CEILING`) wurden genutzt | ssl-Scope ruft nuclei auf |

**Metrik:** `input_valid_rate = valide Tool-Calls / alle Tool-Calls`. Ziel: **≥ 0.95**.
Verstümmelte Inputs werden namentlich gelistet (welches Tool, welche Phase, welches Arg).

### Dimension 2 — Tool-Output-Handling  *(= „Output der Tools")*

**Frage:** Übernimmt der Agent die Tool-Ergebnisse korrekt — ohne zu halluzinieren oder auszulassen?

**Datenquelle:** `trace_*.json` (raw_output je Call) + `crew_*.json` (strukturierte Agent-Outputs:
`cve_references`, `open_ports`, `confirmed_attack_surface`).

**Checks:**
| Check | Methode | Determinismus |
|---|---|---|
| **Keine Halluzination** | Jede CVE/Port im Agent-Output muss in einem Tool-raw_output dieser Session vorkommen (`run_trace.cve_in_raw_outputs`) | ✅ deterministisch (Baustein existiert) |
| **Keine Auslassung** | Ports/Services die nmap fand, müssen im strukturierten Output erscheinen | ✅ deterministisch (Regex auf raw_output vs. structured) |
| **Korrekte Service→CPE-Zuordnung** | erkannter Banner → richtiges CPE (z.B. `Apache-Coyote` → tomcat, nicht apache httpd) | teils deterministisch (cpe_map), teils Review |
| **Versions-Treue** | wenn eine Version im Banner steht, wird sie nicht ignoriert/erfunden | ⚠️ LLM-Judge oder Stichprobe |

**Metriken:** `hallucination_count` (Ziel: **0**), `omission_count` (Ziel: **0** für Ports;
CVE-Auslassung tolerierbar wenn begründet), `cpe_mismatch_count`.

### Dimension 3 — Ground-Truth-Treffer  *(Output-Evaluation)*

**Frage:** Findet das Framework die bekannten Schwachstellen — und erfindet es keine?

**Datenquelle:** `final_report_*.md` + Soll-Liste pro Target (`targets.yaml`).

**Voraussetzung:** Targets mit **vorab exakt bekannten** CVEs:
- **VulHub-Container** (Goldstandard, NVD-unabhängig): Tomcat 8.5.19 → CVE-2017-12615;
  WebLogic 12.2.1.3 → CVE-2023-21839 (+CVE-2018-2628).
- **scanme.nmap.org**: OpenSSH 6.6.1p1 → CVE-2018-15473, CVE-2016-10009/10010.
- **CLEAN-Target** (True-Negative): ein gehärteter Host → **darf keine** kritische CVE melden.

**Metriken (Precision/Recall gegen Soll-Liste):**
- **Recall** = gefundene Soll-CVEs / alle Soll-CVEs. Ziel: **1.0** für die designierten Ziel-CVEs.
- **Precision-Proxy** = (keine erfundene/versionslos-spekulative CVE als „confirmed"). Ziel: **keine FP**
  in der „Versions-verifiziert"-Sektion (BUG-17 trennt diese bereits).
- **True-Negative-Test**: CLEAN-Target → CLEAN-Route, 0 confirmed CVEs.

### Dimension 4 — Konsistenz (k-trial)

**Frage:** Liefert derselbe Scan bei N Wiederholungen dasselbe Ergebnis?

**Vorgehen:** Identischer Scan (gleiches Target/Scope/Modell) **N≥3 mal** (Empfehlung 5).

**Metriken:**
- `cve_jaccard` = mittlere Jaccard-Ähnlichkeit der CVE-Mengen über die N Läufe. Ziel: **≥ 0.8**.
- `port_consistency` = identische offene-Ports-Menge über alle Läufe (sollte 1.0 sein — Ports sind
  deterministisch, Varianz hier = echtes Problem).
- `grade_stddev` = Streuung des Scorecard-Gesamtscores. Ziel: **σ ≤ 5 Punkte**.
- `target_arg_garble_rate` = Anteil Läufe mit ≥1 verstümmeltem Tool-Input (Dim 1 über N Läufe).

**Wichtig:** Server-Ausfälle (NVD 503, Ollama 500) sind als *Infrastruktur*-Varianz von
*Modell*-Varianz zu trennen — der Debug-Logger + `is_error`-Felder erlauben das.

---

## 3. Die Modell-Matrix (Remote × Lokal)

Jeder Test läuft in **zwei Konfigurationen**, gesteuert über `models.json`:

| Konfiguration | Worker-Modell | Planner | Zweck |
|---|---|---|---|
| **REMOTE** | `qwen3-coder:480b` (ollama.com) | lokal qwen2.5:7b | Produktiv-Setup (aktuell) |
| **LOKAL** | `qwen2.5-coder:14b` (localhost) | lokal qwen2.5:7b | Offline/autark-Setup |

**Vergleichsfragen über die Matrix:**
- Finden beide dieselben Ground-Truth-CVEs? (Dim 3 remote vs. lokal)
- Ist die Tool-Input-Qualität gleich? (Dim 1 — verstümmelt ein Modell mehr Targets?)
- Welches ist konsistenter? (Dim 4 — Varianz remote vs. lokal)
- Performance/Kosten: Laufzeit, Anzahl LLM-Calls, Leerantwort-Rate (aus `llm_debug`).

**Bekannte Asymmetrien (vorab dokumentiert):**
- Lokal ist RAM-begrenzt (64 GB, kein GPU) → langsamer, evtl. kleineres `num_ctx`.
- `full`-Scope: Planner ist bei beiden aus (BUG-18, >5 Tasks).
- Remote `gpt-oss` ist NICHT mehr Teil der Matrix (BUG-19 — durch qwen3-coder ersetzt).

---

## 4. Test-Matrix (konkret)

```
{ Targets }            ×  { Konfiguration }  ×  { N Läufe }
─────────────────────     ───────────────     ──────────
VulHub Tomcat (TP)        REMOTE              3–5
VulHub WebLogic (TP)      LOKAL               3–5
scanme.nmap.org (TP)
CLEAN-Target (TN)
```

Minimal-Set für Aussagekraft: **4 Targets × 2 Konfigs × 3 Läufe = 24 Scans**.
Voll (5 Läufe): 40 Scans. Wegen Laufzeit (full ~12–15 min, network ~9 min) ist die
Target/Scope-Wahl entscheidend — Vorschlag: TP-Targets im `network`-Scope (schneller, deckt
Tool-Input + CVE-Findung ab), 1× `full` pro Konfig für die späten Phasen (red_scan/coding).

---

## 5. Geplante Harness-Struktur (Code — erst nach Konzept-Freigabe)

```
testing/
├── TESTKONZEPT.md           # dieses Dokument
├── targets.yaml             # Ground-Truth pro Target (Ports, Services, Soll-CVEs, TP/TN)
├── eval_tool_input.py       # Dim 1 — Trace-Parser, Target-Integrität, Scope-Konformität
├── eval_tool_output.py      # Dim 2 — Halluzination/Auslassung (nutzt cve_in_raw_outputs)
├── eval_groundtruth.py      # Dim 3 — Precision/Recall gegen targets.yaml
├── eval_consistency.py      # Dim 4 — N-Läufe-Aggregation (Jaccard, stddev)
├── run_matrix.py            # Orchestriert {targets}×{configs}×{N}, schaltet models.json um
└── results/                 # JSON+Markdown-Reports pro Matrix-Lauf
```

**Wiederverwendbare Bausteine (existieren bereits):**
- `tools/trace.py::cve_in_raw_outputs()` — CVE-Cross-Check (Dim 2)
- `quality.py::score_scan()` — Scorecard (Dim 4 grade_stddev)
- `tasks.py::_scope_coverage_guardrail` Logik — Scope-Konformität (Dim 1)
- `cpe_map.py` — Service→CPE-Erwartung (Dim 2)
- `RECON_LLM_DEBUG` Logger — LLM-Ebene (Leerantworten, Prompt-Größen)

**Designprinzip:** Die Eval-Skripte lesen **nur Artefakte** (Trace/crew/report/debug-jsonl) —
sie ändern nichts am Framework und laufen *nach* den Scans. Reproduzierbar, CI-fähig.

---

## 6. Offene Designfragen (vor dem Code zu klären)

1. **`models.json`-Umschaltung automatisieren?** `run_matrix.py` müsste zwischen REMOTE/LOKAL
   umschalten. models.json ist gitignored (API-Key) → entweder zwei Profil-Dateien
   (`models.remote.json`/`models.local.json`) die das Skript kopiert, oder Env-Var-Override.
2. **CLEAN-Target wählen:** Welcher Host ist verlässlich „sauber" + scan-erlaubt? (Kandidat:
   ein gehärteter eigener Host, oder example.com — aber der hat kaum Angriffsfläche.)
3. **LLM-Judge für Dim 2 Versions-Treue?** Optional — kostet Remote-Calls. Alternative: Stichprobe
   manuell. Vorschlag: zunächst rein deterministisch, LLM-Judge als spätere Ausbaustufe.
4. **N (Wiederholungen):** 3 (schnell, grobe Varianz) vs. 5 (belastbarer, doppelte Zeit).
5. **VulHub-Container-Lifecycle:** `run_matrix.py` startet/stoppt die Container automatisch
   (snap-Docker braucht `/root`-Pfad, siehe CLAUDE.md) oder werden sie vorab manuell hochgefahren?

---

## 7. Erwartetes Ergebnis

Ein wiederholbarer **Truth-&-Consistency-Report** pro Matrix-Lauf:

```
Target            Config   Recall  Halluz  InputValid  CVE-Jaccard  Grade σ
Tomcat 8.5.19     REMOTE   1.00    0       0.97        0.85         2.1
Tomcat 8.5.19     LOKAL    1.00    0       0.91        0.78         4.8
WebLogic 12.2.1.3 REMOTE   1.00    0       1.00        0.90         1.5
...
```

Damit lässt sich faktenbasiert sagen: *Liefert das Framework wahre, konsistente Ergebnisse —
und tut es das mit beiden Modell-Setups gleichermaßen?*

---

## 8. ERGEBNIS — Matrix-Lauf 2026-06-27 (Remote qwen3-coder:480b)

Stand: 5 von 7 Targets belegt. Lauf über mehrere Session-Limit-Resets verteilt
(qwen3-coder:480b free-tier: Session-Limit ~alle 3h, Weekly knapp). Bei jedem Limit
**sauber abgebrochen** (kein Verfälschen durch exit≠0-Läufe — Schritt-1-Filter greift).

| Target | Kind | Ergebnis |
|---|---|---|
| Tomcat 8.5.19 | TP | ✅ **CVE-2017-12615 in 4/4 Läufen** (Recall 1.0) |
| WebLogic 12.2.1.3 | TP | ✅ **CVE-2023-21839 in 4/4 Läufen** (Recall 1.0) |
| scanme.nmap.org | TP | ✅ **CVE-2018-15473** gefunden (1 valider Lauf; Rest nmap.org 12/Tag-Limit) |
| petstore.swagger.io | feature | ✅ **PASS** — `swagger.json [200]` via httpx api_probe erkannt |
| proofpoint.com | feature | ✅ **PASS** — **dnsx + katana ERSTMALS vom Agenten ausgelöst** (tool-bestätigt: dnsx `-silent -resp`, katana auf 8 Subdomains) |
| nginx:alpine | TN | ⏳ OFFEN — beim Session-Limit-Abbruch nicht abgeschlossen |
| waf-cloudflare | feature | ⏳ OFFEN — beim Session-Limit-Abbruch nicht abgeschlossen |

**Kern-Erkenntnisse:**
1. **CVE-Recall 1.0** über alle TP-Container-Läufe, **0 Halluzinationen** (Dim 1+2 durchg.) —
   bestätigt den Wahrheitsgehalt für versions-präzise Targets.
2. **Durchbruch dnsx/katana:** der seit Projektbeginn offene Punkt („mit qwen3-coder nie
   provoziert") ist gelöst — der subdomain-reiche Kontext (proofpoint, ~20 Subdomains)
   triggert die agenten-ermessensabhängigen Tools. katana crawlte real 8 Subdomains.
3. **Methodischer Befund (kein Framework-Fehler):** Tomcat + WebLogic liefen im Lauf
   **parallel auf 127.0.0.1** (Container-Lifecycle überlappte — beide Ports 8080+7001 in allen
   4 Traces). Beide Ziel-CVEs wurden gefunden, aber nicht sauber getrennt. Für eine isolierte
   Matrix müsste `container_up`/`container_down` strikt sequenziell sein (Backlog).
4. **exit≠0-Filter bewährt:** bei den Session-Limit-Abbrüchen wurden keine kaputten Läufe
   ausgewertet.

## 9. NACHHOLEN (nächste Session, nach User-Freigabe)

- **nginx-TN + waf-cloudflare** nachfahren (je N=1 reicht: TN-Check bzw. WAF/CDN-Signatur):
  `venv/bin/python testing/run_matrix.py --targets nginx-clean-baseline waf-cloudflare --runs 1`
  (Weekly-Budget beachten; ~2 Scans).
- **Optional Backlog:** Container-Lifecycle strikt sequenziell machen, damit Tomcat/WebLogic
  isoliert laufen (für eine saubere getrennte CVE-Konsistenz-Auswertung).
- Danach: Matrix 7/7 vollständig, TESTKONZEPT final.
