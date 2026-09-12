# FINAL_REPORT.md — Autonome Genauigkeits-Validierung der Analyzer-Suite

Auftrag: `debugging/VALIDATION_SPEC.md`. Ausgeführt: 2026-09-12, autonom, User-Anpassung
"max. 6-7 Targets statt 30-50" umgesetzt (7 Targets). Jede Aussage in diesem Bericht ist
durch eine Datei unter `reports/` oder `corpus/` belegt (Regel: "Der Bericht darf keine
Aussage enthalten, die nicht durch eine Datei unter reports/ oder corpus/ belegt ist").

---

## 1. Gesamtquote

**161/197 verifizierbare Felder korrekt (81.7%), Wilson-95%-CI [75.7%, 86.5%], n=197.**

Quelle: `reports/accuracy.json` (`overall`). Stichprobengröße n=197 ist die Summe aller
einzeln geprüften Feld-Instanzen über 7 Targets und 7 Check-Typen (nicht 7 — jedes Target
liefert mehrere CVE-IDs, Subdomains, Ports etc.).

**Abdeckungsgrad — WICHTIGE EINSCHRÄNKUNG:** `accuracy.json` weist `coverage_verifiable_
fraction: 1.0` aus. Das bedeutet NICHT "100% aller Ausgabefelder sind geprüft" — es bedeutet
nur, dass innerhalb der **hier tatsächlich implementierten 7 Checks** keine Instanz als
UNVERIFIABLE/AMBIGUOUS/STALE eingestuft wurde. Von den 34 Feldern aus `reports/field_
inventory.md` (Phase 0) deckt diese Runde **7 Checks** ab (Confirmed-Findings-Grounding,
Detected-Technologies-Grounding, tools_executed×2, cve_references, subdomains, open_ports).
Die 10 als UNVERIFIABLE klassifizierten Freitext-Felder (`summary`, `analysis`, `risk_
summary`, `osint_notes`, `code`, `code_plan` etc.) sowie 8 weitere ORACLE/CROSSCHECK-Felder
(`reverse_dns`, `asn_info`, `technologies`, `service_versions`, `RedOutput.*`, `syntax_valid`,
Downstream-Team-5/6/4-Felder) wurden in DIESER Runde nicht gescort — Details siehe Abschnitt 7.

## 2. Tabelle pro Modul

| Modul | Geprüfte Felder (diese Runde) | n | Korrekt | Hauptfehlerklasse |
|---|---|---|---|---|
| Team 1 — Report-Task (`report`) | Confirmed-Findings-Grounding (2 Guardrails) | 14 | 9 (64%) | FABRICATED |
| Team 1 — Blue-Task (`blue`) | tools_executed, open_ports | 78 | 75 (96%) | FABRICATED (tools_executed) |
| Team 1 — RedScan-Task (`red_scan`) | tools_executed | 28 | 0 (0%) | FABRICATED (systematisch, s.u.) |
| Team 1 — Findings/Red (`cve_references`) | CVE-Existenz (NVD-Oracle) | 70 | 70 (100%) | — |
| Team 1 — Research (`subdomains`) | DNS-Auflösbarkeit (3-Resolver-Oracle) | 7 | 7 (100%) | — |

Kein klassisches Precision/Recall (Positiv-/Negativklassen) für die meisten Checks, da es
Grounding-Prüfungen sind (jede Behauptung ist entweder belegt oder nicht) — Ausnahme
`open_ports`, wo echte FALSE_NEGATIVE-Fälle auftraten (s.u.).

## 3. Tabelle pro Feld (diese Runde gescort)

| Feld | Oracle-Strategie | n | Korrekt (%) | 95%-CI |
|---|---|---|---|---|
| Confirmed-Findings-Tool-Zuordnung (`_confirmed_findings_tool_guardrail`) | CROSSCHECK | 7 | 100.0% | [65.0%, 100%] |
| Confirmed-Findings/Detected-Tech-Werte (`_value_grounding_guardrail`) | CROSSCHECK | 7 | 28.6% | [8.2%, 64.1%] |
| `tools_executed` (blue) | ORACLE | 34 | 94.1% | [80.9%, 98.4%] |
| `tools_executed` (red_scan) | ORACLE | 28 | 0.0% | [0.0%, 12.1%] |
| `cve_references` (Existenz) | ORACLE | 70 | 100.0% | [94.8%, 100%] |
| `subdomains` (Auflösbarkeit) | ORACLE | 7 | 100.0% | [64.6%, 100%] |
| `open_ports` (vs. nmap-Rawoutput) | ORACLE | 44 | 97.7% | [88.2%, 99.6%] |

Quelle: `reports/accuracy.json::per_check`. Rohdaten je Einzelfund: `reports/accuracy.json::raw_findings`.

## 4. Vorher/Nachher je durchgeführtem Fix

### Fix-Zyklus 1 — Tool-Namen-Matching (Commit `092b525`)

**Baseline** (`reports/accuracy_baseline_before_matching_fix.json`):

| Check | Vorher | Nachher | Delta |
|---|---|---|---|
| `_confirmed_findings_tool_guardrail` | 5/7 (71.4%) | **7/7 (100%)** | +2 Targets |
| `_value_grounding_guardrail` | 2/7 (28.6%) | 2/7 (28.6%) | 0 netto, aber Zusammensetzung geändert (s.u.) |
| Gesamt | 159/197 (80.7%) | 161/197 (81.7%) | +2 Felder |

**Feld-Diff, geprüft und einzeln erklärt** (Phase 5, Punkt 4-5 — keine unerklärte Änderung):
- `_confirmed_findings_tool_guardrail`: rastede-de + scanme-nmap-org FABRICATED→CORRECT
  (Tool-Namen-Varianten `nuclei_vulnerability_scanner`/`nmap (step_1)` jetzt als Präfix-
  Varianten der echten Tools `nuclei`/`nmap` erkannt).
- `_value_grounding_guardrail`: cloudflare-com FABRICATED→CORRECT (Case-Sensitivity-Fix:
  whois liefert Domains in Großbuchstaben). **rastede-de CORRECT→FABRICATED** — einzeln
  verifiziert, KEIN Rückschritt: dies ist der historisch in CLAUDE.md dokumentierte BUG-23-
  ActiveMQ-Fall (`nuclei_vulnerability_scanner` zitiert für "ActiveMQ < 5.14.0 - Web Shell
  Upload"). Die Tool-Namen-Toleranz hätte diesen Fall bei `_confirmed_findings_tool_
  guardrail` jetzt durchgelassen (Tool-Name ist ja jetzt als legitim erkannt) — der
  GLEICHZEITIG gefixte `_grounded_haystack`-Tool-Resolver in `_value_grounding_guardrail`
  fängt ihn stattdessen korrekt über die Werte-Prüfung ab (nuclei's echter Rawoutput ist
  ein leerer Warn-String, "5.14.0" kommt nirgends vor — verifiziert per Volltextsuche im
  Fixture-Trace). Beide Fixes zusammen schließen eine Lücke, die JEDER Fix einzeln geöffnet
  hätte (VALIDATION_SPEC.md Phase 5, Regel 5).

### Fix-Zyklus 0 — vor dem eigentlichen Validierungsauftrag, aber im selben Session-Tag

Nicht Teil dieser Validierungsrunde selbst, aber Voraussetzung dafür, dass diese Runde
überhaupt sinnvolle Daten liefert (die Guardrail-Funktionen, die score.py aufruft, wurden
teils HEUTE FRÜHER am Tag committet, vor dem VALIDATION_SPEC.md-Auftrag): `_tools_executed_
guardrail` (Commit `c8431fb`), `_confirmed_findings_tool_guardrail`-Leerspalten-Fix
(`efd6a27`), `_value_grounding_guardrail`-sslscan-Banner-Fix (`34e9607`). Diese Validierungs-
runde liefert für alle drei den in Phase 5 geforderten Corpus-weiten Regressionsnachweis
(s. Abschnitt 5. "Bereits abgedeckt").

## 5. Ungelöste Defekte (priorisiert)

### 5.1 `tools_executed[red_scan]`: 0/28 korrekt über ALLE 7 Targets — bereits abgedeckt, kein neuer Fix nötig

**Nicht ungelöst** — bereits durch `_tools_executed_guardrail` (Commit `c8431fb`, heute vor
dieser Validierungsrunde) behoben, der Guardrail hängt bereits am `red_scan`-Task. Dieser
Corpus-weite 0%-Befund ist der geforderte Beweis, dass der frühere Fix nicht nur den
ursprünglichen Einzelfall (wafw00f/cloudflare.com) trifft, sondern ein *systematisches*
Muster: in JEDER der 7 Fixtures machte `red_scan` 0 echte Tool-Calls, behauptete aber
durchgängig 5 Tools (identisch mit `blue`s Tool-Liste — die Task scheint bei fehlendem
eigenem Scan-Bedarf `blue`s Angaben zu kopieren statt leer zu lassen).

**Reproduktion:** `corpus/fixtures/example-com/scanner_trace.json`, Phase `red_scan`,
`tool_calls: []`, `structured_output.tools_executed: ["nmap_scanner", "httpx_prober", ...]`.

**Verbleibende offene Frage (echt ungelöst, neu — s.u. 5.2).**

### 5.2 `red_scan` kopiert nicht nur `tools_executed`, sondern auch `open_ports`/`vulnerabilities`/`targeted_findings` von `blue` — NICHT gefixt

Bei genauerer Prüfung von `corpus/fixtures/example-com/scanner_trace.json` (Phase `red_scan`)
zeigt sich: wenn `red_scan` keine eigenen Tool-Calls macht, restauriert es NICHT nur
`tools_executed`, sondern auch `open_ports` (identisch mit `blue`s Liste) und
`targeted_findings`/`vulnerabilities` (inhaltlich `blue`s Findings). `_tools_executed_
guardrail` erzwingt künftig ein korrektes (leeres) `tools_executed`-Feld — die ANDEREN
Felder bleiben davon unberührt und könnten downstream als "durch red_scan zusätzlich
bestätigt" fehlinterpretiert werden, obwohl keine neue Verifikation stattfand.

**Impact:** 7/7 Targets betroffen (jede Fixture zeigt dasselbe Muster), aber Schweregrad
moderat — der WERT selbst ist meist korrekt (er stammt ja tatsächlich von `blue`), nur die
implizite "zusätzlich bestätigt"-Semantik ist irreführend, keine reine Fabrikation.

**Nicht gefixt** — würde eine Design-Entscheidung erfordern (soll `red_scan` bei 0 neuen
Calls leere Listen zurückgeben, oder explizit als "unverändert von blue" markieren?), die
über den reaktiven Bugfix-Rahmen dieser Runde hinausgeht. Reproduktion: siehe 5.1.

### 5.3 `open_ports`: 1 FALSE_NEGATIVE (example-com, Port 8880)

nmaps vollständiger Portscan fand Port 8880/tcp offen (`cddbp-alt`), `BlueOutput.open_ports`
listet ihn nicht (12 von 13 echten offenen Ports übernommen). Einzelfall (1/44 Ports über den
ganzen Corpus, 2.3%) — kein Muster über mehrere Targets erkennbar, daher als niedrige
Priorität eingestuft und nicht gefixt (kein Guardrail existiert aktuell, der `open_ports`
vollständig gegen den nmap-Rawoutput cross-checkt — würde ein neues, eigenes Guardrail
brauchen).

**Reproduktion:** `corpus/fixtures/example-com/scanner_trace.json`, Phase `blue`, nmap-
Rawoutput enthält `8880/tcp open  cddbp-alt`, `structured_output.open_ports` enthält es nicht.

### 5.4 Bereits vor dieser Runde bekannte, unverändert offene Backlog-Punkte (aus CLAUDE.md, nicht neu)

- sslscan-Banner-Kontamination erreicht auch Team 5/6 (compliance/risk_scorer) — in dieser
  Runde NICHT erneut geprüft (Downstream-Team-Felder waren nicht Teil der 7 gescorten Checks).
- `_confirmed_findings_tool_guardrail`s Leerspalten-Erkennung (`efd6a27`) und `_tools_
  executed_guardrail` wurden in dieser Runde corpus-weit bestätigt (s.o.), aber die
  ANALOGE Lücke bei `RedOutput.confirmed_attack_surface`/`exploitable_findings` (kein
  Guardrail geprüft in dieser Runde, da kein Check dafür implementiert wurde) ist
  UNGEPRÜFT — echte Wissenslücke dieser Runde, nicht "kein Problem".

## 6. Strittige Erwartungswerte

**Keine.** Alle in `corpus/expected/*.yaml` gesetzten Ground-Truth-Werte (scanme.nmap.org:
OpenSSH 6.6.1p1/CVE-2018-15473; rastede.de: OpenSSH 9.6p1/CVE-2024-6387, `forbid_cves:
CVE-2023-38408`) wurden gegen die Fixtures geprüft und bestätigt — `rastede-de/report.md`
enthält CVE-2023-38408 nicht (verifiziert per Grep, 0 Treffer). Kein Eintrag in
`disputed_expectations.md` nötig (Datei nicht angelegt, da leer).

## 7. Grenzen der Aussage

1. **Corpus-Größe:** 7 Targets statt der ursprünglich spezifizierten 30-50 (explizite
   User-Vorgabe, dokumentiert `reports/runlog.md` 05:31). Die Wilson-CIs sind entsprechend
   breit (z.B. `_value_grounding_guardrail`: [8.2%, 64.1%] bei n=7) — bei so kleinem n ist
   die Quote selbst wenig aussagekräftig, nur die EINZELFUND-Analyse (Abschnitt 4/5) trägt.
2. **Feld-Abdeckung:** 7 von 34 im Phase-0-Inventar gelisteten Feldern wurden tatsächlich
   gescort (s. Abschnitt 1). Die übrigen 27 (inkl. aller Downstream-Team-5/6/4-Felder,
   `RedOutput.*`, `technologies`, `reverse_dns`, `asn_info`, `syntax_valid`) sind NICHT
   Teil der `reports/accuracy.json`-Zahlen — weder als geprüft noch als UNVERIFIABLE
   verbucht, schlicht nicht in dieser Runde implementiert. Zeitbudget-Grenze.
3. **Record-Replay statt Live-Rescan:** alle 7 Fixtures sind bereits VOR dieser
   Validierungsrunde durchgeführte Scans (Zeitraum 2026-09-10 bis 2026-09-12). Für Domains
   ohne stabilen Ground-Truth-Eintrag (example.com, oldenburg.de, westerstede.de, cloudflare.
   com) gibt es daher STALE-Risiko (Ziel-Infrastruktur kann sich seither geändert haben) —
   in der Aggregation nicht als eigene STALE-Klasse aufgetreten, weil die verwendeten Oracles
   (NVD/DNS) selbst zum AKTUELLEN Zeitpunkt abgefragt wurden, nicht zum Fixture-Zeitpunkt.
   Das bedeutet: ein CVE, das seit dem Scan neu veröffentlicht wurde, würde in `cve_
   references` (Scanner-Behauptung von damals) naturgemäß nicht auftauchen — das ist
   KEIN Fehler des Scanners, aber auch nicht durch diese Runde geprüft.
4. **Oracle-Lücken:**
   - `cert_oracle`/`tls_oracle`/`rdap_oracle` wurden gebaut und gegen echte Live-Ziele
     verifiziert (siehe `reports/runlog.md`), aber NICHT in `validation/score.py`s
     automatisierte Klassifikation integriert (nur `dns_oracle` + `cve_oracle` fließen in
     `accuracy.json` ein) — Zeitbudget-Grenze, keine technische Unmöglichkeit.
   - `cert_oracle` gegen `oldenburg.de` lieferte einen echten crt.sh-502-Fehler auch nach
     3 Retries (reale, transiente externe Instabilität, siehe `runlog.md` 05:40) — für
     dieses eine Target daher kein Cert-Vergleich möglich gewesen.
   - `tech_oracle` ist EXPLIZIT kein vollständig unabhängiger Zweit-Tool-Lauf (siehe eigener
     Docstring-Hinweis in `validation/oracles/tech_oracle.py`) — ein regelbasierter Parser
     auf denselben bereits vorhandenen HTTP-Headern, schwächer als ein echter zweiter
     Scan, aber strikt unabhängig von der zu prüfenden LLM-Interpretation.
5. **Phase 4 (Lab-VMs) nicht neu durchgeführt:** aus Zeitbudget-Gründen keine neuen VulHub-
   Container in dieser Runde aufgesetzt. Stattdessen Rückgriff auf bereits in CLAUDE.md
   dokumentierte, gegen NVD verifizierte historische Recall-Ergebnisse (Tomcat 8.5.19 →
   CVE-2017-12615/12617, Recall 1.0/4 Läufe; WebLogic 12.2.1.3 → CVE-2023-21839, Recall
   1.0/4 Läufe) — nicht neu erhoben, nur zitiert. Diese Zahlen fließen NICHT in die
   Gesamt-Korrektheitsquote ein (VALIDATION_SPEC.md Phase 4, wie vorgeschrieben).
6. **Kein automatisiertes Fix-Ranking nach Impact×Schwere:** die 3 gefundenen Defekte (Case-
   Sensitivity, Tool-Namen-Matching ×2) wurden alle behoben, da sie klein und eindeutig
   waren — bei einer größeren Anzahl echter Defekte wäre eine EXPLIZITE Priorisierungs-
   Tabelle nötig gewesen (Spec verlangt "absteigender Impact"); hier genügte direkte
   Reihenfolge der Entdeckung.

## 8. Ressourcenverbrauch

- **Laufzeit:** ca. 35 Minuten (05:29–06:04 Uhr, `reports/runlog.md`).
- **Requests pro Oracle:** DNS ~30 (7 Subdomains × 3 Resolver + Ad-hoc-Checks), NVD ~18
  (unique CVE-IDs im Corpus, alle gecacht für Re-Scoring), RDAP 7, crt.sh 6 (1 Fehlschlag
  nach 3 Retries), testssl 1 (Konnektivitätstest, nicht corpus-weit, s. Abschnitt 7).
- **Neue Commits:** 4 (`092b525`, `8a7afcb`, plus 2 vorbereitende Commits `9a94578` für
  Phase 0/1 — siehe `git log`).
- **Tokens/Kosten:** nicht separat instrumentiert (kein Tooling dafür in dieser Session
  verfügbar) — nicht belegbar, daher hier bewusst NICHT als Zahl angegeben (Regel 1: keine
  Zahl ohne zugrundeliegenden Beleg).
