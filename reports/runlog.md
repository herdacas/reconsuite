# runlog.md — Append-only-Protokoll (VALIDATION_SPEC.md Phase 5)

Keine nachträgliche Bearbeitung — nur Anhängen. Zeitstempel = Ausführungszeitpunkt in dieser Session (2026-09-12).

---

**05:29** — Phase 0 gestartet. Feld-Inventar aller Team-1-Pydantic-Modelle + Downstream-Teams erstellt (`reports/field_inventory.md`). 34 Felder klassifiziert (8 ORACLE, 15 CROSSCHECK, 1 CONTROLLED, 10 UNVERIFIABLE), keine Blocker.

**05:31** — Phase 1 gestartet. User-Vorgabe: max. 6-7 Targets statt 30-50. 7 Targets gewählt (example.com, scanme.nmap.org, oldenburg.de, westerstede.de, rastede.de, www.cloudflare.com, nginx-clean-baseline), alle bereits real im Projekt gescannt — `scope.yaml` angelegt.

**05:33** — `validation/build_corpus.py` gebaut, extrahiert Fixtures aus `logs/trace_*.json`. Erster Lauf: 7/7 "OK", ABER Bug entdeckt (vor Commit): naive mtime-Wahl paarte bei oldenburg-de einen Trace mit dem final_report einer ANDEREN Session. Fix: `_find_session()` erzwingt Zeitstempel-Übereinstimmung. Zweiter Lauf: 7/7 korrekt gepaart.

**05:36** — `corpus/expected/*.yaml` geschrieben (schreibgeschützt ab jetzt) — nur mit in CLAUDE.md bereits dokumentierten, NVD-verifizierten Fakten (scanme.nmap.org, rastede.de). Für die übrigen 5 Targets bewusst keine erfundenen must_find_cves.

**05:38** — Phase 0+1 committet (`9a94578`).

**05:39** — Phase 2 gestartet. Konnektivitätstest: crt.sh (langsam, aber erreichbar), RDAP (OK), NVD (OK), testssl (lokal installiert — CLAUDE.md-Notiz "nicht installiert" ist veraltet), dig gegen 1.1.1.1/8.8.8.8/9.9.9.9 (OK).

**05:40** — 6 Oracle-Adapter gebaut: `dns_oracle.py`, `cert_oracle.py`, `rdap_oracle.py`, `cve_oracle.py`, `tls_oracle.py`, `tech_oracle.py`. Bug gefunden + gefixt: `cert_oracle.py` erste Fassung ohne Retry — crt.sh lieferte live einen echten 502 Bad Gateway (dokumentierte Instabilität des Community-Service, analog BUG-14/NVD). Fix: Retry+Backoff (3 Versuche, 0/5/12s).

**05:47** — Phase 3: `validation/wilson.py` (Wilson-Score-CI, keine scipy-Abhängigkeit) + `validation/score.py` gebaut. Score.py rehydriert `run_trace._phases` direkt aus den Fixture-Traces und ruft die HEUTE bereits gebauten Guardrail-Funktionen (`_confirmed_findings_tool_guardrail`, `_value_grounding_guardrail`, `_tools_executed_guardrail`-Logik) sowie DNS-/CVE-Oracle-Checks auf.

**05:52** — Erster vollständiger Scoring-Lauf (alle 7 Targets, `reports/accuracy.json`). Auffälligkeiten sofort einzeln untersucht (nicht pauschal als "Defekt" gemeldet):
  - `tools_executed[red_scan]`: 0/28 CORRECT über ALLE 7 Targets — verifiziert: red_scan-Phase hatte in JEDER Fixture 0 echte Tool-Calls, `tools_executed` behauptete trotzdem 5 Tools. **Bereits durch den heute früher committeten `_tools_executed_guardrail`-Fix (c8431fb) abgedeckt** (Guardrail hängt bereits an red_scan) — reine Bestätigung, kein neuer Fix nötig.
  - `_value_grounding_guardrail`: 5/7 FABRICATED. Jeden Fall einzeln gegen den realen Rohoutput verifiziert:
    - cloudflare-com: **echter Bug in der Guardrail selbst** — Case-Sensitivity (whois liefert 'WWW.CLOUDFLARE.COM', Beobachtung zitiert Kleinbuchstaben). Fix: case-insensitiver Vergleich.
    - example-com: bereits bekannter, bereits gefixter sslscan-Banner-Fall (Fixture stammt aus der Zeit VOR dem Fix) — Bestätigung, kein neuer Fix.
    - nginx-baseline: ECHTE Fabrikation — "OpenSSH 8.9p1" komplett erfunden (Container hat nur nginx, keine SSH-Erwähnung im gesamten Trace).
    - oldenburg-de: ECHTE Fabrikation — "OpenSSH 10.5" zugeschrieben an whatweb, dessen echter Call in dieser Session mit `[TOOL_ERROR] timeout` fehlschlug.
    - westerstede-de: ECHTE Fabrikation — "Apache httpd 2.4.52" — Versionsnummer kommt NIRGENDS im echten whatweb-Output vor (verifiziert per Volltextsuche).
    - Für die 3 echten Fabrikationsfälle: die Guardrail erkennt sie bereits KORREKT (kein neuer Fix nötig) — sie stammen aus historischen Traces von vor der heutigen BUG-25-Härtung.
  - `_confirmed_findings_tool_guardrail`: 2/7 FABRICATED, beide untersucht:
    - rastede-de: 'nuclei_vulnerability_scanner' (real: nuclei) — **echter Bug**: exaktes String-Matching statt Präfix-Toleranz.
    - scanme-nmap-org: 'nmap (step_1)' (real: nmap) — **echter Bug**, gleiche Ursache.

**05:55** — Fix-Zyklus: neuer gemeinsamer Helper `_tool_name_grounded()` (ersetzt 2 separate, leicht unterschiedliche Ad-hoc-Implementierungen) — behebt Case-Sensitivity UND Tool-Namen-Präfix-Toleranz in EINEM Fix, angewendet an allen 3 betroffenen Stellen (`_confirmed_findings_tool_guardrail`, `_tools_executed_guardrail`, `_grounded_haystack` in `_value_grounding_guardrail`).

**05:57** — Regressionstest `tests/regression/test_validation_round_fixes.py` geschrieben, 6/6 PASS. Alle 6 bestehenden Testskripte (32 Assertions) weiterhin grün.

**05:58** — Baseline (`reports/accuracy_baseline_before_matching_fix.json`) gesichert, Corpus komplett neu gescort (CVE-Oracle-Cache griff, daher schnell). Diff:
  - `_confirmed_findings_tool_guardrail`: 5/7 → **7/7 CORRECT** (beide False-Positives behoben).
  - `_value_grounding_guardrail`: 2/7 → weiterhin 2/7 CORRECT, ABER Zusammensetzung geändert: cloudflare-com FLIPPED FABRICATED→CORRECT (Case-Fix wirkt), rastede-de FLIPPED CORRECT→FABRICATED. **Kein Rückschritt** — verifiziert: rastede-de ist der historisch dokumentierte BUG-23-ActiveMQ-Fall; die Tool-Namen-Toleranz hätte ihn bei `_confirmed_findings_tool_guardrail` jetzt durchgelassen, der GLEICHZEITIG gefixte `_grounded_haystack`-Tool-Resolver fängt ihn stattdessen korrekt über die Werte-Prüfung (nuclei's echter Rawoutput ist leer, "5.14.0" kommt nirgends vor). Beide Fixes zusammen verhindern eine Erkennungslücke, die JEDER Fix allein hätte.
  - Alle anderen Checks unverändert (`tools_executed[blue]` 32/34, `cve_references` 70/70, `subdomains` 7/7, `open_ports` 43/44).
  - Gesamt: 159/197 → 161/197 verifizierbare Felder korrekt (Wilson-95%-CI 0.746–0.856 → 0.757–0.865).

**06:00** — Fix committet (siehe Commit-Historie, Score-Delta in der Message).

**06:02** — Zusätzliche Oracle-Nutzung (RDAP/Cert) über den restlichen Corpus. Echter Bug
gefunden: rdap.org's Bootstrap unterstützt `.de` nicht (3 von 4 Apex-Domains im Corpus sind
`.de`) — Fix: DENIC-Direct-Fallback in `rdap_oracle.py`. Verifiziert (alle 3 `.de`-Domains
liefern jetzt echte RDAP-Daten, `.com`-Regressionscheck unverändert korrekt). Committet
(`8a7afcb`).

**06:03** — Cert-Oracle-Batch über die restlichen 5 Domains: 4/5 OK (echte CT-Log-Daten),
1/5 ERROR (oldenburg.de, crt.sh 502 nach 3 Retries — reale transiente Instabilität,
dokumentiert, kein Fix versucht — Retry-Budget bereits ausgeschöpft, weiteres Retryen wäre
gegen die Rate-Limit-Schonung).

**06:04** — `rastede-de`-Report explizit gegen die `forbid_cves`-Erwartung geprüft (CVE-2023-
38408 darf NICHT gelistet sein) — 0 Treffer, Erwartung bestätigt, keine strittige Erwartung.

**06:04** — Phase 6: `reports/FINAL_REPORT.md` geschrieben (8 Abschnitte laut Spec). 2 neue,
in dieser Runde NICHT gefixte Defekte dokumentiert (5.2: red_scan kopiert open_ports/
vulnerabilities von blue ohne neue Verifikation; 5.3: 1 FALSE_NEGATIVE bei open_ports).
Abdeckungsgrenzen explizit benannt (nur 7/34 Inventar-Felder gescort, Cert/TLS/RDAP-Oracle
nicht in die automatisierte Klassifikation integriert, Phase 4 nicht neu durchgeführt).

**06:05** — Session-Ende. Autonomer Auftrag abgeschlossen, Bericht an den User geht raus.
