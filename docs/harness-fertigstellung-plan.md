# Arbeitsplan: Testkonzept-Harness fertigstellen + verifizieren

**Status:** Plan / wartet auf Freigabe — NICHT umgesetzt.
**Datum:** 2026-06-26
**Scope:** Betrifft NUR `testing/` (das Harness, bleibt LOKAL — nicht gepusht). Keine Änderung am
ausgelieferten Programm (`agentscanit/` etc.).
**Quelle der offenen Punkte:** CLAUDE.md („Offene Harness-Schwachpunkte" + „NÄCHSTE SESSION")
+ Code-Inspektion von `run_matrix.py`, `eval_*.py`, `targets.yaml`.

---

## 0. Ausgangslage (faktisch, Stand 2026-06-26)

**Was steht:** Harness gebaut (`eb45fbb`, lokal). 6 Bausteine mit Pos/Neg-Kontrolle bestanden.
Volle Matrix 2026-06-23 gelaufen (3 Targets × N=4 = 12 Scans, REMOTE qwen3-coder):
- Tomcat 8.5.19 (TP): Recall 1.0, 0 Halluz, Ports 1.0
- WebLogic 12.2.1.3 (TP): Recall 1.0 (3/4 Läufe), 0 Halluz, Ports 1.0
- nginx:alpine (TN): 0 Halluz, ABER echtes nuclei-CVE gefunden → TN-Annahme zu optimistisch

**Was offen ist (4 Harness-Schwachpunkte + 3 Coverage-Lücken):**
1. `run_matrix.py` filtert `exit≠0`-Läufe NICHT → `_newest` greift alten Report (verfälschte Dim3)
2. CVE-Jaccard auf GESAMT-Menge zu streng als Pass-Kriterium
3. TN-Target nginx hat ein echtes CVE → unsauberes True-Negative
4. Lokal-Achse (llama3-groq / qwen3-coder:30b) E2E steht aus
   → ERLEDIGT/ABGESCHLOSSEN (2026-06-26): 3 Modelle getestet (qwen3-coder:30b erfolglos,
     llama3.1:8b durch aber Tool-Coverage 0 + 71min, llama3-groq:8b Abbruch/zu langsam).
     Befund: Framework lokal-fähig (0 Leerantworten, Halluzinationen gefiltert), aber lokale
     Modelle/HW zu schwach → Remote (qwen3-coder:480b) bleibt verlässlicher Pfad.
   → EINGESCHOBENER ZWISCHENSCHRITT (dokumentiert, extern beim Nutzer): LLM-Performance-
     Benchmark in separater Umgebung. Spec dafür: `docs/bench_req.md` (Mindestanforderungen +
     Schwellen + 3 Prüf-Fallstricke). Modell-Mindestanforderungen: `docs/modell-mindestanforderungen.md`.
     Letzter Benchmark-Durchlauf beim Nutzer; danach Lokal-Achse endgültig abgeschlossen.
5. scanme.nmap.org bewusst nicht in Matrix (12-Scans/Tag-Limit) → separat mit kleinem N
6. `dnsx`/`katana` mit qwen3-coder nie provoziert
7. **NEU (diese Session):** WAF/API/Misconfig-Tools (Commit `0f23f73`) sind NACH der Matrix
   dazugekommen → vom Harness noch nicht abgedeckt

---

## 1. Arbeitsschritte (priorisiert, jeder mit Verifikation)

Reihenfolge nach „Risiko für valide Ergebnisse zuerst" — Schwachpunkte, die die Aussagekraft der
Matrix verfälschen, vor neuen Coverage-Zielen.

| # | Schritt | Datei | Verifikation (Pos+Neg) | Aufwand |
|---|---|---|---|---|
| 1 | **exit≠0-Filter** in der Auswertung: Läufe mit `exit!=0` aus Dim1–3 + Konsistenz ausnehmen (NICHT `_newest` auf altem Report greifen lassen). `evaluate_run` nur bei `exit==0`; sonst Lauf als „failed" markieren, aus `consistency`-Paaren entfernen. | `run_matrix.py` (`evaluate_run`/`main`/`_print_summary`) | Künstlich `exit=1` injizieren → Lauf erscheint als „failed", fließt NICHT in drate/Jaccard. Gesunder Lauf → unverändert ausgewertet. | niedrig |
| 2 | **Jaccard-Metrik schärfen:** zusätzlich zur Gesamt-Jaccard einen **Ziel-CVE-Konsistenz-Wert** (Recall der `must_find_cves` über N Läufe) ODER Jaccard NUR auf versions-verifizierte CVEs. Gesamt-Jaccard bleibt als Info, ist aber NICHT mehr alleiniges Pass-Kriterium. | `eval_consistency.py` (`evaluate_consistency`) + `targets.yaml` (`must_find_cves` schon da) | Synthetisch: 4 Reports mit identischer Ziel-CVE aber variierenden Begleit-CVEs → Ziel-CVE-Konsistenz 1.0, Gesamt-Jaccard <1.0. Beide Werte getrennt sichtbar. | niedrig-mittel |
| 3 | **TN-Target sauber machen:** nginx:alpine hat reales nuclei-CVE (CVE-2026-42530). Option A: `forbid_cves` nutzen (vorhandenes Feld) + das eine reale CVE als bekannt akzeptieren. Option B: älteres, gehärtetes Image als echtes TN. **Empfehlung A** (kleiner, dokumentiert die Realität). | `targets.yaml` (nginx-Eintrag) | TN-Check (eval_groundtruth) läuft PASS, weil das reale CVE explizit erlaubt/erwartet ist statt als FP zu zählen. | niedrig |
| 4 | **Neue Tools ins Harness (Session-Lücke #7):** je 1 Target in `targets.yaml` für WAF (Cloudflare-Host, web), API (petstore.swagger.io, web, objective='API'), Misconfig (Target mit bekannter CORS-Misconfig). Diese sind KEINE TP/TN-CVE-Targets → eigener `kind`-Wert (z.B. `feature`) ODER nur Dim1/Dim2 (Input-Sauberkeit + 0 Halluz) prüfen, kein Recall. | `targets.yaml` + ggf. `eval_*.py` (kind=feature-Zweig) | WAF-Target: `=== WAF/CDN DETECTED ===` im Report (deterministisch greifbar). API-Target: `swagger.json [200]` im Trace. Beide mit Negativ (scanme: keine WAF, keine API). | mittel |
| 5 | **scanme separat (Coverage #5):** kleiner Lauf N=1–2 (12/Tag-Limit), nicht in die Haupt-Matrix. Dokumentiert als eigener Aufruf. | `run_matrix.py` (`--targets scanme --runs 2`) | TP-Recall der bekannten scanme-CVEs (OpenSSH/Apache) 1.0; Rate-Limit nicht verletzt. | niedrig |
| 6 | **Lokal-Achse (Coverage #4):** ein E2E-Matrixlauf mit lokalem Modell. llama3-groq:8b lief network durch, scheitert aber an findings-CVE (BUG-21-Guardrail → ehrlicher Abbruch). Kandidat `qwen3-coder:30b` testen. Misst Dim1/Dim4 (Tool-Input-Sauberkeit + Leerantwort-Rate über `RECON_LLM_DEBUG`). | `models.json` (manuell, User entfernt Key) + `run_matrix.py` | qwen3-coder:30b: 0 Leerantworten im Multi-Turn, Dim1 ≥0.95. Vergleich gegen Remote-Baseline. | mittel-hoch (LLM-abhängig) |
| 7 | **dnsx/katana provozieren (Coverage #6):** Subdomain-reiches Target in die Matrix, das den Subdomain-Fanout + katana-Crawl auslöst. | `targets.yaml` (neues Target) | dnsx/katana erscheinen im Trace (`command`-Feld); bisher mit qwen3-coder nie ausgelöst. | niedrig-mittel |

---

## 2. Verifikations-Philosophie (unverändert, aus TESTKONZEPT.md)

- Jeder `eval_*.py`-Change mit **Positiv- UND Negativ-Kontrolle** (misst es wirklich, oder immer grün?).
- Eval-Skripte bleiben **read-only** auf Framework-Output → kein Einfluss auf Scan-Ergebnis.
- Nur `run_matrix.py` löst echte Scans aus → dort zusätzlich Scorecard/Artefakt-Existenz prüfen.
- Synthetische Fixtures (für Schritt 1+2) statt echter Scans, wo möglich → schnell + deterministisch.

## 3. Abschluss-Definition (wann ist das Harness „fertig") — Stand 2026-06-26

- [x] Schritte 1–3 umgesetzt + verifiziert (Aussagekraft-Schwachpunkte) → Matrix-Ergebnisse valide
- [x] Schritt 4 (neue Tools abgedeckt: WAF + API Feature-Targets) → kein Feature ungetestet
- [ ] **Volle Matrix (6 Targets × N=4) — OFFEN, bewusst pausiert** bis qwen3-coder:480b Weekly-Limit
      zurückgesetzt ist (~2 Tage ab 2026-06-26). Bei 26% Restbudget würde die volle Bandbreite
      abbrechen → kein Teil-Lauf, lieber später vollständig. Code/Config steht vollständig.
- [x] scanme (Schritt 5, Remote N=2 PASS) + Lokal-Achse (Schritt 6, abgeschlossen) +
      dnsx/katana-Target (Schritt 7, proofpoint konfiguriert) dokumentiert.
- [x] CLAUDE.md „Aktueller Stand" auf finalen Harness-Stand aktualisiert.
- [ ] TESTKONZEPT.md final nachziehen (nach der vollen Matrix, zusammen mit den Endergebnissen).

**Fazit:** Harness-Code + Config zu 100% fertig & verifiziert. Einziger offener Punkt ist die
*Ausführung* der vollen Matrix (Budget-/Zeitgrund, nicht technisch) + der finale TESTKONZEPT-Eintrag
danach.

## 4. Was NICHT Teil dieses Plans ist

- Unit-Test-Schicht (`pytest tests/`) für die deterministische Logik (Guardrails/cpe_map/quality) —
  das ist ein SEPARATER, ergänzender Strang (Programm-Code, nicht Harness). Hier bewusst getrennt.
- Push des Harness — bleibt lokal (Protokoll, CLAUDE.md).

## 5. Backlog — CrewAI 1.15.0 Upgrade (NACH Fertigstellung dieser Tasks)

**Aktuell installiert:** crewai 1.14.7. **Verfügbar:** 1.15.0. **Entscheidung (2026-06-26): NICHT
jetzt upgraden — erst nach Abschluss der geplanten Harness-/Programm-Tasks.**

- **Nutzen gering:** 1.15.0 ist überwiegend deklarative/JSON-first Flows + CLI-TUI
  (`FlowDefinition`, `each.do`, inline crew loading, DMN-Mode). Die Suite definiert Flows
  PROGRAMMATISCH (`ReconSuiteFlow(Flow[State])`, `@start`/`@listen`/`@persist`) → diese Schiene
  berührt uns nicht.
- **Risiko mittel — genau unsere empfindlichen Stellen:** Changelog/Docs nennen
  „flow.py split into DSL/definition/runtime" + „flow condition evaluation stateless per event".
  Das ist die Engine, auf der `@persist(SQLiteFlowPersistence)`, `@listen(or_(...))` und die
  Resume-Skip-Guards (`completed_steps`) aufsetzen. Zusätzlich: „guardrail callables serialized
  as null for JSON checkpointing" (wir nutzen SQLite, nicht JSON — vermutlich unkritisch, aber
  beobachten). Die teuersten Bugs des Projekts (BUG-7-Familie, findings-Crash) saßen in genau
  dieser Flow-/Checkpoint-Serialisierung.
- **Sicherer Upgrade-Weg (wenn soweit):**
  1. Isoliert in Worktree/Branch, NICHT im aktiven venv.
  2. `uv sync --upgrade-package crewai`
  3. **Harness als Regressionstest drüberlaufen** (scanme N=2 + 1 Container-TP) — Dim 1–4 müssen
     PASS bleiben. Das ist der Eigen-Anwendungsfall des Harness: „bricht das Upgrade die
     Verifikations-Kette?"
  4. Gezielt prüfen: `--resume` (Persistence), `@listen(or_(...))`-Trigger, Guardrail-Reject-Flow.
- **Quellen:** github.com/crewAIInc/crewAI/releases/tag/1.15.0 + docs.crewai.com/en/changelog.

---

> Reihenfolge bewusst: zuerst die Schwachpunkte, die bestehende Matrix-Ergebnisse VERFÄLSCHEN
> (Schritt 1–2), dann Sauberkeit (3), dann Coverage (4–7). Konform zur Arbeitsweise in CLAUDE.md
> (Risiko für valide Kernaussage zuerst). Reine Planung — wartet auf Freigabe.
