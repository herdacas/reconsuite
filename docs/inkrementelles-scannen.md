# Skizze: Inkrementelles Scannen / Scan-Wissen wiederverwenden

**Status:** Entwurf / Diskussionsgrundlage — NICHT umgesetzt.
**Datum:** 2026-06-26
**Kontext:** Ausgelöst durch die Frage „Wenn ein Target schon gescannt wurde (alle Subdomains
ermittelt) und ich starte einen neuen Scan — was wird aus der Memory geholt?"

---

## 1. Ist-Zustand (faktisch, belegt am Code)

**Es wird nichts aus einer Memory geholt. Jeder Scan startet bei Null.**

- Das LanceDB-Agent-Memory-Subsystem ist seit **Phase 7, Stufe 3b entfernt** — alle Crews/Agents
  laufen hart `memory=False` ([agentscanit/crew.py:300-302](../agentscanit/crew.py#L300-L302),
  [agentscanit/agents.py:193](../agentscanit/agents.py#L193) ff.). Grund war ein PyO3-Panic aus dem
  Embedder-Hintergrund-Thread, der den blue_agent hängen ließ.
- Der einzige Rückgriff auf „schon mal gescannt" ist ein `glob` nach `recon_report_<target>_*.md`
  ([agentscanit/main.py:152-155](../agentscanit/main.py#L152-L155)). Das ergibt **ein Boolean**
  (`has_prior_data`), das **nur eine Banner-Zeile** steuert (`History: prior scan on disk`) und in
  **keine Scan-Logik** einfließt. Kommentar im Code: „der Agent nutzt Prior-Daten ohnehin nicht."
- Persistenter Zustand zwischen Läufen:
  - `logs/*.md` + `logs/crew_<target>_<ts>.json` — Artefakte, werden nicht zurückgelesen.
  - `logs/workflow_last.json` — **letzter** Lauf, wird beim nächsten Scan **überschrieben**.
  - `logs/flow_state.db` — nur für `--resume` eines **unterbrochenen** Laufs, keine Wissensquelle.

**Folge für das gefragte Szenario:** Scan 1 auf `example.com` findet `api.example.com` etc.;
Scan 2 auf `api.example.com` weiß davon nichts und enumeriert komplett neu. (Das Banner zeigt für
die Subdomain sogar `first run`, weil das glob auf `recon_report_api.example.com_*` sucht, nicht
auf das Parent.)

---

## 2. Ziel des Features

Ein **neuer** Scan soll **strukturierte Ergebnisse eines früheren** Scans desselben (oder eines
verwandten) Targets als Startwissen nutzen — primär:

1. **Subdomain-Wiederverwendung:** bereits ermittelte, als live verifizierte Hosts nicht erneut
   enumerieren, sondern direkt in die Blue-Phase (Active Scan) einspeisen.
2. **CVE-/Service-Kontext:** früher bestätigte Services/Versionen/CVEs als Hinweis an die
   findings-Phase (z. B. „bei letztem Scan lief hier WebLogic 12.2.1.3").

**Nicht-Ziel:** kein Wiederaufleben des LanceDB-Memory (PyO3-Problem). Die Wiederverwendung soll
**deterministisch + dateibasiert** sein — passt zur bestehenden Architektur (Teams kommunizieren
ohnehin über `workflow_last.json`).

---

## 3. Vorhandene Andockpunkte (was schon da ist und genutzt werden kann)

Wichtig: das Rad ist halb erfunden. Es gibt bereits einen deterministischen Mechanismus, der
Subdomains live-prüft und in den Scan-Fluss einspeist:

- **`ResearchOutput.subdomains`** ([tasks.py:373](../agentscanit/tasks.py#L373)) — strukturiertes Feld,
  hart auf `v[:25]` gecappt (`cap_subdomains`, [tasks.py:383](../agentscanit/tasks.py#L383)).
- **`ResearchOutput.memory_hit`** ([tasks.py:385-392](../agentscanit/tasks.py#L385-L392)) — **toter
  Andockpunkt aus der LanceDB-Ära**: Feld existiert noch, beschreibt ein „long-term memory system,
  das Prior-Scan-Daten injiziert", ist aber seit `memory=False` immer `False`. Ein Prior-Scan-Feature
  würde genau dieses Feld sinnvoll wiederbeleben (Signal: „dieser Lauf nutzt Vorlauf-Wissen").
- **`_subdomain_fanout_guardrail`** ([tasks.py:327](../agentscanit/tasks.py#L327)) — prüft entdeckte
  Subdomains via httpx auf Liveness (Code, kein LLM) und hängt einen Block
  `=== VERIFIED LIVE HOSTS (deterministic httpx) ===` an den research-Output. Dieser fließt via
  `context=[research]` in die blue-Task. **Genau dieser Block ist der natürliche Injektionspunkt.**
- **`_httpx_live_hosts()`** ([tasks.py:305](../agentscanit/tasks.py#L305)) — wiederverwendbarer
  Liveness-Check (re-validiert ob alte Subdomains noch leben).
- **`workflow_last.json` / `crew_<target>_<ts>.json`** — enthalten `tasks.research.subdomains`,
  `tasks.findings.cve_references` etc. ([main.py:347-358](../agentscanit/main.py#L347-L358)) —
  die Datenquelle für Prior-Wissen ist bereits strukturiert vorhanden.

Das Feature ist deshalb primär **„alte JSON lesen → in den vorhandenen Fanout-/Kontext-Mechanismus
einspeisen"**, nicht ein neues Subsystem.

---

## 4. Architektur-Skizze

### 4.1 Neues Modul: `agentscanit/prior.py` (deterministisch, kein LLM)

```python
def load_prior_scan(target: str) -> dict | None:
    """Neuesten crew_<target>_*.json für dieses Target finden (mtime), laden.
    Gibt {'subdomains': [...], 'services': [...], 'cve_references': [...],
          'report_path': ..., 'scanned_at': ts} zurück oder None."""

def merge_targets(target: str) -> dict | None:
    """Optional: auch Prior-Scans der Parent-Domain berücksichtigen
    (Scan auf api.example.com darf Subdomains aus example.com-Scan erben)."""
```

- Quelle: `logs/crew_<safe_target>_*.json` (nicht `workflow_last.json` — das ist nur der allerletzte
  Lauf, evtl. ein anderes Target). `_safe_target` via `re.sub(r"[^\w.-]", "_", target)`
  wie in [main.py:152](../agentscanit/main.py#L152).
- Beim Einspeisen den `cap_subdomains`-Hardcap (`[:25]`, [tasks.py:383](../agentscanit/tasks.py#L383))
  beachten: geerbte + neu enumerierte Hosts konkurrieren um dieselben 25 Slots → Merge sollte VOR
  dem Cap dedupen, sonst verdrängen alte Hosts evtl. neue Funde.
- **Re-Validierung Pflicht:** alte Subdomains durch `_httpx_live_hosts()` jagen, bevor sie als
  „live" gelten — eine Subdomain von vor 3 Wochen kann tot sein. Tote werden verworfen.
- **Alters-Schwelle (Stale-Guard):** Prior-Daten älter als N Tage (z. B. 14) nur mit Hinweis nutzen
  oder ignorieren — Versionsstände/CVE-Lage veralten.

### 4.2 Einspeisung (zwei saubere Optionen)

**Option A — Fanout-Block anreichern (empfohlen, minimal-invasiv):**
`_subdomain_fanout_guardrail` zusätzlich aus `load_prior_scan()` füttern: alte verifizierte Hosts
in die Liste mergen (dedupe), gemeinsam durch `_httpx_live_hosts()`, dann in den bestehenden
`=== VERIFIED LIVE HOSTS ===`-Block. **Kein neuer Pfad**, der Block existiert und wird von blue
schon konsumiert. Geringstes Risiko für die Kernfunktion.

**Option B — Eigener Prior-Knowledge-Block:**
research-Task einen separaten Block `=== PRIOR SCAN CONTEXT ===` voranstellen (Subdomains +
Service/Version-Hypothesen + frühere CVEs als *Hinweis*, nicht als Fakt). Mehr Kontext für die
LLM-Phasen, aber höheres Halluzinations-/Confirmation-Bias-Risiko → die findings-Phase darf alte
CVEs **nicht** ungeprüft übernehmen (der `_cve_trace_guardrail` greift ohnehin: jede CVE muss im
Trace **dieses** Laufs belegt sein — gut, das verhindert „Geister-CVEs" aus dem Vorlauf).

**Empfehlung:** A für Subdomains (hoher Nutzen, niedriges Risiko) zuerst; B nur additiv und klar
als „potenziell, aus Vorlauf — neu zu verifizieren" markiert.

### 4.3 CLI / Steuerung

Opt-in, damit das Default-Verhalten (sauberer Neuscan) unverändert bleibt:

```
python3 main.py api.example.com web --use-prior      # nutzt Vorlauf-Wissen
python3 main.py api.example.com web                  # wie bisher: Scan bei Null
```

Plus Banner-Zeile: `Prior: 12 hosts reused (8 still live, scanned 2026-06-20)`.

---

## 5. Risiken / offene Punkte

| Risiko | Gegenmaßnahme |
|---|---|
| Stale-Daten (tote Subdomains, veraltete Versionen) | `_httpx_live_hosts()`-Re-Validierung + Alters-Schwelle; Versionen nie blind übernehmen |
| Confirmation Bias (Agent „findet" alte CVEs ohne neuen Beleg) | `_cve_trace_guardrail` bleibt scharf — CVE muss im Trace DIESES Laufs stehen; Prior-CVEs nur als Hinweis |
| Falsches Parent/Child-Merging | Default: nur exaktes Target; Parent-Merge nur explizit (`--use-prior-parent`) |
| Subdomain-Fluten aus altem Lauf | zwei Caps greifen: `cap_subdomains` `[:25]` auf dem Feld + `_FANOUT_MAX_SUBS` im httpx-Pfad — Merge muss vor dem `[:25]`-Cap dedupen |
| Reproduzierbarkeit der Tests leidet | `--use-prior` ist opt-in → Verifikations-/Matrix-Läufe (testing/) bleiben deterministisch ohne Prior |

---

## 6. Minimaler erster Schritt (wenn umgesetzt wird)

1. `agentscanit/prior.py` mit `load_prior_scan()` (lesen + Schema + Stale-Guard) — read-only,
   ohne Einspeisung. Mit Positiv/Negativ-Kontrolle testen (existierender vs. fehlender Vorlauf).
2. `_httpx_live_hosts()`-Re-Validierung der Prior-Subdomains verdrahten — isoliert prüfen
   (tote Subdomain wird verworfen).
3. Erst dann Option A: Merge in `_subdomain_fanout_guardrail` hinter `--use-prior`-Flag.
4. E2E: Scan 1 (enumeriert) → Scan 2 mit `--use-prior` zeigt im blue-Trace die geerbten Hosts,
   ohne erneute Enumeration.

> Reihenfolge bewusst so, dass die Kernfunktion (Scan bei Null) bis zum letzten Schritt unberührt
> bleibt — konform zur Arbeitsweise in CLAUDE.md (Risiko für Hauptfunktionalität minimieren).

---

## 7. Ausbaustufe 2 — Baseline-Diff steuert den Scan (Konzept, weitergehend)

**Abgrenzung zu Abschnitt 1–6:** Die obige Skizze speist alte Daten als **zusätzlichen Input** ein
(„hier sind frühere Subdomains, scanne sie mit"). Diese Ausbaustufe ist qualitativ anders: die Memory
hält einen **Baseline-Zustand pro Target**, und ein neuer Scan **vergleicht zuerst** — das Diff-Ergebnis
**steuert den Scan-Umfang** (Memory wird Entscheidungsgrundlage, nicht nur Input).

### 7.1 Idee (Beispiel aus der Diskussion)

Pro Target wird eine Baseline gehalten: `{ip, open_ports, services, last_verified}`. Beim neuen Scan:

```
target = www.gmx.de, Baseline-IP = x.x.x.x
 ├─ aktuelle IP ≠ x.x.x.x  → Annahme „Host neu / umgezogen"
 │                            → großer nmap-Scan (-p 1-65535 -sV), Baseline verwerfen + neu aufbauen
 └─ aktuelle IP = x.x.x.x  → Annahme „Baseline-Kandidat gültig"
                              → bekannte offene Ports gezielt re-checken statt voll enumerieren
```

Erweiterbar auf weitere Datenpunkte als Diff-Trigger: TLS-Zertifikat-Fingerprint geändert,
Server-Banner-Version geändert, neue/verschwundene Subdomain, geänderter HTTP-Statuscode.

### 7.2 Drei Designentscheidungen, die das ERZWINGT (ehrlich, nicht trivial)

1. **„Bestätigen statt scannen" ist blind für Neues.** Gleiche IP ≠ gleiche Angriffsfläche — auf
   unveränderter IP kann ein **neuer Port** geöffnet worden sein. Entscheidung nötig:
   - (a) **Tempo-Variante:** nur bekannte Ports re-checken → schnell, aber verpasst neue Ports.
   - (b) **Ehrlich-Variante:** trotzdem voll scannen, aber nur das **Diff** hervorheben
     (neu/geschlossen/unverändert) → kein Tempo-Gewinn, aber kein blinder Fleck.
   - Empfehlung: (b) als Default. Der Wert liegt im **Diff-Bericht** („Port 6379 ist NEU seit
     2026-06-20"), nicht im Sparen des Scans. „Schneller scannen durch Memory" ist die schwächere,
     riskantere Motivation.

2. **Kollision mit dem Pentest-Scope-Prinzip der Suite.** Das Projekt trägt nur **tool-bestätigte
   Fakten DIESES Laufs** in den Report (Trace-Kreuzvalidierung, BUG-20/21). „Ports aus Memory
   bestätigen" trägt Fakten aus einem **früheren** Lauf in den aktuellen Report — eine bewusste
   Aufweichung. Nur vertretbar mit expliziter Markierung im Report:
   *„aus Baseline (IP unverändert), zuletzt verifiziert am 2026-06-20"* — niemals als frischer Befund
   getarnt. Sonst entsteht genau das, was BUG-14/BUG-17 verhindern sollten (alte/unbestätigte Daten
   als „confirmed").

3. **Braucht echten strukturierten Speicher, nicht `glob`.** Der Diff erfordert einen pro-Target
   gekeyten Zustand. Optionen:
   - **`baseline_<safe_target>.json`** in `logs/` — schlank, dateibasiert, passt zur bestehenden
     Filesystem-Kommunikation (vgl. `workflow_last.json`). Bevorzugt für den ersten Wurf.
   - **`flow_state.db`** (SQLite, existiert bereits für `--resume`) — wäre der „richtige" Ort für
     dauerhaften Target-Zustand, aber vermischt Flow-Resume-State mit Domänen-Baseline.
   - Das ist konzeptionell der **deterministische Ersatz** für das entfernte LanceDB-Memory:
     gleicher Zweck (Target-Wissen über Läufe hinweg), aber Key-Value/Diff statt Vektor-Recall —
     ohne den PyO3-Hintergrund-Thread-Panic, der LanceDB unbrauchbar machte.

### 7.3 Skizzierter Ablauf

```
neuer Scan auf www.gmx.de
  1. load_baseline("www.gmx.de")  → {ip, ports, services, last_verified} | None
  2. aktuelle IP via dig/dnsx auflösen
  3. Diff-Router (deterministisch, kein LLM):
       - keine Baseline       → voller Scan, Baseline anlegen
       - IP geändert          → voller Scan, Baseline ersetzen, "IP changed" markieren
       - IP gleich            → voller Scan, Ergebnis gegen Baseline diffen,
                                 Report zeigt nur Δ (neu/weg) + "bestätigt (unverändert seit DATUM)"
  4. Baseline mit aktuellem Ergebnis + frischem last_verified überschreiben
```

> Der Router ist deterministisch (wie `route_results` in [flow.py](../flow.py)) — kein LLM in der
> Steuerentscheidung, konsistent mit der Architektur (Risk-Scorer, CVE-Gates sind ebenfalls
> deterministisch). Das LLM bewertet nur die *Inhalte*, nie *ob* gescannt wird.

### 7.4 Bewertung

- **Höchster Nutzen, geringstes Risiko:** der **Diff-Bericht** auf unveränderter IP („was ist NEU
  seit dem letzten Scan") — das ist echter Mehrwert für wiederkehrende Assessments und kollidiert
  nicht mit dem Scope-Prinzip, solange voll gescannt und nur das Delta markiert wird.
- **Mittleres Risiko:** Scan-Umfang verkleinern, wenn IP gleich (Tempo-Variante 7.2.1a) — spart Zeit,
  führt aber blinde Flecken ein. Bewusst gegen die Gründlichkeit der Suite. Nur mit Bedacht.
- **Voraussetzung für alles:** strukturierter Baseline-Speicher (7.2.3) + ehrliche Report-Markierung
  (7.2.2). Ohne die zweite Maßnahme verletzt das Feature die Kern-Designlinie der Suite.

> Eigenständiges Konzept, baut aber auf derselben Memory-Quelle wie Abschnitt 1–6 auf
> (Eskalation: Subdomains wiederverwenden → Baseline-Diff steuert Scan). Reine Dokumentation,
> nicht umgesetzt.
