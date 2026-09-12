# VALIDATION_SPEC.md — Autonome Genauigkeits-Validierung der Analyzer-Suite

## Auftrag

Baue eine deterministische Validierungs-Harness, die misst, wie viel Prozent der
Ausgaben dieses Projekts nachweislich korrekt sind — pro Modul, pro Feld, mit
Fehlerklassen und Konfidenzintervall. Anschließend behebe gefundene Defekte und
weise für jeden Fix nach, dass er über den gesamten Target-Korpus wirkt und keine
Regression in anderen Feldern erzeugt.

Arbeite vollständig autonom. Stelle keine Rückfragen. Melde dich erst mit dem
Abschlussbericht (Phase 6) zurück.

---

## Nicht verhandelbare Regeln

1. **Du bewertest deine eigene Ausgabe nicht.** Jede Korrektheitsaussage stammt
   aus einem Vergleich gegen eine externe Referenz (Oracle) oder gegen einen
   kontrolliert gesetzten Soll-Wert. Geschätzte, "eingeschätzte" oder aus dem
   Modellwissen ergänzte Prozentzahlen sind verboten. Eine Zahl ohne
   zugrundeliegenden Diff kommt nicht in den Bericht.
2. **Soll-Werte sind schreibgeschützt.** Du darfst `corpus/expected/*.yaml`
   niemals ändern, um einen Test grün zu bekommen. Wenn ein Soll-Wert falsch
   ist, trage ihn in `reports/disputed_expectations.md` mit Beleg ein und lasse
   den Test rot. Jede Änderung an `corpus/expected/` gilt als Fehlschlag des
   gesamten Laufs.
3. **Scope.** Es wird ausschließlich gegen Targets aus `scope.yaml` gescannt.
   Alles andere wird verweigert und protokolliert. Keine Scans gegen fremde
   Infrastruktur, keine aktiven Exploits, kein Brute-Force, keine
   Lasterzeugung.
4. **Keine erfundenen Quellen.** Jede externe Referenz wird mit URL, Abrufzeit
   und Roh-Response gespeichert. Kein Beleg aus dem Gedächtnis.
5. **Nicht verifizierbar ≠ korrekt.** Felder ohne zugeordnetes Oracle werden als
   `UNVERIFIABLE` gezählt und aus der Korrektheitsquote herausgerechnet, nicht
   stillschweigend als richtig gewertet.

---

## Phase 0 — Inventar

Erzeuge `reports/field_inventory.md`: für jedes Analyzer-Modul jedes Ausgabefeld
mit Typ, Beispielwert und Quelle (welcher Code-Pfad erzeugt es).

Ordne jedem Feld genau eine Oracle-Strategie zu:

| Strategie | Bedeutung |
|---|---|
| `CONTROLLED` | Soll-Wert von uns gesetzt (eigene Domain / eigene VM) |
| `ORACLE` | Unabhängige Zweitquelle verfügbar |
| `CROSSCHECK` | Nur Konsistenzprüfung gegen andere Felder möglich |
| `UNVERIFIABLE` | Keine unabhängige Prüfung möglich |

Felder ohne Zuordnung sind ein Blocker — lieber `UNVERIFIABLE` eintragen als raten.

---

## Phase 1 — Scope und Korpus

Lege `scope.yaml` an:

```yaml
allowlist:
  controlled_domains: []     # eigene Domains, Soll-Zustand bekannt
  lab_networks:  ["10.0.0.0/24"]   # lokale VMs, kein Routing nach außen
  external_readonly: []      # explizit freigegebene Dritt-Domains, nur passiv
forbidden:
  - active_exploitation
  - credential_bruteforce
  - any_target_not_listed
rate_limits:
  requests_per_oracle_per_minute: 20
  total_runtime_minutes: 240
```

Baue `corpus/` mit 30–50 Targets, gemischt: kontrollierte eigene Domains,
Lab-VMs, passiv erfasste Dritt-Domains aus der Allowlist. Stratifiziere bewusst
über die Eigenschaften, die deine Module unterscheiden (mit/ohne DNSSEC,
Wildcard-Zertifikate, CDN vs. Direct-Origin, verschiedene Registrare, IPv6-only,
tote Domains, frisch registrierte Domains).

**Record-Replay ist Pflicht.** Zeichne pro Target die rohen Netzwerkantworten
einmal auf und friere sie ein:

```
corpus/
  fixtures/<target_id>/
    meta.yaml            # captured_at, target, kategorie, notizen
    dns/*.json
    http/*.raw
    tls/chain.pem
    rdap/*.json
  expected/<target_id>.yaml   # SCHREIBGESCHÜTZT
```

Jeder spätere Testlauf läuft offline gegen die Fixtures. Damit ist ein Bugfix in
Sekunden gegen alle Targets prüfbar und zeitliche Drift fällt raus.

---

## Phase 2 — Oracle-Adapter

Implementiere unter `validation/oracles/` je einen Adapter mit einheitlichem
Interface `fetch(target) -> dict` und lokalem Cache. Mindestens:

- **DNS:** mehrere unabhängige Resolver, Mehrheitsentscheid, Dissens wird als
  eigener Status `AMBIGUOUS` geführt
- **Zertifikate:** crt.sh / CT-Logs gegen die live gelesene Chain
- **Registrar/Domaindaten:** RDAP (strukturiertes JSON, nicht Whois-Freitext)
- **TLS-Konfiguration:** testssl.sh lokal als Zweitmeinung
- **CVE/Schwachstellen-Mapping:** NVD, OSV, CISA KEV, EPSS — CVE-IDs müssen
  gegen die API auflösbar sein, sonst `FABRICATED`
- **Tech-Fingerprinting:** zweiter unabhängiger Fingerprinter

Regel: Stimmen Scanner und Oracle nicht überein, prüfe *zuerst*, ob das Oracle
recht hat. Dokumentiere die Entscheidung.

---

## Phase 3 — Scoring-Harness

`validation/score.py` vergleicht Scanner-Ausgabe gegen Erwartung und klassifiziert
**jedes Feld** in genau eine Klasse:

```
CORRECT            Wert stimmt
FALSE_POSITIVE     Finding behauptet, das es nicht gibt
FALSE_NEGATIVE     Vorhandenes Finding nicht erkannt
WRONG_VALUE        Feld vorhanden, Inhalt falsch
MISSING_VALUE      Feld fehlt/null, obwohl Wert existiert
MALFORMED          Typ-/Formatfehler, Schema verletzt
FABRICATED         Quelle/CVE/Referenz existiert nicht (eigene Klasse!)
STALE              Legitime Änderung seit Fixture-Zeitpunkt → zählt NICHT als Fehler
AMBIGUOUS          Oracles widersprechen sich → zählt NICHT
UNVERIFIABLE       Kein Oracle → zählt NICHT
```

Ausgabe `reports/accuracy.json`:

- Precision und Recall **pro Modul**
- Korrektheitsquote **pro Feld**
- Gewichtetes Gesamtaggregat plus **Wilson-Konfidenzintervall (95 %)**
- Anteil `UNVERIFIABLE` an der Gesamtausgabe (Abdeckungsgrad der Validierung)

Der Bericht nennt immer Quote *und* Intervall *und* Stichprobengröße. Eine nackte
Prozentzahl ist ungültig.

---

## Phase 4 — Lab-VMs (nachrangig)

Setze lokale Vulnerability-VMs auf (z. B. Metasploitable2, DVWA, VulnHub-Images),
NAT ohne Route nach außen, Snapshot vor jedem Lauf. Nutze sie ausschließlich für
**Recall-Messung** gegen den dokumentierten Lösungsschlüssel.

Ihre Ergebnisse fließen **nicht** in die Gesamt-Korrektheitsquote ein — die
Schwachstellendichte ist künstlich und würde die Kalibrierung verzerren. Sie
werden im Bericht als separater Abschnitt geführt.

---

## Phase 5 — Fix-Zyklus mit Regressionsnachweis

Für jeden Defekt, nach absteigendem Impact (Anzahl betroffener Targets × Schwere):

1. Baseline-Score speichern
2. Fix implementieren
3. **Gesamten Korpus** neu scoren
4. `validation/diff.py` erzeugt einen Feld-Diff über alle Targets:
   *"Patch verändert 47 Felder über 12 Targets: 44 erwartet, 3 unerwartet."*
5. Jede unerwartete Änderung wird erklärt oder der Fix wird zurückgerollt.
   Ein Fix, der Target A repariert und Target B verschlechtert, wird **nicht**
   gemergt, bis beides gelöst ist.
6. Regressionstest aus dem Fall ableiten und in `tests/regression/` ablegen
7. Einzelner Commit pro Fix mit Score-Delta in der Commit-Message

Abbruch und Bericht, wenn eine Bedingung eintritt: Laufzeitbudget erschöpft,
drei Fix-Versuche am selben Defekt gescheitert, Gesamtscore nach einem Fix
niedriger als die Baseline und nicht innerhalb eines Versuchs behebbar, oder
`corpus/expected/` wurde verändert.

Führe durchgehend `reports/runlog.md` als Append-only-Protokoll: Zeitstempel,
Aktion, Target, Ergebnis. Keine nachträgliche Bearbeitung.

---

## Phase 6 — Abschlussbericht

`reports/FINAL_REPORT.md`, in dieser Reihenfolge:

1. **Gesamtquote** mit 95-%-Konfidenzintervall, Stichprobengröße und
   Abdeckungsgrad (Anteil verifizierbarer Felder)
2. **Tabelle pro Modul:** Precision, Recall, Hauptfehlerklasse, n
3. **Tabelle pro Feld:** Korrektheitsquote, Oracle-Strategie
4. **Vorher/Nachher** je durchgeführtem Fix, mit Feld-Diff-Zusammenfassung
5. **Ungelöste Defekte,** priorisiert, mit Reproduktionsschritten
6. **Strittige Erwartungswerte** aus `disputed_expectations.md`
7. **Grenzen der Aussage:** was nicht geprüft werden konnte und warum;
   explizit die Verzerrung durch Korpuszusammensetzung und Fixture-Alter
8. **Ressourcenverbrauch:** Laufzeit, Requests pro Oracle, Tokens

Der Bericht darf keine Aussage enthalten, die nicht durch eine Datei unter
`reports/` oder `corpus/` belegt ist.
