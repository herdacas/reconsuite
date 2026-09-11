# Bewertung: recon-suite

## 1. Betriebsmodi (Korrektur)

Entgegen der ersten Analyse läuft das Framework **nicht primär lokal**. Es unterstützt zwei Modi, gesteuert über `agentscanit/models.json`:

### Local Mode (Default)
- **Bedingung:** Kein `OLLAMA_API_KEY` gesetzt (oder Platzhalter wie `"DEIN_API_KEY_HIER"`)
- **Modelle:** Lokale Ollama-Instanz auf `localhost:11434`
  - Analysis: `qwen2.5-coder:14b` (Standard, überschreibbar)
  - Code: `qwen2.5-coder:14b`
  - Research: `qwen2.5:7b`
  - Planner: `qwen2.5:7b-instruct` (immer lokal)

### Remote Mode
- **Bedingung:** Gültiger `OLLAMA_API_KEY` in `models.json`
- **Modelle:** Haupt-LLMs laufen über remote Ollama-Endpunkt (z.B. `ollama.com`)
  - Empfohlen: `qwen3-coder:480b` (Non-Reasoning, agentic Tool-Calling)
  - Läuft stabil durch alle 7 Phasen, 0 Retries (BUG-19)
- **Planner läuft immer lokal** — remote Modelle unterstützen Ollamas native Function-Calling-API nicht zuverlässig

---

## 2. Tool-Ökosystem (26 Tools)

### Active Scanning (12 Tools) — `blue_agent`

| Tool | Typ | Zweck | Status |
|---|---|---|---|
| `nmap` | Port/Service-Scan | Vollständiger Port-Scan + Service-Detection | ✅ 7.94SVN |
| `nikto` | Web-Vuln-Scanner | 7000+ Web-Checks, Security-Header | ✅ 2.1.5 |
| `whatweb` | Tech-Fingerprinting | CMS, Frameworks, Versionen | ✅ Aktuell |
| `sslscan` | TLS-Basischeck | Protokolle, Ciphers, Zertifikate | ✅ 2.1.2 |
| `testssl.sh` | TLS-Vollaudit | Alle bekannten TLS-Angriffe | ✅ 3.3dev |
| `curl` | HTTP-Header | Security-Header, Server-Banner | ✅ |
| `ping` | ICMP-Check | Host-Erreichbarkeit | ✅ |
| `nuclei` | CVE-Scanner | 25.000+ Templates, technologie-spezifisch | ✅ v3.8.0 |
| `httpx` | HTTP-Probing | Massen-Screening, Tech-Detection | ✅ v1.2.1 (Snap) |
| `ffuf` | Web-Fuzzer | Directory/Endpoint-Enumeration | ✅ (nur full) |
| `enum4linux` | SMB-Enum | Samba/Windows-Shares | ✅ (nur Port 445) |
| `naabu` | Port-Discovery | SYN-Scan, schneller Vorlauf für nmap | ✅ v2.6.1 |

### Passive Recon (14 Tools) — `research_agent`

| Tool | Typ | Zweck | Status |
|---|---|---|---|
| `subfinder` | Subdomain-Enum | passive, 10+ Quellen, primär | ✅ v2.13.0 |
| `sublist3r` | Subdomain-Enum | Suchmaschinen-basiert | ✅ |
| `amass` | Subdomain-Enum | breiteste Quellen-Basis | ✅ v4.2.0 (nur osint/full) |
| `assetfinder` | Subdomain-Enum | crt.sh + Facebook CT | ✅ |
| `dnsrecon` | DNS-Vollanalyse | alle Record-Typen + Zone-Transfer | ✅ 1.1.5 |
| `dig` | DNS-Abfrage | einfache Einzel-Records | ✅ |
| `dnsx` | DNS-Massen-Resolver | Host-Validierung | ✅ v1.2.3 |
| `whois` | Domain/IP-Registry | Registrar, ASN, ISP | ✅ |
| `theHarvester` | OSINT-Sammlung | E-Mails, Hosts, Subdomains | ✅ |
| `ddg_search` | Web-Suche | DuckDuckGo OSINT | ✅ |
| `katana` | Web-Crawler | URL/Endpoint-Findung | ✅ v1.2.1 |
| `waybackurls` | Archiv-URLs | Wayback Machine | ✅ |
| `gau` | Multi-Source URLs | WA + OTX + CommonCrawl | ✅ v2.2.4 |
| `searchsploit` | Exploit-DB | lokale Exploit-Suche | ✅ |

### CVE/Enrichment-Tools (alle Agents)

| Tool | Zweck | Genutzt von |
|---|---|---|
| `nvd_tool` | NVD-Keyword-Suche | research_agent (findings), red_agent |
| `nvd_cpe_tool` | CPE-basierter NVD-Lookup | research_agent (findings) |
| `searchsploit` | Lokale Exploit-DB | research_agent, red_agent |
| `ddg_search` | PoC-Recherche | red_agent |

### Bewertung der Toolauswahl

**Stärken:**
- Fundierte Auswahl bewährter Security-Tools (nmap, nikto, nuclei, ProjectDiscovery-Reihe)
- Keine Duplikationen — jedes Tool hat eine klar abgegrenzte Nische
- ProjectDiscovery-Tools decken moderne Recon-Bedürfnisse ab (httpx, katana, dnsx, nuclei)
- Go-Tools via `go env GOPATH` dynamisch gefunden — portabel
- Alle Binaries sind System-/Go-Tools, keine Python-Abhängigkeiten (schneller, stabiler)

**Schwächen:**
- `httpx` über Snap-Pfad (`/snap/bin/httpx`) — systemspezifisch, bricht ohne Snap
- 5 Tools haben keine expliziten `config.py`-Konstanten (naabu, dnsx, katana, waybackurls, gau) — laufen über PATH, inkonsistent zu nuclei/amass/subfinder
- `testssl.sh` läuft im Dev-Branch (3.3dev statt 3.2 stable)
- `enum4linux` benötigt impacket/ldap3 — keine Abhängigkeitsprüfung
- Kein WAF-Erkennungstool (z.B. wafw00f)
- Kein API-Endpunkt-Fuzzer (z.B. kiterunner, arjun)
- Kein JWT-Analyse-Tool

---

## 3. CrewAI-Framework-Konformität

### ✅ Erfüllt

**Flow-Architektur:**
- Nutzung von `@persist(SQLiteFlowPersistence)` — korrekte Implementierung des CrewAI-Resume-Mechanismus
- `@router` für dynamische Entscheidungen — idiomatischer CrewAI-Weg
- `@start()` / `@listen()` / `or_()` — korrekte Verwendung des Event-Systems
- `ScanState` als Pydantic-BaseModel — saubere State-Definition

**Agent/Task-Architektur:**
- Agents mit klaren Rollen, Goals, Backstories — korrekt nach CrewAI-Konvention
- Tasks mit `output_pydantic`, `guardrails`, `context` — vollständige Task-Spezifikation
- `Process.sequential` (Standard) und `Process.hierarchical` für den Manager-Modus
- `memory=False` auf allen Agents — bewusste Design-Entscheidung, dokumentiert

**Guardrails:**
- Implementierung von `_tool_call_guardrail`, `_cve_trace_guardrail`, etc. — korrekte Nutzung des Guardrail-Systems
- `guardrail_max_retries=2` für erlaubte Wiederholungen

### ⚠️ Einschränkungen

**Resume-Mechanismus:**
- Resume läuft NUR auf Flow-Ebene (Teams 1→6), nicht Intra-Crew
- CrewAI bietet keinen nativen Intra-Crew-Resume — das ist ein Framework-Limit, kein Code-Fehler
- Aber: Flow-@persist bei Breaking Changes am Flow-Graphen nicht mehr resumable (dokumentiert)

**Planner-Deaktivierung (BUG-18):**
- CrewAI AgentPlanner wird bei >5 Tasks deaktiviert, weil der Plan-Prompt zu groß wird
- Das ist ein Workaround, keine korrekte Lösung — `planning=True` sollte bei 7 Tasks funktionieren
- Ursache: lokales Planner-Modell mit `num_ctx=4096` vs. ~32k Tokens Plan-Prompt
- Echte Lösung wäre: Planner-Prompt reduzieren ODER `num_ctx` dynamisch anpassen

**Kein Memory-Subsystem:**
- `memory=False` ist bewusst, aber CrewAI bietet Long-Term-Memory für Cross-Scan-Learning
- Das Framework hat stattdessen einen eigenen "prior scan on disk"-Mechanismus (Datei-basiert)
- Erkennt Prior-Scans aus Dateinamen, nutzt sie aber effektiv nicht (nur Banner)

**Hierarchical-Process:**
- `_make_manager_agent()` erbt `allow_delegation=True` — das ist korrekt
- Aber: Delegation triggert native Function-Calling auf lokalen Modellen, die das Schema nicht zuverlässig ausführen (dokumentiert in README)

### Erweiterbarkeit & Integration

**Positiv:**
- `flow.py` importiert alle Teams als Module — ein neues Team wird durch `import + @listen` hinzugefügt
- `ScanState` nimmt neue Felder via Pydantic auf — Datenfluss erweiterbar
- Alle Teams sind in sich geschlossen (eigene `__init__.py`, eigene Flows)
- `run_flow()` / `resume_flow()` als saubere API — kann aus anderen CrewAI-Flows aufgerufen werden

**Verbesserungspotenzial:**
-— Teams kommunizieren über Dateien (`workflow_last.json`), nicht über Flow-State direkt  das ist robuster aber weniger idiomatisch für CrewAI
- Kein einheitliches Error-Handling-Interface zwischen Teams
- Team 2 (interpret) und Team 4 (threatintel) parsen `workflow_last.json` neu statt State zu nutzen — Redundanz
- `--plot`-Feature erzeugt Flow-Graphen, aber nur für den Master-Flow

**Fazit CrewAI-Konformität:** Die Anwendung nutzt CrewAI idiomatisch und korrekt, mit einigen pragmatischen Abweichungen (File-basierte Kommunikation, kein Memory, Planner-Deaktivierung). Die Abweichungen sind dokumentiert und begründet.

---

## 4. Informationsumfang für Webdomain-Reconnaissance

### Was das Framework aktuell liefert

| Bereich | Detail | Vollständigkeit |
|---|---|---|
| **Subdomains** | subfinder, amass, assetfinder, sublist3r, dnsrecon | ✅ Sehr gut (4+ Tools) |
| **DNS** | A/AAAA/MX/NS/TXT/SOA/CNAME, Zone-Transfer, Reverse-DNS | ✅ Sehr gut |
| **WHOIS** | Registrar, Nameserver, Dates, ASN | ✅ Gut |
| **IP/ASN** | ASN, ISP, Geo (via whois) | ✅ Gut |
| **Open Ports** | Vollständiger Port-Scan (nmap -p 1-65535) | ✅ Exzellent |
| **Service-Versionen** | nmap -sV, whatweb, httpx | ✅ Exzellent |
| **Web-Tech-Stack** | whatweb, httpx, curl-Header | ✅ Exzellent |
| **TLS-Konfiguration** | sslscan + testssl.sh (100+ Checks) | ✅ Exzellent |
| **CVEs** | searchsploit + NVD API v2 + nuclei | ✅ Exzellent |
| **Exploit-PoC** | searchsploit, DDG, nuclei-Treffer | ✅ Sehr gut |
| **Threat Intel** | OTX, Shodan, VirusTotal | ✅ Gut (API-Keys nötig) |
| **OWASP Mapping** | OWASP Top 10 via Knowledge Source | ✅ Gut |
| **Risk Score** | Deterministisch aus CVSS + Exploit + Threat | ✅ Sehr gut |
| **Archiv-URLs** | waybackurls + gau (Multi-Source) | ✅ Sehr gut |
| **Web-Crawling** | katana (JS-Rendering optional) | ✅ Gut |
| **HTTP-Security-Header** | curl -I + whatweb | ✅ Grundlegend |
| **Directory-Fuzzing** | ffuf (nur full + bei explizitem Objective) | ✅ Eingeschränkt |

### Was fehlt (Lücken für Vollständigkeit)

#### 🔴 Kritische Lücken (deutlicher Mehrwert)

1. ~~**WAF-Erkennung**~~ ✅ **UMGESETZT (2026-06-26)**
   - ~~Kein wafw00f oder ähnliches Tool~~
   - `Wafw00fTool` (`wafw00f_detect`) in `tools/active_scanning.py`, am `blue_agent`, läuft bei
     `web`/`full`-Scope zuerst. Graceful-Disable via `shutil.which` (Binary noch nicht installiert →
     `pip install wafw00f`).
   - Report-Hinweis „Target hinter WAF" deterministisch über `_waf_detection_guardrail` (tasks.py):
     hängt bei Treffer `=== WAF/CDN DETECTED ===` an den blue-Output → fließt via context in findings
     + Final Report. Positiv/Negativ-Kontrolle verifiziert (erkennt Cloudflare, ignoriert „No WAF").
   - Adressiert genau die Folge „Banner täuschen generische Server vor → CVE-Analyse bleibt leer":
     leeres CVE-Ergebnis hinter WAF wird im Report explizit als NICHT-aussagekräftig markiert.

2. **Authentifizierte Scans**
   - Keine Login/API-Key-Unterstützung
   - Applications hinter Login bleiben unsichtbar
   - **Empfehlung:** Session-Cookie/Token als Input-Parameter, httpx/nikto mit Auth-Header

3. **JavaScript-Analyse**
   - katana crawlt, aber kein JS-Parsing (source map analyse, hidden endpoints in JS)
   - Moderne SPAs (React, Vue, Angular) verstecken API-Endpunkte im JS-Bundle
   - **Empfehlung:** `subjs` oder `jsubfinder` + Linkfinder-ähnliche Analyse

#### 🟡 Wichtige Ergänzungen

4. **API-Endpunkt-Fuzzing**
   - ffuf fuzzt nur Verzeichnisse, keine REST-API-Endpunkte
   - REST-APIs (GraphQL, Swagger/OpenAPI) werden nicht angetastet
   - **Empfehlung:** `kiterunner` (REST-API-Fuzzer) + OpenAPI-Swagger-Detektion via whatweb

5. **ParamStringer/Parameter-Analyse**
   - Welche Parameter akzeptiert ein Endpunkt? Welche sind verwundbar?
   - **Empfehlung:** `arjun` für Parameter-Enumeration

6. **Screenshot/Visuelle Recon**
   - EyeWitness war vorhanden, wurde entfernt (Selenium fehlte)
   - Screenshots helfen Pentestern, Targets schnell zu priorisieren
   - **Empfehlung:** `gowitness` (Go, keine Selenium-Abhängigkeit) als Ersatz

7. ~~**CORS/Misconfiguration-Checks**~~ ✅ **UMGESETZT (2026-06-26)**
   - Objective-getriggert (kein neues Tool, keine separate Phase): wenn das Objective
     Fehlkonfiguration/CORS/Misconfiguration/Open-Redirect erwähnt, weist der blue-Task
     `nuclei tags='misconfiguration,cors,redirect'` an — systematisch statt zufällig.
   - Verifiziert: nuclei lädt für diese Tags real Templates (misconfiguration 9, cors 6,
     redirect 186); Tool-Pfad E2E sauber. Gleiches Muster wie API-Erkennung (#4) + wafw00f (#1).
   - Hinweis: „separate Phase" (urspr. Empfehlung) bewusst NICHT gebaut — objective-getriggerte
     Tags sind leichtgewichtiger und scope-konform (Misconfig = Infra, kein DAST).

8. **CDN-Erkennung**
   - Wer steckt hinter cloudflare/fastly/cloudfront?
   - **Empfehlung:** `bypass-firewalls-by-DNS-history` oder `cloudfail`-ähnliche Logik

#### 🟢 Nice-to-have

9. **Technologie-Versionsdatenbank**
   - Erkannte Versionen mit EOL-Daten anreichern (z.B. "PHP 7.4 ist EOL seit Nov 2022")
   - **Empfehlung:** Lokale versions-DB (JSON) mit EOL/LTS-Status

10. ~~**CVE-Suche in GitHub Advisories / OSV**~~ ❌ **BEWUSST ABGELEHNT (2026-06-26)**
    - Begründung: OSV.dev + GitHub Security Advisories sind **package-/ecosystem-zentriert**
      (indexiert nach npm/PyPI/Maven/Go-Koordinaten → beantwortet „welche Vulns hat `lodash@4.17.20`?").
      Die Suite scannt aber **Infrastruktur von außen** und kennt **Server-Software-Banner**
      (`OpenSSH 9.6p1`, `Apache 2.4.7`, `WebLogic 12.2.1.3`). Das ist eine Identitäts-Diskrepanz:
      **NVD ist CPE-basiert → passt zu Bannern** (genau deshalb der `cpe_map.py`-Ansatz aus Phase 9);
      OSV glänzt bei SCA (package-lock scannen), nicht bei Remote-Infra. Für klassische Server-
      Software ist die OSV-Abdeckung zudem dünner als NVD.
    - Der wahre Kern der Empfehlung („NVD nicht immer aktuell/erreichbar") ist real, heißt aber
      **NVD-Verfügbarkeit als Single Point of Failure** (siehe BUG-14: 503/Timeout sichtbar gemacht) —
      NICHT „OSV fehlt". OSV als NVD-Ausfall-*Fallback* wäre denkbar, erfordert aber Banner→Ecosystem-
      Mapping und liefert bei Server-Software wenig → Nutzen/Aufwand zu gering.
    - Würde OSV/GHSA erst lohnen, wenn die Suite Web-App-**Dependencies** fände (npm/PyPI-Versionen) —
      das tut sie nicht (kein SCA, kein JS-Bundle-Parsing, außerhalb Scope).

11. **Docker-Image-Analyse**
    - Erkennt das Target Docker? Welche Images laufen?
    - **Empfehlung:** `dockscan` oder nuclei-docker-Templates

12. **Git-Repository-Erkennung**
    - `.git`-Header-Leak, exposed Repositories
    - **Empfehlung:** nuclei exposure-Templates oder `gitdumper`-Wrapper

### Bewertungsskala

| Aspekt | Aktuell | Potenzial |
|---|---|---|
| Passive Recon | 8/10 | 9/10 |
| Active Scanning | 9/10 | 10/10 |
| CVE-Analyse | 9/10 | 10/10 |
| Threat Intelligence | 7/10 | 8/10 |
| Compliance | 7/10 | 8/10 |
| Reporting | 8/10 | 9/10 |
| API-Testing | 2/10 | 7/10 |
| JS/SPA-Analyse | 3/10 | 7/10 |
| Screenshots | 0/10 | 6/10 |
| **Gesamt** | **~6/10** | **~8/10** |

---

## 5. Code- und Struktur-Bewertung

### Architektur

| Kriterium | Bewertung | Begründung |
|---|---|---|
| **Modularität** | ⭐⭐⭐⭐⭐ | Sechs unabhängige Teams mit klaren Schnittstellen, jedes in eigenem Package |
| **Kohäsion** | ⭐⭐⭐⭐⭐ | Jede Datei hat genau eine Verantwortung (crew.py = Crew-Logik, tasks.py = Task-Defs, agents.py = Agent-Defs) |
| **Kopplung** | ⭐⭐⭐⭐ | Lose Kopplung über ScanState/JSON-Dateien — keine direkten Team-zu-Team-Aufrufe |
| **Erweiterbarkeit** | ⭐⭐⭐⭐ | Neues Team = neues Package + @listen in flow.py. State per Pydantic erweiterbar |
| **Testbarkeit** | ⭐⭐⭐ | Guardrails haben Unit-Test-Logik (NVD-Fallback), aber keine durchgängigen Tests |

### Code-Qualität

| Kriterium | Bewertung | Begründung |
|---|---|---|
| **Typisierung** | ⭐⭐⭐⭐⭐ | Durchgängig Type Hints, Pydantic-Modelle, mypy-konform |
| **Dokumentation** | ⭐⭐⭐⭐⭐ | Jede Datei hat ausführlichen Docstring, JEDE Entscheidung ist kommentiert (auch "warum NICHT") |
| **Fehlerbehandlung** | ⭐⭐⭐⭐⭐ | Retry-Logik, Backoff, graceful Degradation, BUG-Guards (BUG-6, BUG-14, BUG-17) |
| **Lesbarkeit** | ⭐⭐⭐⭐⭐ | Klare Struktur, sprechende Namen, einheitlicher Style |
| **Wartbarkeit** | ⭐⭐⭐⭐ | Hervorragend dokumentiert, aber viele "Phase 7"-Kommentare deuten auf historische Refactorings hin |

### Besonders positiv

1. **Selbstdokumentierender Code**: Jede Datei beginnt mit Usage-Beispiel und Architekturbeschreibung. Jede Konfigurationsentscheidung hat einen Kommentar der das "Warum" erklärt (nicht nur das "Was").

2. **Bug-Tracking im Code**: Bugs werden mit IDs (BUG-6, BUG-14, BUG-17, BUG-18, BUG-19) referenziert und die Lösungen dokumentiert — das ist außergewöhnlich gut.

3. **Guardrail-System**: Die Guardrails sind durchdacht und verhindern systematisch Halluzinationen:
   - `_tool_call_guardrail` → kein Tool = rejected
   - `_cve_trace_guardrail` → CVE nicht im Tool-Output = rejected  
   - `_cve_tool_used_guardrail` → kein CVE-Tool = rejected
   - `_scope_coverage_guardrail` → Pflicht-Tools fehlen = rejected

4. **Pentest-Fokus**: Die konsequente Ausrichtung auf Penetrationtesting (nicht Audit) zieht sich durch ALLE Teams — vom Task-Prompt bis zum Risk-Scoring.

5. **Resilienz-Design**:
   - Retry mit Backoff (5× LLM, 3× strukturell)
   - Vollneustart statt Intra-Crew-Resume
   - Graceful Degradation ohne API-Keys
   - BUG-6-Detection (stille Scan-Fehler)

### Verbesserungspotenzial

1. **Test-Abdeckung**: Es gibt ein `debugging/`-Verzeichnis mit Diagnose-Skripten, aber keine strukturierten Unit-/Integration-Tests. Das ist für ein Framework dieser Größe und Komplexität ein Risiko.

2. **Logging statt Print**: Die Anwendung nutzt `rich.console` für Output — das ist für CLI gut, aber für Debugging/Produktion wäre ein `logging`-Modul mit Level-Steuerung besser.

3. **Hardcoded Pfade**: `EMBED_BASE_URL` default auf `localhost:11434`, `PLANNER_BASE_URL` hardcoded auf `localhost:11434` — bei Remote-Setup mit verschachtelten Ollama-Instanzen kann das brechen.

4. **Kein Caching-Layer**: NVD-API-Abfragen werden nicht gecached. Bei 10 Targets × 5 CVEs = 50 API-Calls → Rate-Limit-Probleme (5 req/30s ohne API-Key).

5. **Kein Config-Validation**: `models.json` wird ohne Schema-Validierung geladen — Tippfehler führen zu stillen Fallbacks.

6. **Historische Altlasten**: `_ShallowMemory`, `_crew_memory`, LanceDB-Entfernungen sind als "Phase 7" dokumentiert. Das ist gut dokumentiert, aber der Code könnte von einer Bereinigung profitieren.

---

## 6. Zusammenfassung

### Was ist recon-suite?

recon-suite ist ein **agentisches Vulnerability-Assessment-Framework** das sechs spezialisierte Teams orchestriert, um Webdomains und IPs automatisiert zu analysieren — von passiver Reconnaissance über aktives Scanning, CVE-Validierung, Threat Intelligence, Compliance-Mapping bis zum priorisierten Risk-Score.

### Stärken

1. **Umfassende Tool-Kette**: 26 bewährte Security-Tools (nmap, nuclei, whatweb, nikto, sslscan, testssl.sh, ProjectDiscovery-Reihe) decken die wichtigsten Recon-Bereiche ab.
2. **Strukturierte Pipeline**: 7 Phasen in Team 1 + 5 Post-Scan-Teams mit dynamischem Routing — keine starre Abarbeitung.
3. **Halluzinations-Prävention**: 5 Guardrails verhindern erfundene CVEs und erzwingen echten Tool-Einsatz.
4. **Pentest-Optimierung**: Berichte sind auf Exploit-Entwicklung ausgerichtet, nicht auf Compliance-Listen.
5. **Resume & Resilience**: Flow-Persistenz, Retry-Logik, Backoff, BUG-Detection.
6. **Dokumentation**: Außergewöhnlich gute Code-Kommentare und Architektur-Dokumentation.

### Schwächen

1. **Fehlende API/SPA-Analyse**: Keine systematische REST-API-, GraphQL- oder JavaScript-Analyse.
2. **Keine Screenshots**: Visuelle Recon fehlt komplett.
3. **Kein WAF-Bypass**: Cloudflare/CDN erkannt, aber nicht umgangen.
4. **Test-Abdeckung**: Keine strukturierten Tests.
5. **Kein Caching**: NVD-API-Calls werden nicht zwischengespeichert.
6. **Historische Altlasten**: Mehrere Refactoring-Runden (Phase 7) haben Spuren hinterlassen.

### CrewAI-Konformität

recon-suite nutzt CrewAI **idiomatisch und korrekt**. Resume, Router, Guardrails, Pydantic-Outputs, Persist — alles wird wie vorgesehen verwendet. Die Abweichungen (kein Memory, File-basierte Team-Kommunikation, Planner-Deaktivierung) sind dokumentiert und haben gute Gründe. Die Anwendung lässt sich mit anderen CrewAI-Flows kombinieren (via `run_flow()` / `resume_flow()`).

### Gesamtbewertung

| Kategorie | Note | Begründung |
|---|---|---|
| Architektur | 1–2 (sehr gut) | Modular, lose gekoppelt, erweiterbar |
| Code-Qualität | 1 (hervorragend) | Sauber typisiert, dokumentiert, fehlertolerant |
| Tool-Auswahl | 2 (gut) | Umfassend aber Lücken bei API/JS/WAF |
| Informationsumfang | 2–3 (gut) | Exzellent für klassische Recon, schwach bei modernen Web-Apps |
| CrewAI-Integration | 1–2 (sehr gut) | Idiomatisch mit pragmatischen Ausnahmen |
| Erweiterbarkeit | 2 (gut) | Neues Team = neues Package + @listen |
| Test-Abdeckung | 4–5 (mangelhaft) | Keine strukturierten Tests |
| **Gesamt** | **2 (gut)** | Produktionsreifes Framework mit klaren Stärken und dokumentierten Lücken |

### Empfohlene nächste Schritte für Vollständigkeit

1. **Kurzfristig (niedriger Aufwand, hoher Nutzen):**
   - `wafw00f`-Wrapper → WAF-Erkennung
   - NVD-Response-Caching → Weniger API-Calls
   - `gowitness`-Wrapper → Screenshots (kein Selenium nötig)

2. **Mittelfristig (moderater Aufwand):**
   - `kiterunner`-Wrapper → API-Endpunkt-Fuzzing
   - `arjun`-Wrapper → Parameter-Enumeration
   - `subjs`/`jsubfinder` → JavaScript-Endpunkt-Extraktion
   - Unit-Tests für Guardrails und Tools

3. **Langfristig (höherer Aufwand):**
   - Authentifizierte Scan-Modi (Session/Token)
   - OpenAPI/Swagger-Detektion + strukturiere API-Tests
   - CVE-Caching (lokale SQLite-DB statt NVD-API)
   - CDN-Bypass-Logik (Origin-IP-Findung)