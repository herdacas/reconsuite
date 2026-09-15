# AgentScanIT — Agentic Vulnerability Assessment Framework

Multi-Agent Security Assessment auf Basis von [CrewAI](https://crewai.com) und LLMs via [Ollama](https://ollama.com) (lokal oder remote). Sechs spezialisierte Teams arbeiten sequenziell: vom passiven OSINT-Scan bis zum priorisierten Risk-Score mit OWASP-Compliance-Mapping.

---

## Einordnung im Pentest-Prozess

Diese Suite ist kein eigenständiges Pentest-Tool, sondern deckt einen definierten Ausschnitt der [PTES](http://www.pentest-standard.org/)-Methodik ab — die Ausgabe ist der Input für die nachfolgenden Phasen eines echten Penetrationstests:

| PTES-Phase | Abgedeckt | Wo |
|---|---|---|
| 1. Pre-Engagement (Scoping, Rules of Engagement) | — | manueller Prozess außerhalb der Suite |
| 2. Intelligence Gathering | ✅ | Team 1 — passive Recon/OSINT (`research_agent`) |
| 3. Threat Modeling | ✅ | Team 4 — Threat Intelligence (OTX/Shodan/VirusTotal) |
| 4. Vulnerability Analysis | ✅ | Team 1 (Active Scan + CVE-Analyse) · Team 2 (NVD-Enrichment) · Team 6 (Risk Scoring) |
| 5. Exploitation | ↗️ separates Programm | bewusst außerhalb dieser Suite — siehe unten |
| 6. Post-Exploitation | — | bewusst außerhalb des Scopes |
| 7. Reporting | ✅ | Team 3 — Final Report · Team 5 — OWASP-Mapping |

Die Reports sind entsprechend als **Übergabeartefakt an Phase 5** konzipiert: `final_report_*.md`, `risk_score_*.json` und `RedOutput.confirmed_attack_surface`/`exploitable_findings` liefern die Kandidaten für eine Exploitation-Phase — bewusst als Aufgabe eines separaten, eigenständigen Programms, nicht dieser Suite (siehe `roadmap.md`, „Scope-Grenze“). recon-suite endet bei strukturierten, tool-bestätigten Findings, nicht beim Endergebnis eines vollständigen Pentests.

---

## Was es macht

```
Passive Recon  →  Active Scan  →  CVE-Analyse  →  NVD-Enrichment
      ↓
Threat Intel  →  Compliance-Mapping  →  Risk-Scoring  →  Final Report
```

Jede Phase ist ein eigenständiger CrewAI-Flow oder deterministischer Prozess. Ein LLM-Planner wählt anhand von Scope und Objective die relevanten Phasen aus. Das Routing nach dem Scan entscheidet dynamisch welche Teams aktiv werden.

### Report-Scope: Pentest, nicht Audit

Die Berichte sind auf einen **Penetrationstest** ausgerichtet, nicht auf ein defensives Audit:

- **Fokus auf Ausnutzung** — die Reports bereiten die Tool-Daten so auf, dass sie zur Exploit-Entwicklung weiterverwendet werden können (exakte Versionen inkl. Patch-Level, Angriffsvektoren, exponierte Endpunkte, Payloads).
- **Security-/Remediation-Empfehlungen NUR bei nachgewiesener Ausnutzbarkeit (PoC).** „Nachgewiesen" heißt deterministisch: ein aktiver `nuclei`-Treffer gegen das Ziel — nicht „ein PoC existiert irgendwo". Ohne PoC beschreiben die Reports ausschließlich die Angriffsfläche und potenzielle Ausnutzungs-Pfade.
- **Versionslose generische CVEs** (Banner ohne Version) werden NICHT als Findings gelistet — eine Liste „alle CVEs für Apache" ohne Versions-Match ist wertloses Rauschen. Ausnahme: aktiv ausgenutzte (CISA-KEV).

---

## Architektur

### 6-Team-System

| Team | Package | Technologie | Aufgabe |
|---|---|---|---|
| 1 | `agentscanit/` | CrewAI Crew · 5 Agents · 19 Tools | Passive Recon + Active Scan + CVE-Analyse |
| 2 | `interpret_agent/` | CrewAI Flow | NVD API v2 — CVE-Details, CVSS, Severity |
| 3 | `reporting/` | CrewAI Flow | Merge aller Reports → `final_report_*.md` |
| 4 | `threatintel_agent/` | CrewAI Flow (kein LLM) | OTX · Shodan · VirusTotal — In-the-Wild-Status |
| 5 | `compliance_agent/` | CrewAI Crew · LLM · OWASP Knowledge | OWASP Top 10 Mapping |
| 6 | `risk_scorer/` | CrewAI Flow (kein LLM) | Deterministisches Risk-Scoring |

### Flow-Routing

Nach dem Scan entscheidet der Router welche Teams laufen:

```
Kein CVE gefunden   →  CLEAN         →  Team 3 (direkt)
CVEs, kein Exploit  →  CVA_ANALYSIS  →  Teams 2 → 5 → 6 → 3
CVEs + Exploit      →  FULL_ANALYSIS →  Teams 2 → 4 → 5 → 6 → 3
```

### Kommunikation zwischen Teams

Teams kommunizieren **nicht direkt**. Alle Übergaben laufen über `ScanState` — ein Pydantic-Modell im CrewAI Flow:

```
Team 1  →  scan_json_path, has_cve_findings, has_exploitable
Team 2  →  nvd_results (CVSS, Severity pro CVE)
Team 4  →  threat_intel_output (In-the-Wild-Summary)
Team 5  →  compliance_output (OWASP-Mapping-Text)
Team 6  →  risk_score_output ("Score: 7.8 / 10 — HIGH")
Team 3  →  final_report_path
```

Innerhalb von Team 1 kommunizieren die 5 Agents über den CrewAI Task-Kontext (Pydantic-Output einer Task als Kontext der nächsten).

### Agents in Team 1

| Agent | Aufgabe | Tools |
|---|---|---|
| `research_agent` | Passive OSINT: Subdomains, DNS, WHOIS | 10 |
| `blue_agent` | Active Scanning: nmap, nikto, nuclei, sslscan, httpx | 9 |
| `research_agent` | CVE-Analyse (findings_task) | searchsploit, DDG, NVD |
| `blue_agent` | Targeted Follow-up (red_scan_task, nur `full`-Scope) | nuclei, nikto |
| `red_agent` | Exploitability-Analyse: PoC-Check, Attack-Surface | searchsploit, DDG, NVD |
| `coding_agent` | Automatisierungs-Skript aus Scan-Schritten | — |
| `reporter_agent` | Markdown-Report aus allen Phasen | — |

---

## Tools

Team 1 setzt 19 externe Scan-Tools ein, aufgeteilt auf `research_agent` (passiv) und `blue_agent` (aktiv). Ausführliche technische Doku pro Tool (Binary, Version, Parameter): [`agentscanit/toolinfo.md`](agentscanit/toolinfo.md).

### Active Scanning (`blue_agent`)

| Tool | Zweck |
|---|---|
| `nmap` | Port-Scan + Service-/Versions-Erkennung (Discovery über alle 65535 Ports, dann `-sV` auf offene Ports) |
| `httpx` | HTTP-Probing vieler Hosts gleichzeitig, Tech-Detect, optionale API-Pfad-Erkennung |
| `whatweb` | Web-Technologie-Fingerprinting (CMS, Framework, Server-Software) |
| `wafw00f` | WAF-/CDN-Erkennung (Cloudflare, Akamai, ModSecurity u. a.) — läuft bei `web`/`full` zuerst |
| `nikto` | Web-Vulnerability-Scan: fehlende Security-Header, veraltete Software, Fehlkonfigurationen |
| `nuclei` | Template-basierter Vulnerability-Scanner (CVEs, Exposures, Misconfigurations) |
| `sslscan` | TLS/SSL-Konfigurationsanalyse: Protokolle, Cipher-Suites, Zertifikate |
| `curl` | HTTP-Response-Header (Security-Header, Server-Banner, Cookies) |
| `ping` | ICMP-Erreichbarkeitsprüfung vor aufwändigeren Scans |

### Passive Recon / OSINT (`research_agent`)

| Tool | Zweck |
|---|---|
| `subfinder` | Passive Subdomain-Enumeration (Certificate Transparency, DNS-Datenbanken) |
| `dnsrecon` | DNS-Enumeration, Zone-Transfer-Check (AXFR) |
| `dnsx` | DNS-Massen-Resolver, filtert nicht-existente Subdomains |
| `dig` | Einzelne DNS-Abfragen (A/AAAA/MX/NS/TXT/…) |
| `whois` | Registrar, Nameserver, Registrierungsdatum |
| `katana` | Web-Crawler: URLs, API-Endpunkte, Formulare, JS-Links |
| `ddgs` (DuckDuckGo) | OSINT- und CVE-PoC-Recherche |
| `searchsploit` | Lokale ExploitDB-Suche nach Software + Version |
| NVD API v2 (`nvd_cpe_lookup`, `nvd_cve_search`) | CVE-Lookup per CPE bzw. Keyword, CVSS/Severity |

`red_agent`, `coding_agent` und `reporter_agent` erhalten keine eigenen Tools — sie arbeiten analytisch auf Basis der strukturierten Outputs vorangehender Tasks (`red_agent` nutzt `searchsploit`/DDG/NVD zur Verifikation, s. o.).

---

## Voraussetzungen

- Python 3.11+
- Ollama lokal oder remote (API-kompatibler Endpunkt)
- **Externe Scan-Tools** (System-Binaries, KEINE Python-Pakete): `nmap`, `nikto`, `whatweb`,
  `sslscan`, `dnsrecon`, `whois`, `dig`, `curl`, `ping` (apt) · `nuclei`, `httpx`, `dnsx`,
  `katana`, `subfinder` (ProjectDiscovery, Go) · `searchsploit` (exploitdb, Git)

```bash
# 1. Python-Abhängigkeiten
pip install -r requirements.txt

# 2. Externe Scan-Tools (Kali/Debian/Ubuntu) — idempotent, installiert nur Fehlendes
sudo bash setup_tools.sh
bash setup_tools.sh --check        # nur prüfen welche Tools fehlen (installiert nichts)

# 3. Modelle konfigurieren
cp agentscanit/models.json.example agentscanit/models.json
```

> **Hinweis:** Die Scan-Tools sind kompilierte Binaries (C/Go), keine Python-Pakete — sie
> gehören daher NICHT in `requirements.txt`. `setup_tools.sh` installiert sie aus den
> korrekten Quellen (apt / `go install` / Git). Wichtig: `httpx` ist die **ProjectDiscovery**-
> Variante (Go), nicht das gleichnamige apt-/Python-Paket.

---

## Modell-Anforderungen

Das Framework treibt die Agents über **Ollama native Function-Calling**. Nicht jedes LLM ist geeignet —
die Anforderungen sind empirisch ermittelt (mehrere Modelle gegen echte Scans getestet, Details in `roadmap.md`).

**Ein verwendbares Modell MUSS:**
1. **Natives Tool-Calling / Function-Calling** beherrschen. Reine Chat-Modelle scheitern mit
   „Invalid response from LLM call". Geeignet sind Coder-/Tool-Use-trainierte Modelle.
2. **Stabil bei tiefen Multi-Turn-Tool-Ketten** sein (≥10 Nachrichten). Das ist der eigentliche Test —
   ein einzelner Tool-Call sagt nichts aus. Manche Modelle bestehen Einzel-Calls, scheitern aber im
   echten Scan mit leeren Antworten.
3. **Non-Reasoning sein ODER `think:False` respektieren.** Reasoning-Modelle verlieren bei tiefen
   Ketten sporadisch ihre Antwort im verworfenen Reasoning-Kanal.

**Empirisch als tauglich bestätigt (Stand variiert — aktuelle Auswahl über `models.json`):**

| Rolle | Modell-Kandidaten |
|---|---|
| **Remote-Worker** (analysis/research/code) | Non-Reasoning Tool-Use-Modelle, z. B. `qwen3-coder`, `nemotron-3`-Familie |
| **Lokal-Worker** | `qwen2.5:7b-instruct`, `llama3-groq-tool-use:8b`, `qwen3-coder:30b` |
| **Planner** (läuft immer lokal) | `qwen2.5:7b-instruct` — remote Modelle unterstützen Ollama's native FC-API nicht zuverlässig |

**Nicht geeignet:** Gemma-Familie (schwaches agentic Function-Calling, scheitert im echten Scan trotz
bestandener Einzel-Calls), reine Reasoning-Modelle ohne `think:False`-Konformität.

> **Diagnose-Werkzeug:** `RECON_LLM_DEBUG=1 python3 main.py …` protokolliert jeden LLM-Call
> (Prompt-Größe, Status, Leerantworten) nach `logs/llm_debug_<pid>.jsonl` — nützlich um ein neues
> Modell auf Tauglichkeit zu prüfen.

---

## Schnellstart

```bash
# Top-Level-Flow (empfohlen — alle 6 Teams)
python3 main.py example.com
python3 main.py example.com web                  # Scope als Argument
python3 main.py example.com "CVE-Suche" web      # Objective + Scope
python3 main.py                                  # interaktiv

# Flow-Resume nach Unterbrechung
python3 main.py --list                           # gespeicherte Runs anzeigen
python3 main.py --resume <flow-id>               # fortsetzen

# Nur Team 1 (Scanner ohne NVD + Reporting)
cd agentscanit && python3 main.py example.com
```

### Scopes

Der Scope bestimmt, welche Tasks innerhalb Team 1 laufen (`research_agent`/`blue_agent` nutzen dabei
immer dieselben registrierten Tools — der Scope steuert Tiefe/Fokus über die Task-Prompts, z. B.
Portbereich bei `nmap`):

| Scope | Tasks (Team 1) | Team 1 folgt Routing zu |
|---|---|---|
| `osint` | research → report | Team 3 (direkt) |
| `ssl` | research → blue → report | Team 3 (direkt) |
| `quick` | research → blue → findings → report | Router (Teams 2–6 je nach Funden) |
| `web` / `network` | research → blue → findings → red → report | Router (Teams 2–6 je nach Funden) |
| `full` | research → blue → findings → red_scan → red → coding → report | Router (Teams 2–6 je nach Funden) |

`web` und `network` nutzen aktuell dieselbe Task-Pipeline — der Unterschied liegt in der
Scan-Tiefe/-Fokussierung, die den Agents über die Task-Beschreibung vorgegeben wird (z. B. Portbereich).

---

## Outputs

Alle Outputs landen in `logs/` (Automatisierungs-Skript in `scans/`):

| Datei | Erzeugt von | Inhalt |
|---|---|---|
| `recon_report_*.md` | Team 1 | Recon-Report mit Ports, Services, CVEs |
| `crew_*.json` | Team 1 | Strukturierter JSON-Log (Tasks, CVE-Refs, Ports) |
| `trace_*.json` | Team 1 | Tool-Calls mit Raw-Output + Timings |
| `scans/scan_*.py` | Team 1 (`coding_agent`) | Ausführbares Python-Skript, automatisiert die Scan-Schritte |
| `interpret_*.md` | Team 2 | NVD-Detaildaten pro CVE (CVSS, CWE, References) |
| `final_report_*.md` | Team 3 | Merged Final Report |
| `threatintel_*.md` | Team 4 | OTX/Shodan/VT — In-the-Wild-Status pro CVE + IP-Reputation |
| `compliance_*.md` | Team 5 | OWASP Top 10 Mapping der Findings |
| `risk_score_*.md` / `.json` | Team 6 | Risk Score + Level + Top-Findings + Next Steps (Markdown + maschinenlesbar) |
| `workflow_last.json` | Team 1 | Letzter Scan (überschrieben) — Eingabe für Teams 2–6 |
| `flow_state.db` | Flow | SQLite — Flow-State pro Run (für `--resume`) |

---

## Konfiguration

`.env` oder Umgebungsvariablen:

| Variable | Bedeutung | Default |
|---|---|---|
| `OLLAMA_BASE_URL` | Ollama-Endpunkt | `http://localhost:11434` |
| `OLLAMA_API_KEY` | API-Key für remote Ollama | — |
| `MODEL_ANALYSIS` | Modell für Analyse-Agents | aus `models.json` |
| `MODEL_RESEARCH` | Modell für Research-Agent | aus `models.json` |
| `MODEL_CODE` | Modell für Coding-Agent | aus `models.json` |
| `EMBED_MODEL` | Embedding-Modell (Knowledge Sources) | aus `models.json` |
| `NVD_API_KEY` | NVD API-Key (erhöht Rate-Limit 5→50 req/30s) | — |
| `OTX_API_KEY` | AlienVault OTX (kostenlos) | — |
| `SHODAN_API_KEY` | Shodan (paid-tier) | — |
| `VT_API_KEY` | VirusTotal (free-tier verfügbar) | — |

Teams 4–6 degradieren **graceful** ohne API-Keys — kein Crash, kein Timeout, nur `"no_key"`-Status im Output.

Modell-Auswahl über `models.json` (von `models.json.example` ableiten).

**Threat-Intel-Keys (Team 4)** lassen sich alternativ an einer Stelle eintragen statt als Env-Vars: [threatintel_agent/api_keys.md](threatintel_agent/api_keys.md.example) (von `api_keys.md.example` ableiten, gitignored — gleiches Prinzip wie `models.json`). Eine gesetzte Umgebungsvariable hat immer Vorrang.

---

## Weiterführende Dokumentation

| Datei | Inhalt |
|---|---|
| [`agentscanit/toolinfo.md`](agentscanit/toolinfo.md) | Detaillierte Tool-Referenz (Binary, Version, Parameter je Tool) |
| `roadmap.md` | Entwicklungsverlauf, Architektur-Entscheidungen, technische Schulden (nicht Teil des Repos — lokal) |
| `CLAUDE.md` | Laufende Session-Doku für KI-gestützte Weiterentwicklung: Architektur-Patterns, gelöste Bugs mit Root-Cause, offene Punkte |
