# AgentScanIT – Tool Chain Analysis

> Erstellt: 2026-05-23 | Aktualisiert: 2026-05-23 (Config-Lücken geschlossen, EyeWitness entfernt)  
> Grundlage: tools.py, agents.py, config.py + Live-Checks auf dem System

---

## Übersicht

Das Framework integriert **26 Tools** in zwei Kategorien:

| Kategorie | Agent | Anzahl Tools |
|---|---|---|
| Active Scanning | `blue_agent` | 12 |
| Passive Recon / OSINT | `research_agent` | 14 |

`red_agent`, `coding_agent` und `reporter_agent` erhalten keine Tools — sie arbeiten analytisch auf Basis der Pydantic-Outputs der vorangehenden Tasks.

---

## Gruppe A – Active Scanning (`blue_agent`)

### 1. `nmap_scanner` – NmapTool

**Binary:** `nmap` (System-PATH)  
**Version installiert:** 7.94SVN (Development Snapshot)  
**Letzte stabile Version:** 7.95 (März 2024)

Port- und Service-Scanner. Unterstützt zwei Modi:
- **Standard**: Top-1000-Ports, schneller Überblick
- **Aggressiv + Full-Range**: Zweistufiger Scan — Discovery über alle 65535 Ports, dann Service-Detection (`-sV -sC -A`) nur für die gefundenen offenen Ports

Adaptive Parameter: `ports` (Portbereich), `aggressive` (Versions- und OS-Detection).  
Timeout: 360s (Discovery) + 300s (Scan).

**Status:** ✓ Installiert. Dev-Snapshot statt Stable — für Pentest-Zwecke kein Risiko.

---

### 2. `nikto_scanner` – NiktoTool

**Binary:** `nikto` (System-PATH)  
**Version installiert:** 2.1.5  
**Letzte stabile Version:** 2.1.6

Web-Vulnerability-Scanner: prüft Webserver auf bekannte Schwachstellen, fehlende Security-Header (HSTS, CSP, X-Frame-Options), veraltete Software und Fehlkonfigurationen. Arbeitet mit einer Datenbank von über 7000 Checks.

Adaptive Parameter (P1):
- `port`: Non-Standard-Ports aus Nmap-Findings (z.B. 8080, 8443)
- `tuning`: Fokus auf bestimmte Check-Kategorien (z.B. `4` = Injection, `1234` = kombiniert)

Timeout: 300s.

**Status:** ✓ Installiert. Eine Minor-Version hinter aktuellem Stand.

---

### 3. `whatweb_fingerprint` – WhatwebTool

**Binary:** `whatweb` (System-PATH)  
**Version installiert:** 0.5.5  
**Letzte stabile Version:** 0.5.5 (aktuell)

Web-Technologie-Fingerprinting: erkennt CMS (WordPress, Drupal, Joomla), Frameworks (Django, Laravel, React), Server-Software (Apache, nginx, IIS), Plugins und Versionsinformationen aus HTTP-Headern, Cookies und HTML-Inhalt.

Output wird von `blue_agent` genutzt um `nuclei`-Tags zu befüllen.

**Status:** ✓ Installiert, aktuelle Version.

---

### 4. `sslscan_tls` – SslscanTool

**Binary:** `sslscan` (System-PATH)  
**Version installiert:** 2.1.2  
**Letzte stabile Version:** 2.1.4

SSL/TLS-Konfigurationsanalyse: prüft unterstützte Protokollversionen (SSLv2/3, TLS 1.0–1.3), Cipher-Suites (starke vs. schwache), Zertifikatsdetails (Aussteller, Gültigkeit, SANs) und bekannte Angriffe (Heartbleed, POODLE, BEAST, CRIME). Schneller als testssl.sh für Basisprüfungen.

Flag `--no-failed` filtert fehlgeschlagene Handshakes aus der Ausgabe.

**Status:** ✓ Installiert. Zwei Minor-Versionen hinter aktuellem Stand.

---

### 5. `testssl_full` – TestsslTool

**Binary:** `testssl.sh/testssl.sh` (externes Skript)  
**Version installiert:** 3.3dev (Development Branch)  
**Letzte stabile Version:** 3.2

Vollständiger TLS-Audit: prüft alle Protokolle, alle Cipher-Suites, Zertifikate, Certificate Transparency, OCSP Stapling und alle bekannten TLS-Angriffe. Deutlich umfangreicher als sslscan, entsprechend langsamer.

Wird aus seinem eigenen Verzeichnis (`TESTSSL_DIR`) ausgeführt da es relative Datenbankpfade nutzt.

**Status:** ✓ Installiert (externes Repo-Klon). Development-Branch — stabiles 3.2 wäre robuster.

---

### 6. `curl_http_headers` – CurlTool

**Binary:** `curl` (System-PATH, nicht in config.py — hardcoded)  
**Version:** System-curl

Ruft ausschließlich HTTP-Response-Header ab (`curl -s -I`). Nützlich für manuelle Prüfung von Security-Headern (HSTS, CSP, X-Frame-Options, CORS), Server-Bannern und gesetzten Cookies. Unterstützt Redirect-Following.

**Status:** ✓ Verfügbar. Kein eigener config.py-Eintrag für den Binary-Pfad — pragmatisch da curl überall vorhanden.

---

### 7. `ping_check` – PingTool

**Binary:** `ping` (System-PATH)  
**Version:** System-ping

ICMP-Erreichbarkeitsprüfung mit konfigurierbarer Paketanzahl und Latenzausgabe. Erste Stufe zur Host-Validierung vor aufwändigeren Scans.

**Status:** ✓ Verfügbar.

---

### 8. `nuclei_vulnerability_scanner` – NucleiTool

**Binary:** `/root/go/bin/nuclei`  
**Version installiert:** v3.8.0  
**Letzte stabile Version:** v3.x (ProjectDiscovery veröffentlicht häufig)

Template-basierter Vulnerability-Scanner mit Community-gepflegter Template-Bibliothek (25.000+ Templates). Prüft auf bekannte CVEs, Fehlkonfigurationen, exponierte Administrations-Interfaces, Default-Credentials und veraltete Software.

Adaptive Parameter (P1):
- `templates`: Template-Kategorie (z.B. `cves`, `exposures`, `misconfigurations`)
- `severity`: Filtert nach Kritikalität (`critical,high` für CVE-Fokus)
- `tags`: Technologie-spezifisches Scanning (z.B. `apache`, `wordpress`, `django`) — befüllt aus whatweb/httpx-Findings

**Status:** ✓ Installiert, aktuell.

---

### 9. `ffuf_fuzzer` – FfufTool

**Binary:** `ffuf` (System-PATH)  
**Version installiert:** 2.1.0-dev  
**Letzte stabile Version:** 2.1.0

Web-Fuzzer für Directory-, File- und VHost-Enumeration. Findet versteckte Pfade, Admin-Bereiche, Backup-Dateien und nicht verlinkte Endpunkte. Nutzt FUZZ-Platzhalter in der URL.

Standard-Wordlist: `/usr/share/dirb/wordlists/common.txt`  
Konfigurierbarer HTTP-Status-Code-Filter.

Scope-Restriktion: nur bei Scope `full` und wenn Objective explizit Pfade/Endpunkte erwähnt.

**Status:** ✓ Installiert. Dev-Version, funktional identisch zu 2.1.0.

---

### 10. `enum4linux_smb` – Enum4linuxTool

**Binary:** `enum4linux-ng/enum4linux-ng.py` (externes Skript, via `venv/bin/python3`)  
**Version:** Git-Klon (kein explizites Versionsetikett)

SMB/NetBIOS-Enumeration für Windows- und Samba-Hosts: listet Shares, User-Accounts, Gruppen, Passwort-Policies und Domain-Informationen auf. Verbesserte Python-Neuimplementation des klassischen enum4linux.

Wird nur bei bestätigtem offenem Port 445 eingesetzt (STOPP-Regel in blue_task).

**Status:** ✓ Skript vorhanden. Dependency-Check empfohlen (impacket, ldap3).

---

### 11. `httpx_prober` – HttpxTool

**Binary:** `/snap/bin/httpx` (Snap-Paket, expliziter Pfad in config.py)  
**Version installiert:** v1.2.1  
**Letzte stabile Version:** v1.x (ProjectDiscovery)

HTTP-Probing für viele Hosts gleichzeitig: prüft Erreichbarkeit, ermittelt HTTP-Statuscodes, Seitentitel und erkannte Technologien (`-tech-detect`). Liest Targets von stdin (kommagetrennte Liste). Ideal für schnelles Screening von Subdomain-Listen.

**Status:** ✓ Installiert (Snap). Expliziter Pfad notwendig da Snap-Binaries nicht immer im System-PATH landen.

---

### 12. `naabu_port_scanner` – NaabuTool

**Binary:** `naabu` (via PATH → `/root/go/bin/naabu`)  
**Version installiert:** v2.6.1  
**Letzte stabile Version:** v2.x (ProjectDiscovery)

Schneller TCP-Port-Scanner auf SYN-Basis. Deutlich schneller als nmap für reine Port-Discovery. Unterstützt Top-N-Port-Scans und individuelle Portbereiche. Output wird von blue_task als Input für nmap genutzt (adaptive Port-Parameter).

⚠️ **Config-Lücke:** Kein eigener `NAABU_BIN`-Eintrag in config.py. Verwendet bare command `"naabu"` — funktioniert weil `/root/go/bin` in `$PATH`, aber inkonsistent zu nuclei/amass/subfinder.

**Status:** ✓ Installiert, aktuell.

---

### 13. `eyewitness_screenshots` – EyewitnessTool

**Binary:** `EyeWitness/Python/EyeWitness.py` (externes Skript, via `venv/bin/python3`)  
**Version:** Git-Klon

Erstellt Screenshots von Webseiten und dokumentiert HTTP-Header für schnelle visuelle Bewertung. Schreibt HTML-Report in ein konfigurierbares Ausgabeverzeichnis.

⚠️ **Kritische Abhängigkeit fehlt:** Selenium ist nicht installiert.  
Ausgabe beim Test: `[*] Selenium not found. Try: sudo apt install python3-selenium`  
→ **EyewitnessTool wird bei Ausführung mit Fehler abbrechen.**

Scope-Restriktion: nur bei Scope `full`.

**Status:** ✗ Skript vorhanden, aber nicht funktionsfähig (Selenium fehlt).

---

## Gruppe B – Passive Recon / OSINT (`research_agent`)

### 14. `ddg_web_search` – DdgSearchTool

**Package:** `ddgs` (Python, pip)  
**Import-Fallback:** `duckduckgo_search` (älterer Paketname)

DuckDuckGo-Websuche für OSINT, CVE-Recherche und Technologie-Informationen. Kein eigenes Binary — vollständig in Python implementiert. Konfigurierbare Anzahl Ergebnisse (1–10).

**Status:** ✓ Verfügbar (ddgs-Paket installiert).

---

### 15. `theharvester_osint` – TheharvesterTool

**Binary:** `uv run theHarvester` im Verzeichnis `theHarvester/` (externes Repo)  
**Version:** Git-Klon (Python 3.13 erwartet laut pyproject.toml)

Passives OSINT-Tool: sammelt E-Mail-Adressen, Subdomains, Hosts und IP-Adressen aus öffentlichen Quellen (crt.sh, Google, Bing, DuckDuckGo, Shodan u.a.). Kein direkter Kontakt zum Zielsystem.

**Status:** ✓ Verzeichnis vorhanden, läuft via `uv run`.

---

### 16. `sublist3r_subdomains` – Sublist3rTool

**Binary:** `sublist3r` (System-PATH)  
**Version:** Systempaket (Version-Flag nicht unterstützt)

Passive Subdomain-Enumeration via Suchmaschinen (Google, Bing, Yahoo, Baidu) und öffentliche DNS-Datenbanken. Multi-threaded für schnellere Ausführung. Ergänzt subfinder um andere Quellen.

**Status:** ✓ Installiert.

---

### 17. `subfinder_passive` – SubfinderTool

**Binary:** `/root/go/bin/subfinder`  
**Version installiert:** v2.13.0  
**Letzte stabile Version:** v2.x (ProjectDiscovery)

Schnelle passive Subdomain-Enumeration. Nutzt Certificate Transparency Logs (crt.sh), DNS-Datenbanken, Web-Archive und viele weitere passive Quellen. Bevorzugtes primäres Subdomain-Tool wegen Geschwindigkeit und Quellen-Vielfalt.

**Status:** ✓ Installiert, aktuell.

---

### 18. `dnsrecon_enum` – DnsreconTool

**Binary:** `dnsrecon` (System-PATH)  
**Version installiert:** 1.1.5  
**Letzte stabile Version:** 1.1.6

DNS-Enumeration: ermittelt A/AAAA/MX/NS/TXT/SOA-Records, prüft Zone-Transfer-Verwundbarkeit (AXFR), brute-forcet Subdomains und nutzt Suchmaschinen für weitere Enumeration. Umfassender als `dig` für detaillierte DNS-Analyse.

**Status:** ✓ Installiert. Eine Minor-Version hinter aktuellem Stand.

---

### 19. `dig_dns_lookup` – DigTool

**Binary:** `dig` (System-PATH)  
**Version:** System-dig (bind9-utils)

Einfache DNS-Abfragen für einzelne Record-Typen (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, ANY). Lightweight und direkt — erste Wahl für schnelle IP-Auflösung und Reverse-DNS. `+short` für kompakte Ausgabe.

**Status:** ✓ Verfügbar.

---

### 20. `whois_lookup` – WhoisTool

**Binary:** `whois` (System-PATH)  
**Version installiert:** 5.5.22

WHOIS-Abfragen für Domains und IP-Adressen: liefert Registrar, Inhaber (soweit nicht datenschutzgeschützt), Nameserver, Registrierungsdatum, Ablaufdatum und ASN/ISP-Informationen für IPs. Grundlegendes OSINT-Tool.

**Status:** ✓ Installiert.

---

### 21. `amass_enum` – AmassTool

**Binary:** `/root/go/bin/amass`  
**Version installiert:** v4.2.0  
**Letzte stabile Version:** v4.x (v3 ist EOL)

Passive Subdomain-Enumeration mit besonders breiter Quellen-Basis: Certificate Transparency, DNS-Datenbanken, ASN-Lookup, Web-Archive, Shodan (mit API-Key). Langsamer als subfinder aber umfangreicher. Scope-Restriktion: nur bei Scope `full` oder `osint`.

**Status:** ✓ Installiert, aktuell (v4-Branch).

---

### 22. `assetfinder_subdomains` – AssetfinderTool

**Binary:** `/root/go/bin/assetfinder`  
**Version:** Kein Version-Flag (Go-Binary, im go/bin)

Subdomain-Finder von Tomnomnom: nutzt primär crt.sh und Facebook Certificate Transparency. Sehr schnell, minimal, ideal als ergänzende Quelle neben subfinder.

**Status:** ✓ Installiert.

---

### 23. `dnsx_resolver` – DnsxTool

**Binary:** `dnsx` (via PATH → `/root/go/bin/dnsx`)  
**Version installiert:** v1.2.3

DNS-Massen-Resolver: löst DNS-Records für viele Hosts gleichzeitig auf (stdin-basiert). Ideal zum Validieren von Subdomain-Listen — filtert nicht-existente Subdomains heraus. Unterstützt A, AAAA, CNAME, MX, NS, TXT, PTR.

⚠️ **Config-Lücke:** Kein `DNSX_BIN`-Eintrag in config.py (bare command).

**Status:** ✓ Installiert, aktuell.

---

### 24. `katana_crawler` – KatanaTool

**Binary:** `katana` (via PATH → `/root/go/bin/katana`)  
**Version installiert:** v1.2.1

Web-Crawler von ProjectDiscovery: crawlt Webseiten und findet URLs, API-Endpunkte, Formulare und JavaScript-Links. Unterstützt optionales JavaScript-Rendering für SPAs. Konfigurierbare Crawl-Tiefe.

⚠️ **Config-Lücke:** Kein `KATANA_BIN`-Eintrag in config.py (bare command).

**Status:** ✓ Installiert, aktuell.

---

### 25. `waybackurls_archive` – WaybackurlsTool

**Binary:** `waybackurls` (via PATH → `/root/go/bin/waybackurls`)  
**Version:** Kein Version-Flag

Ruft archivierte URLs für eine Domain aus der Wayback Machine (archive.org) ab. Findet historische Endpunkte, Parameter und Pfade die nicht mehr verlinkt aber noch erreichbar sein können. Output auf 200 Zeilen begrenzt.

⚠️ **Config-Lücke:** Kein `WAYBACKURLS_BIN`-Eintrag in config.py (bare command).

**Status:** ✓ Installiert.

---

### 26. `gau_url_collector` – GauTool

**Binary:** `gau` (via PATH → `/root/go/bin/gau`)  
**Version installiert:** 2.2.4  
**Letzte stabile Version:** 2.2.4 (aktuell)

"Get All URLs" — sammelt historische URLs aus mehreren Quellen gleichzeitig: Wayback Machine, AlienVault OTX, Common Crawl und urlscan.io. Breiter als waybackurls durch Multi-Source-Ansatz. Konfigurierbare Provider.

⚠️ **Config-Lücke:** Kein `GAU_BIN`-Eintrag in config.py (bare command).

**Status:** ✓ Installiert, aktuelle Version.

---

### 27. `searchsploit_exploits` – SearchsploitTool

**Binary:** `/usr/local/bin/searchsploit` (expliziter Pfad in config.py)  
**Version:** Systeminstallation (exploitdb-Paket)

Durchsucht die lokale Exploit-DB-Kopie nach bekannten Exploits für Software und Versionen. Gibt Exploit-Titel, Kategorie (Remote/Local, DoS, PoC) und Pfad zur PoC-Datei zurück. Wird von `research_agent` und `findings_task` für CVE-Recherche genutzt.

**Status:** ✓ Installiert.

---

## Befunde & Status

### Behoben (2026-05-23)

| # | Befund | Maßnahme |
|---|---|---|
| ~~K1~~ | ~~EyeWitness: Selenium fehlt~~ | **Entfernt** — kein Nutzen auf reinen Serversystemen ohne Display. EyewitnessTool aus tools.py, agents.py und config.py entfernt. |
| ~~I1~~ | ~~GOBUSTER_BIN toter Import~~ | **Bereinigt** — `GOBUSTER_BIN` aus tools.py-Import entfernt. |
| ~~I2~~ | ~~5 Go-Tools ohne config.py-Konstante~~ | **Behoben** — `NAABU_BIN`, `DNSX_BIN`, `KATANA_BIN`, `WAYBACKURLS_BIN`, `GAU_BIN` in config.py ergänzt; alle 5 Tools nutzen jetzt Konstanten statt bare commands. |
| ~~I3~~ | ~~`GO_BIN` hardcoded auf `/root/go/bin`~~ | **Behoben** — `GO_BIN` ermittelt jetzt dynamisch via `go env GOPATH` (Fallback: `~/go/bin`). Portierbar für jeden User auf jedem System. |

---

### Version-Status

| Tool | Installiert | Aktuell | Anmerkung |
|---|---|---|---|
| nmap | 7.94SVN | 7.95 | Dev-Snapshot, kein Risiko |
| nikto | 2.1.5 | 2.1.6 | 1 Minor hinter |
| whatweb | 0.5.5 | 0.5.5 | ✓ Aktuell |
| sslscan | 2.1.2 | 2.1.4 | 2 Minor hinter |
| testssl.sh | 3.3dev | 3.2 stable | Dev-Branch, mehr Features |
| ffuf | 2.1.0-dev | 2.1.0 | Funktional identisch |
| nuclei | v3.8.0 | v3.x | ✓ Aktuell |
| httpx | v1.2.1 (snap) | v1.x | ✓ Aktuell |
| naabu | v2.6.1 | v2.x | ✓ Aktuell |
| dnsx | v1.2.3 | v1.x | ✓ Aktuell |
| katana | v1.2.1 | v1.x | ✓ Aktuell |
| amass | v4.2.0 | v4.x | ✓ Aktuell (v3 EOL) |
| subfinder | v2.13.0 | v2.x | ✓ Aktuell |
| gau | 2.2.4 | 2.2.4 | ✓ Aktuell |
| dnsrecon | 1.1.5 | 1.1.6 | 1 Minor hinter |
| gobuster | 3.6 | 3.6 | ✓ Installiert, kein Tool-Wrapper |
| whois | 5.5.22 | — | System-Tool |
| searchsploit | system | — | exploitdb-Paket |

---

## Tool-zu-Agent-Mapping

```
blue_agent (12 Tools):
  ping_tool          → Erreichbarkeit
  nmap_tool          → Port-/Service-Scan
  naabu_tool         → Schnelle Port-Discovery (Vorläufer für nmap)
  httpx_tool         → HTTP-Probing vieler Hosts
  whatweb_tool       → Web-Tech-Fingerprinting
  curl_tool          → HTTP-Header-Prüfung
  nikto_tool         → Web-Vulnerability-Scan
  ffuf_tool          → Directory/Endpoint-Fuzzing
  sslscan_tool       → SSL/TLS-Basischeck
  testssl_tool       → Vollständiger TLS-Audit
  nuclei_tool        → Template-basierte CVE-Suche
  enum4linux_tool    → SMB/Windows-Enumeration

research_agent (14 Tools):
  ddg_search_tool    → OSINT-Websuche
  theharvester_tool  → E-Mail/Subdomain-OSINT
  whois_tool         → Domain/IP-Registrierungsinfo
  dig_tool           → DNS-Abfragen
  dnsrecon_tool      → DNS-Vollanalyse
  subfinder_tool     → Passive Subdomain-Enum (primär)
  sublist3r_tool     → Passive Subdomain-Enum (Suchmaschinen)
  amass_tool         → Passive Subdomain-Enum (umfangreich)
  assetfinder_tool   → Subdomain/Asset-Finder
  dnsx_tool          → DNS-Massen-Resolver
  katana_tool        → Web-Crawler
  waybackurls_tool   → Historische URL-Sammlung
  gau_tool           → Multi-Source URL-Sammlung
  searchsploit_tool  → Exploit-DB-Suche
```

---

## Offene Punkte

1. **sslscan Update**: 2.1.2 → 2.1.4 bringt neue Cipher-Checks; lohnt sich für akkuratere TLS-Bewertung (`sudo apt upgrade sslscan`).

2. **gobuster**: Binary installiert (v3.6), kein Tool-Wrapper vorhanden. Wäre eine gute Alternative zu ffuf für reine Directory-Enumeration (`GobusterTool` könnte ergänzt werden wenn benötigt).

3. **httpx Snap-Pfad**: `/snap/bin/httpx` ist systemspezifisch. Falls Snap nicht installiert ist (z.B. minimaler Server), schlägt httpx fehl. Alternativ via `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` als Go-Binary beziehen und `HTTPX_BIN` auf `os.path.join(GO_BIN, "httpx")` umstellen.
