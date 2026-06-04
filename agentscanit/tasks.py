"""
tasks.py – CrewAI Task-Definitionen für AgentScanIT (Agentic Vulnerability Assessment Framework)

Sprachkonvention: Task-Beschreibungen und Agent-Prompts sind auf Deutsch (Zielgruppe:
deutschsprachige Pentest-Teams). Tool-Beschreibungen und der Planner-Prompt sind auf Englisch,
damit LLMs — die primär auf englischen Daten trainiert wurden — die Schemas zuverlässiger
interpretieren.

Inputs für kickoff():
    target    – Ziel (IP oder Domain)
    objective – Was soll untersucht werden? z.B. "Web-App auf Schwachstellen prüfen",
                "SSL/TLS-Konfiguration analysieren", "offene Ports und Services erfassen"
    scope     – Obergrenze des Assessments: "osint" | "quick" | "ssl" | "web" | "network" | "full"
                osint   → nur passive Recon, kein aktiver Scan
                quick   → max. 3 Tools, kein Fuzzing, kein Screenshot
                ssl     → NUR sslscan + testssl
                web     → HTTP/HTTPS-Fokus: httpx, whatweb, nikto, nuclei, ffuf
                network → Port-Discovery: nmap, naabu, httpx (kein SMB ohne offenen Port)
                full    → alle verfügbaren Tools (vollständiges Assessment)
"""

from crewai import Task
from pydantic import BaseModel, Field, field_validator
from typing import Any, List, Dict, Optional

from agents import (
    research_agent,
    blue_agent,
    red_agent,
    coding_agent,
    reporter_agent,
)


# ─── Output-Modelle ───────────────────────────────────────────────────────────

class ResearchOutput(BaseModel):
    target_type: str                    # "domain" oder "ip"
    summary: str
    subdomains: List[str]
    technologies: List[str]
    osint_notes: List[str]
    reverse_dns: Optional[str] = None
    asn_info: Optional[str] = None

    @field_validator("subdomains")
    @classmethod
    def cap_subdomains(cls, v: List[str]) -> List[str]:
        # Hard cap — prevents context overflow when passing research output to blue task.
        # The research_task prompt instructs the LLM to pre-filter to 20; this is the safety net.
        return v[:25]

    memory_hit: bool = Field(
        default=False,
        description=(
            "Set to True if your context window contains prior scan data for this specific "
            "target injected by the long-term memory system (e.g. subdomains, IPs, or findings "
            "from a previous run). Set to False if no such prior context is visible."
        ),
    )


class BlueOutput(BaseModel):
    tools_executed: List[str]
    open_ports: List[int]
    services: Dict[str, Any]            # "80" → "Apache 2.4.51" or nested dict
    vulnerabilities: List[str]
    analysis: str


class FindingsOutput(BaseModel):
    service_versions: List[str]
    cve_references: List[str]
    risk_summary: str

    @field_validator("cve_references")
    @classmethod
    def validate_cve_references(cls, v: List[str]) -> List[str]:
        import re, logging
        log = logging.getLogger(__name__)

        # Step 1: format check — CVE-YYYY-NNNNN, year 1999–2030, 4–7 digits
        fmt = re.compile(r'^CVE-(\d{4})-(\d{4,7})$', re.IGNORECASE)
        formatted = []
        for cid in v:
            m = fmt.match(cid.strip())
            if m and 1999 <= int(m.group(1)) <= 2030:
                formatted.append(cid.strip().upper())
        if not formatted:
            return []

        # Step 2: trace cross-check — only allow IDs that appeared in a tool's raw output.
        # This is the primary hallucination filter: if the LLM invented a CVE that no tool
        # returned, it will not appear in any raw_output and is dropped here.
        try:
            from tools.trace import run_trace
            if run_trace.is_active:
                all_outputs = run_trace.get_all_raw_outputs()
                trace_confirmed = [cid for cid in formatted if cid in all_outputs]
                removed = [cid for cid in formatted if cid not in trace_confirmed]
                if removed:
                    log.warning("CVE hallucination filter (trace): removed %s", removed)
                return trace_confirmed
        except Exception:
            pass

        # Step 3: NVD fallback — used when trace is unavailable (unit tests, direct invocation).
        # Confirms the ID exists in NVD; does NOT confirm relevance to the target.
        try:
            from tools.nvd import fetch_cves
            results  = fetch_cves(formatted)
            confirmed = [r["id"] for r in results if "error" not in r]
            removed   = [cid for cid in formatted if cid not in confirmed]
            if removed:
                log.warning("CVE hallucination filter (NVD): removed %s", removed)
            return confirmed
        except Exception:
            return formatted


class RedScanOutput(BaseModel):
    targeted_findings: List[str]        # CVEs/Versionen die diesen Scan ausgelöst haben
    tools_executed: List[str]
    open_ports: List[int]
    vulnerabilities: List[str]
    analysis: str


class RedOutput(BaseModel):
    confirmed_attack_surface: List[str]  # only findings confirmed by tool output
    exploitable_findings: List[str]
    cve_references: List[str] = Field(
        default_factory=list,
        description="CVE IDs confirmed by searchsploit or DDG tool output in this task.",
    )

    # Reuse the same trace + NVD validator as FindingsOutput.
    validate_cve_references = field_validator("cve_references", mode="before")(
        FindingsOutput.__dict__["validate_cve_references"].__func__
    )


class CodingOutput(BaseModel):
    filename: str
    code: str
    code_plan: List[str]
    syntax_valid: bool


class ReportOutput(BaseModel):
    path: str
    executive_summary: str


# ─── Tasks ────────────────────────────────────────────────────────────────────

research_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"

        "Führe passive Reconnaissance durch – ANGEPASST an Scope und Objective.\n\n"

        "SCHRITT 1 – Zieltyp:\n"
        "Ist {target} eine IP-Adresse oder eine Domain?\n\n"

        "SCHRITT 2 – Tool-Auswahl nach Scope:\n"
        "Scope 'osint':   dig + whois + subfinder + theHarvester + DuckDuckGo-Suche. "
        "Maximal 5 Tools. Kein aktiver Scan. Kein nmap.\n"
        "Scope 'quick':   NUR dig + whois. Keine Subdomain-Enumeration.\n"
        "Scope 'ssl':     NUR dig für IP-Auflösung. Keine weiteren Recon-Tools.\n"
        "Scope 'web':     dig + whois + subfinder (1 Tool reicht). Kein amass, kein gau.\n"
        "Scope 'network': dig + whois. Kein Subdomain-Enum, kein OSINT.\n"
        "Scope 'full':    Subfinder, dig, dnsrecon, theHarvester, DuckDuckGo-Suche.\n\n"

        "Bei IP-Adresse (egal welcher Scope):\n"
        "- Subdomain-Enumeration ÜBERSPRINGEN\n"
        "- Nur: dig -x {target} (Reverse-DNS), whois {target} (ASN/ISP)\n\n"

        "SCHRITT 3 – Zusammenfassung:\n"
        "Fasse NUR gefundene Fakten zusammen. Keine Spekulation.\n\n"

        "SUBDOMAINS-AUSGABE:\n"
        "Gib im 'subdomains' Feld maximal 20 der relevantesten Subdomains aus. "
        "Filtere aktiv: KEINE internen Host-IPs (host-195-*, b200srv*, utmi*), "
        "KEINE Masseninstanzen (026.sixcms.*, 113.sixcms.*), "
        "KEINE staging-/dev-/test-Hosts außer sie sind explizit Scan-Ziel. "
        "Priorisiere: bekannte Dienste (mail, gitlab, vpn, serviceportal, api), "
        "öffentlich relevante Subdomains, auffällige Hostnamen.\n\n"

        "MEMORY HIT:\n"
        "Setze 'memory_hit: true' im Output, wenn du zu Beginn dieser Task "
        "Kontext oder Ergebnisse zu {target} aus einem vorherigen Run erhalten hast "
        "(d.h. wenn Memory-Kontext im Prompt vorhanden war). "
        "Andernfalls setze 'memory_hit: false'."
    ),
    expected_output=(
        "Strukturierter Recon-Report: Zieltyp, IP-Adresse, "
        "relevante Subdomains (scope-angepasst), DNS-Infos, WHOIS-Infos."
    ),
    output_pydantic=ResearchOutput,
    agent=research_agent,
)

blue_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"

        "Führe einen autorisierten Sicherheitsscan durch.\n"
        "Nutze die Recon-Ergebnisse als Grundlage.\n\n"

        "WICHTIG – Tool-Auswahl-Prinzip:\n"
        "Wähle NUR die Tools die direkt zum Objective '{objective}' beitragen.\n"
        "Führe NICHT alle verfügbaren Tools aus. Plane zuerst, dann execute.\n\n"

        "ADAPTIVE PARAMETER – nutze die Recon-Ergebnisse:\n"
        "- nikto: Wenn nmap einen non-standard Web-Port gefunden hat (z.B. 8080, 8443), "
        "  übergib diesen als 'port'-Parameter. Nutze 'tuning=4' für Injection-Tests wenn "
        "  ein CMS oder Login-Formular erkannt wurde.\n"
        "- nuclei: Nutze 'tags' mit den von whatweb/httpx erkannten Technologien "
        "  (z.B. tags='apache' oder tags='wordpress'). Nutze 'severity=critical,high' "
        "  für gezielte CVE-Suche.\n"
        "- nmap: Nutze 'ports' mit konkreten Ports aus naabu-Discovery statt Top-1000.\n\n"

        "Tool-Auswahl nach Scope:\n"
        "Scope 'quick':   ping + nmap (Top-100-Ports) + httpx. Fertig.\n"
        "Scope 'web':     httpx + whatweb + curl + nikto. SSL nur wenn HTTPS aktiv. Kein nmap full-scan.\n"
        "Scope 'network': nmap (alle Ports, -T4) + naabu + httpx für offene Web-Ports.\n"
        "Scope 'ssl':     NUR sslscan + testssl auf {target}. Keine anderen Tools.\n"
        "Scope 'full':    Starte mit nmap Top-1000 (aggressive=False), dann basierend auf Ergebnissen:\n"
        "                 - PFLICHT nach Port-Discovery: nmap erneut mit aggressive=True NUR auf den "
        "gefundenen offenen Ports aufrufen (z.B. ports='22,80,443,9200') — das liefert -sV Versionsinfo "
        "in unter 30s. Ohne Versionsinfo können nachgelagerte CVE-Tasks nicht arbeiten.\n"
        "                 - Web-Ports offen → httpx, whatweb, nikto (mit port-Parameter), nuclei (mit tags)\n"
        "                 - HTTPS → sslscan\n"
        "                 - Port 445 → enum4linux\n"
        "                 - Fuzzing NUR wenn Objective es explizit fordert\n\n"

        "STOPP-Regeln:\n"
        "- Kein ffuf/Fuzzing außer Scope 'full' und Objective erwähnt Pfade/Endpunkte\n"
        "- Kein enum4linux außer Port 445 ist nachweislich offen\n"
        "- Max. 6 Tool-Aufrufe für Scope 'quick' und 'web'\n"
        "- Tool-Fehler: Wenn ein Tool-Output mit '[TOOL_ERROR]' beginnt, "
        "dieses Tool ÜBERSPRINGEN und das nächste Tool im Plan ausführen. "
        "Kein Retry. '[TOOL_ERROR] nmap: binary not found' → naabu als Ersatz nutzen. "
        "'[TOOL_ERROR] nikto: timeout after 300s' → mit httpx/whatweb weiterarbeiten.\n\n"

        "Nach den Scans: Analysiere alle Outputs und identifiziere sicherheitsrelevante Findings."
    ),
    expected_output=(
        "Scope-angepasster Scan-Report: ausgeführte Tools (mit Begründung), "
        "offene Ports, erkannte Services und Versionen, bestätigte Findings aus Tool-Output."
    ),
    output_pydantic=BlueOutput,
    agent=blue_agent,
    context=[research_task],
)

findings_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective}\n\n"
        "Extrahiere aus den Blue-Agent-Ergebnissen:\n"
        "1. Erkannte Service-Versionen und Software-Komponenten (exakt so wie Tools sie gemeldet haben)\n"
        "2. Bekannte CVEs NUR für tatsächlich gefundene Services — via searchsploit, NVD und DuckDuckGo\n\n"
        "CVE-SUCHE — Reihenfolge:\n"
        "SCHRITT A: Wenn Versionsnummer bekannt → searchsploit '<service> <version>'.\n"
        "SCHRITT B: Immer (mit oder ohne Version) → nvd_cve_search aufrufen:\n"
        "  - Mit Version: 'Apache 2.4.51', 'OpenSSH 8.2p1'\n"
        "  - Ohne Version: Service-Name reicht ('Elasticsearch', 'OpenSSH', 'nginx') — "
        "NVD liefert dann die aktuellen High/Critical CVEs für diesen Dienst.\n"
        "  Ruf nvd_cve_search für JEDEN identifizierten Dienst auf — auch wenn blue_task "
        "keine Versionsnummer gemeldet hat.\n"
        "SCHRITT C: Wenn NVD Treffer liefert → DuckDuckGo '<CVE-ID> exploit PoC' zur Bestätigung.\n\n"
        "RELEVANZ-PRÜFUNG: Prüfe bei jedem Treffer ob Produktname passt. "
        "'Ingress-NGINX' ≠ 'nginx'. 'OpenSSH 7.x' ≠ 'OpenSSH 9.x'. "
        "Ohne bekannte Version: nur HIGH/CRITICAL CVEs aus den letzten 3 Jahren eintragen.\n"
        "REGEL: Trage in 'cve_references' NUR CVE-IDs ein die nach obiger Prüfung bestätigt sind. "
        "Keine CVE-IDs aus LLM-Trainingswissen.\n"
        "REGEL: 'risk_summary' enthält ausschließlich direkt beobachtete Fakten aus Tool-Outputs — "
        "keine Einschätzungen, keine Wahrscheinlichkeiten, kein 'may' oder 'could'.\n\n"
        "HINWEIS FÜR NACHFOLGENDE TASKS:\n"
        "Dokumentiere erkannte Technologien explizit (z.B. 'Apache 2.4.51', 'WordPress 6.1', "
        "'OpenSSH 8.2p1') damit der Red-Scan-Agent nuclei mit den passenden "
        "Tags ('apache', 'wordpress', 'openssh') und 'severity=critical,high' aufrufen kann."
    ),
    expected_output=(
        "Extrahierte Service-Versionen, CVE-IDs (nur tool-bestätigt), "
        "faktische Zusammenfassung der beobachteten Findings."
    ),
    output_pydantic=FindingsOutput,
    agent=research_agent,
    context=[blue_task],
)

red_scan_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective}\n\n"
        "Führe gezielte Nachscans für die aus findings_task bekannten CVEs und Schwachstellen durch.\n"
        "Nutze NUR Ports und Services die bereits durch blue_task bestätigt wurden – kein neuer Port-Scan.\n\n"
        "SCHRITT 1 – HTTP-RESPONSE-HEADER ANALYSIEREN:\n"
        "Prüfe alle curl/httpx-Outputs aus blue_task auf CMS- und Tech-Stack-Indikatoren:\n"
        "- 'x-redirect-by': TYPO3, WordPress, Drupal u.a. CMS\n"
        "- 'x-powered-by': PHP-Version, ASP.NET, Express usw.\n"
        "- 'via': Varnish, Squid, nginx-Cache (Cache-Layer-Erkennung)\n"
        "- 'x-generator', 'x-cms', 'x-drupal-*', 'x-wp-*': CMS-spezifische Header\n"
        "Wenn ein CMS oder Tech-Stack identifiziert wurde: notiere ihn als confirmed Technology "
        "und rufe nuclei mit dem passenden Tag auf (z.B. tags='typo3', tags='wordpress').\n\n"
        "SCHRITT 2 – ADAPTIVE NACHSCANS:\n"
        "- nuclei: 'templates=cves', 'severity=critical,high', 'tags' aus erkannten Technologien\n"
        "- nikto: bestätigte non-standard Ports, 'tuning=4' bei Login-Formularen oder CMS\n\n"
        "STOPP-Regeln:\n"
        "- Max. 4 Tool-Aufrufe\n"
        "- Kein nmap, kein naabu – nur Applikations-Layer-Tools\n"
        "- Wenn '[TOOL_ERROR]' im Output: überspringen, nächstes Tool\n\n"
        "Ziel: Bestätige oder schließe aus – jedes Finding braucht ein klares Scan-Ergebnis."
    ),
    expected_output=(
        "Gezielte Scan-Ergebnisse für bestätigte Findings: "
        "erkannte Technologien aus HTTP-Headern, welche CVEs bestätigt wurden, welche ausgeschlossen."
    ),
    output_pydantic=RedScanOutput,
    agent=blue_agent,
    context=[findings_task],
)

# red_scan_task ist NICHT in context= — dessen Output fließt automatisch via
# sequential Process ein wenn er in der Pipeline ist (scope=full). Eine explizite
# Referenz würde bei Scopes ohne red_scan_task zur Laufzeit brechen.
red_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"
        "Verifiziere die vorliegenden Findings mit deinen Tools. "
        "Arbeite NUR mit Findings die durch blue_task, findings_task oder red_scan_task bestätigt wurden.\n\n"
        "CVE-VERIFIKATION – nutze deine Tools:\n"
        "- searchsploit <service> <version>: prüfe ob ein Exploit in der lokalen DB existiert\n"
        "- DuckDuckGo '<CVE-ID> PoC': prüfe ob ein PoC publiziert ist\n"
        "Recherchiere NUR für CVEs die findings_task oder red_scan_task mit konkreter ID gemeldet haben.\n\n"
        "OUTPUT-REGELN:\n"
        "- 'confirmed_attack_surface': Liste nur Findings die ein Tool-Output direkt bestätigt hat. "
        "Kein 'may', kein 'could', kein 'potential'. Format: '<service>:<port> — <was das Tool meldete>'\n"
        "- 'exploitable_findings': Nur Findings für die searchsploit einen Exploit-Eintrag "
        "oder DDG einen publizierten PoC zurückgegeben hat.\n"
        "- 'cve_references': Liste der CVE-IDs die searchsploit oder DDG in diesem Task "
        "zurückgegeben haben — exakt so wie sie im Tool-Output stehen (Format: CVE-YYYY-NNNNN). "
        "Keine CVE-IDs aus LLM-Trainingswissen.\n"
        "Keine Einträge aus LLM-Trainingswissen ohne Tool-Bestätigung."
    ),
    expected_output=(
        "Tool-bestätigte Angriffsfläche: welche Exploits searchsploit gefunden hat, "
        "welche PoCs DDG zurückgegeben hat — nichts darüber hinaus."
    ),
    output_pydantic=RedOutput,
    agent=red_agent,
    context=[blue_task, findings_task],
)

coding_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective}\n\n"
        "Generiere ein ausführbares Python-Skript das genau die Tool-Calls automatisiert "
        "die der Blue Agent ausgeführt hat.\n"
        "NUR die tatsächlich verwendeten Tools abbilden – kein generisches Template.\n"
        "Fehlerbehandlung und Logging hinzufügen.\n\n"
        "WICHTIG für das Output-Schema:\n"
        "- 'filename': z.B. 'scan_ssl_rastede.py'\n"
        "- 'code': der VOLLSTÄNDIGE Python-Code als String (kein Markdown, keine Backticks)\n"
        "- 'code_plan': Liste der Schritte die der Code abbildet\n"
        "- 'syntax_valid': true wenn der Code syntaktisch korrekt ist"
    ),
    expected_output=(
        "CodingOutput mit vollständigem Python-Code im 'code'-Feld, "
        "Dateiname und Schritt-Liste."
    ),
    output_pydantic=CodingOutput,
    agent=coding_agent,
    context=[blue_task, red_task],
)

report_task = Task(
    description=(
        "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"
        "Erstelle einen Recon-Report als Markdown. "
        "Der Report ist Rohdaten-Dokumentation — er dient als Input für nachgelagerte Analyse-Agents.\n\n"
        "PFLICHT-REGEL: Jede Aussage im Report muss direkt aus einem Tool-Output ableitbar sein. "
        "Keine Einschätzungen, keine Wahrscheinlichkeiten, kein 'may', 'could', 'potential'. "
        "Wenn ein Tool nichts gefunden hat: das sauber dokumentieren, nicht spekulieren.\n\n"
        "Struktur:\n"
        "# Recon Report: {target}\n"
        "## Reconnaissance Summary\n"
        "  Faktische Zusammenfassung: IP, offene Ports, erkannte Services — aus Tool-Outputs.\n"
        "## Scope & Methodik\n"
        "  Tabelle: Tool | Zweck | Abgedeckte Assets\n"
        "## Confirmed Findings\n"
        "  Tabelle aller durch Tools bestätigten Observationen.\n"
        "  Spalten: Service | Port | Beobachtung | Tool | Trace-Seq#\n"
        "  Nur was ein Tool explizit gemeldet hat — keine Interpretation.\n"
        "## Detected Technologies\n"
        "  Direkt aus whatweb/curl/httpx/nuclei extrahiert: Server, CMS, Cache-Layer, Versionen.\n"
        "  Format: '<header/tool-output> → <erkannte Technologie>'\n"
        "## CVE References\n"
        "  Nur wenn searchsploit oder DDG eine konkrete CVE-ID zurückgegeben haben.\n"
        "  Leer lassen wenn keine tool-bestätigten CVEs vorliegen.\n\n"
        "Keine Füllsätze über nicht ausgeführte Tools.\n"
        "Der Bericht wird vom System gespeichert – gib NUR den Markdown-Text aus.\n"
        "Für 'path' im Output: verwende 'pending' – das System setzt den echten Pfad."
    ),
    expected_output=(
        "Recon-Report als Markdown — ausschließlich auf Basis der Tool-Outputs. "
        "Confirmed Findings Tabelle mit Tool-Quellenangabe, Detected Technologies, "
        "CVE References nur wenn tool-bestätigt."
    ),
    output_pydantic=ReportOutput,
    agent=reporter_agent,
    # Kein explizites context= — in sequential process erhält der Reporter
    # die Outputs aller vorangehenden Tasks automatisch. So funktioniert
    # der Task für alle Scopes (osint hat z.B. keine blue/red Tasks).
)
