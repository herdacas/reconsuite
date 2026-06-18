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
                network → Port-Discovery: nmap, httpx (kein SMB ohne offenen Port)
                full    → alle verfügbaren Tools (vollständiges Assessment)
"""

import re as _re

from crewai import Task
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Any, List, Dict, Optional

# ─── CVE-Format-Validator + Guardrails ────────────────────────────────────────

_CVE_FMT = _re.compile(r'^CVE-(\d{4})-(\d{4,7})$', _re.IGNORECASE)


def _tool_call_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail: Lehnt Task-Output ab wenn kein echtes Tool aufgerufen wurde.

    Prüft run_trace._pending — enthält bei Guardrail-Auswertung genau die
    Tool-Calls der aktuellen Task (close_phase() läuft erst im task_callback
    nach bestandenem Guardrail). _pending == [] bedeutet: kein Subprocess
    wurde gestartet, der Agent hat halluziniert.

    Gibt bei Erfolg (True, raw_string) zurück — CrewAI ruft dann _aexport_output()
    auf dem String auf und befüllt task_output.pydantic korrekt. Bei (True, TaskOutput)
    bleibt pydantic=None (CrewAI-Verhalten bei aktiven Guardrails, task.py:684-689).
    """
    try:
        from tools.trace import run_trace
        if run_trace.is_active and len(run_trace._pending) == 0:
            if run_trace._guardrail_reject_count >= 1:
                return True, getattr(output, "raw", output)
            run_trace._guardrail_reject_count += 1
            return (
                False,
                "FEHLER: Kein Tool wurde aufgerufen. Du hast eine vollständige "
                "Antwort ohne jeden Tool-Einsatz generiert — das ist nicht erlaubt. "
                "Rufe JETZT das erste erforderliche Tool auf (z.B. dig, nmap, httpx) "
                "und liefere danach ein Ergebnis das ausschließlich auf echten "
                "Tool-Outputs basiert.",
            )
    except Exception:
        pass
    return True, getattr(output, "raw", output)


def _filter_cve_format(cves: List[str]) -> List[str]:
    """Format-only check: CVE-YYYY-NNNNN, year 1999–2030. No trace/NVD checks."""
    return [
        c.strip().upper() for c in cves
        if (m := _CVE_FMT.match(c.strip())) and 1999 <= int(m.group(1)) <= 2030
    ]


_SCOPE_REQUIRED_TOOLS: dict[str, set[str]] = {
    "quick":   {"nmap", "httpx"},
    "web":     {"httpx", "whatweb"},
    "network": {"nmap", "httpx"},
    "ssl":     {"sslscan"},
    "full":    {"nmap", "httpx", "whatweb", "sslscan"},
}


def _scope_coverage_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail: Stellt sicher dass Kern-Tools pro Scope aufgerufen wurden.

    Prüft run_trace._pending (läuft vor close_phase). Gibt beim ERSTEN Fehlen
    Feedback zurück damit der Agent die fehlenden Tools noch aufrufen kann.
    Beim zweiten Fehlschlag (count≥1) wird akzeptiert um Endlosschleifen zu vermeiden.
    """
    try:
        from tools.trace import run_trace
        if not run_trace.is_active:
            return True, getattr(output, "raw", output)

        # Scope aus dem laufenden kickoff-Input lesen — liegt im _pending nicht direkt
        # vor. Wir lesen ihn aus dem task description-Template nicht; stattdessen
        # versuchen wir den Scope aus dem Pydantic-Output (falls befüllt) zu ermitteln,
        # oder überspringen die Prüfung wenn der Scope nicht bestimmbar ist.
        # Der Scope wird als {scope} in der Task-Description übergeben — das reicht für
        # den Guardrail-Feedback-Text nicht; wir lesen ihn aus run_trace._current_scope.
        scope = getattr(run_trace, "_current_scope", None)
        if not scope:
            return True, getattr(output, "raw", output)

        required = _SCOPE_REQUIRED_TOOLS.get(scope, set())
        if not required:
            return True, getattr(output, "raw", output)

        used = {c.get("tool_name", "") for c in run_trace._pending}
        missing = required - used

        if missing:
            reject_key = f"scope_coverage_{scope}"
            count = run_trace._guardrail_reject_count
            if count >= 1:
                return True, getattr(output, "raw", output)
            run_trace._guardrail_reject_count += 1
            return (
                False,
                f"SCOPE-GARANTIE VERLETZT (scope={scope}): Pflicht-Tools noch nicht aufgerufen: "
                f"{sorted(missing)}. Rufe diese Tools jetzt auf bevor du den Output lieferst.",
            )
    except Exception:
        pass
    return True, getattr(output, "raw", output)


def _cve_trace_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail: CVE-IDs gegen Session-Trace validieren + NOTABLE_CVES auto-pinnen.

    Trace cross-check (primär): ID muss im Raw-Output eines Tool-Calls erscheinen.
    NVD-Fallback: wenn Trace inaktiv (Unit-Tests), prüft NVD-Existenz.
    Bei Failure bekommt der Agent die halluzinierten IDs explizit zurückgemeldet
    und kann die Task korrigiert wiederholen (guardrail_max_retries=2).

    NVD-Tool-Guarantee: Wenn CPE_MAP-bekannte Services im blue-Trace erkannt wurden
    aber kein nvd_cpe_lookup/nvd_cve_search in der findings-Phase aufgerufen wurde,
    wird abgelehnt (ERSTER Fehler) und Agent aufgefordert die NVD-Tools zu nutzen.

    Auto-Pin: NOTABLE_CVES die im Tool-Output dieser Session erscheinen aber nicht
    in cve_references eingetragen wurden, werden deterministisch hinzugefügt —
    ohne Agent-Retry (Anreicherung, keine Ablehnung).
    """
    pydantic_out = getattr(output, "pydantic", None)
    raw = getattr(output, "raw", output) if not isinstance(output, str) else output
    if not pydantic_out:
        return True, raw
    cves = list(getattr(pydantic_out, "cve_references", None) or [])
    current_ids = {c.upper() for c in cves}

    # 1 — Trace cross-check + NVD-Tool-Guarantee + Auto-Pin
    try:
        from tools.trace import run_trace
        if run_trace.is_active:
            # Halluzinations-Check: CVEs die nicht im Trace-Output erscheinen
            confirmed    = [c for c in cves if run_trace.cve_in_raw_outputs(c)]
            hallucinated = [c for c in cves if c not in confirmed]
            if hallucinated:
                return False, (
                    f"Halluzinierte CVE-IDs: {hallucinated} erscheinen in keinem "
                    f"Tool-Output dieser Session. Entferne sie aus 'cve_references'. "
                    f"Tool-bestätigt: {confirmed if confirmed else 'keine'}"
                )

            # NVD-Tool-Guarantee + NOTABLE_CVES direkt pinnen wenn "Kein CPE-Mapping"
            # für bekannte Services im finding-Output erscheint.
            try:
                from tools.cpe_map import CPE_MAP, NOTABLE_CVES as _NC_MAP
            except ImportError:
                try:
                    from agentscanit.tools.cpe_map import CPE_MAP, NOTABLE_CVES as _NC_MAP
                except ImportError:
                    CPE_MAP = {}
                    _NC_MAP = {}

            blue_outputs = " ".join(
                c.get("raw_output", "")
                for p, pd in run_trace._phases.items()
                if p in ("blue", "red_scan")
                for c in pd.get("tool_calls", [])
            ).lower()

            # Services die im blue-Output erkannt wurden und NOTABLE_CVES haben
            notable_missing: list[str] = []
            for keyword, cpe_tuple in CPE_MAP:
                if keyword in blue_outputs and cpe_tuple in _NC_MAP:
                    for cve_id in _NC_MAP[cpe_tuple]:
                        if cve_id not in current_ids and cve_id not in notable_missing:
                            notable_missing.append(cve_id)

            # Direkt pinnen (deterministisch, kein Agent-Retry nötig).
            # BUG-16: NOTABLE_CVES sind hardcoded bekannte CVEs für erkannte Services.
            # Das Pinning darf NICHT von NVD-Erreichbarkeit abhängen — bei 503/timeout
            # wird trotzdem gepinnt (das Enrichment markiert sie dann via BUG-14b als
            # UNBESTÄTIGT). Nur ein eindeutiges "existiert nicht in NVD" verwirft die ID.
            if notable_missing:
                direct_pinned: list[str] = []
                _nvd_transient = ("HTTP 503", "HTTP 502", "HTTP 504", "HTTP 429",
                                  "timed out", "timeout", "Read timed out",
                                  "ConnectionError", "Connection")
                try:
                    from tools.nvd import lookup_cve
                    for cve_id in notable_missing:
                        result = lookup_cve(cve_id)
                        err = result.get("error", "") if isinstance(result, dict) else ""
                        if not err:
                            direct_pinned.append(cve_id)          # NVD-bestätigt
                        elif any(t in err for t in _nvd_transient):
                            direct_pinned.append(cve_id)          # NVD tot → trotzdem pinnen
                        # else: "not found in NVD" → CVE existiert wirklich nicht, verwerfen
                except Exception:
                    direct_pinned = notable_missing  # fallback: vertraue NOTABLE_CVES

                if direct_pinned:
                    updated_direct = list(cves) + direct_pinned
                    try:
                        object.__setattr__(pydantic_out, "cve_references", updated_direct)
                        cves = updated_direct
                        current_ids = {c.upper() for c in cves}
                    except Exception:
                        pass
                    import json as _json2
                    try:
                        raw_dict2 = _json2.loads(raw)
                        raw_dict2["cve_references"] = updated_direct
                        raw = _json2.dumps(raw_dict2, ensure_ascii=False)
                    except Exception:
                        pass

            _nvd_tools = {"nvd_cpe_lookup", "nvd_cve_search", "searchsploit"}
            _findings_tools = {c.get("tool_name", "") for c in run_trace._pending}
            _nvd_called = bool(_findings_tools & _nvd_tools)

            if not _nvd_called:
                known_services = [kw for kw, _ in CPE_MAP if kw in blue_outputs]
                if known_services and run_trace._guardrail_reject_count < 1:
                    run_trace._guardrail_reject_count += 1
                    return False, (
                        f"PFLICHT: Für erkannte Services {known_services[:5]} MÜSSEN "
                        f"CVE-Lookups durchgeführt werden. Rufe jetzt auf: "
                        f"nvd_cpe_lookup oder nvd_cve_search für jeden Service. "
                        f"searchsploit als Ergänzung. Ohne NVD-Lookup ist diese Task unvollständig."
                    )

            # Auto-Pin: NOTABLE_CVES die im Trace stehen aber nicht in cve_references
            # Gilt auch wenn cve_references leer ist (Agent hat Tool-Output ignoriert).
            try:
                from tools.cpe_map import NOTABLE_CVES
            except ImportError:
                try:
                    from agentscanit.tools.cpe_map import NOTABLE_CVES
                except ImportError:
                    NOTABLE_CVES = {}

            all_notable = {cve for ids in NOTABLE_CVES.values() for cve in ids}
            current_ids = {c.upper() for c in cves}
            to_pin = [
                cve for cve in all_notable
                if cve not in current_ids and run_trace.cve_in_raw_outputs(cve)
            ]
            if to_pin:
                updated = list(cves) + to_pin
                try:
                    object.__setattr__(pydantic_out, "cve_references", updated)
                except Exception:
                    pass
                import json as _json
                try:
                    raw_dict = _json.loads(raw)
                    raw_dict["cve_references"] = updated
                    raw = _json.dumps(raw_dict, ensure_ascii=False)
                except Exception:
                    pass

            return True, raw
    except Exception:
        pass

    # 2 — NVD-Fallback (Trace inaktiv, z.B. Unit-Tests)
    try:
        from tools.nvd import fetch_cves
        results      = fetch_cves(cves)
        confirmed    = [r["id"] for r in results if "error" not in r]
        hallucinated = [c for c in cves if c not in confirmed]
        if hallucinated:
            return False, (
                f"NVD-Fallback: {hallucinated} nicht in NVD gefunden. "
                f"Entferne diese IDs aus 'cve_references'."
            )
    except Exception:
        pass

    return True, raw


# ─── Subdomain-Fanout (deterministisch) ───────────────────────────────────────
# Problem: research entdeckt Subdomains (subfinder), aber blue scannte bisher nur
# die Apex-Domain → die eigentliche Angriffsfläche (auth/api/backoffice/…) wurde nie
# gescannt. Fix: nach research deterministisch via httpx prüfen welche Subdomains LIVE
# sind, und einen markierten Block an den research-Output anhängen, den blue über
# context=[research] erhält. Liveness = Code (deterministisch), kein LLM-Ermessen.
# Hinweis (Backlog): bei Domains mit vielen Fake-Subdomains ist „LLM wählt relevante →
# ggf. bestätigen → scannen" der bessere Weg — hier vorerst httpx-Liveness (gecappt).

_FANOUT_MAX_SUBS = 15   # Cap nach LLM-Filter (research-Task filtert bereits auf relevante Hosts)

def _httpx_live_hosts(subdomains: list) -> list:
    """Deterministisch: gibt die per httpx erreichbaren Hosts zurück (live-only)."""
    subs = [s.strip() for s in subdomains if s and s.strip()][:_FANOUT_MAX_SUBS]
    if not subs:
        return []
    try:
        import subprocess as _sp
        from config import HTTPX_BIN
        proc = _sp.run(
            [HTTPX_BIN, "-silent", "-no-color"],
            input="\n".join(subs), capture_output=True, text=True, timeout=120,
        )
        live = []
        for line in proc.stdout.splitlines():
            host = line.strip().replace("https://", "").replace("http://", "").split("/")[0]
            if host and host not in live:
                live.append(host)
        return live
    except Exception:
        return []


def _subdomain_fanout_guardrail(output: Any) -> tuple[bool, Any]:
    """Hängt eine deterministisch ermittelte LIVE-HOSTS-Liste an den research-Output.

    Lehnt NIE ab (gibt immer True zurück) — reine Anreicherung. Liest Subdomains aus
    dem Pydantic-Output (Fallback: Raw-Text), prüft Liveness via httpx, und ergänzt
    einen markierten Block, den die blue-Task über context=[research] verbindlich scannt.
    """
    try:
        subs: list = []
        pd = getattr(output, "pydantic", None)
        if pd is not None and getattr(pd, "subdomains", None):
            subs = list(pd.subdomains)
        else:
            # Fallback: Subdomains aus dem Raw-Text ziehen (falls Pydantic-Feld leer)
            raw = getattr(output, "raw", "") or ""
            subs = list(dict.fromkeys(_re.findall(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+', raw, _re.I)))
            subs = [s for s in subs if s.count(".") >= 2][:_FANOUT_MAX_SUBS]

        if not subs:
            return True, output

        live = _httpx_live_hosts(subs)
        if not live:
            return True, output

        block = (
            "\n\n=== VERIFIED LIVE HOSTS (deterministic httpx) ===\n"
            "Diese Hosts sind erreichbar und MÜSSEN von der Scan-Phase abgedeckt werden:\n"
            + "\n".join(f"- {h}" for h in live)
        )
        raw = getattr(output, "raw", "") or ""
        if "VERIFIED LIVE HOSTS" not in raw:
            try:
                object.__setattr__(output, "raw", raw + block)
            except Exception:
                pass
    except Exception:
        pass
    return True, output


# ─── Output-Modelle ───────────────────────────────────────────────────────────

class ResearchOutput(BaseModel):
    target_type: str                    # "domain" oder "ip"
    summary: str
    subdomains: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    osint_notes: List[str] = Field(default_factory=list)
    reverse_dns: Optional[str] = None
    asn_info: Optional[str] = None

    @field_validator("subdomains")
    @classmethod
    def cap_subdomains(cls, v: List[str]) -> List[str]:
        # Hard cap — prevents context overflow when passing research output to blue task.
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
    tools_executed: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[str, Any] = Field(default_factory=dict)
    vulnerabilities: List[str] = Field(default_factory=list)
    analysis: str


class FindingsOutput(BaseModel):
    service_versions: List[str] = Field(default_factory=list)
    cve_references: List[str] = Field(default_factory=list)
    risk_summary: str

    @field_validator("cve_references")
    @classmethod
    def validate_cve_format(cls, v: List[str]) -> List[str]:
        return _filter_cve_format(v)


class RedScanOutput(BaseModel):
    targeted_findings: List[str] = Field(default_factory=list)
    tools_executed: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    analysis: str


class RedOutput(BaseModel):
    confirmed_attack_surface: List[str] = Field(default_factory=list)
    exploitable_findings: List[str] = Field(default_factory=list)
    exploitable_findings_count: int = Field(
        default=0,
        description="Derived from len(exploitable_findings) — do not set manually.",
    )
    cve_references: List[str] = Field(
        default_factory=list,
        description="CVE IDs confirmed by searchsploit or DDG tool output in this task.",
    )

    @field_validator("cve_references")
    @classmethod
    def validate_cve_format(cls, v: List[str]) -> List[str]:
        return _filter_cve_format(v)

    @model_validator(mode="after")
    def derive_count(self) -> "RedOutput":
        self.exploitable_findings_count = len(self.exploitable_findings)
        return self


class CodingOutput(BaseModel):
    filename: str
    code: str
    code_plan: List[str] = Field(default_factory=list)
    syntax_valid: bool = False


class ReportOutput(BaseModel):
    path: str
    executive_summary: str


# ─── Task Factory ─────────────────────────────────────────────────────────────
# Tasks are created fresh per run via make_tasks() to avoid shared mutable state
# across retries and concurrent calls. Pydantic output models above are stateless
# and safe to share.

def make_tasks() -> dict:
    """Return a fresh dict of Task instances for one crew run.

    Tasks are NOT module-level singletons — each call creates new objects so
    that internal CrewAI state (processed_by_agents, output, etc.) is isolated
    per run. Context references point to instances within the same dict.
    """
    from agents import (
        research_agent, blue_agent, red_agent, coding_agent, reporter_agent,
    )

    research = Task(
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
            "SUBDOMAINS-AUSGABE — LLM-Filter (PFLICHT):\n"
            "Trage ins 'subdomains' Feld NUR Subdomains ein die sicherheitsrelevant sind. "
            "Maximal 15 Einträge. Bewerte JEDEN gefundenen Hostnamen einzeln:\n"
            "REIN (sicherheitsrelevant): auth, api, admin, backoffice, vpn, mail, "
            "webmail, gitlab, jenkins, jira, confluence, dev, staging, test, beta, "
            "portal, login, sso, oauth, dashboard, monitor, grafana, kibana, elastic, "
            "shop, checkout, payment, upload, files, ftp, remote, citrix, rdp.\n"
            "RAUS (kein Sicherheitswert): cdn-*, img-*, static-*, assets-*, "
            "numerische Präfixe (026.*, 113.*), interne Hostnamen (host-*-*, b200srv*, "
            "utmi*), Masseninstanzen mit Nummern (server42.*, node7.*), "
            "reine Mail-Server ohne Web (mx1.*, mx2.*).\n"
            "Wenn unklar: RAUS. Qualität vor Quantität — 5 relevante Hosts sind besser "
            "als 20 CDN-Instanzen.\n\n"
            "TOOL-PFLICHT:\n"
            "Rufe IMMER mindestens ein Tool auf, auch wenn Memory-Kontext aus vorherigen "
            "Runs vorliegt. Memory-Daten können veraltet sein — aktuelle Tool-Outputs haben Vorrang.\n\n"
            "TECHNOLOGIES-FELD:\n"
            "Trage NUR Technologien ein, die ein Tool in DIESER Session explizit im "
            "Raw-Output zurückgegeben hat (z.B. in httpx-, whatweb- oder curl-Output "
            "sichtbar). Keine Annahmen, keine Schätzungen, keine Beispiele aus "
            "Knowledge-Sources. Wenn kein Tool eine Technologie bestätigt hat: leere Liste [].\n\n"
            "MEMORY HIT:\n"
            "Setze 'memory_hit: true' im Output, wenn du zu Beginn dieser Task "
            "Kontext oder Ergebnisse zu {target} aus einem vorherigen Run erhalten hast. "
            "Andernfalls setze 'memory_hit: false'."
        ),
        expected_output=(
            "Strukturierter Recon-Report: Zieltyp, IP-Adresse, "
            "relevante Subdomains (scope-angepasst), DNS-Infos, WHOIS-Infos."
        ),
        output_pydantic=ResearchOutput,
        guardrails=[_tool_call_guardrail, _subdomain_fanout_guardrail],
        guardrail_max_retries=2,
        agent=research_agent,
    )

    blue = Task(
        description=(
            "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"
            "Führe einen autorisierten Sicherheitsscan durch.\n"
            "Nutze die Recon-Ergebnisse als Grundlage.\n\n"
            "ANGRIFFSFLÄCHE — PFLICHT:\n"
            "Wenn der Recon-Kontext einen Block 'VERIFIED LIVE HOSTS' enthält, MUSST du "
            "JEDEN dieser Hosts scannen (httpx + whatweb + nuclei pro Host; nmap/nikto bei "
            "auffälligen Ports) — NICHT nur die Apex-Domain. Subdomains wie auth/api/backoffice/"
            "cockpit/sandbox sind oft die eigentliche Angriffsfläche. Apex-only ist unzureichend.\n"
            "SERVICE-ERKENNUNG: nmap-Default-Portnamen (z.B. 'EtherNetIP-1' auf 2222, "
            "'snet-sensor-mgmt' auf 10000) sind RATE-NAMEN aus /etc/services, KEINE erkannten "
            "Dienste. Verifiziere immer mit -sV/httpx: Port 10000 ist meist Webmin, 2222 meist "
            "SSH. Trage nur tatsächlich erkannte Dienste als Service ein.\n\n"
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
            "- nmap: Nutze 'ports' mit konkreten Ports aus vorheriger nmap-Discovery statt Top-1000.\n\n"
            "Tool-Auswahl nach Scope:\n"
            "Scope 'quick':   ping + nmap (Top-100-Ports) + httpx. Fertig.\n"
            "Scope 'web':     httpx + whatweb + curl + nikto. SSL nur wenn HTTPS aktiv. Kein nmap full-scan.\n"
            "Scope 'network': nmap (alle Ports, -T4) + httpx für offene Web-Ports. "
            "Nach Port-Discovery: nmap erneut mit aggressive=True auf den gefundenen offenen Ports "
            "aufrufen um Versionsinfo (-sV) zu erhalten — ohne Version ist CVE-Analyse unmöglich. "
            "httpx IMMER mit 'targets' aufrufen: targets='{target}' oder targets='{target},sub.{target}'. "
            "Niemals httpx ohne targets-Parameter aufrufen — ohne Ziel liefert httpx leeren Output.\n"
            "Scope 'ssl':     NUR sslscan + testssl auf {target}. Keine anderen Tools.\n"
            "Scope 'full':    Starte mit nmap Full-Port-Scan (-p 1-65535, -T4, aggressive=False) — "
            "nicht Top-1000, da CTF/Pentest-Targets oft nicht-Standard-Ports nutzen (z.B. 4280, 5013, 6379).\n"
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
            "Kein Retry. '[TOOL_ERROR] nmap: binary not found' → mit httpx weiterarbeiten. "
            "'[TOOL_ERROR] nikto: timeout after 300s' → mit httpx/whatweb weiterarbeiten.\n\n"
            "Nach den Scans: Analysiere alle Outputs und identifiziere sicherheitsrelevante Findings.\n\n"
            "TOOL-PFLICHT:\n"
            "Rufe IMMER mindestens ein Tool auf. Auch wenn Memory-Kontext aus vorherigen Runs "
            "vorhanden ist: die Scan-Ergebnisse im 'tools_executed' Feld müssen aus Tool-Aufrufen "
            "DIESER Session stammen. Keine Daten aus Memory als Ersatz für Tool-Calls verwenden."
        ),
        expected_output=(
            "Scope-angepasster Scan-Report: ausgeführte Tools (mit Begründung), "
            "offene Ports, erkannte Services und Versionen, bestätigte Findings aus Tool-Output."
        ),
        output_pydantic=BlueOutput,
        guardrails=[_tool_call_guardrail, _scope_coverage_guardrail],
        guardrail_max_retries=2,
        agent=blue_agent,
        context=[research],
    )

    findings = Task(
        description=(
            "Ziel: {target} | Objective: {objective}\n\n"
            "Extrahiere aus den Blue-Agent-Ergebnissen:\n"
            "1. Erkannte Service-Versionen und Software-Komponenten (exakt so wie Tools sie gemeldet haben)\n"
            "2. Bekannte CVEs NUR für tatsächlich gefundene Services — via searchsploit, NVD und DuckDuckGo\n\n"
            "SERVICE-NORMALISIERUNG — vor der CVE-Suche:\n"
            "Nutze deine Knowledge Source um rohe HTTP-Header-Werte in kanonische Produktnamen "
            "zu übersetzen (z.B. 'Apache-Coyote' → 'Apache Tomcat'). "
            "Verwende IMMER whatweb/httpx-erkannte Technologienamen statt roher Header-Werte.\n"
            "WICHTIG Apache-Coyote: 'Apache-Coyote/1.1' → die Zahl nach dem Schrägstrich ist "
            "die Connector-Version, NICHT die Tomcat-Version. Schreibe 'Apache Tomcat (Version unbekannt)' "
            "— nie 'Apache Tomcat 1.1'. Tomcat-Version nur aus whatweb/nmap-Banner übernehmen.\n\n"
            "CVE-SUCHE — Reihenfolge (deterministisch, CPE-first):\n"
            "SCHRITT A: searchsploit '<service> <version>' — lokale Exploit-DB zuerst.\n"
            "SCHRITT B: nvd_cpe_lookup aufrufen (PRIMÄR — präziser als Keyword-Suche):\n"
            "  - Übergib den exakten Service-Banner aus dem Scan-Output als 'banner'-Parameter\n"
            "  - Beispiele: banner='Oracle WebLogic 12.2.1', banner='nginx/1.22.1', banner='OpenSSH 8.2p1'\n"
            "  - Das Tool mappt deterministisch auf CPE und liefert die NEUESTEN CVEs nach CVSS-Score\n"
            "  - Ruf nvd_cpe_lookup für JEDEN identifizierten Dienst auf\n"
            "SCHRITT C: nvd_cve_search als Fallback — NUR wenn nvd_cpe_lookup 'Kein CPE-Mapping' meldet:\n"
            "  - Mit Version: 'Apache Tomcat 8.5', 'jQuery 1.8.2'\n"
            "  - Ohne Version: normalisierter Service-Name ('nginx', 'Elasticsearch')\n"
            "SCHRITT D: Wenn NVD/CPE Treffer liefert → DuckDuckGo '<CVE-ID> exploit PoC' zur Bestätigung.\n\n"
            "RELEVANZ-PRÜFUNG: Prüfe bei jedem Treffer ob Produktname passt. "
            "'Ingress-NGINX' ≠ 'nginx'. 'OpenSSH 7.x' ≠ 'OpenSSH 9.x'. "
            "Ohne bekannte Version: nur HIGH/CRITICAL CVEs aus den letzten 3 Jahren eintragen.\n"
            "PRODUKT-FILTER: NVD-Keyword-Suche matcht Versionsnummern quer über alle Apache-Subprojekte. "
            "Prüfe immer das betroffene Produkt in der NVD-Beschreibung und CPE:\n"
            "  - 'Apache Groovy' ≠ 'Apache HTTP Server' ≠ 'Apache CXF' ≠ 'Apache Tomcat'\n"
            "  - Nur CVEs für das tatsächlich gefundene Produkt eintragen.\n"
            "  - Beispiel: whatweb zeigt 'Apache/2.4.7' → nur CVEs für 'Apache HTTP Server', "
            "nicht für Apache Groovy oder Apache CXF auch wenn deren Version '2.4.7' ist.\n"
            "KONFIGURATIONS-FILTER: Wenn NVD-Beschreibung ein Konfigurations-Prerequisite nennt "
            "('ProxyRequests on', 'mod_status enabled', 'allowLinking enabled') das im Scan "
            "nicht nachgewiesen wurde, füge einen Hinweis in risk_summary hinzu aber trage die CVE "
            "nur ein wenn das Prerequisite plausibel ist (z.B. mod_status auf öffentlichen Servern häufig aktiv).\n"
            "PLATTFORM-FILTER: Wenn die NVD-Beschreibung explizit 'on Windows' enthält "
            "und es keine Evidenz gibt dass der Ziel-Server Windows nutzt (Apache/nginx/Linux-Banner "
            "weisen auf Linux hin), trage die CVE NICHT in cve_references ein.\n"
            "REGEL: Trage in 'cve_references' JEDE CVE-ID ein die ein Tool in dieser Session "
            "zurückgegeben hat — searchsploit, nvd_cve_search ODER nvd_cpe_lookup zählen alle als Bestätigung. "
            "Wenn nvd_cpe_lookup für 'Oracle WebLogic' CVE-2023-21839 zurückgibt → in cve_references eintragen. "
            "Wenn nvd_cpe_lookup für 'Redis' CVE-2022-0543 zurückgibt → in cve_references eintragen. "
            "Keine CVE-IDs aus LLM-Trainingswissen die KEIN Tool zurückgegeben hat.\n"
            "REGEL: 'risk_summary' enthält ausschließlich direkt beobachtete Fakten aus Tool-Outputs — "
            "keine Einschätzungen, keine Wahrscheinlichkeiten, kein 'may' oder 'could'.\n\n"
            "SIGNATURE-SERVICES — CPE-Lookup bei bekannten Admin-Ports:\n"
            "Wenn ein Service auf einem bekannten Admin-Port läuft, nutze nvd_cpe_lookup:\n"
            "  - Port 7001/7002 → nvd_cpe_lookup banner='Oracle WebLogic' (→ CVE-2023-21839, CVE-2025-21535)\n"
            "  - Port 6379 → nvd_cpe_lookup banner='Redis' (→ CVE-2022-0543 Lua RCE)\n"
            "  - Port 4848 → nvd_cpe_lookup banner='GlassFish' (→ CVE-2011-0807)\n"
            "  - Port 8161 → nvd_cpe_lookup banner='ActiveMQ' (→ CVE-2023-46604 CVSS 10.0)\n"
            "  - Port 9200 → nvd_cpe_lookup banner='Elasticsearch' (→ aktuelle ES CVEs)\n"
            "nvd_cpe_lookup liefert immer die neuesten CVEs nach CVSS — kein Keyword-Rauschen.\n\n"
            "HINWEIS FÜR NACHFOLGENDE TASKS:\n"
            "Dokumentiere erkannte Technologien explizit (z.B. 'Apache 2.4.51', 'WordPress 6.1', "
            "'OpenSSH 8.2p1') damit der Red-Scan-Agent nuclei mit den passenden "
            "Tags ('apache', 'wordpress', 'openssh') und 'severity=critical,high' aufrufen kann."
        ),
        expected_output=(
            "Extrahierte Service-Versionen, alle CVE-IDs die searchsploit/nvd_cve_search/nvd_cpe_lookup "
            "zurückgegeben haben (vollständig in cve_references), faktische Zusammenfassung."
        ),
        output_pydantic=FindingsOutput,
        guardrails=[_cve_trace_guardrail],
        guardrail_max_retries=2,
        agent=research_agent,
        context=[research, blue],
    )

    red_scan = Task(
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
        context=[blue, findings],
    )

    # red_scan is NOT in context= — its output flows in automatically via sequential
    # Process when it's in the pipeline (scope=full). An explicit reference would
    # break at runtime for scopes that don't include red_scan.
    red = Task(
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
        guardrails=[_cve_trace_guardrail],
        guardrail_max_retries=2,
        agent=red_agent,
        context=[blue, findings],
    )

    coding = Task(
        description=(
            "Ziel: {target} | Objective: {objective}\n\n"
            "Generiere ein ausführbares Python-Skript das genau die Tool-Calls automatisiert "
            "die der Blue Agent ausgeführt hat.\n"
            "NUR die tatsächlich verwendeten Tools abbilden – kein generisches Template.\n"
            "Fehlerbehandlung und Logging hinzufügen.\n\n"
            "AUSGABE-FORMAT: Antworte mit einem einzigen rohen JSON-Objekt.\n"
            "KEIN ```json ... ``` drumherum. KEIN Markdown. Nur das JSON-Objekt selbst.\n\n"
            "Schema:\n"
            "- 'filename': z.B. 'scan_heise.py'\n"
            "- 'code': der VOLLSTÄNDIGE Python-Code als String (kein Markdown, keine Backticks im Code)\n"
            "- 'code_plan': Liste der Schritte die der Code abbildet\n"
            "- 'syntax_valid': true wenn der Code syntaktisch korrekt ist"
        ),
        expected_output=(
            "Rohes JSON-Objekt (KEIN Markdown-Wrapper) mit vollständigem Python-Code im 'code'-Feld, "
            "Dateiname und Schritt-Liste."
        ),
        agent=coding_agent,
        context=[blue, red],
    )

    report = Task(
        description=(
            "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"
            "Erstelle einen kompakten Recon-Report als Markdown. "
            "Der Report ist Rohdaten-Dokumentation — er dient als Input für nachgelagerte Analyse-Agents.\n\n"
            "KOMPAKT-PFLICHT: Schreibe den Report IN EINEM DURCHGANG ohne Iteration. "
            "Jede Sektion max. 5 Zeilen. Keine Raw-Tool-Outputs kopieren — nur extrahierte Fakten. "
            "Wenn ein Fakt unklar ist: weglassen statt iterieren.\n\n"
            "FAKTEN-PFLICHT: Jede Aussage muss direkt aus einem Tool-Output ableitbar sein. "
            "Keine Einschätzungen, keine Wahrscheinlichkeiten, kein 'may', 'could', 'potential'. "
            "Wenn ein Tool nichts gefunden hat: eine Zeile dokumentieren, nicht spekulieren.\n\n"
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
        # No explicit context= — sequential process passes all prior task outputs
        # automatically. Works for all scopes (osint has no blue/red tasks).
    )

    return {
        "research": research,
        "blue":     blue,
        "findings": findings,
        "red_scan": red_scan,
        "red":      red,
        "coding":   coding,
        "report":   report,
    }
