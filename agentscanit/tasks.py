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


_VERSION_TOKEN_RE = _re.compile(r'\d+\.\d+')


def _searchsploit_version_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail (red): lehnt versionslose searchsploit-Treffer als Findings ab.

    BUG-23 (2026-09-11): searchsploit ohne Versionsangabe (z.B. 'searchsploit Apache'
    statt 'searchsploit Apache 2.4.49') liefert einen ungefilterten Keyword-Dump der
    gesamten lokalen ExploitDB — teils >100 KB, älteste Treffer von 1996, KEIN Bezug
    zur tatsächlich laufenden Version des Ziels. Beobachteter Realfall (rastede.de):
    'searchsploit --json Apache' lieferte 7 Treffer (u.a. ActiveMQ, Apache 0.8.x/1.0.x/
    1.1/1.2/1.3), die der Agent 1:1 als confirmed_attack_surface/exploitable_findings
    übernahm — obwohl ActiveMQ auf dem Ziel gar nicht läuft und nie eine Apache-Version
    erkannt wurde. Der Prompt verlangt 'searchsploit <service> <version>', das ist aber
    reine Vorgabe, kein Code-Zwang (gleiches Muster wie BUG-20, dort für die NVD-CVE-
    Liste gelöst — hier für den red-Task nachgezogen).

    Teilt sich den Reject-Counter mit den anderen Guardrails dieser Session (gleiches
    Muster wie beim findings-Task, wo _cve_tool_used_guardrail + _cve_trace_guardrail
    ebenfalls einen gemeinsamen Counter nutzen) — ein Retry-Budget pro Task-Versuch,
    nicht pro Guardrail-Typ.
    """
    pydantic_out = getattr(output, "pydantic", None)
    raw = getattr(output, "raw", output) if not isinstance(output, str) else output
    if not pydantic_out:
        return True, raw

    surface     = list(getattr(pydantic_out, "confirmed_attack_surface", None) or [])
    exploitable = list(getattr(pydantic_out, "exploitable_findings", None) or [])
    if not surface and not exploitable:
        return True, raw

    try:
        from tools.trace import run_trace
        if not run_trace.is_active:
            return True, raw

        versionless_calls = []
        for call in run_trace._pending:
            if call.get("tool_name", "") != "searchsploit":
                continue
            cmd = call.get("command") or call.get("agent_params") or []
            query = " ".join(str(c) for c in cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if not _VERSION_TOKEN_RE.search(query):
                versionless_calls.append(query)

        if versionless_calls and run_trace._guardrail_reject_count < 1:
            run_trace._guardrail_reject_count += 1
            return False, (
                f"FEHLER: searchsploit wurde ohne Versionsangabe aufgerufen "
                f"({versionless_calls}) — das liefert einen ungefilterten Keyword-Dump "
                f"der gesamten lokalen ExploitDB (ggf. hunderte Treffer seit 1996), "
                f"KEINE tool-bestätigte Aussage über das aktuelle Ziel. "
                f"'confirmed_attack_surface'/'exploitable_findings' sind aber nicht leer. "
                f"Entweder: rufe searchsploit erneut mit '<service> <version>' auf "
                f"(Version aus blue-/findings-Context entnehmen), oder — falls keine "
                f"konkrete Version bekannt ist — leere 'confirmed_attack_surface' und "
                f"'exploitable_findings' (keine Version = kein bestätigter Treffer)."
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


# wafw00f meldet einen konkreten Treffer als "is behind <WAF> WAF".
# NUR diese Zeile trägt den echten WAF-Namen. Die generische Fallback-Zeile
# ("seems to be behind a WAF or some sort of security solution") ist KEIN Name,
# nur ein schwaches Heuristik-Signal → bewusst NICHT als Name extrahiert.
# Negativ-Markierungen ("No WAF detected", "Number of requests") fallen raus.
_WAF_HIT_RE = _re.compile(r"\bis behind\b\s+(.+?)\s+WAF\b", _re.I)
# wafw00f färbt seinen Output (ANSI-Escape-Sequenzen) — vor dem Parsen strippen.
_ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def _waf_detection_guardrail(output: Any) -> tuple[bool, Any]:
    """Hängt einen WAF/CDN-Hinweis an den blue-Output, wenn wafw00f eine WAF erkannt hat.

    Lehnt NIE ab (reine Anreicherung, wie _subdomain_fanout_guardrail). Liest den
    wafw00f-Output aus dem Trace DIESER Session und ergänzt — bei Treffer — einen
    markierten Block '=== WAF/CDN DETECTED ===', der via context=[blue] in findings
    und in den Final Report fließt. Zweck: leere CVE-Ergebnisse hinter einer WAF
    sind NICHT als 'Ziel sicher' zu lesen — Banner/CVEs gehören evtl. der WAF, nicht
    dem Origin. Deterministisch, kein LLM (vgl. BUG-20: CVE-Kontrolle braucht Guardrail).
    """
    try:
        from tools.trace import run_trace
        if not run_trace.is_active:
            return True, output
        outputs = _ANSI_RE.sub("", run_trace.get_all_raw_outputs())
        if "wafw00f" not in outputs.lower() and "WAF" not in outputs:
            # wafw00f gar nicht gelaufen → nichts anzuhängen.
            return True, output
        wafs: list = []
        for m in _WAF_HIT_RE.finditer(outputs):
            tag = m.group(1).strip().rstrip(".")[:80]
            # Generische Fallback-Phrase ist kein WAF-Name → ausschließen.
            if tag and "some sort of" not in tag.lower() and tag not in wafs:
                wafs.append(tag)
        if not wafs:
            return True, output
        block = (
            "\n\n=== WAF/CDN DETECTED (wafw00f, deterministic) ===\n"
            "Vor dem Ziel wurde eine WAF/ein CDN erkannt: " + ", ".join(wafs) + ".\n"
            "WICHTIG für die Bewertung: Server-Banner und CVE-Treffer können die der WAF/des "
            "CDN sein, NICHT die des Origin-Servers. Ein leeres CVE-Ergebnis bedeutet hier NICHT, "
            "dass das Ziel sicher ist — die eigentliche Angriffsfläche ist evtl. verdeckt."
        )
        raw = getattr(output, "raw", "") or ""
        if "WAF/CDN DETECTED" not in raw:
            try:
                object.__setattr__(output, "raw", raw + block)
            except Exception:
                pass
    except Exception:
        pass
    return True, output


def _tools_executed_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail (blue/red_scan): 'tools_executed'-Feld gegen echte Tool-Calls
    DIESER Task validieren.

    Live gefunden (2026-09-12, www.cloudflare.com web, Test-Matrix-Nachtrag):
    BlueOutput.tools_executed nannte ['wafw00f', 'httpx_prober'], obwohl diese
    Task nur EINEN echten Tool-Call machte (httpx). 'httpx_prober' ist legitim
    (CrewAI-Tool-Klassenname für den echten 'httpx'-Call — Präfix-Match nötig,
    gleiches Muster wie bei der 'Detected Technologies'-Zuordnung in
    _value_grounding_guardrail) — 'wafw00f' dagegen ist komplett erfunden, kein
    einziger Call dazu im Trace. Bisher rein Prompt-Vorgabe ('tools_executed
    muss aus echten Tool-Aufrufen stammen', s.u.), kein Guardrail — mit dem
    erwarteten Ergebnis (vgl. BUG-20/23/25: Werte-Kontrolle braucht einen
    Guardrail, keine Prompt-Bitte).

    Prüft run_trace._pending (Calls DIESER Task — close_phase() läuft erst im
    task_callback NACH bestandenem Guardrail, wie bei _tool_call_guardrail).

    Erweiterung (2026-09-15, Validierungs-Corpus-Backlog §5.1/5.2): red_scan
    darf legitim 0 echte Tool-Calls machen ("nichts Neues zu scannen" — anders
    als blue hat red_scan KEIN _tool_call_guardrail). Corpus-Befund (7/7
    Targets): in diesem Fall kopiert das Modell trotzdem open_ports/
    vulnerabilities/targeted_findings 1:1 von blue UND behauptet in
    tools_executed dieselben Tools wie blue — der reporter-Task (kein
    explizites context=, sieht ALLE Vorgänger-Outputs automatisch) übernimmt
    das dann als "durch red_scan zusätzlich bestätigt", obwohl keine neue
    Verifikation stattfand. Reject+Retry allein behebt das nachweislich NICHT
    zuverlässig (derselbe Corpus zeigt 0/28 tools_executed korrekt trotz
    bereits aktivem Guardrail) — deshalb hier deterministisch: wenn red_scan
    (erkannt an 'targeted_findings', ein Feld das nur RedScanOutput hat) ohne
    echten Tool-Call abschließt, werden alle vier Felder hart geleert statt
    auf Selbstkorrektur zu hoffen. Kein Datenverlust — blue's Originalwerte
    bleiben über den sequenziellen Task-Context ohnehin für red/report
    erreichbar, nur die irreführende Zuschreibung an red_scan entfällt.
    """
    pydantic_out = getattr(output, "pydantic", None)
    raw = getattr(output, "raw", output) if not isinstance(output, str) else output
    if not pydantic_out:
        return True, raw

    try:
        from tools.trace import run_trace
        if not run_trace.is_active:
            return True, raw
        real_used = {c.get("tool_name", "") for c in run_trace._pending if c.get("tool_name")}

        is_red_scan = hasattr(pydantic_out, "targeted_findings")
        if is_red_scan and not real_used:
            for field in ("open_ports", "vulnerabilities", "targeted_findings", "tools_executed"):
                if getattr(pydantic_out, field, None):
                    setattr(pydantic_out, field, [])
            return True, raw

        if not real_used:
            return True, raw

        claimed = [t for t in (getattr(pydantic_out, "tools_executed", None) or []) if t]
        if not claimed:
            return True, raw

        fabricated = [t for t in claimed if not _tool_name_grounded(t, real_used)]
        if fabricated and run_trace._guardrail_reject_count < 1:
            run_trace._guardrail_reject_count += 1
            return False, (
                f"FEHLER: 'tools_executed' nennt {fabricated}, für die es in "
                f"dieser Task KEINEN echten Tool-Call gibt (echte Calls: "
                f"{sorted(real_used)}). Entferne nicht wirklich aufgerufene "
                f"Tools aus 'tools_executed'."
            )
    except Exception:
        pass
    return True, raw


# ─── Output-Modelle ───────────────────────────────────────────────────────────

class ResearchOutput(BaseModel):
    # BUG-26 (2026-09-12): beide Felder werden nirgends im Code konsumiert (reine
    # Anzeige-/Kontext-Felder) — gleiches Default-""-Muster wie BlueOutput.analysis
    # etc., verhindert einen Pipeline-Crash falls das Modell eines weglässt.
    target_type: str = ""               # "domain" oder "ip"
    summary: str = ""
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


# BUG-26 (2026-09-12): analysis/risk_summary waren die einzigen bare-required str-
# Felder (kein Default) in ihren jeweiligen Output-Modellen — jedes andere Feld hat
# bereits default_factory. Live beobachtet in zwei separaten Sessions (example.com
# full, BlueOutput.analysis fehlte; FindingsOutput.risk_summary fehlte): wenn
# nemotron-3-nano:30b dieses eine Feld im JSON wegließ, warf Pydantic einen harten
# ValidationError, der main.py als "Field required" klassifiziert (structural,
# nur 3 Vollneustart-Versuche statt 5 bei LLM-Fehlern) — bei ungünstigem Timing
# (Fehler auf dem letzten Versuch) crashte der GESAMTE Scan wegen EINES fehlenden
# Freitext-Felds, das für nachgelagerte Teams (interpret/risk_scorer/reporting)
# nicht strukturell benötigt wird (die nutzen cve_references/vulnerabilities etc.,
# nicht analysis/risk_summary direkt). Default "" verhindert den Crash; der Prompt
# fordert das Feld weiterhin an (Verhaltensänderung nur bei Modell-Fehlverhalten
# sichtbar, nicht bei normalem Betrieb).
class BlueOutput(BaseModel):
    tools_executed: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    services: Dict[str, Any] = Field(default_factory=dict)
    vulnerabilities: List[str] = Field(default_factory=list)
    analysis: str = ""


class FindingsOutput(BaseModel):
    service_versions: List[str] = Field(default_factory=list)
    cve_references: List[str] = Field(default_factory=list)
    risk_summary: str = ""

    @field_validator("cve_references")
    @classmethod
    def validate_cve_format(cls, v: List[str]) -> List[str]:
        return _filter_cve_format(v)


class RedScanOutput(BaseModel):
    targeted_findings: List[str] = Field(default_factory=list)
    tools_executed: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    analysis: str = ""


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


# CVE-Recherche-Tools die die findings-Phase nutzen MUSS bevor sie ein Urteil fällt.
_CVE_RESEARCH_TOOLS = {"searchsploit", "nvd_cpe_lookup", "nvd_cve_search", "ddg_search"}


def _cve_tool_used_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail (findings): erzwingt mind. EINEN CVE-Recherche-Tool-Aufruf.

    Befund (lokales 8B llama3-groq, 2026-06-25): das Modell schloss die findings-
    Phase MIT VALIDEM JSON ('No vulnerabilities found') ab, OHNE ein einziges CVE-
    Tool (searchsploit/nvd_*) aufzurufen — es urteilte direkt aus dem Banner. Der
    _cve_trace_guardrail fängt das NICHT (er prüft nur eingetragene CVEs gegen den
    Trace; bei leerer cve_references gibt es nichts zu prüfen). Diese Lücke betrifft
    JEDES Modell, wird aber nur bei schwächeren (lokal) sichtbar.

    Prüft run_trace._pending (Tool-Calls der aktuellen findings-Phase) auf ein CVE-
    Recherche-Tool. Reject-Count-Muster wie _tool_call_guardrail (No-Tool-Fallback
    nach 1 Reject gegen Endlosschleifen).
    """
    try:
        from tools.trace import run_trace
        if run_trace.is_active:
            used = {c.get("tool_name", "") for c in run_trace._pending}
            if not (used & _CVE_RESEARCH_TOOLS):
                if run_trace._guardrail_reject_count >= 1:
                    return True, getattr(output, "raw", output)  # Fallback: akzeptieren
                run_trace._guardrail_reject_count += 1
                return (
                    False,
                    "FEHLER: Du hast die CVE-Analyse abgeschlossen OHNE ein CVE-"
                    "Recherche-Tool aufzurufen. Ein Urteil ('keine Schwachstellen') "
                    "allein aus dem Banner ist nicht erlaubt. Rufe JETZT mindestens "
                    "eines auf: nvd_cpe_lookup (mit Service-Banner), searchsploit "
                    "('<service> <version>') oder nvd_cve_search. Erst NACH echtem "
                    "Tool-Output darfst du cve_references füllen oder begründet leer lassen.",
                )
    except Exception:
        pass
    return True, getattr(output, "raw", output)


_CONFIRMED_FINDINGS_SECTION_RE = _re.compile(
    r'## Confirmed Findings(.*?)(?=\n## |\Z)', _re.DOTALL,
)


def _extract_report_text(output: Any) -> tuple[str, Any]:
    """Extract the reporter's markdown text (executive_summary) + the raw fallback value.

    Shared by every report-task guardrail (BUG-23 tool-name check, BUG-25 value-
    grounding check). 'output.raw' is the ROHE JSON-Antwort
    ('{"path":...,"executive_summary":"# Recon Report:...\\n\\n##..."}') — die
    Zeilenumbrüche darin sind JSON-escaped (zwei Zeichen '\\'+'n'), kein echtes
    '\\n'. Liest deshalb bevorzugt aus dem bereits geparsten
    'output.pydantic.executive_summary' (echte Python-Newlines); Fallback: 'raw'
    selbst als JSON parsen und entpacken; letzter Fallback: 'raw' direkt als Text.
    """
    raw = getattr(output, "raw", output) if not isinstance(output, str) else output
    pydantic_out = getattr(output, "pydantic", None)

    text = getattr(pydantic_out, "executive_summary", None) if pydantic_out is not None else None
    if not text:
        try:
            import json as _json3
            parsed = _json3.loads(raw)
            if isinstance(parsed, dict):
                text = parsed.get("executive_summary")
        except Exception:
            pass
    if not text and isinstance(raw, str):
        text = raw
    return text, raw


def _tool_name_grounded(claimed: str, real_tools) -> bool:
    """True wenn `claimed` echt gelaufen ist — exakt, als Präfix (CrewAI-Tool-
    Klassennamen wie 'httpx_prober'/'nuclei_vulnerability_scanner' für die
    realen Bin-Namen 'httpx'/'nuclei') ODER als führendes Wort vor einem
    Nicht-Alnum-Suffix ('nmap (step_1)' -> 'nmap').

    Gemeinsamer Helper für alle drei Tool-Namen-Guardrails (gefunden bei der
    Validierungsrunde 2026-09-12: _confirmed_findings_tool_guardrail prüfte
    bisher nur exakte Gleichheit — 'nuclei_vulnerability_scanner' (real:
    nuclei) und 'nmap (step_1)' (real: nmap) wurden dadurch FÄLSCHLICH als
    fabriziert gemeldet, obwohl die Tools echt liefen. _tools_executed_
    guardrail und der Detected-Technologies-Teil von _value_grounding_
    guardrail hatten diese Toleranz bereits — jetzt konsolidiert, damit alle
    drei Guardrails denselben, bereits bewährten Maßstab anlegen.

    Toleriert nur Paraphrasierung DES TOOL-NAMENS, nicht des behaupteten
    WERTS — ein Tool das nie lief, bleibt weiterhin ein Reject.
    """
    low = claimed.strip().strip("`").lower()
    lead = _re.split(r"[\s(]", low, 1)[0]
    for real in real_tools:
        rl = real.lower()
        if low == rl or low.startswith(rl) or lead == rl:
            return True
    return False


def _confirmed_findings_tool_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail (report): 'Tool'-Spalte der Confirmed-Findings-Tabelle gegen die
    real in dieser Session gelaufenen Tools validieren.

    BUG-23 (2026-09-11): ReportOutput hat kein Pydantic-Feld für die Tabelle (nur
    'path' + 'executive_summary') — sie ist ungeschütztes Markdown-Freitext im
    raw-Output, den der reporter_agent OHNE eigenen Tool-Zugriff aus dem Kontext
    vorheriger Tasks synthetisiert. Beobachteter Realfall (rastede.de): der Reporter
    schrieb 'nuclei_vulnerability_scanner' als Quelle für 7 Findings, deren echte
    Quelle ein versionsloser searchsploit-Dump war — der einzige echte nuclei-Call
    dieser Session lieferte 0 Treffer. Diese Guardrail parst die Tabelle und lehnt
    ab, wenn ein genanntes Tool nie aufgerufen wurde.

    Folgefund (oldenburg.de, 2026-09-11): der erste Verifikationslauf zeigte, dass
    diese Guardrail wirkungslos blieb — 'nikto_scanner'/'sslscan_tls' wurden für
    Findings genannt, obwohl nikto/sslscan in der Session NIE liefen, und kein
    Reject erfolgte. Ursache: 'output.raw' ist die ROHE JSON-Antwort
    ('{"path":...,"executive_summary":"# Recon Report:...\\n\\n##..."}') — die
    Zeilenumbrüche darin sind JSON-escaped (zwei Zeichen '\\'+'n'), kein echtes
    '\\n'. '.splitlines()'/die Regex fanden dadurch keine einzige Tabellenzeile,
    liefen leer durch und akzeptierten stillschweigend. Fix: bevorzugt aus dem
    bereits geparsten 'output.pydantic.executive_summary' lesen (dort echte
    Python-Newlines); Fallback: 'raw' selbst als JSON parsen und entpacken.

    Zweiter Folgefund (www.cloudflare.com, 2026-09-12): eine Zeile mit KOMPLETT
    LEERER Tool-Spalte ('| Cloudflare | 443 | WAF/CDN detected: ... |  |  |',
    wafw00f wurde in dieser Session nie aufgerufen) wurde bisher übersprungen
    ('not tool_col' → continue) statt geprüft — eine unbelegte Behauptung ohne
    JEDE Tool-Angabe ist mindestens so verdächtig wie ein falscher Tool-Name,
    entging aber beiden Guardrails (auch _value_grounding_guardrail überspringt
    Zeilen ohne Tool-Spalte). Fix: eine echte Datenzeile (Beobachtung vorhanden,
    keine Kopf-/Trennzeile) mit leerer Tool-Spalte gilt jetzt selbst als
    Fabrikation.
    """
    text, raw = _extract_report_text(output)
    if not text or "## Confirmed Findings" not in text:
        return True, raw

    try:
        from tools.trace import run_trace
        if not run_trace.is_active:
            return True, raw

        real_tools = run_trace.get_all_tool_names()
        if not real_tools:
            return True, raw

        section_match = _CONFIRMED_FINDINGS_SECTION_RE.search(text)
        if not section_match:
            return True, raw

        fabricated: set = set()
        unattributed: list = []
        for row in section_match.group(1).splitlines():
            row = row.strip()
            if not row.startswith("|"):
                continue
            cols = [c.strip() for c in row.strip("|").split("|")]
            if len(cols) < 4:
                continue
            observation, tool_col = cols[2], cols[3]
            if tool_col == "Tool" or (tool_col and _re.fullmatch(r'-+', tool_col)):
                continue  # Kopfzeile / Trennzeile
            if not tool_col:
                # Echte Datenzeile (Beobachtung vorhanden, keine Kopf-/Trennzeile)
                # ohne JEDE Tool-Angabe — unbelegte Behauptung, siehe Docstring.
                if observation and not _re.fullmatch(r'-+', observation):
                    unattributed.append(observation)
                continue
            for name in _re.split(r'[,/]', tool_col):
                name = name.strip().strip('`')
                if name and not _tool_name_grounded(name, real_tools):
                    fabricated.add(name)

        if (fabricated or unattributed) and run_trace._guardrail_reject_count < 1:
            run_trace._guardrail_reject_count += 1
            parts = []
            if fabricated:
                parts.append(
                    f"Tool(s) {sorted(fabricated)} als Quelle genannt, die in dieser "
                    f"Session NIE aufgerufen wurden"
                )
            if unattributed:
                parts.append(
                    f"Zeile(n) ohne JEDE Tool-Angabe: {unattributed[:5]}"
                )
            return False, (
                f"FEHLER: Die 'Confirmed Findings'-Tabelle enthält unbelegte "
                f"Behauptungen — {'; '.join(parts)}. Real gelaufene Tools: "
                f"{sorted(real_tools)}. Korrigiere die 'Tool'-Spalte auf das Tool, "
                f"das die jeweilige Beobachtung laut Kontext tatsächlich lieferte, "
                f"oder entferne die Zeile falls kein Tool sie bestätigt."
            )
    except Exception:
        pass

    return True, raw


# BUG-25: faktische Anker (Version/Hostname/wörtliches Zitat) — bewusst NICHT der
# ganze Satz, Paraphrasierung der Beobachtung ist erlaubt. Nur diese drei Muster
# deckten die real beobachteten Fabrikationsfälle ab (example.com, 2026-09-12):
# "Apache 2.4.54" (Versionsanker fehlte komplett im Trace), "WordPress 5.9" +
# "<title>...WordPress 5.9</title>" (Versionsanker + Zitat fehlten), "admin.
# example.com" (Hostnamen-Anker fehlte — reale Subdomains waren admin11/17/20/24).
_VERSION_ANCHOR_RE  = _re.compile(r'\d+(?:\.\d+){1,3}[a-zA-Z0-9]*')
_HOSTNAME_ANCHOR_RE = _re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,}\b'
)
_QUOTED_TAG_ANCHOR_RE = _re.compile(r'<[^<>]{3,200}>')
_DETECTED_TECH_SECTION_RE = _re.compile(
    r'## Detected Technologies(.*?)(?=\n## |\Z)', _re.DOTALL,
)
_TECH_LINE_RE = _re.compile(r'^([\w./`\'"\[\] -]+?)\s*(?:→|->)\s*(.+)$')

# BUG-25-Nachtrag (2026-09-12, live bestätigt bei erneutem example.com-full-Lauf):
# der im ursprünglichen BUG-25-Fix dokumentierte "Sonderfall sslscan-Eigenbanner"
# wurde bewusst NUR im blue-Prompt behandelt (reine Prompt-Anweisung), NICHT als
# Guardrail — mit genau dem im Projekt schon mehrfach belegten Ergebnis (BUG-20/
# BUG-23-Lehre: "CVE-/Werte-Kontrolle braucht Guardrail, nicht Prompt-Bitte"):
# der Live-Scan übernahm sslscans Eigenbanner ("Version: 2.1.2\nOpenSSL 3.0.13
# ...") trotzdem erneut als angebliche Ziel-TLS-Version, in BEIDEN Sektionen
# (Confirmed Findings UND Detected Technologies). Die reine Substring-Prüfung
# von _value_grounding_guardrail hätte das nicht gefangen — der Wert steht ja
# wörtlich im Raw-Output, nur die Interpretation ist falsch. Fix: die ersten
# 1-2 Banner-Zeilen werden aus dem Grounding-Haystack für sslscan-Tools entfernt,
# BEVOR die Anker-Suche läuft — ein Anker der NUR im Banner vorkommt (wie bei
# 55-Zeichen-sslscan-Outputs ohne echte Scan-Daten, z.B. hinter Cloudflare-TLS-
# Terminierung) gilt dann korrekt als nicht belegt.
_ANSI_ESCAPE_RE = _re.compile(r'\x1b\[[0-9;]*m')
_SSLSCAN_SELF_BANNER_RE = _re.compile(
    r'^\s*Version:\s*\d+(?:\.\d+){1,3}\s*\n\s*OpenSSL\s+\d+(?:\.\d+){1,3}[^\n]*\n?',
    _re.IGNORECASE,
)


def _strip_sslscan_self_banner(raw: str) -> str:
    """sslscans eigenen Versions-Banner (Tool-Version + kompilierte OpenSSL-
    Version) aus dem Raw-Output entfernen, bevor er als Grounding-Nachweis dient.
    Diese Zeilen sind immer die ersten 1-2 Zeilen von sslscan-Output, nie das
    Scan-Ergebnis gegen das Ziel (siehe Modul-Kommentar oben, BUG-25-Nachtrag)."""
    cleaned = _ANSI_ESCAPE_RE.sub('', raw or '')
    return _SSLSCAN_SELF_BANNER_RE.sub('', cleaned, count=1)


def _extract_value_anchors(text: str) -> list:
    """Faktische Anker aus einer Beobachtungs-Zeichenkette extrahieren (BUG-25).

    Nicht jede Beobachtung hat einen Anker (z.B. 'Missing X-Frame-Options header'
    ist eine reine Boolean-Aussage ohne Produkt/Version/Hostname) — solche Zeilen
    werden von _value_grounding_guardrail übersprungen (kein Anker = nichts zu
    prüfen, kein Fehlalarm-Risiko).
    """
    anchors = []
    anchors += _QUOTED_TAG_ANCHOR_RE.findall(text)
    anchors += _HOSTNAME_ANCHOR_RE.findall(text)
    anchors += _VERSION_ANCHOR_RE.findall(text)
    return anchors


def _value_grounding_guardrail(output: Any) -> tuple[bool, Any]:
    """Guardrail (report): faktische Anker der 'Beobachtung'-Spalte gegen den
    Raw-Output des in derselben Zeile zitierten Tools cross-checken.

    BUG-25 (2026-09-12): Anders als BUG-23 (falscher Tool-*Name*) stimmt hier der
    zitierte Tool-Name — aber der behauptete WERT (Produktname+Version, Hostname,
    wörtliches Zitat) hat keine Deckung im tatsächlichen Tool-Output. Beobachtet
    bei example.com full: "WordPress version 5.9 identified" + Fake-Zitat
    '<title>Example Site - WordPress 5.9</title>' zugeschrieben an whatweb
    (echter Output: nur 'Title[Example Domain]'); "nmap_service_version → Apache
    2.4.54" (echter nmap-Output nennt nirgends 'Apache'); "Subdomain
    admin.example.com discovered" zugeschrieben an subfinder (echte Funde waren
    admin11/17/20/24.example.com, nie exakt 'admin.example.com'). Der bestehende
    _confirmed_findings_tool_guardrail (BUG-23) prüft nur ob das zitierte Tool
    IRGENDWANN lief — nicht ob der konkrete Wert aus dessen Output stammt.

    Bewusst KEIN Exact-Match des ganzen Satzes (Paraphrasierung erlaubt) — nur
    strukturierte Anker (Versionsnummern, Hostnamen, HTML-Tag-Zitate) müssen
    wörtlich im Raw-Output des zitierten Tools vorkommen. Zeilen ohne extrahierbare
    Anker werden übersprungen (nicht generisch faktengeprüft — siehe CLAUDE.md
    BUG-25-Arbeitsplan, Abgrenzung).

    Deckt ZWEI Sektionen ab: 'Confirmed Findings' (Tabelle, Tool-Spalte explizit)
    UND 'Detected Technologies' (Zeilen '<label> → <wert>', z.B. 'nmap_service_
    version → Apache 2.4.54' — Tool wird über Präfix-Match des Labels gegen die
    real gelaufenen Tools aufgelöst, da das Label meist '<tool>_<zweck>' ist).
    Der reale "Apache 2.4.54"-Fabrikationsfall stand NUR in Detected Technologies,
    nicht in der Confirmed-Findings-Tabelle — beide Sektionen müssen geprüft
    werden, sonst bleibt genau dieser Fall unentdeckt.

    Sonderfall sslscan-Eigenbanner (BUG-25-Nachtrag, jetzt AUCH hier behandelt):
    die ersten Zeilen von sslscan-Output sind das Tool selbst (Versions-Banner),
    nicht das Scan-Ergebnis — der Versionsanker steht dort zwar wörtlich, ist
    aber trotzdem eine Fehlinterpretation. Ursprünglich nur im blue-Prompt
    adressiert (reine Prompt-Anweisung) — live bestätigt UNZUREICHEND (siehe
    _strip_sslscan_self_banner()). _grounded_haystack() entfernt den Banner jetzt
    deterministisch, bevor die Anker-Suche läuft.
    """
    text, raw = _extract_report_text(output)
    if not text or ("## Confirmed Findings" not in text and "## Detected Technologies" not in text):
        return True, raw

    try:
        from tools.trace import run_trace
        if not run_trace.is_active:
            return True, raw

        real_tools = run_trace.get_all_tool_names()

        def _grounded_haystack(tool_names: list) -> list:
            # Präfix-tolerante Tool-Auflösung (2026-09-12, Validierungsrunde):
            # ein zitierter Name wie 'nuclei_vulnerability_scanner' hat sonst
            # KEINEN Raw-Output unter genau diesem String im Trace (real:
            # 'nuclei') — get_all_tool_names() + _tool_name_grounded() löst das
            # auf denselben real gelaufenen Tool-Namen auf, statt stillschweigend
            # 0 Ergebnisse zu liefern (und damit die Wertprüfung zu überspringen).
            parts = []
            for name in tool_names:
                resolved = [r for r in real_tools if _tool_name_grounded(name, {r})] or [name]
                for r in resolved:
                    for out in run_trace.get_raw_outputs_for_tool(r):
                        if r.lower().startswith("sslscan"):
                            out = _strip_sslscan_self_banner(out)
                        parts.append(out)
            return parts

        ungrounded: list = []

        # --- Sektion 1: Confirmed Findings (Tabelle, Tool-Spalte explizit) ---
        section_match = _CONFIRMED_FINDINGS_SECTION_RE.search(text)
        if section_match:
            for row in section_match.group(1).splitlines():
                row = row.strip()
                if not row.startswith("|"):
                    continue
                cols = [c.strip() for c in row.strip("|").split("|")]
                if len(cols) < 4:
                    continue
                observation, tool_col = cols[2], cols[3]
                if not tool_col or tool_col == "Tool" or _re.fullmatch(r'-+', tool_col):
                    continue  # Kopfzeile / Trennzeile

                anchors = _extract_value_anchors(observation)
                if not anchors:
                    continue  # keine strukturierte Behauptung — nichts zu prüfen

                tool_names = [n.strip().strip('`') for n in _re.split(r'[,/]', tool_col) if n.strip()]
                haystack_parts = _grounded_haystack(tool_names)
                if not haystack_parts:
                    continue  # kein Raw-Output für dieses Tool auffindbar — von
                              # _confirmed_findings_tool_guardrail (BUG-23) abgedeckt,
                              # hier kein Doppel-Reject auf denselben Root Cause

                haystack = "\n".join(haystack_parts)
                # Case-insensitiv (2026-09-12, Validierungsrunde): whois liefert
                # Domains z.B. als 'WWW.CLOUDFLARE.COM', die Beobachtung zitiert
                # 'www.cloudflare.com' — Hostnamen sind laut RFC 4343 ohnehin
                # case-insensitiv; ein case-sensitiver Vergleich hätte hier eine
                # korrekt gegroundete Aussage fälschlich als Fehler gewertet.
                if not any(anchor.lower() in haystack.lower() for anchor in anchors):
                    ungrounded.append((observation, tool_col, anchors))

        # --- Sektion 2: Detected Technologies (Zeilen 'label → wert') ---
        tech_match = _DETECTED_TECH_SECTION_RE.search(text)
        if tech_match:
            for row in tech_match.group(1).splitlines():
                row = row.strip()
                m = _TECH_LINE_RE.match(row)
                if not m:
                    continue
                label, value = m.group(1).strip(), m.group(2).strip()

                anchors = _extract_value_anchors(value)
                if not anchors:
                    continue

                # Label ist meist '<tool>_<zweck>' (z.B. 'nmap_service_version') —
                # Tool über Präfix-Match gegen die real gelaufenen Tools auflösen.
                matched_tools = [t for t in real_tools if label.lower().startswith(t.lower())]
                if not matched_tools:
                    continue  # unbekanntes Label — von BUG-23-Logik nicht abgedeckt,
                              # aber auch hier kein sicherer Tool-Bezug herstellbar
                haystack_parts = _grounded_haystack(matched_tools)
                if not haystack_parts:
                    continue

                haystack = "\n".join(haystack_parts)
                if not any(anchor.lower() in haystack.lower() for anchor in anchors):
                    ungrounded.append((value, label, anchors))

        if ungrounded and run_trace._guardrail_reject_count < 1:
            run_trace._guardrail_reject_count += 1
            details = "; ".join(
                f"'{obs}' (Tool: {tool}, Anker {anc} nicht im Raw-Output gefunden)"
                for obs, tool, anc in ungrounded[:5]
            )
            return False, (
                f"FEHLER: Die 'Confirmed Findings'-Tabelle enthält Beobachtungen, "
                f"deren zitiertes Tool NIE diesen Wert geliefert hat: {details}. "
                f"Jede Beobachtung muss WÖRTLICH aus dem Tool-Kontext dieser "
                f"Session stammen — keine Produktnamen/Versionen/Subdomains "
                f"erfinden oder aus Trainingsdaten ergänzen. Entferne oder "
                f"korrigiere diese Zeilen anhand des tatsächlichen Tool-Outputs."
            )
    except Exception:
        pass

    return True, raw


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
            "SSH. Trage nur tatsächlich erkannte Dienste als Service ein.\n"
            "SSLSCAN-BANNER (BUG-25): die ERSTEN 1-2 Zeilen von sslscan-Output (z.B. "
            "'Version: 2.1.2' / 'OpenSSL 3.0.13 30 Jan 2024') sind sslscan's EIGENE Tool-/Build-"
            "Version — NICHT die TLS-Version des gescannten Ziels. Die Ziel-Info (Protokolle, "
            "Cipher-Suites, Zertifikat) steht immer in den Zeilen DANACH. Wenn sslscan KEINE "
            "solchen Zeilen liefert (nur der Banner, sonst nichts — z.B. weil ein Reverse-Proxy/"
            "CDN die Verbindung terminiert), gilt die TLS-Version des Ziels als NICHT ermittelt — "
            "niemals den Banner als Ziel-Version eintragen oder danach eine CVE suchen.\n\n"
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
            "API-ERKENNUNG — NUR wenn das Objective '{objective}' API/REST/GraphQL/Swagger/OpenAPI "
            "erwähnt (sonst überspringen):\n"
            "  1. httpx mit 'api_probe=true' aufrufen (targets='{target}') — probt bekannte API-Pfade "
            "(/api, /graphql, /swagger.json, /openapi.json u.a.) und meldet Status + Content-Type. "
            "'application/json' auf einem solchen Pfad = API vorhanden.\n"
            "  2. nuclei mit tags='exposures,graphql,swagger' — findet exponierte API-Doku "
            "(Swagger-UI, OpenAPI-Spec, GraphQL-Introspection, Spring-Actuator).\n"
            "  Ziel ist NUR die ERKENNUNG eines API-Service (existiert eine API, welcher Typ, "
            "Doku exponiert?). KEINE Endpunkt-Enumeration / kein Fuzzing — das ist außerhalb des Scopes.\n\n"
            "FEHLKONFIGURATIONS-CHECKS — NUR wenn das Objective '{objective}' Fehlkonfiguration/"
            "CORS/Misconfiguration/Open-Redirect erwähnt (sonst überspringen):\n"
            "  nuclei mit tags='misconfiguration,cors,redirect' aufrufen — findet CORS-"
            "Fehlkonfiguration, Open Redirects und sonstige Misconfigurations systematisch. "
            "Trage nur tool-bestätigte Treffer als Findings ein.\n\n"
            "Tool-Auswahl nach Scope:\n"
            "Scope 'quick':   ping + nmap (Top-100-Ports) + httpx. Fertig.\n"
            "Scope 'web':     wafw00f (zuerst) + httpx + whatweb + curl + nikto. SSL nur wenn HTTPS aktiv. Kein nmap full-scan.\n"
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
            "                 - Web-Ports offen → wafw00f (WAF/CDN-Check zuerst), httpx, whatweb, nikto (mit port-Parameter), nuclei (mit tags)\n"
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
        guardrails=[_tool_call_guardrail, _scope_coverage_guardrail, _waf_detection_guardrail,
                    _tools_executed_guardrail],
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
            "SCHRITT C: nvd_cve_search als Fallback — NUR wenn nvd_cpe_lookup 'Kein CPE-Mapping' meldet "
            "UND eine konkrete Version bekannt ist:\n"
            "  - Mit Version: 'Apache Tomcat 8.5', 'jQuery 1.8.2'\n"
            "SCHRITT D: Wenn NVD/CPE Treffer liefert → DuckDuckGo '<CVE-ID> exploit PoC' zur Bestätigung.\n\n"
            "❌ KEINE GENERISCHEN CVEs OHNE VERSION (wichtig!):\n"
            "Wenn für einen Dienst KEINE konkrete Versionsnummer erkannt wurde (Banner nur 'Apache', "
            "'nginx', 'Server: Apache' ohne \\d.\\d), dann trage für diesen Dienst KEINE produkt-generischen "
            "CVEs in cve_references ein. Eine versionslose Liste 'alle Critical-CVEs für Apache' hat KEINEN "
            "praktischen Wert — sie ist reine Spekulation und Rauschen. Schreibe stattdessen in risk_summary: "
            "'<Produkt> erkannt, Version durch Server-Härtung nicht ermittelbar — keine versionsspezifische "
            "CVE-Analyse möglich. Empfehlung: interne Versionsprüfung.' "
            "AUSNAHME: Eine CVE die NACHWEISLICH aktiv ausgenutzt wird (CISA KEV / 'exploited in the wild' "
            "in der NVD-Beschreibung) darf als expliziter Hinweis eingetragen werden, MUSS aber im "
            "risk_summary als 'versions-unbestätigt, aber aktiv ausgenutzt' markiert sein.\n"
            "RELEVANZ-PRÜFUNG: Prüfe bei jedem Treffer ob Produktname passt. "
            "'Ingress-NGINX' ≠ 'nginx'. 'OpenSSH 7.x' ≠ 'OpenSSH 9.x'.\n"
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
        guardrails=[_cve_tool_used_guardrail, _cve_trace_guardrail],
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
        guardrails=[_tools_executed_guardrail],
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
        guardrails=[_cve_trace_guardrail, _searchsploit_version_guardrail],
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
        guardrails=[_confirmed_findings_tool_guardrail, _value_grounding_guardrail],
        guardrail_max_retries=2,
        description=(
            "Ziel: {target} | Objective: {objective} | Scope: {scope}\n\n"
            "Erstelle einen Recon-Report als Markdown. Der Report ist Rohdaten-Aufbereitung "
            "für einen PENTEST — er dient als Input für nachgelagerte Analyse + die EXPLOIT-"
            "ENTWICKLUNG. Bereite die Tool-Daten so auf dass ein Pentester direkt damit weiterarbeiten kann.\n\n"
            "EFFIZIENZ: Schreibe den Report IN EINEM DURCHGANG ohne Iteration. Keine Raw-Tool-Outputs "
            "1:1 kopieren — extrahierte Fakten. Aber NICHT auf Kosten der pentest-relevanten Details kürzen.\n\n"
            "DETAIL-PFLICHT (pentest-relevant — diese Details NIEMALS weglassen):\n"
            "  - EXAKTE Versionen inkl. Patch-Level/Distro (z.B. 'OpenSSH 9.6p1 Ubuntu 3ubuntu13.16', "
            "nicht nur 'OpenSSH 9.6') — versions-genaue CVE-Zuordnung hängt daran.\n"
            "  - ANGRIFFSVEKTOREN explizit markieren wenn ein Tool sie meldet (z.B. 'T3 enabled' bei "
            "WebLogic = T3-Deserialization-Vektor; 'PUT allowed'; 'mod_status exposed').\n"
            "  - EXPONIERTE Dienste/Ports MIT Service-Hypothese — auch unidentifizierte Ports nennen "
            "(z.B. '11434 — vermutlich Ollama API'; '8443 — Plesk Panel'), nicht kommentarlos listen.\n"
            "  - Interessante ENDPUNKTE/Pfade die Tools (nikto/httpx/nuclei) meldeten (Redirect-Ziele, "
            "Login-Panels, exponierte Verzeichnisse).\n"
            "FAKTEN-PFLICHT: Jede Aussage muss direkt aus einem Tool-Output ableitbar sein. "
            "Keine Härtungs-/Security-Empfehlungen (Pentest-Scope: Angriffsfläche, nicht Verteidigung). "
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
