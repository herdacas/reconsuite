"""Active scanning tools — assigned to blue_agent."""

import re
from typing import Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config import (
    CURL_BIN, ENUM4LINUX_BIN, ENUM4LINUX_DIR, FFUF_BIN, HTTPX_BIN,
    NAABU_BIN, NIKTO_BIN, NMAP_BIN, NUCLEI_BIN, PING_BIN, SSLSCAN_BIN,
    TESTSSL_BIN, TESTSSL_DIR, VENV_PYTHON, WAFW00F_BIN, WHATWEB_BIN, WORDLIST_DEFAULT,
    TIMEOUT_DEFAULT, TIMEOUT_MEDIUM, TIMEOUT_NIKTO, TIMEOUT_NMAP_DISC,
    TIMEOUT_NMAP_SCAN, TIMEOUT_NUCLEI, TIMEOUT_SHORT, TIMEOUT_TESTSSL,
)
# _run here is the module-level subprocess helper from _base (see _base.py docstring).
# Within each tool class, `_run(cmd)` calls this helper; BaseTool._run is the interface.
from tools._base import _run, _limit


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

class NmapInput(BaseModel):
    target: str = Field(description="IP-Adresse oder Hostname des Ziels")
    ports: str = Field(default="top1000", description=(
        "Portbereich: 'top1000', '80,443', '1-65535', '1-1024', usw."
    ))
    aggressive: bool = Field(default=False, description=(
        "Aktiviert -sV (Service/Version-Detection). Nur bei ports='1-65535' "
        "sinnvoll — für top-1000 reicht der Standard-Scan."
    ))


class NmapTool(BaseTool):
    name: str = "nmap_scanner"
    description: str = (
        "Führt einen Nmap-Port-Scan durch. "
        "Für vollständige Host-Analyse: aggressive=True, ports='1-65535'. "
        "Gibt offene Ports, Services und Versionsinformationen zurück."
    )
    args_schema: Type[BaseModel] = NmapInput

    def _run(self, target: str, ports: str = "top1000", aggressive: bool = False) -> str:
        # BUG (2026-09-15, gmx.de-Live-Fund): nur der exakte String "top1000" wurde
        # als Preset erkannt — jeder andere plausibel aussehende Wert (z.B. "top100",
        # "top-100", vom Agenten vermutlich mit NaabuTools "top-100"-Default
        # verwechselt) fiel ungeprüft in den -p-Zweig durch. nmap kennt "top100"
        # nicht als Portname/-preset und bricht mit "QUITTING!" ab, OHNE einen
        # einzigen Port zu scannen — der Fehler blieb bisher unsichtbar (siehe
        # zweiter Fix in _base.py._run) und wurde im Report fälschlich als
        # "gescannt, keine offenen Ports (CDN/LB-Filterung)" dargestellt.
        # Fix: jedes "top<N>"/"top-<N>" (case-insensitive, optionaler Bindestrich)
        # wird jetzt als --top-ports N erkannt, nicht nur "top1000" exakt.
        _top_n = re.match(r"^top-?(\d+)$", (ports or "").strip(), re.IGNORECASE)
        if ports in ("top1000", "") or _top_n:
            port_arg = "--top-ports"
            port_val = _top_n.group(1) if _top_n else "1000"
        else:
            port_arg = "-p"
            port_val = ports

        if aggressive and ports in ("1-65535", "0-65535", "all"):
            # -Pn: skip host-discovery ping — many hosts block ICMP/SYN-ACK probes
            # and appear as "down" without it, causing nmap to skip all port scanning.
            disc_cmd = [NMAP_BIN, "-T4", "-Pn", "-p", ports, "--open", "-n",
                        "--host-timeout", "300s", target]
            disc_out = _run(disc_cmd, timeout=TIMEOUT_NMAP_DISC)
            open_ports = [
                m.group(1)
                for line in disc_out.splitlines()
                if (m := re.match(r"(\d+)/tcp\s+open", line))
            ]
            if not open_ports:
                return _limit(disc_out or "Keine offenen Ports gefunden", "nmap")
            port_list = ",".join(open_ports[:50])
            cmd = [NMAP_BIN, "-T4", "-Pn", "-sV", "--host-timeout", "540s",
                   "-p", port_list, "--open", target]
            return _limit(_run(cmd, timeout=TIMEOUT_NMAP_SCAN), "nmap")

        cmd = [NMAP_BIN, "-T4", "-Pn"]
        if port_arg == "--top-ports":
            cmd += ["--top-ports", port_val]
        else:
            cmd += ["-p", port_val]
        cmd += ["--open"]
        if aggressive:
            cmd += ["-sV", "--host-timeout", "540s"]
        cmd.append(target)
        return _limit(_run(cmd, timeout=TIMEOUT_NMAP_SCAN), "nmap")


# ---------------------------------------------------------------------------
# nikto
# ---------------------------------------------------------------------------

class NiktoInput(BaseModel):
    target: str = Field(description="URL oder Hostname (z.B. https://example.com oder example.com)")
    port: Optional[int] = Field(default=None, description=(
        "Port-Nummer wenn nicht Standard (80/443). "
        "Nutze den aus nmap gefundenen Web-Port, z.B. 8080 oder 8443."
    ))
    tuning: Optional[str] = Field(default=None, description=(
        "Nikto Tuning-Flags: '1'=Interessante Dateien, '2'=Fehlkonfigurationen, "
        "'3'=Info-Disclosure, '4'=Injection, '5'=Remote File Retrieval, "
        "'6'=DoS (skip), '7'=Remote Source Inclusion, '8'=Command Execution, "
        "'9'=SQL Injection. Mehrere kombinieren: '1234'. Leer = alle."
    ))


class NiktoTool(BaseTool):
    name: str = "nikto_scanner"
    description: str = (
        "Scannt einen Webserver mit Nikto auf bekannte Schwachstellen, "
        "fehlende Security-Header, veraltete Software und Fehlkonfigurationen. "
        "Nutze 'port' wenn nmap einen non-standard Web-Port gefunden hat. "
        "Nutze 'tuning' um den Scan auf relevante Kategorien einzugrenzen."
    )
    args_schema: Type[BaseModel] = NiktoInput

    def _run(self, target: str, port: Optional[int] = None,
             tuning: Optional[str] = None) -> str:
        cmd = [NIKTO_BIN, "-h", target, "-nointeractive", "-maxtime", "90s", "-timeout", "5"]
        if port:
            cmd += ["-p", str(port)]
        if tuning:
            cmd += ["-Tuning", tuning]
        return _limit(_run(cmd, timeout=TIMEOUT_NIKTO), "nikto")


# ---------------------------------------------------------------------------
# whatweb
# ---------------------------------------------------------------------------

class WhatwebInput(BaseModel):
    target: str = Field(description="URL oder Hostname")


class WhatwebTool(BaseTool):
    name: str = "whatweb_fingerprint"
    description: str = (
        "Erkennt Web-Technologien (CMS, Frameworks, Server-Software, Plugins) "
        "anhand von HTTP-Headern, Cookies und HTML-Inhalt."
    )
    args_schema: Type[BaseModel] = WhatwebInput

    def _run(self, target: str) -> str:
        cmd = [WHATWEB_BIN, target, "--no-errors"]
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "whatweb")


# ---------------------------------------------------------------------------
# wafw00f — WAF/CDN-Erkennung
# ---------------------------------------------------------------------------

class Wafw00fInput(BaseModel):
    target: str = Field(description="URL oder Hostname des Web-Ziels, z.B. 'example.com' oder 'https://example.com'")


class Wafw00fTool(BaseTool):
    name: str = "wafw00f_detect"
    description: str = (
        "Erkennt eine vorgeschaltete Web Application Firewall (WAF) oder einen CDN/Reverse-Proxy "
        "(Cloudflare, Akamai, AWS WAF, ModSecurity u.a.) vor dem Ziel. "
        "WICHTIG für die Bewertung: Wird eine WAF erkannt, sind Server-Banner und CVE-Treffer "
        "potenziell die der WAF/des CDN — NICHT des dahinterliegenden Origin-Servers. Ein leeres "
        "CVE-Ergebnis hinter einer WAF bedeutet NICHT zwingend, dass das Ziel sicher ist."
    )
    args_schema: Type[BaseModel] = Wafw00fInput

    def _run(self, target: str) -> str:
        import shutil
        bin_path = shutil.which(WAFW00F_BIN)
        if not bin_path:
            return "[wafw00f] nicht installiert — Tool nicht verfügbar."
        # -a: alle Treffer melden (nicht beim ersten stoppen); -o -: maschinenlesbar auf stdout
        cmd = [bin_path, "-a", target]
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "wafw00f")


# ---------------------------------------------------------------------------
# sslscan
# ---------------------------------------------------------------------------

class SslscanInput(BaseModel):
    host: str = Field(description=(
        "FQDN des TLS-Endpunkts — der Hostname auf dem das TLS-Zertifikat liegt. "
        "Wenn whatweb/nmap einen Redirect auf 'www.target.de' zeigen, dann 'www.target.de' "
        "übergeben, NICHT 'target.de'. Ohne https://, optional mit Port: 'host:8443'."
    ))


class SslscanTool(BaseTool):
    name: str = "sslscan_tls"
    description: str = (
        "Prüft SSL/TLS-Konfiguration: Protokollversionen, Cipher-Suites, "
        "Zertifikatsdetails, Heartbleed, POODLE usw. "
        "WICHTIG: 'host' muss der FQDN des HTTPS-Endpunkts sein (z.B. 'www.example.de'), "
        "nicht die Basis-Domain die per HTTP-Redirect weiterleitet."
    )
    args_schema: Type[BaseModel] = SslscanInput

    def _run(self, host: str) -> str:
        cmd = [SSLSCAN_BIN, host, "--no-failed"]
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "sslscan")


# ---------------------------------------------------------------------------
# testssl.sh
# ---------------------------------------------------------------------------

class TestsslInput(BaseModel):
    host: str = Field(description="Hostname oder IP (ohne https://)")


class TestsslTool(BaseTool):
    name: str = "testssl_full"
    description: str = (
        "Führt einen vollständigen SSL/TLS-Test durch (testssl.sh). "
        "Prüft alle Protokolle, Cipher-Suites, Zertifikate und bekannte TLS-Angriffe."
    )
    args_schema: Type[BaseModel] = TestsslInput

    def _run(self, host: str) -> str:
        cmd = [TESTSSL_BIN, "--quiet", host]
        return _limit(_run(cmd, timeout=TIMEOUT_TESTSSL, cwd=TESTSSL_DIR), "testssl")


# ---------------------------------------------------------------------------
# curl (HTTP-Header)
# ---------------------------------------------------------------------------

class CurlInput(BaseModel):
    url: str = Field(description="Vollständige URL (z.B. https://example.com)")
    follow_redirects: bool = Field(default=True, description="HTTP-Weiterleitungen folgen")


class CurlTool(BaseTool):
    name: str = "curl_http_headers"
    description: str = (
        "Ruft HTTP-Response-Header ab. Nützlich um Security-Header "
        "(CSP, HSTS, X-Frame-Options), Server-Banner und Cookies zu prüfen."
    )
    args_schema: Type[BaseModel] = CurlInput

    def _run(self, url: str, follow_redirects: bool = True) -> str:
        cmd = [CURL_BIN, "-s", "-I", "--max-time", "15"]
        if follow_redirects:
            cmd.append("-L")
        cmd.append(url)
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "default")


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------

class PingInput(BaseModel):
    host: str = Field(description="Hostname oder IP-Adresse")
    count: int = Field(default=3, description="Anzahl der ICMP-Pakete")


class PingTool(BaseTool):
    name: str = "ping_check"
    description: str = "Prüft ob ein Host per ICMP erreichbar ist und misst die Latenz."
    args_schema: Type[BaseModel] = PingInput

    def _run(self, host: str, count: int = 3) -> str:
        cmd = [PING_BIN, "-c", str(count), "-W", "2", host]
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "default")


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------

class NucleiInput(BaseModel):
    target: str = Field(description="URL oder Hostname des Ziels")
    templates: Optional[str] = Field(default=None, description=(
        "Template-Kategorie oder -Pfad, z.B. 'cves', 'exposures', 'misconfigurations', "
        "'technologies', 'network'. Leer = Nuclei-Standard-Templates."
    ))
    severity: Optional[str] = Field(default=None, description=(
        "Nur Templates dieser Severity ausführen: 'critical', 'high', 'medium', 'low', 'info'. "
        "Mehrere kommagetrennt: 'critical,high'. "
        "Nutze 'critical,high' wenn CVEs aus findings_task bekannt sind."
    ))
    tags: Optional[str] = Field(default=None, description=(
        "Template-Tags filtern, kommagetrennt. Beispiele: 'apache', 'wordpress', 'ssl', "
        "'rce', 'sqli'. Nutze erkannte Technologien aus whatweb/httpx als Tags. "
        "Für API-Service-Erkennung (nur bei API-Objective): 'exposures,graphql,swagger' "
        "— findet exponierte Swagger-/OpenAPI-Doku, GraphQL-Introspection, Spring-Actuator. "
        "Für Fehlkonfigurations-Checks (nur bei Misconfig/CORS-Objective): "
        "'misconfiguration,cors,redirect' — findet CORS-Fehlkonfiguration, Open Redirects "
        "und sonstige Misconfigurations."
    ))


class NucleiTool(BaseTool):
    name: str = "nuclei_vulnerability_scanner"
    description: str = (
        "Scannt ein Ziel mit Nuclei auf bekannte CVEs, Fehlkonfigurationen "
        "und Schwachstellen anhand von Community-Templates. "
        "Nutze 'severity' um kritische Findings zu priorisieren. "
        "Nutze 'tags' mit erkannten Technologien (z.B. 'apache', 'wordpress') "
        "für gezieltes Scanning. "
        "Nutze 'templates=cves' wenn konkrete CVE-IDs aus dem Findings-Task vorliegen."
    )
    args_schema: Type[BaseModel] = NucleiInput

    def _run(self, target: str, templates: Optional[str] = None,
             severity: Optional[str] = None, tags: Optional[str] = None) -> str:
        cmd = [NUCLEI_BIN, "-u", target, "-silent", "-no-color", "-timeout", "10", "-max-host-error", "3"]
        if templates:
            cmd += ["-t", templates]
        if severity:
            cmd += ["-severity", severity]
        if tags:
            cmd += ["-tags", tags]
        # Without tags/templates nuclei scans all ~10k templates — add a broad cap
        if not templates and not tags:
            cmd += ["-severity", severity or "critical,high"]
        return _limit(_run(cmd, timeout=TIMEOUT_NUCLEI), "nuclei")


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------

class FfufInput(BaseModel):
    url: str = Field(description=(
        "URL mit FUZZ-Platzhalter, z.B. https://example.com/FUZZ "
        "oder https://FUZZ.example.com/"
    ))
    wordlist: str = Field(default=WORDLIST_DEFAULT, description="Pfad zur Wordlist")
    extensions: str = Field(default="", description="Dateiendungen, z.B. 'php,html,js'")
    filter_code: str = Field(default="404", description="HTTP-Statuscodes filtern (kommagetrennt)")


class FfufTool(BaseTool):
    name: str = "ffuf_fuzzer"
    description: str = (
        "Führt Directory-, File- oder VHost-Fuzzing mit ffuf durch. "
        "Findet versteckte Pfade, Admin-Bereiche und Backup-Dateien."
    )
    args_schema: Type[BaseModel] = FfufInput

    def _run(self, url: str, wordlist: str = WORDLIST_DEFAULT,
             extensions: str = "", filter_code: str = "404") -> str:
        cmd = [FFUF_BIN, "-u", url, "-w", wordlist, "-mc", "all",
               "-fc", filter_code, "-s"]
        if extensions:
            cmd += ["-e", extensions]
        return _limit(_run(cmd, timeout=TIMEOUT_DEFAULT), "ffuf")


# ---------------------------------------------------------------------------
# enum4linux-ng
# ---------------------------------------------------------------------------

class Enum4linuxInput(BaseModel):
    target: str = Field(description="IP-Adresse oder Hostname des SMB/Windows-Hosts")
    full: bool = Field(default=False, description="Vollständige Enumeration (-A)")


class Enum4linuxTool(BaseTool):
    name: str = "enum4linux_smb"
    description: str = (
        "Enumeriert SMB/NetBIOS-Informationen (Shares, User, Gruppen, Policies) "
        "von Windows- und Samba-Hosts mit enum4linux-ng."
    )
    args_schema: Type[BaseModel] = Enum4linuxInput

    def _run(self, target: str, full: bool = False) -> str:
        cmd = [VENV_PYTHON, ENUM4LINUX_BIN]
        if full:
            cmd += ["-A"]
        cmd.append(target)
        return _limit(_run(cmd, timeout=TIMEOUT_DEFAULT, cwd=ENUM4LINUX_DIR), "enum4linux")


# ---------------------------------------------------------------------------
# httpx
# ---------------------------------------------------------------------------

class HttpxInput(BaseModel):
    targets: str = Field(description=(
        "Einzelnes Ziel oder kommagetrennte Liste von Hosts/URLs. "
        "Beispiel: 'example.com' oder 'example.com,sub.example.com'"
    ))
    options: str = Field(default="-title -status-code -tech-detect", description=(
        "Zusätzliche httpx-Flags als String"
    ))
    api_probe: bool = Field(default=False, description=(
        "Wenn True: probt bekannte API-Pfade (/api, /graphql, /swagger.json, /openapi.json u.a.) "
        "und meldet Status-Code + Content-Type je Pfad. Dient der ERKENNUNG eines API-Service "
        "(existiert eine API, welcher Typ, Doku exponiert?), NICHT der Endpunkt-Enumeration. "
        "Nur nutzen wenn das Objective API/REST/GraphQL/Swagger erwähnt."
    ))


# Bekannte API-/Doku-Pfade für api_probe — feste, kuratierte Liste (kein Fuzzing,
# kein Wordlist-Bruteforce): nur die kanonischen Pfade die einen API-Service verraten.
_API_PROBE_PATHS = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
    "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/v2/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/api-docs",
    "/actuator", "/actuator/health", "/.well-known/openapi.json",
]


class HttpxTool(BaseTool):
    name: str = "httpx_prober"
    description: str = (
        "Probt HTTP/HTTPS-Endpunkte: prüft Erreichbarkeit, ermittelt Titel, "
        "Status-Codes und Technologien. Ideal für schnelles Screening vieler Hosts. "
        "PFLICHT: 'targets' muss immer angegeben werden (z.B. 'example.com' oder "
        "'example.com,sub.example.com'). Ohne 'targets' liefert das Tool leeren Output. "
        "Setze 'api_probe=true' um bekannte API-Pfade auf einen API-Service zu prüfen "
        "(nur bei API-bezogenem Objective)."
    )
    args_schema: Type[BaseModel] = HttpxInput

    def _run(self, targets: str, options: str = "-title -status-code -tech-detect",
             api_probe: bool = False) -> str:
        hosts = [t.strip() for t in targets.split(",") if t.strip()]
        if api_probe:
            # Kreuzprodukt host × API-Pfad; httpx meldet Status + Content-Type je URL.
            urls = [h.rstrip("/") + p for h in hosts for p in _API_PROBE_PATHS]
            target_list = "\n".join(urls)
            # -mc 200,401,403: nur "existiert" (auch auth-geschützt) zählt; -ct: Content-Type.
            base_cmd = [HTTPX_BIN, "-silent", "-no-color", "-status-code", "-content-type",
                        "-mc", "200,201,401,403"]
            return _limit(_run(base_cmd, timeout=TIMEOUT_MEDIUM, stdin=target_list), "httpx")
        target_list = "\n".join(hosts)
        base_cmd = [HTTPX_BIN, "-silent"] + options.split()
        return _limit(_run(base_cmd, timeout=TIMEOUT_MEDIUM, stdin=target_list), "httpx")


# ---------------------------------------------------------------------------
# naabu
# ---------------------------------------------------------------------------

class NaabuInput(BaseModel):
    target: str = Field(description="Hostname oder IP-Adresse")
    ports: str = Field(default="top-100", description=(
        "'top-100', 'top-1000', oder Portbereich z.B. '1-1024'"
    ))


class NaabuTool(BaseTool):
    name: str = "naabu_port_scanner"
    description: str = (
        "Schneller Port-Scanner (naabu). Findet offene TCP-Ports, "
        "deutlich schneller als nmap für reine Port-Discovery."
    )
    args_schema: Type[BaseModel] = NaabuInput

    def _run(self, target: str, ports: str = "top-100") -> str:
        cmd = [NAABU_BIN, "-host", target, "-silent"]
        if ports.startswith("top-"):
            cmd += ["-top-ports", ports[4:]]
        else:
            cmd += ["-p", ports]
        return _limit(_run(cmd, timeout=TIMEOUT_DEFAULT), "default")


# ---------------------------------------------------------------------------
# Tool instances
# ---------------------------------------------------------------------------

nmap_tool       = NmapTool()
nikto_tool      = NiktoTool()
whatweb_tool    = WhatwebTool()
wafw00f_tool    = Wafw00fTool()
sslscan_tool    = SslscanTool()
testssl_tool    = TestsslTool()
curl_tool       = CurlTool()
ping_tool       = PingTool()
nuclei_tool     = NucleiTool()
ffuf_tool       = FfufTool()
enum4linux_tool = Enum4linuxTool()
httpx_tool      = HttpxTool()
naabu_tool      = NaabuTool()
