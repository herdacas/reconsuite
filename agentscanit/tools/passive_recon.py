"""Passive recon / OSINT tools — assigned to research_agent."""

from typing import Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from config import (
    AMASS_BIN, ASSETFINDER_BIN, DIG_BIN, DNSRECON_BIN, DNSX_BIN,
    GAU_BIN, KATANA_BIN, SEARCHSPLOIT_BIN, SUBLIST3R_BIN, SUBFINDER_BIN,
    THEHARVESTER_DIR, WAYBACKURLS_BIN, WHOIS_BIN,
    TIMEOUT_DEFAULT, TIMEOUT_MEDIUM, TIMEOUT_SHORT,
)
# _run here is the module-level subprocess helper from _base (see _base.py docstring).
# Within each tool class, `_run(cmd)` calls this helper; BaseTool._run is the interface.
from tools._base import _run, _limit


# ---------------------------------------------------------------------------
# DuckDuckGo Search
# ---------------------------------------------------------------------------

class DdgSearchInput(BaseModel):
    query: str = Field(description="Suchanfrage")
    max_results: int = Field(default=5, description="Maximale Anzahl Ergebnisse (1-10)")


class DdgSearchTool(BaseTool):
    name: str = "ddg_web_search"
    description: str = (
        "Führt eine DuckDuckGo-Websuche durch. "
        "Ideal für OSINT, CVE-Recherche und Technologie-Informationen."
    )
    args_schema: Type[BaseModel] = DdgSearchInput

    def _run(self, query: str, max_results: int = 5) -> str:
        import time
        from tools.trace import run_trace
        t0 = time.time()
        try:
            try:
                from ddgs import DDGS
            except ImportError:
                from duckduckgo_search import DDGS
            results = []
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=max_results):
                    results.append(f"**{r['title']}**\n{r['href']}\n{r.get('body', '')[:300]}")
            out = "\n\n".join(results) if results else "Keine Suchergebnisse"
            run_trace.record_execution(["ddg_search", query], out, time.time() - t0)
            return out
        except Exception as e:
            out = f"Suche fehlgeschlagen: {e}"
            run_trace.record_execution(["ddg_search", query], out, time.time() - t0)
            return out


# ---------------------------------------------------------------------------
# theHarvester
# ---------------------------------------------------------------------------

class TheharvesterInput(BaseModel):
    domain: str = Field(description="Domain für OSINT-Suche (z.B. example.com)")
    sources: str = Field(default="crtsh", description=(
        "Datenquellen kommagetrennt: crtsh, google, bing, baidu, duckduckgo, ..."
    ))
    limit: int = Field(default=30, description="Maximale Anzahl Ergebnisse")


class TheharvesterTool(BaseTool):
    name: str = "theharvester_osint"
    description: str = (
        "Sammelt E-Mail-Adressen, Subdomains, Hosts und IPs aus öffentlichen Quellen "
        "mit theHarvester. Passives OSINT ohne direkten Kontakt zum Ziel."
    )
    args_schema: Type[BaseModel] = TheharvesterInput

    def _run(self, domain: str, sources: str = "crtsh", limit: int = 30) -> str:
        # Try direct binary first; fall back to running the script via python
        # (avoids dependency on `uv` which is not installed in all environments)
        import shutil
        if shutil.which("theHarvester"):
            cmd = ["theHarvester", "-d", domain, "-b", sources, "-l", str(limit)]
        else:
            cmd = ["python3", "theHarvester.py", "-d", domain, "-b", sources, "-l", str(limit)]
        out = _run(cmd, timeout=TIMEOUT_MEDIUM, cwd=THEHARVESTER_DIR)
        if "Hosts found:" in out:
            section = out.split("Hosts found:")[1]
            # Strip trailing sections; try multiple separators for version robustness
            for sep in ("-----", "\n\n", "\n["):
                if sep in section:
                    section = section.split(sep)[0]
                    break
            return _limit(section.strip(), "theharvester")
        return _limit(out, "theharvester")


# ---------------------------------------------------------------------------
# sublist3r
# ---------------------------------------------------------------------------

class Sublist3rInput(BaseModel):
    domain: str = Field(description="Domain für Subdomain-Enumeration")
    threads: int = Field(default=10, description="Anzahl Threads")


class Sublist3rTool(BaseTool):
    name: str = "sublist3r_subdomains"
    description: str = (
        "Findet Subdomains passiv via Suchmaschinen und öffentliche DNS-Datenbanken "
        "mit Sublist3r."
    )
    args_schema: Type[BaseModel] = Sublist3rInput

    def _run(self, domain: str, threads: int = 10) -> str:
        cmd = [SUBLIST3R_BIN, "-d", domain, "-t", str(threads)]
        return _limit(_run(cmd, timeout=TIMEOUT_MEDIUM), "sublist3r")


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

class SubfinderInput(BaseModel):
    domain: str = Field(description="Domain für Subdomain-Enumeration")


class SubfinderTool(BaseTool):
    name: str = "subfinder_passive"
    description: str = (
        "Schnelle passive Subdomain-Enumeration mit subfinder "
        "(nutzt Certificate Transparency, DNS-Datenbanken)."
    )
    args_schema: Type[BaseModel] = SubfinderInput

    def _run(self, domain: str) -> str:
        cmd = [SUBFINDER_BIN, "-d", domain, "-silent"]
        return _limit(_run(cmd, timeout=TIMEOUT_MEDIUM), "subfinder")


# ---------------------------------------------------------------------------
# dnsrecon
# ---------------------------------------------------------------------------

class DnsreconInput(BaseModel):
    domain: str = Field(description="Domain für DNS-Enumeration")
    scan_type: str = Field(default="std", description=(
        "Scan-Typ: 'std' (Standard), 'axfr' (Zone Transfer), "
        "'brute' (Brute-Force), 'bing' (Bing-Suche)"
    ))


class DnsreconTool(BaseTool):
    name: str = "dnsrecon_enum"
    description: str = (
        "DNS-Enumeration mit dnsrecon: findet A/MX/NS/TXT-Records, "
        "prüft Zone-Transfers und enumeriert Subdomains."
    )
    args_schema: Type[BaseModel] = DnsreconInput

    def _run(self, domain: str, scan_type: str = "std") -> str:
        cmd = [DNSRECON_BIN, "-d", domain, "-t", scan_type]
        return _limit(_run(cmd, timeout=TIMEOUT_MEDIUM), "dnsrecon")


# ---------------------------------------------------------------------------
# dig
# ---------------------------------------------------------------------------

class DigInput(BaseModel):
    domain: str = Field(description="Domain oder IP für DNS-Abfrage")
    record_type: str = Field(default="ANY", description=(
        "DNS-Record-Typ: ANY, A, AAAA, MX, NS, TXT, SOA, CNAME, PTR"
    ))


class DigTool(BaseTool):
    name: str = "dig_dns_lookup"
    description: str = "Führt DNS-Abfragen durch und gibt die gewünschten Record-Typen zurück."
    args_schema: Type[BaseModel] = DigInput

    def _run(self, domain: str, record_type: str = "ANY") -> str:
        cmd = [DIG_BIN, domain, record_type, "+short"]
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "default")


# ---------------------------------------------------------------------------
# whois
# ---------------------------------------------------------------------------

class WhoisInput(BaseModel):
    domain: str = Field(description="Domain oder IP-Adresse für WHOIS-Abfrage")


class WhoisTool(BaseTool):
    name: str = "whois_lookup"
    description: str = (
        "WHOIS-Abfrage für Domain oder IP: liefert Registrar, Inhaber, "
        "Nameserver, Registrierungs- und Ablaufdaten."
    )
    args_schema: Type[BaseModel] = WhoisInput

    def _run(self, domain: str) -> str:
        cmd = [WHOIS_BIN, domain]
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "whois")


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------

class AmassInput(BaseModel):
    domain: str = Field(description="Domain für passive Subdomain-Enumeration")


class AmassTool(BaseTool):
    name: str = "amass_enum"
    description: str = (
        "Passive Subdomain-Enumeration mit Amass. Nutzt Certificate Transparency, "
        "DNS-Datenbanken und viele weitere passive Quellen."
    )
    args_schema: Type[BaseModel] = AmassInput

    def _run(self, domain: str) -> str:
        cmd = [AMASS_BIN, "enum", "-passive", "-d", domain]
        return _limit(_run(cmd, timeout=TIMEOUT_DEFAULT), "amass")


# ---------------------------------------------------------------------------
# assetfinder
# ---------------------------------------------------------------------------

class AssetfinderInput(BaseModel):
    domain: str = Field(description="Domain für Subdomain-Suche")
    subs_only: bool = Field(default=True, description="Nur Subdomains zurückgeben")


class AssetfinderTool(BaseTool):
    name: str = "assetfinder_subdomains"
    description: str = (
        "Findet Subdomains und verwandte Assets mit assetfinder "
        "(nutzt crt.sh, Facebook Certificate Transparency u.a.)."
    )
    args_schema: Type[BaseModel] = AssetfinderInput

    def _run(self, domain: str, subs_only: bool = True) -> str:
        cmd = [ASSETFINDER_BIN]
        if subs_only:
            cmd.append("--subs-only")
        cmd.append(domain)
        return _limit(_run(cmd, timeout=TIMEOUT_MEDIUM), "assetfinder")


# ---------------------------------------------------------------------------
# dnsx
# ---------------------------------------------------------------------------

class DnsxInput(BaseModel):
    domains: str = Field(description="Kommagetrennte Domains oder Subdomains zum Auflösen")
    record_types: str = Field(default="a,cname,mx", description=(
        "DNS-Record-Typen kommagetrennt: a, aaaa, cname, mx, ns, txt, ptr"
    ))


class DnsxTool(BaseTool):
    name: str = "dnsx_resolver"
    description: str = (
        "Löst DNS-Records für viele Hosts gleichzeitig auf (dnsx). "
        "Ideal zum schnellen Validieren von Subdomain-Listen."
    )
    args_schema: Type[BaseModel] = DnsxInput

    def _run(self, domains: str, record_types: str = "a,cname,mx") -> str:
        domain_list = "\n".join(d.strip() for d in domains.split(",") if d.strip())
        cmd = [DNSX_BIN, "-silent", "-resp"]
        for rt in record_types.split(","):
            cmd += [f"-{rt.strip()}"]
        return _limit(_run(cmd, timeout=TIMEOUT_MEDIUM, stdin=domain_list), "default")


# ---------------------------------------------------------------------------
# katana
# ---------------------------------------------------------------------------

class KatanaInput(BaseModel):
    url: str = Field(description="Start-URL für den Crawler")
    depth: int = Field(default=2, description="Maximale Crawl-Tiefe")
    js_crawl: bool = Field(default=False, description="JavaScript-Rendering aktivieren")


class KatanaTool(BaseTool):
    name: str = "katana_crawler"
    description: str = (
        "Crawlt eine Webseite mit Katana und findet URLs, Endpunkte, "
        "Formulare und JavaScript-Links."
    )
    args_schema: Type[BaseModel] = KatanaInput

    def _run(self, url: str, depth: int = 2, js_crawl: bool = False) -> str:
        cmd = [KATANA_BIN, "-u", url, "-d", str(depth), "-silent"]
        if js_crawl:
            cmd.append("-js-crawl")
        return _limit(_run(cmd, timeout=TIMEOUT_DEFAULT), "default")


# ---------------------------------------------------------------------------
# waybackurls
# ---------------------------------------------------------------------------

class WaybackurlsInput(BaseModel):
    domain: str = Field(description="Domain für Wayback Machine URL-Suche")


class WaybackurlsTool(BaseTool):
    name: str = "waybackurls_archive"
    description: str = (
        "Ruft archivierte URLs für eine Domain aus der Wayback Machine ab. "
        "Findet alte Endpunkte, Parameter und Pfade."
    )
    args_schema: Type[BaseModel] = WaybackurlsInput

    def _run(self, domain: str) -> str:
        result = _run([WAYBACKURLS_BIN, domain], timeout=TIMEOUT_MEDIUM)
        lines = result.splitlines()[:200]
        return _limit("\n".join(lines), "default")


# ---------------------------------------------------------------------------
# gau
# ---------------------------------------------------------------------------

class GauInput(BaseModel):
    domain: str = Field(description="Domain für URL-Sammlung aus Web-Archiven")
    providers: str = Field(default="wayback,otx,commoncrawl", description=(
        "Quellen kommagetrennt: wayback, otx, commoncrawl, urlscan"
    ))


class GauTool(BaseTool):
    name: str = "gau_url_collector"
    description: str = (
        "Sammelt historische URLs aus Wayback Machine, OTX, Common Crawl "
        "und urlscan.io mit gau (Get All URLs)."
    )
    args_schema: Type[BaseModel] = GauInput

    def _run(self, domain: str, providers: str = "wayback,otx,commoncrawl") -> str:
        cmd = [GAU_BIN, "--providers", providers, domain]
        result = _run(cmd, timeout=TIMEOUT_MEDIUM)
        lines = result.splitlines()[:200]
        return _limit("\n".join(lines), "default")


# ---------------------------------------------------------------------------
# searchsploit
# ---------------------------------------------------------------------------

class SearchsploitInput(BaseModel):
    query: str = Field(description=(
        "Suchbegriff für Exploit-Suche, z.B. 'Apache 2.4.49' oder 'OpenSSH 7.4'"
    ))
    json_output: bool = Field(default=False, description="JSON-Ausgabe aktivieren")


class SearchsploitTool(BaseTool):
    name: str = "searchsploit_exploits"
    description: str = (
        "Sucht in der Exploit-DB nach bekannten Exploits für Software und Versionen. "
        "Gibt Exploit-Titel, Typ und Pfad zur PoC-Datei zurück."
    )
    args_schema: Type[BaseModel] = SearchsploitInput

    def _run(self, query: str, json_output: bool = False) -> str:
        cmd = [SEARCHSPLOIT_BIN]
        if json_output:
            cmd.append("--json")
        cmd += query.split()
        return _limit(_run(cmd, timeout=TIMEOUT_SHORT), "default")


# ---------------------------------------------------------------------------
# Tool instances
# ---------------------------------------------------------------------------

ddg_search_tool    = DdgSearchTool()
theharvester_tool  = TheharvesterTool()
sublist3r_tool     = Sublist3rTool()
subfinder_tool     = SubfinderTool()
dnsrecon_tool      = DnsreconTool()
dig_tool           = DigTool()
whois_tool         = WhoisTool()
amass_tool         = AmassTool()
assetfinder_tool   = AssetfinderTool()
dnsx_tool          = DnsxTool()
katana_tool        = KatanaTool()
waybackurls_tool   = WaybackurlsTool()
gau_tool           = GauTool()
searchsploit_tool  = SearchsploitTool()
