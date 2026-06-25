"""
reporting/flow.py — Team 3: Assessment Reporting

Führt Scan-Report (agentscanit) und NVD-Daten (interpret-agent)
zu einem einzigen final_report_*.md zusammen.

Kein LLM — reine Datenzusammenführung.
"""

import os
import re
from datetime import datetime

from pydantic import BaseModel, Field
from crewai.flow.flow import Flow, start, listen
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

_TEAM_DIR  = os.path.dirname(os.path.abspath(__file__))
_SUITE_DIR = os.path.dirname(_TEAM_DIR)
LOG_DIR    = os.path.join(_SUITE_DIR, "logs")

console = Console()

_SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def _cve_product_keywords(cve: dict) -> set[str]:
    """Produkt-Keywords einer CVE aus den affected_cpe-Einträgen extrahieren.

    cpe:2.3:a:openbsd:openssh:* → {'openssh'}, apache:tomcat → {'tomcat'}.
    Genutzt um zu prüfen ob der Scan für dieses Produkt eine Version erkannt hat.
    """
    # Produkt-Aliasse: NVD-CPE-Produktname → Banner-Schreibweise(n) des Scanners.
    # NVD nennt es "http_server", nmap-Banner sagt "httpd"/"apache httpd".
    _ALIAS = {
        "http server": ["httpd"],
        "weblogic server": ["weblogic"],
    }
    # Generische Tokens die als alleiniges Keyword zu breit matchen würden
    _too_generic = {"server", "http", "https", "service", "manager", "core", "web",
                    "linux", "enterprise", "framework"}
    kws: set[str] = set()
    for cpe in cve.get("affected_cpe", []) or []:
        parts = cpe.split(":")
        # cpe:2.3:<part>:<vendor>:<product>:<version>:...
        if len(parts) >= 5:
            product = parts[4].replace("_", " ").strip().lower()
            if not product or product == "*":
                continue
            kws.add(product)                           # volles Produkt, z.B. "weblogic server"
            kws.update(_ALIAS.get(product, []))        # Banner-Aliasse, z.B. "httpd"
            last = product.split()[-1]
            if last not in _too_generic:               # last-token nur wenn spezifisch
                kws.add(last)                          # z.B. "tomcat", "openssh"
    return kws


def _format_cve_entries(cves: list[dict]) -> list[str]:
    """Markdown-Zeilen für eine Liste NVD-CVE-Dicts (Detail-Darstellung)."""
    lines: list[str] = []
    for cve in cves:
        sev   = (cve.get("cvss_severity") or "N/A").upper()
        score = cve.get("cvss_score")
        icon  = _SEVERITY_ICON.get(sev, "⚪")
        lines += [
            f"### {icon} {cve['id']} — CVSS {score} ({sev})",
            f"- **Published:** {cve.get('published', 'N/A')}  "
            f"**Last Modified:** {cve.get('last_modified', 'N/A')}",
            f"- **Vector:** `{cve.get('cvss_vector') or 'N/A'}`",
            "",
            f"**Description:** {cve.get('description', '')}",
            "",
        ]
        if cve.get("affected_cpe"):
            lines.append("**Affected Products (CPE):**")
            lines += [f"- `{cpe}`" for cpe in cve["affected_cpe"][:5]]
            lines.append("")
        if cve.get("references"):
            lines.append("**References:**")
            lines += [f"- {ref}" for ref in cve["references"]]
            lines.append("")
    return lines


def _version_confirmed_in_scan(cve: dict, scan_body: str) -> bool:
    """True wenn der Scan für das CVE-Produkt eine konkrete Version erkannt hat.

    Banner-Versions-Gate (BUG-17): Eine CVE ist nur dann versions-verifizierbar wenn
    im Scan-Body das Produkt-Keyword von einer Versionsnummer (\\d+\\.\\d+) gefolgt
    wird (z.B. "OpenSSH 6.6.1p1"). Bei versionslosem Banner ("Apache Tomcat version
    unknown") bleibt der Versions-Match unbestätigt → potenzielles False-Positive.
    """
    if not scan_body:
        return False
    body = scan_body.lower()
    for kw in _cve_product_keywords(cve):
        if len(kw) < 3:
            continue
        # Produkt-Keyword gefolgt (innerhalb ~20 Zeichen) von einer Versionsnummer
        pattern = re.escape(kw) + r"[^\n]{0,20}?\d+\.\d+"
        if re.search(pattern, body):
            return True
    return False


# ─── State ────────────────────────────────────────────────────────────────────

class ReportingState(BaseModel):
    scan_target:      str        = ""
    scan_report_path: str        = ""   # recon_report_*.md
    nvd_results:      list[dict] = Field(default_factory=list)
    final_report_path: str       = ""


# ─── Flow ─────────────────────────────────────────────────────────────────────

class ReportingFlow(Flow[ReportingState]):
    """Merge scan + NVD data → final_report_*.md. Kein LLM."""

    @start()
    def merge(self):
        target   = self.state.scan_target
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M")
        safe     = re.sub(r"[^\w.-]", "_", target)

        # ── Scan-Report laden ─────────────────────────────────────────────────
        scan_body = ""
        if self.state.scan_report_path and os.path.exists(self.state.scan_report_path):
            with open(self.state.scan_report_path, encoding="utf-8") as f:
                raw = f.read()
            match = re.search(r'^(#.+)', raw, re.MULTILINE)
            if match:
                raw = raw[match.start():]
            raw = re.split(r'\n## CVE References', raw)[0].rstrip()
            scan_body = re.sub(
                r'^# (?:Recon|Initial Recon) Report:',
                '# Final Report:',
                raw, count=1, flags=re.MULTILINE,
            )

        # ── NVD-Sektion aufbauen ──────────────────────────────────────────────
        valid    = [r for r in self.state.nvd_results if "error" not in r]
        errors   = [r for r in self.state.nvd_results if "error" in r]
        valid.sort(key=lambda r: r.get("cvss_score") or 0, reverse=True)

        # BUG-17 — Banner-Versions-Gate: trenne versions-verifizierte CVEs von solchen
        # ohne erkannte Service-Version. Eine CVE mit echtem CVSS ist NICHT automatisch
        # ein bestätigtes Finding — fehlt die Version (Banner wie "Apache-Coyote/1.1"),
        # ist der Versions-Match spekulativ (potenzielles False-Positive).
        version_ok  = [r for r in valid if _version_confirmed_in_scan(r, scan_body)]
        version_unk = [r for r in valid if r not in version_ok]
        split_sections = bool(version_ok and version_unk)

        # Kopfzeilen-Zählung: nur die TATSÄCHLICH gelisteten CVEs zählen (versions-
        # verifizierte + KEV-Ausnahmen) — versionslose generische CVEs werden weder
        # gelistet noch gezählt, sonst täuscht "Critical: 14" eine Bedrohung vor die
        # nur aus versionsloser Spekulation besteht (User-Entscheidung 2026-06-25).
        def _sev(r, s): return (r.get("cvss_severity") or "").upper() == s
        _counted = version_ok  # KEV-Ausnahmen werden unten ergänzt (siehe version_unk_kev)

        nvd_lines = [
            "\n## CVE Validation (NVD API v2)\n",
            f"*Source: https://nvd.nist.gov — {ts_human}*\n",
            "__HEADER_COUNTS__",   # Platzhalter — final ersetzt nachdem KEV bekannt ist
        ]

        if version_ok:
            if split_sections:
                nvd_lines += [
                    "### ✅ Versions-verifizierte CVEs\n",
                    "*Service-Version im Scan erkannt und passt zum betroffenen Produkt.*",
                    "",
                ]
            nvd_lines += _format_cve_entries(version_ok)

        # Versionslose CVEs werden NICHT mehr gelistet (User-Entscheidung 2026-06-25):
        # eine Liste produkt-generischer "alle Critical-CVEs für Apache"-Treffer ohne
        # erkannte Version hat keinen praktischen Wert (reine Spekulation/Rauschen).
        # AUSNAHME: aktiv ausgenutzte CVEs (CISA-KEV-Heuristik: "exploited" in der
        # NVD-Beschreibung) werden als expliziter Hinweis behalten — die sind auch
        # ohne Versions-Match relevant.
        def _is_kev(r: dict) -> bool:
            desc = (r.get("description") or "").lower()
            return ("exploited in the wild" in desc or "known to be exploited" in desc
                    or "actively exploited" in desc)

        version_unk_kev = [r for r in version_unk if _is_kev(r)]
        version_unk_dropped = [r for r in version_unk if not _is_kev(r)]

        # Header-Zählung final: nur gelistete CVEs (verifiziert + KEV-Ausnahmen)
        _counted = version_ok + version_unk_kev
        _crit = sum(1 for r in _counted if _sev(r, "CRITICAL"))
        _high = sum(1 for r in _counted if _sev(r, "HIGH"))
        _hdr = (f"- Gelistet: **{len(_counted)}**  Critical: **{_crit}**  High: **{_high}**"
                + (f"  ·  {len(version_unk_dropped)} versionslose generische CVE(s) ausgeblendet"
                   if version_unk_dropped else "") + "\n")
        nvd_lines = [(_hdr if ln == "__HEADER_COUNTS__" else ln) for ln in nvd_lines]

        if version_unk_kev:
            nvd_lines += [
                "\n### ⚠️ Aktiv ausgenutzt — ABER Version unbestätigt\n",
                "*Diese CVE(s) werden laut NVD aktiv ausgenutzt (KEV) und sind daher auch "
                "ohne Versions-Match relevant. Der Scan hat KEINE konkrete Produkt-Version "
                "erkannt — ob die laufende Version betroffen ist, ist UNBESTÄTIGT. Manuelle "
                "Versionsprüfung empfohlen.*",
                "",
            ]
            nvd_lines += _format_cve_entries(version_unk_kev)

        if version_unk_dropped and not version_ok and not version_unk_kev:
            # Nichts Verwertbares: klarer Hinweis statt einer Fantasie-CVE-Liste
            prods = sorted({_cve_product_keywords(r) and sorted(_cve_product_keywords(r))[0]
                            for r in version_unk_dropped if _cve_product_keywords(r)})
            prod_str = ", ".join(p for p in prods if p) or "die erkannten Dienste"
            nvd_lines += [
                "### ℹ️ Keine versionsspezifische CVE-Analyse möglich\n",
                f"*Für {prod_str} hat das Ziel KEINE konkrete Version preisgegeben (Banner ohne "
                f"Versionsnummer — gehärtete Konfiguration). {len(version_unk_dropped)} produkt-"
                f"generische CVE(s) wurden daher NICHT gelistet (versionslose Treffer sind ohne "
                f"Versions-Match nicht verwertbar). Nächster Angriffsschritt: Version über andere "
                f"Wege fingerprinten (Error-Pages, Verhaltens-Unterschiede, Default-Pfade), dann "
                f"versions-gezielter Re-Scan.*",
                "",
            ]
        elif version_unk_dropped:
            # Es gibt verwertbare CVEs daneben → nur knapper Vermerk über die verworfenen
            nvd_lines += [
                f"\n*({len(version_unk_dropped)} weitere produkt-generische CVE(s) ohne "
                f"Versions-Match wurden als nicht-verwertbar ausgeblendet.)*",
                "",
            ]

        if errors:
            # Unterscheide NVD-Unerreichbarkeit (503/timeout) von echtem "existiert nicht".
            # Transiente Fehler bedeuten NICHT, dass die CVE valide ist — sie ist nur
            # UNBESTÄTIGT. Solche CVEs stammen oft aus versionslosen searchsploit-
            # Keyword-Treffern (z.B. "Apache Tomcat" ohne Version) und dürfen nicht als
            # confirmed findings gelesen werden (BUG-14).
            _transient = ("HTTP 503", "HTTP 502", "HTTP 504", "HTTP 429",
                          "timed out", "timeout", "ConnectionError", "Connection")
            unconfirmed = [r for r in errors
                           if any(t in str(r.get("error", "")) for t in _transient)]
            not_in_nvd  = [r for r in errors if r not in unconfirmed]

            if unconfirmed:
                nvd_lines += [
                    "**⚠️ UNBESTÄTIGT — NVD nicht erreichbar (keine Versions-/CVSS-Bestätigung):**",
                    "*Diese CVE-IDs stammen aus Tool-Outputs (z.B. searchsploit-Keyword-Suche), "
                    "konnten aber nicht gegen NVD verifiziert werden. Ohne Versions-Match sind sie "
                    "spekulativ und KEINE bestätigten Findings.*",
                    "",
                ] + [f"- {r['id']} — {r['error']}" for r in unconfirmed] + [""]
            if not_in_nvd:
                nvd_lines += ["**Not found in NVD:**"] + [
                    f"- {r['id']} — {r['error']}" for r in not_in_nvd
                ] + [""]

        # ── Zusammenführen ────────────────────────────────────────────────────
        header = (
            f"**Target:** {target}  \n"
            f"**Date:** {ts_human}  \n"
            f"**Source:** AgentScanIT scan + NVD API v2\n\n---\n\n"
        )

        if scan_body:
            content = header + scan_body + "\n" + "\n".join(nvd_lines)
        else:
            content = (
                header
                + f"# Final Report: {target}\n\n"
                + "\n".join(nvd_lines)
            )

        path = os.path.join(LOG_DIR, f"final_report_{safe}_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        self.state.final_report_path = path

        # ── Completion Panel ──────────────────────────────────────────────────
        table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
        table.add_column(style="dim", min_width=16)
        table.add_column()
        table.add_row("Target",    f"[bold white]{target}[/]")
        table.add_row("CVEs",      str(len(_counted)))
        table.add_row("Critical",  f"[red]{_crit}[/]")
        table.add_row("High",      f"[yellow]{_high}[/]")
        table.add_row("", "")
        if self.state.scan_report_path:
            table.add_row("Scan report",   f"[dim]{self.state.scan_report_path}[/]")
        table.add_row("Final report",  f"[bold]{path}[/]")

        console.print()
        console.print(Panel(
            table,
            title="[bold green]Final Report Complete[/]",
            border_style="green",
            padding=(1, 2),
        ))
        console.print()


# ─── Entry point ──────────────────────────────────────────────────────────────

def run_reporting_flow(
    scan_target: str,
    scan_report_path: str,
    nvd_results: list[dict],
) -> ReportingFlow:
    flow = ReportingFlow()
    flow.state.scan_target      = scan_target
    flow.state.scan_report_path = scan_report_path
    flow.state.nvd_results      = nvd_results
    flow.kickoff()
    return flow
