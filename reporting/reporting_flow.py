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
        critical = [r for r in valid if (r.get("cvss_severity") or "").upper() == "CRITICAL"]
        high     = [r for r in valid if (r.get("cvss_severity") or "").upper() == "HIGH"]

        valid.sort(key=lambda r: r.get("cvss_score") or 0, reverse=True)

        nvd_lines = [
            "\n## CVE Validation (NVD API v2)\n",
            f"*Source: https://nvd.nist.gov — {ts_human}*\n",
            f"- Total: **{len(self.state.nvd_results)}**  "
            f"Critical: **{len(critical)}**  High: **{len(high)}**\n",
        ]

        for r in valid:
            sev   = (r.get("cvss_severity") or "N/A").upper()
            score = r.get("cvss_score")
            icon  = _SEVERITY_ICON.get(sev, "⚪")
            nvd_lines += [
                f"### {icon} {r['id']} — CVSS {score} ({sev})",
                f"- **Published:** {r.get('published', 'N/A')}  "
                f"**Last Modified:** {r.get('last_modified', 'N/A')}",
                f"- **Vector:** `{r.get('cvss_vector') or 'N/A'}`",
                "",
                f"**Description:** {r.get('description', '')}",
                "",
            ]
            if r.get("affected_cpe"):
                nvd_lines.append("**Affected Products (CPE):**")
                for cpe in r["affected_cpe"][:5]:
                    nvd_lines.append(f"- `{cpe}`")
                nvd_lines.append("")
            if r.get("references"):
                nvd_lines.append("**References:**")
                for ref in r["references"]:
                    nvd_lines.append(f"- {ref}")
                nvd_lines.append("")

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
        table.add_row("CVEs",      str(len(self.state.nvd_results)))
        table.add_row("Critical",  f"[red]{len(critical)}[/]")
        table.add_row("High",      f"[yellow]{len(high)}[/]")
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
