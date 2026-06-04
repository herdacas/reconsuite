"""
interpret-agent/flow.py — Team 2: CVE Enrichment & Validation

Liest CVE-IDs aus einem Scan-JSON, fragt die NVD API v2 ab,
schreibt interpret_<target>_<ts>.md nach recon-suite/logs/.

Kein LLM — alle Daten kommen direkt aus der NVD REST API.
"""

import json
import os
import re
import sys
from datetime import datetime

from pydantic import BaseModel, Field
from crewai.flow.flow import Flow, start, listen
from rich.console import Console
from rich.panel import Panel

# LOG_DIR relativ zum recon-suite Root
_TEAM_DIR  = os.path.dirname(os.path.abspath(__file__))
_SUITE_DIR = os.path.dirname(_TEAM_DIR)
LOG_DIR    = os.path.join(_SUITE_DIR, "logs")

from nvd import fetch_cves  # lokal im Team-Verzeichnis

console = Console()

_SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


# ─── State ────────────────────────────────────────────────────────────────────

class InterpretState(BaseModel):
    scan_json_path:   str        = ""
    scan_report_path: str        = ""
    scan_target:      str        = ""
    scan_timestamp:   str        = ""
    cve_ids:          list[str]  = Field(default_factory=list)
    nvd_results:      list[dict] = Field(default_factory=list)
    report_path:      str        = ""   # interpret_*.md


# ─── Flow ─────────────────────────────────────────────────────────────────────

class InterpretFlow(Flow[InterpretState]):
    """CVE Enrichment — NVD API v2, kein LLM."""

    @start()
    def load_findings(self):
        path = self.state.scan_json_path or os.path.join(LOG_DIR, "workflow_last.json")

        try:
            with open(path) as f:
                summary = json.load(f)
        except Exception as e:
            console.print(f"  [red]✗[/]  InterpretFlow: {e}")
            return

        self.state.scan_target     = summary.get("target", "unknown")
        self.state.scan_timestamp  = summary.get("timestamp", "")
        self.state.scan_report_path = summary.get("report", "")

        # Collect only from structured cve_references fields (findings + red tasks).
        # The regex-on-preview fallback was removed: scanning preview text included
        # reporter_agent markdown which contained hallucinated CVE IDs from LLM training.
        cve_ids: list[str] = []
        for task_data in summary.get("tasks", {}).values():
            for cve_id in task_data.get("cve_references", []):
                if cve_id not in cve_ids:
                    cve_ids.append(cve_id)

        self.state.cve_ids = cve_ids

        console.print()
        console.print(Panel(
            f"[bold cyan]interpret-agent[/]  ·  CVE Enrichment (NVD API v2)\n\n"
            f"  [dim]Target:[/]  [bold white]{self.state.scan_target}[/]\n"
            f"  [dim]CVEs:[/]    {', '.join(cve_ids) if cve_ids else '[dim]none[/]'}",
            border_style="cyan", expand=False, padding=(0, 2),
        ))

        if not cve_ids:
            console.print("  [dim]Keine CVE-IDs — nichts zu enrichen.[/]")

    @listen(load_findings)
    def fetch_nvd(self):
        if not self.state.cve_ids:
            return
        console.print(f"  [dim]NVD API v2 — {len(self.state.cve_ids)} CVE(s)...[/]")
        self.state.nvd_results = fetch_cves(self.state.cve_ids)
        ok = sum(1 for r in self.state.nvd_results if "error" not in r)
        console.print(f"  [green]✓[/]  {ok}/{len(self.state.cve_ids)} fetched")

    @listen(fetch_nvd)
    def write_report(self):
        if not self.state.nvd_results:
            return

        target   = self.state.scan_target
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M")
        safe     = re.sub(r"[^\w.-]", "_", target)

        valid    = [r for r in self.state.nvd_results if "error" not in r]
        errors   = [r for r in self.state.nvd_results if "error" in r]
        critical = [r for r in valid if (r.get("cvss_severity") or "").upper() == "CRITICAL"]
        high     = [r for r in valid if (r.get("cvss_severity") or "").upper() == "HIGH"]

        valid.sort(key=lambda r: r.get("cvss_score") or 0, reverse=True)

        lines = [
            f"**Target:** {target}  ",
            f"**Date:** {ts_human}  ",
            "**Source:** NVD API v2 — https://nvd.nist.gov\n",
            "---\n",
            f"# CVE Enrichment Report: {target}\n",
            "## Summary\n",
            f"- Total: **{len(self.state.nvd_results)}**  "
            f"Critical: **{len(critical)}**  High: **{len(high)}**\n",
            "## CVE Details\n",
        ]

        for r in valid:
            sev   = (r.get("cvss_severity") or "N/A").upper()
            score = r.get("cvss_score")
            icon  = _SEVERITY_ICON.get(sev, "⚪")
            lines += [
                f"### {icon} {r['id']} — CVSS {score} ({sev})",
                f"- **Published:** {r.get('published', 'N/A')}  "
                f"**Last Modified:** {r.get('last_modified', 'N/A')}",
                f"- **Vector:** `{r.get('cvss_vector') or 'N/A'}`",
                "",
                f"**Description:** {r.get('description', '')}",
                "",
            ]
            if r.get("affected_cpe"):
                lines.append("**Affected Products (CPE):**")
                for cpe in r["affected_cpe"][:5]:
                    lines.append(f"- `{cpe}`")
                lines.append("")
            if r.get("references"):
                lines.append("**References:**")
                for ref in r["references"]:
                    lines.append(f"- {ref}")
                lines.append("")

        if errors:
            lines += ["## Not Found in NVD\n"] + [
                f"- **{r['id']}** — {r['error']}" for r in errors
            ]

        path = os.path.join(LOG_DIR, f"interpret_{safe}_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        self.state.report_path = path
        console.print(f"  [dim]NVD report → {path}[/]")


# ─── Entry point ──────────────────────────────────────────────────────────────

def run_interpret_flow(scan_json_path: str = "") -> InterpretFlow:
    # nvd.py muss im Pfad sein wenn als Package aufgerufen
    if _TEAM_DIR not in sys.path:
        sys.path.insert(0, _TEAM_DIR)
    flow = InterpretFlow()
    flow.state.scan_json_path = scan_json_path
    flow.kickoff()
    return flow


if __name__ == "__main__":
    run_interpret_flow(sys.argv[1] if len(sys.argv) > 1 else "")
