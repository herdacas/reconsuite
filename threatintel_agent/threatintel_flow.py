"""
threatintel_agent/threatintel_flow.py — Team 4: Threat Intelligence

Reichert CVEs und IPs mit Echtzeit-Threat-Daten an:
  - AlienVault OTX  (kostenlos, OTX_API_KEY empfohlen)
  - Shodan           (paid, SHODAN_API_KEY optional)
  - VirusTotal       (free-tier, VT_API_KEY optional)

Alle drei Tools degradieren graceful wenn kein API-Key konfiguriert ist.

Eingabe:  workflow_last.json (CVE-IDs + IPs aus Team 1 Scan)
Ausgabe:  logs/threatintel_<target>_<ts>.md
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

_TEAM_DIR  = os.path.dirname(os.path.abspath(__file__))
_SUITE_DIR = os.path.dirname(_TEAM_DIR)
LOG_DIR    = os.path.join(_SUITE_DIR, "logs")

from threatintel_agent.tools import otx_cves, otx_ips, shodan_ips, vt_cves, vt_ips

console = Console()


# ─── State ────────────────────────────────────────────────────────────────────

class ThreatIntelState(BaseModel):
    scan_json_path: str        = ""
    scan_target:    str        = ""
    scan_timestamp: str        = ""
    cve_ids:        list[str]  = Field(default_factory=list)
    ips:            list[str]  = Field(default_factory=list)
    otx_cve_data:   list[dict] = Field(default_factory=list)
    otx_ip_data:    list[dict] = Field(default_factory=list)
    shodan_data:    list[dict] = Field(default_factory=list)
    vt_cve_data:    list[dict] = Field(default_factory=list)
    vt_ip_data:     list[dict] = Field(default_factory=list)
    report_path:    str        = ""
    threat_summary: str        = ""


# ─── Flow ─────────────────────────────────────────────────────────────────────

class ThreatIntelFlow(Flow[ThreatIntelState]):
    """Threat Intelligence — OTX + Shodan + VirusTotal, kein LLM."""

    @start()
    def load_findings(self):
        path = self.state.scan_json_path or os.path.join(LOG_DIR, "workflow_last.json")

        try:
            with open(path) as f:
                summary = json.load(f)
        except Exception as e:
            console.print(f"  [red]✗[/]  ThreatIntelFlow: {e}")
            return

        self.state.scan_target    = summary.get("target", "unknown")
        self.state.scan_timestamp = summary.get("timestamp", "")

        # CVE-IDs aus strukturierten cve_references-Feldern
        cve_ids: list[str] = []
        for task_data in summary.get("tasks", {}).values():
            for cve_id in task_data.get("cve_references", []):
                if cve_id not in cve_ids:
                    cve_ids.append(cve_id)
        self.state.cve_ids = cve_ids

        # IPs aus open_ports / blue_task Output
        ips: list[str] = []
        for task_data in summary.get("tasks", {}).values():
            for ip in task_data.get("target_ips", []):
                if ip not in ips:
                    ips.append(ip)
        # Fallback: Ziel-Host direkt wenn keine IPs extrahiert
        if not ips and self.state.scan_target:
            import socket
            try:
                resolved = socket.gethostbyname(self.state.scan_target)
                ips = [resolved]
            except Exception:
                pass
        self.state.ips = ips

        console.print()
        console.print(Panel(
            f"[bold red]threatintel-agent[/]  ·  Threat Intelligence\n\n"
            f"  [dim]Target:[/]  [bold white]{self.state.scan_target}[/]\n"
            f"  [dim]CVEs:[/]    {', '.join(cve_ids) if cve_ids else '[dim]none[/]'}\n"
            f"  [dim]IPs:[/]     {', '.join(ips) if ips else '[dim]none[/]'}",
            border_style="red", expand=False, padding=(0, 2),
        ))

        if not cve_ids and not ips:
            console.print("  [dim]Keine CVEs oder IPs — nichts zu enrichen.[/]")

    @listen(load_findings)
    def run_otx(self):
        if self.state.cve_ids:
            console.print(f"  [dim]OTX — {len(self.state.cve_ids)} CVE(s)...[/]")
            self.state.otx_cve_data = otx_cves(self.state.cve_ids)
            ok = sum(1 for r in self.state.otx_cve_data if r.get("status") == "ok")
            _log_api_result("OTX CVE", ok, len(self.state.cve_ids), self.state.otx_cve_data)

        if self.state.ips:
            console.print(f"  [dim]OTX — {len(self.state.ips)} IP(s)...[/]")
            self.state.otx_ip_data = otx_ips(self.state.ips)
            ok = sum(1 for r in self.state.otx_ip_data if r.get("status") == "ok")
            _log_api_result("OTX IP", ok, len(self.state.ips), self.state.otx_ip_data)

    @listen(run_otx)
    def run_shodan(self):
        if not self.state.ips:
            return
        console.print(f"  [dim]Shodan — {len(self.state.ips)} IP(s)...[/]")
        self.state.shodan_data = shodan_ips(self.state.ips)
        ok = sum(1 for r in self.state.shodan_data if r.get("status") == "ok")
        _log_api_result("Shodan", ok, len(self.state.ips), self.state.shodan_data)

    @listen(run_shodan)
    def run_virustotal(self):
        if self.state.cve_ids:
            console.print(f"  [dim]VT — {len(self.state.cve_ids)} CVE(s)...[/]")
            self.state.vt_cve_data = vt_cves(self.state.cve_ids)
            ok = sum(1 for r in self.state.vt_cve_data if r.get("status") == "ok")
            _log_api_result("VT CVE", ok, len(self.state.cve_ids), self.state.vt_cve_data)

        if self.state.ips:
            console.print(f"  [dim]VT — {len(self.state.ips)} IP(s)...[/]")
            self.state.vt_ip_data = vt_ips(self.state.ips)
            ok = sum(1 for r in self.state.vt_ip_data if r.get("status") == "ok")
            _log_api_result("VT IP", ok, len(self.state.ips), self.state.vt_ip_data)

    @listen(run_virustotal)
    def write_report(self):
        target   = self.state.scan_target
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_human = datetime.now().strftime("%Y-%m-%d %H:%M")
        safe     = re.sub(r"[^\w.-]", "_", target)

        lines = [
            f"**Target:** {target}  ",
            f"**Date:** {ts_human}  ",
            "**Sources:** AlienVault OTX · Shodan · VirusTotal\n",
            "---\n",
            f"# Threat Intelligence Report: {target}\n",
        ]

        # ── CVE Threat Intel ──
        # Output-Qualitäts-Fix Punkt 4 (2026-09-19): live gefunden — bei 40 CVEs ohne
        # jede OTX/VT-Nutzdaten (z.B. Rate-Limit, "not found" für sehr neue/fiktive
        # CVE-IDs, oder fehlender API-Key) rendert der alte Code 40 leere "### CVE-X"-
        # Abschnitte ohne eine einzige Detailzeile darunter — reines Rauschen. Zusätzlich
        # hatte der alte if/elif-Zweig KEIN else für einen echten API-Fehlerstring
        # (data["error"] aus otx_tool.py/virustotal_tool.py) — der wurde bisher komplett
        # verschluckt, statt dem Leser zu zeigen DASS/WARUM ein Lookup fehlschlug. Fix:
        # nur CVEs mit echten Nutzdaten bekommen einen vollen Abschnitt; alle anderen
        # werden nach ihrem (jetzt sichtbaren) Grund gruppiert in Sammelzeilen zusammengefasst.
        if self.state.cve_ids:
            lines += ["## CVE Threat Intelligence\n"]
            cve_otx = {r["id"]: r for r in self.state.otx_cve_data if "id" in r}
            cve_vt  = {r["id"]: r for r in self.state.vt_cve_data  if "id" in r}

            no_data: dict[str, list[str]] = {}  # Grund -> [CVE-IDs]
            for cve_id in self.state.cve_ids:
                otx = cve_otx.get(cve_id, {})
                vt  = cve_vt.get(cve_id, {})

                otx_line = None
                if otx.get("status") == "ok":
                    otx_line = (f"**OTX Pulses:** {otx.get('pulse_count', 0)} "
                                f"({'aktiv in-the-wild' if otx.get('in_the_wild') else 'keine aktiven Pulse'})")
                vt_lines: list[str] = []
                if vt.get("status") == "ok":
                    exploits = vt.get("exploit_urls", [])
                    vt_lines.append(f"**VT Exploits:** {len(exploits)} URL(s) bekannt")
                    vt_lines += [f"  - {url}" for url in exploits]

                if otx_line or vt_lines:
                    in_wild = otx.get("in_the_wild", False) or vt.get("has_exploit", False)
                    icon = "🔴" if in_wild else "⚪"
                    lines.append(f"### {icon} {cve_id}")
                    if otx_line:
                        lines.append(f"- {otx_line}")
                    lines += [f"- {ln}" if not ln.startswith("  ") else ln for ln in vt_lines]
                    lines.append("")
                else:
                    # Kein Treffer bei OTX UND VT — Grund für die Sammelzeile ermitteln
                    # (sichtbar statt verschluckt: "no_key" ODER der rohe Fehlerstring).
                    otx_status = otx.get("status") or "keine Antwort"
                    vt_status  = vt.get("status") or "keine Antwort"
                    reason = f"OTX: {otx_status} · VT: {vt_status}"
                    no_data.setdefault(reason, []).append(cve_id)

            if no_data:
                total_no_data = sum(len(v) for v in no_data.values())
                lines.append(f"*{total_no_data}/{len(self.state.cve_ids)} CVE(s) ohne "
                             f"Threat-Intel-Treffer (weder OTX-Pulse noch VT-Exploit-URLs):*")
                for reason, ids in no_data.items():
                    lines.append(f"  - {reason}: {', '.join(ids)}")
                lines.append("")

        # ── IP Threat Intel ──
        if self.state.ips:
            lines += ["## IP Reputation\n"]
            otx_map    = {r["ip"]: r for r in self.state.otx_ip_data   if "ip" in r}
            shodan_map = {r["ip"]: r for r in self.state.shodan_data    if "ip" in r}
            vt_map     = {r["ip"]: r for r in self.state.vt_ip_data     if "ip" in r}

            for ip in self.state.ips:
                otx = otx_map.get(ip, {})
                sh  = shodan_map.get(ip, {})
                vt  = vt_map.get(ip, {})
                malicious = otx.get("malicious", False) or vt.get("flagged", False)
                icon = "🔴" if malicious else "🟢"

                lines.append(f"### {icon} {ip}")
                if otx.get("status") == "ok":
                    lines.append(f"- **OTX Pulses:** {otx.get('pulse_count', 0)}, "
                                 f"Reputation: {otx.get('reputation', 'N/A')}")
                elif otx.get("status") == "no_key":
                    lines.append("- **OTX:** kein API-Key konfiguriert")
                if sh.get("status") == "ok":
                    lines.append(f"- **Shodan:** Org: {sh.get('org', 'N/A')}, "
                                 f"Ports: {sh.get('ports', [])}, "
                                 f"Country: {sh.get('country', 'N/A')}")
                    if sh.get("vulns"):
                        lines.append(f"  - Shodan-erkannte CVEs: {', '.join(sh['vulns'][:5])}")
                elif sh.get("status") == "no_key":
                    lines.append("- **Shodan:** kein API-Key konfiguriert")
                if vt.get("status") == "ok":
                    lines.append(f"- **VT:** {vt.get('malicious', 0)} malicious, "
                                 f"{vt.get('suspicious', 0)} suspicious "
                                 f"({'⚠ flagged' if vt.get('flagged') else 'clean'})")
                elif vt.get("status") == "no_key":
                    lines.append("- **VT:** kein API-Key konfiguriert")
                lines.append("")

        # ── Summary ──
        wild_cves = [
            r["id"] for r in self.state.otx_cve_data
            if r.get("in_the_wild") and "id" in r
        ] + [
            r["id"] for r in self.state.vt_cve_data
            if r.get("has_exploit") and "id" in r
        ]
        wild_cves = list(dict.fromkeys(wild_cves))

        malicious_ips = [
            r["ip"] for r in self.state.otx_ip_data
            if r.get("malicious") and "ip" in r
        ] + [
            r["ip"] for r in self.state.vt_ip_data
            if r.get("flagged") and "ip" in r
        ]
        malicious_ips = list(dict.fromkeys(malicious_ips))

        summary = (
            f"CVEs in-the-wild: {len(wild_cves)} / {len(self.state.cve_ids)} — "
            f"Malicious IPs: {len(malicious_ips)} / {len(self.state.ips)}"
        )
        self.state.threat_summary = summary

        lines += [
            "## Summary\n",
            f"- {summary}",
        ]
        if wild_cves:
            lines.append(f"- In-the-wild CVEs: {', '.join(wild_cves)}")
        if malicious_ips:
            lines.append(f"- Malicious IPs: {', '.join(malicious_ips)}")

        path = os.path.join(LOG_DIR, f"threatintel_{safe}_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        self.state.report_path = path
        console.print(f"  [green]✓[/]  {summary}")
        console.print(f"  [dim]Threat Intel → {path}[/]")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _log_api_result(label: str, ok: int, total: int, results: list[dict]) -> None:
    no_key = sum(1 for r in results if r.get("status") == "no_key")
    if no_key == total:
        console.print(f"  [dim]{label}: kein API-Key — übersprungen[/]")
    else:
        console.print(f"  [green]✓[/]  {label}: {ok}/{total - no_key} fetched")


# ─── Entry point ──────────────────────────────────────────────────────────────

def run_threatintel_flow(scan_json_path: str = "") -> ThreatIntelFlow:
    flow = ThreatIntelFlow()
    flow.state.scan_json_path = scan_json_path
    flow.kickoff()
    return flow


if __name__ == "__main__":
    import sys as _sys
    run_threatintel_flow(_sys.argv[1] if len(_sys.argv) > 1 else "")
