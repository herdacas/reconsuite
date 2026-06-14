"""
recon-suite/main.py — Top-Level CLI

Startet den Master-Flow (alle drei Teams sequentiell).
Für reinen Scan ohne NVD-Enrichment: python3 agentscanit/main.py

Usage:
    python3 main.py example.com
    python3 main.py example.com "full assessment" full
    python3 main.py --resume <flow-id>
    python3 main.py --list
    python3 main.py --score [trace_file]  → Scan Quality Scorecard
    python3 main.py              → interaktiver Modus
"""

import sys
import os
import json
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flow import run_flow, resume_flow, _FLOW_DB
from agentscanit.main import _validate_target, console
from agentscanit.crew import VALID_SCOPES
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table


def _cmd_list() -> None:
    """Print recent flow runs from the SQLite persistence DB."""
    if not os.path.exists(_FLOW_DB):
        console.print("  [dim]Keine gespeicherten Flows gefunden.[/]  (noch kein Run abgeschlossen)")
        return
    try:
        with sqlite3.connect(_FLOW_DB, timeout=10) as conn:
            rows = conn.execute(
                """
                SELECT flow_uuid, method_name, timestamp, state_json
                FROM flow_states
                WHERE id IN (
                    SELECT MAX(id) FROM flow_states GROUP BY flow_uuid
                )
                ORDER BY timestamp DESC
                LIMIT 20
                """
            ).fetchall()
    except Exception as exc:
        console.print(f"[red]✗[/]  DB-Lesefehler: {exc}")
        return

    if not rows:
        console.print("  [dim]Keine gespeicherten Flows gefunden.[/]")
        return

    table = Table(title="Gespeicherte Flows", border_style="cyan", show_lines=False)
    table.add_column("Flow ID", style="cyan", no_wrap=True)
    table.add_column("Target", style="bold")
    table.add_column("Scope")
    table.add_column("Letzter Schritt")
    table.add_column("Zeitstempel", style="dim")

    for flow_uuid, method_name, timestamp, state_json in rows:
        try:
            state = json.loads(state_json)
        except Exception:
            state = {}
        table.add_row(
            flow_uuid,
            state.get("target", "?"),
            state.get("scope", "?"),
            method_name,
            timestamp[:19].replace("T", " "),
        )

    console.print()
    console.print(table)
    console.print()
    console.print("  [dim]Fortsetzen:[/]  python3 main.py --resume <Flow ID>")
    console.print()


def _cmd_score(trace_arg: str = "") -> None:
    """Print quality scorecard for a trace file (or the latest scan)."""
    from agentscanit.quality import score_scan, print_scorecard
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    if trace_arg:
        path = trace_arg if os.path.isabs(trace_arg) else os.path.join(log_dir, trace_arg)
    else:
        traces = sorted(
            [f for f in os.listdir(log_dir) if f.startswith("trace_") and f.endswith(".json")],
            reverse=True,
        )
        if not traces:
            console.print("[red]✗[/]  Keine trace_*.json Dateien in logs/")
            sys.exit(1)
        path = os.path.join(log_dir, traces[0])
    try:
        report = score_scan(path)
        print_scorecard(report)
    except FileNotFoundError:
        console.print(f"[red]✗[/]  Datei nicht gefunden: {path}")
        sys.exit(1)


if __name__ == "__main__":
    args = sys.argv[1:]

    if args and args[0] == "--list":
        _cmd_list()
        sys.exit(0)

    if args and args[0] == "--score":
        _cmd_score(args[1] if len(args) > 1 else "")
        sys.exit(0)

    if args and args[0] == "--resume":
        if len(args) < 2:
            console.print("[red]✗[/]  --resume benötigt eine Flow-ID")
            sys.exit(1)
        resume_flow(args[1])
        sys.exit(0)

    if len(args) >= 1:
        _target, _err = _validate_target(args[0])
        if _err:
            console.print(f"[red]✗[/]  {_err}")
            sys.exit(1)
        # Allow `main.py target scope` without an explicit objective:
        # if the second arg is a known scope, treat it as scope not objective.
        if len(args) == 2 and args[1].lower() in VALID_SCOPES:
            _objective = ""
            _scope     = args[1].lower()
        else:
            _objective = args[1] if len(args) >= 2 else ""
            _scope     = args[2] if len(args) >= 3 else "full"
    else:
        console.print()
        console.print(Panel(
            "[bold cyan]recon-suite[/]  ·  Agentic Security Assessment\n\n"
            "  [dim]Teams:[/]  agentscanit  ·  interpret-agent  ·  reporting",
            border_style="cyan", expand=False, padding=(0, 2),
        ))
        console.print()
        while True:
            raw = Prompt.ask("[bold]Target[/] [dim](domain or IP)[/]")
            _target, _err = _validate_target(raw)
            if not _err:
                break
            console.print(f"  [red]✗[/]  {_err}")
        _objective = Prompt.ask(
            "[bold]Objective[/] [dim](Enter für full scan)[/]", default=""
        )
        console.print(
            "  [dim]Scopes:[/]  "
            "[cyan]osint[/] · [cyan]ssl[/] · [cyan]quick[/] · "
            "[cyan]web[/] · [cyan]network[/] · [cyan]full[/] · [cyan]hierarchical[/]"
        )
        _scope = Prompt.ask("[bold]Scope[/]", default="full")

    run_flow(_target, _objective, _scope)
