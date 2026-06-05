"""
recon-suite/main.py — Top-Level CLI

Startet den Master-Flow (alle drei Teams sequentiell).
Für reinen Scan ohne NVD-Enrichment: python3 agentscanit/main.py

Usage:
    python3 main.py example.com
    python3 main.py example.com "full assessment" full
    python3 main.py              → interaktiver Modus
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flow import run_flow
from agentscanit.main import _validate_target, console
from agentscanit.crew import VALID_SCOPES
from rich.prompt import Prompt
from rich.panel import Panel


if __name__ == "__main__":
    args = sys.argv[1:]
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
            "[cyan]web[/] · [cyan]network[/] · [cyan]full[/]"
        )
        _scope = Prompt.ask("[bold]Scope[/]", default="full")

    run_flow(_target, _objective, _scope)
