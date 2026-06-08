"""
main.py – CLI-Einstiegspunkt und Output-Handler für AgentScanIT

Verwendung:
    python3 main.py example.com
    python3 main.py example.com "DNS-History prüfen" full
    python3 main.py              → fragt interaktiv nach Target, Objective, Scope

Scopes:
    osint   – passive Recon only
    ssl     – sslscan + testssl
    quick   – ping + nmap Top-100 + httpx
    web     – httpx, whatweb, nikto, nuclei + Red-Analyse
    network – nmap + naabu + httpx + Red-Analyse
    full    – alle Tools

Als Flow-Crew importieren:
    from crew import AgentScanITCrew
    result = AgentScanITCrew(target, objective, scope).crew().kickoff(inputs=...)
"""

import sys
import json
import re
import os
import time
import textwrap
from datetime import datetime
from pathlib import Path

# Memory patches (suppress LLM-analysis calls + log noise) are applied in
# crew.py via _apply_memory_patches() at import time — co-located with the
# Memory configuration that needs them.

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table

from config import (
    LOG_DIR, SCAN_DIR,
    ACTIVE_ANALYSIS, ACTIVE_CODE, ACTIVE_RESEARCH, ACTIVE_BASE_URL,
    OLLAMA_API_KEY, EMBED_MODEL, EMBED_BASE_URL,
)
from crew import AgentScanITCrew, MEMORY_DIR, PHASE_LABEL, VALID_SCOPES, _crew_memory
from tools.trace import run_trace

console = Console()


# ─── Task-Progress-Tracker ────────────────────────────────────────────────────
# Modulebene erforderlich — Pydantic serialisiert task_callback und akzeptiert
# keine Lambdas oder nested functions.

_tp_pipeline:      list[str]   = []
_tp_timing:        list[float] = []
_tp_idx:           list[int]   = [0]
_completed_labels: set[str]    = set()   # task-Namen die in dieser Session abgeschlossen sind


def _reset_task_progress(pipeline: list[str], start_time: float) -> None:
    _tp_pipeline.clear();  _tp_pipeline.extend(pipeline)
    _tp_timing.clear();    _tp_timing.append(start_time)
    _tp_idx.clear();       _tp_idx.append(0)
    _completed_labels.clear()


def _on_task_done(output) -> None:
    idx     = _tp_idx[0]
    label   = _tp_pipeline[idx] if idx < len(_tp_pipeline) else "?"
    now     = time.time()
    elapsed = now - _tp_timing[0]
    _tp_timing[0] = now
    _tp_idx[0]   += 1
    _completed_labels.add(label)
    run_trace.close_phase(label)
    console.print(f"  [green]✓[/]  [bold]{PHASE_LABEL.get(label, label):<26}[/] [dim]{elapsed:>5.0f}s[/]")


# ─── Modell-Warmup (nur Local-Mode) ──────────────────────────────────────────
# Lokales Ollama lädt ein Modell erst beim ersten Request in den VRAM. Ohne
# Vorladen verlängert sich die erste Phase (Planner-Call) erheblich oder läuft
# in einen Timeout. Ein /api/generate mit leerem Prompt zwingt Ollama das Modell
# zu laden ohne Tokens zu generieren. Im Remote-Mode (OLLAMA_API_KEY gesetzt)
# entfällt dieser Schritt — der Server hält die Modelle bereits vor.

def _warmup_models() -> None:
    """Lädt die aktiven lokalen LLMs + das Embedding-Modell parallel in den VRAM."""
    import requests
    import concurrent.futures

    llm_models = list(dict.fromkeys([ACTIVE_ANALYSIS, ACTIVE_CODE, ACTIVE_RESEARCH]))
    console.print(f"  [dim]Warming up {len(llm_models) + 1} local model(s) (parallel)...[/]", end="")

    def _load_llm(model: str) -> None:
        try:
            requests.post(
                f"{ACTIVE_BASE_URL.rstrip('/')}/api/generate",
                json={"model": model, "prompt": "", "keep_alive": "30m"},
                timeout=300,
            )
        except Exception as exc:
            console.print(f"\n  [yellow]⚠[/]  Warmup '{model}' fehlgeschlagen: {exc}")

    def _load_embed() -> None:
        try:
            requests.post(
                f"{EMBED_BASE_URL.rstrip('/')}/api/embeddings",
                json={"model": EMBED_MODEL, "prompt": "warmup", "keep_alive": "30m"},
                timeout=120,
            )
        except Exception as exc:
            console.print(f"\n  [yellow]⚠[/]  Warmup embed '{EMBED_MODEL}' fehlgeschlagen: {exc}")

    with concurrent.futures.ThreadPoolExecutor() as pool:
        futs = [pool.submit(_load_llm, m) for m in llm_models]
        futs.append(pool.submit(_load_embed))
        concurrent.futures.wait(futs)

    console.print("  [green]ready[/]")


# ─── run() ───────────────────────────────────────────────────────────────────

def run(target: str, objective: str = "", scope: str = "full") -> object:
    scanner = AgentScanITCrew(target, objective, scope)
    target, objective, scope = scanner.target, scanner.objective, scanner.scope

    # Pre-run shallow recall: vector search for the target name — no LLM call.
    # A "hit" requires at least one returned memory whose content mentions the
    # target name; generic memories from other targets always score ~0.66-0.68
    # and never contain the target name, avoiding false-positives for new targets.
    has_prior_data = False
    try:
        lancedb_path = MEMORY_DIR / "lancedb"
        if lancedb_path.exists() and any(lancedb_path.iterdir()):
            _hits = _crew_memory.recall(target, depth="shallow", limit=3)
            has_prior_data = any(
                target.lower() in h.record.content.lower() for h in _hits
            )
    except Exception:
        pass
    db_status = (
        "[green]warm[/] [dim](prior run data for this target)[/]"
        if has_prior_data
        else "[yellow]fresh[/] [dim](first run for this target)[/]"
    )

    console.print()
    console.print(Panel(
        f"[bold cyan]AgentScanIT[/]  ·  Agentic Vulnerability Assessment Framework\n\n"
        f"  [dim]Target:[/]     [bold white]{target}[/]\n"
        f"  [dim]Objective:[/]  {objective}\n"
        f"  [dim]Scope:[/]      [yellow]{scope}[/]   [dim]Model:[/] {ACTIVE_ANALYSIS}\n"
        f"  [dim]Memory DB:[/]   {db_status}   [dim]Cache:[/] [green]on[/]",
        border_style="cyan",
        expand=False,
        padding=(0, 2),
    ))
    console.print()

    # Local-Mode: Modelle vor dem ersten LLM-Call (Planner) in den VRAM laden.
    if not OLLAMA_API_KEY:
        _warmup_models()
        console.print()

    _run_ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    _safe_target = re.sub(r"[^\w.-]", "_", target)
    checkpoint_dir = Path(LOG_DIR) / "checkpoints" / f"{_safe_target}_{_run_ts}"

    run_start = time.time()
    crew_obj  = scanner.crew(task_callback=_on_task_done, checkpoint_dir=checkpoint_dir)
    pipeline  = scanner.pipeline
    run_trace.activate(target, objective, scope, pipeline)

    pipeline_display = "  →  ".join(
        f"[cyan]{PHASE_LABEL.get(p, p)}[/]" for p in pipeline
    )
    console.print(f"  [bold]Pipeline[/]  {pipeline_display}")
    console.print()

    _reset_task_progress(pipeline, run_start)

    console.print(f"  [dim]Running {len(scanner._active_tasks)} phases — this may take several minutes...[/]")
    console.print()

    for _attempt in range(3):
        try:
            result = crew_obj.kickoff(inputs=scanner.inputs)
            break
        except Exception as _exc:
            exc_str = str(_exc)
            _is_schema_err = (
                "json_invalid"    in exc_str or
                "ValidationError" in exc_str or
                "Field required"  in exc_str
            )
            if _is_schema_err and _attempt < 2:
                _n_done  = len(_completed_labels)
                _resumed = False

                # Checkpoint-Resume: wenn mindestens eine Phase abgeschlossen ist,
                # versuche die Crew aus dem letzten Checkpoint wiederherzustellen.
                if _n_done > 0:
                    _ckpt_main = checkpoint_dir / "main"
                    if _ckpt_main.exists():
                        _ckpt_files = sorted(
                            _ckpt_main.glob("*.json"),
                            key=lambda p: p.stat().st_mtime,
                        )
                        if _ckpt_files:
                            try:
                                from crewai import Crew as _CrewCls
                                from crewai.state.checkpoint_config import CheckpointConfig as _CC
                                from tasks import FindingsOutput, RedOutput, _cve_trace_guardrail
                                _restored = _CrewCls.from_checkpoint(
                                    _CC(restore_from=str(_ckpt_files[-1]))
                                )
                                # Re-attach callbacks — non-serializable, dropped by checkpoint
                                _restored.task_callback = _on_task_done
                                for _t in _restored.tasks:
                                    _t.callback = _on_task_done
                                # Re-attach CVE guardrails — callables dropped by checkpoint
                                for _t in _restored.tasks:
                                    _op = getattr(_t, "output_pydantic", None)
                                    if _op in (FindingsOutput, RedOutput):
                                        _t.guardrails = [_cve_trace_guardrail]
                                        object.__setattr__(_t, "_guardrails", [_cve_trace_guardrail])
                                        object.__setattr__(_t, "_guardrail",  None)
                                crew_obj = _restored
                                _resumed = True
                                console.print(
                                    f"  [cyan]↻[/]  Checkpoint-Resume — "
                                    f"{_n_done}/{len(scanner.pipeline)} Phase(n) übersprungen, "
                                    f"weiter ab Fehlerphase... (Versuch {_attempt + 2}/3)"
                                )
                                _reset_task_progress(scanner.pipeline, time.time())
                            except Exception as _ckpt_err:
                                console.print(
                                    f"  [yellow]⚠[/]  Checkpoint-Resume fehlgeschlagen "
                                    f"({type(_ckpt_err).__name__}) — Vollneustart"
                                )

                if not _resumed:
                    console.print(
                        f"  [yellow]⚠[/]  LLM schema error — retry {_attempt + 2}/3 (Vollneustart)..."
                    )
                    crew_obj = scanner.crew(task_callback=_on_task_done, checkpoint_dir=checkpoint_dir)
                    _reset_task_progress(scanner.pipeline, time.time())
            else:
                raise

    total_time = time.time() - run_start
    console.print()
    console.print(Rule(style="dim"))

    _save_outputs(
        result, target, objective, scope,
        scanner._active_tasks, scanner.task_label,
        total_time, has_prior_data,
        checkpoint_dir=checkpoint_dir,
    )
    return result


# ─── Output-Speicherung ───────────────────────────────────────────────────────

def _save_outputs(
    result,
    target: str,
    objective: str,
    scope: str,
    active_tasks: list,
    task_label: dict,
    total_time: float = 0.0,
    has_prior_data: bool = False,
    checkpoint_dir: Path | None = None,
) -> None:
    _now        = datetime.now()
    ts          = _now.strftime("%Y%m%d_%H%M%S")
    ts_readable = _now.strftime("%Y-%m-%d %H:%M")
    safe_target = re.sub(r"[^\w.-]", "_", target)

    task_outputs: dict = {}
    if hasattr(result, "tasks_output") and result.tasks_output:
        for i, task_out in enumerate(result.tasks_output):
            label = task_label.get(id(active_tasks[i]), f"task_{i}") if i < len(active_tasks) else f"task_{i}"
            task_outputs[label] = task_out

    # ── Markdown-Bericht ─────────────────────────────────────────────────────
    report_md = ""
    if "report" in task_outputs:
        t = task_outputs["report"]
        if hasattr(t, "pydantic") and t.pydantic:
            report_md = t.pydantic.executive_summary or ""
        if not report_md and hasattr(t, "raw"):
            report_md = t.raw or ""
    if not report_md:
        report_md = str(result.raw) if hasattr(result, "raw") else str(result)

    md_path = os.path.join(LOG_DIR, f"recon_report_{safe_target}_{ts}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"**Target:** {target}  \n**Objective:** {objective}  \n**Scope:** {scope}  \n**Date:** {ts_readable}\n\n---\n\n")
        f.write(report_md)

    # ── Python-Skript ─────────────────────────────────────────────────────────
    py_path  = None
    code_raw = ""
    if "coding" in task_outputs:
        t = task_outputs["coding"]
        if hasattr(t, "pydantic") and t.pydantic and hasattr(t.pydantic, "code"):
            code_raw = t.pydantic.code or ""
        if not code_raw and hasattr(t, "raw"):
            raw = (t.raw or "").strip()
            # Model often wraps JSON in ```json...``` fences — strip and parse
            stripped = re.sub(r"^```(?:json)?\s*\n?", "", raw)
            stripped = re.sub(r"\n?```\s*$", "", stripped).strip()
            try:
                code_raw = json.loads(stripped).get("code", "") or ""
            except Exception:
                code_raw = raw
    if code_raw:
        # Strip Python code fences if the code field itself contains them
        code_raw = re.sub(r"^```(?:python)?\n?", "", code_raw.strip())
        code_raw = re.sub(r"\n?```$", "", code_raw).strip()
    if code_raw:
        py_path = os.path.join(SCAN_DIR, f"scan_{safe_target}_{ts}.py")
        with open(py_path, "w", encoding="utf-8") as f:
            f.write(code_raw)

    # ── JSON-Log ──────────────────────────────────────────────────────────────
    def _snippet(text: str, n: int = 120) -> list[str]:
        text = (text or "").strip()
        return textwrap.wrap(text[:600], width=n) if text else []

    task_summaries = {}
    for name, t in task_outputs.items():
        raw   = (getattr(t, "raw", "") or "").strip()
        entry: dict = {"status": "completed", "preview": _snippet(raw)}
        if hasattr(t, "pydantic") and t.pydantic:
            pd = t.pydantic
            if hasattr(pd, "open_ports"):      entry["open_ports"]      = pd.open_ports
            if hasattr(pd, "vulnerabilities"): entry["vulnerabilities"] = pd.vulnerabilities[:5]
            if hasattr(pd, "cve_references"):  entry["cve_references"]  = pd.cve_references[:5]
            if hasattr(pd, "confirmed_attack_surface"): entry["attack_surface_count"] = len(pd.confirmed_attack_surface)
            if hasattr(pd, "memory_hit"):      entry["memory_hit"]      = pd.memory_hit
            # Feed structured Pydantic output into the trace for validation
            run_trace.set_phase_output(name, pd.model_dump())
        task_summaries[name] = entry

    pipeline = [task_label.get(id(t), "?") for t in active_tasks]
    summary  = {
        "target":    target,
        "objective": objective,
        "scope":     scope,
        "pipeline":  pipeline,
        "timestamp": ts,
        "report":    md_path,
        "memory_hit": has_prior_data,
        "tasks":     task_summaries,
    }

    json_path = os.path.join(LOG_DIR, f"crew_{safe_target}_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    last_path = os.path.join(LOG_DIR, "workflow_last.json")
    with open(last_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # ── Trace File ────────────────────────────────────────────────────────────
    trace_path = None
    if run_trace.is_active:
        trace_data = run_trace.to_dict()
        trace_path = os.path.join(LOG_DIR, f"trace_{safe_target}_{ts}.json")
        with open(trace_path, "w", encoding="utf-8") as f:
            json.dump(trace_data, f, indent=2, ensure_ascii=False)
        run_trace.reset()

    # ── Completion Panel ──────────────────────────────────────────────────────
    mins, secs   = divmod(int(total_time), 60)
    duration_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    blue_out     = task_summaries.get("blue", {})
    ports        = blue_out.get("open_ports", [])
    vulns        = blue_out.get("vulnerabilities", [])
    findings_out = task_summaries.get("findings", {})
    cves         = findings_out.get("cve_references", [])
    # Use the pre-run shallow recall result — LLM-reported memory_hit is unreliable
    # because the deep RecallFlow sub-query analysis may not match stored facts.
    memory_hit   = has_prior_data

    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column(style="dim", min_width=14)
    table.add_column()

    table.add_row("Target",   f"[bold white]{target}[/]")
    table.add_row("Scope",    f"[yellow]{scope}[/]")
    table.add_row("Duration", duration_str)
    table.add_row("Phases",   "  →  ".join(f"[cyan]{p}[/]" for p in pipeline))

    if ports:
        table.add_row("Open Ports", ", ".join(str(p) for p in ports))
    if vulns:
        table.add_row("Findings",   f"[red]{len(vulns)}[/] issue(s) detected")
    else:
        table.add_row("Findings",   "[green]No vulnerabilities confirmed[/]")
    if cves:
        table.add_row("CVEs",       ", ".join(cves[:3]) + (" …" if len(cves) > 3 else ""))

    table.add_row("", "")
    table.add_row("Report",   f"[dim]{md_path}[/]")
    if py_path:
        table.add_row("Script",    f"[dim]{py_path}[/]")
    table.add_row("JSON Log", f"[dim]{json_path}[/]")
    if trace_path:
        table.add_row("Trace",     f"[dim]{trace_path}[/]  [dim](tool calls + raw output)[/]")
    table.add_row("Memory DB", f"[dim]{MEMORY_DIR / 'lancedb'}[/]  [dim](persisted — reused on next run)[/]")
    if checkpoint_dir is not None:
        _ckpt_main = checkpoint_dir / "main"
        if _ckpt_main.exists() and any(_ckpt_main.glob("*.json")):
            table.add_row("Checkpoints", f"[dim]{checkpoint_dir}[/]  [dim](per-task recovery files)[/]")
    hit_label = (
        "[green]hit[/] [dim](prior run data was available for this target)[/]"
        if memory_hit else
        "[dim]miss[/] [dim](no prior data for this target at run start)[/]"
    )
    table.add_row("Memory hit", hit_label)

    console.print()
    console.print(Panel(table, title="[bold green]Assessment Complete[/]", border_style="green", padding=(1, 2)))
    console.print()


# ─── Input Validation ────────────────────────────────────────────────────────

def _validate_target(raw: str) -> tuple[str, str | None]:
    target = raw.strip().lower()
    if not target:
        return "", "Target cannot be empty."
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        if all(0 <= int(p) <= 255 for p in target.split('.')):
            return target, None
        return "", f"Invalid IPv4 address: '{target}'"
    if re.match(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', target):
        return target, None
    if re.match(r'^[a-z0-9][a-z0-9\-]{0,61}$', target):
        return target, None
    return "", f"Invalid target '{raw.strip()}' — enter a domain (e.g. heise.de) or IP."


def _prompt_target() -> str:
    while True:
        raw = Prompt.ask("[bold]Target[/] [dim](domain or IP)[/]")
        target, error = _validate_target(raw)
        if error:
            console.print(f"  [red]✗[/]  {error}")
            continue
        return target


# ─── CLI ─────────────────────────────────────────────────────────────────────

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
            "[bold cyan]AgentScanIT[/]  ·  Agentic Vulnerability Assessment Framework",
            border_style="cyan",
            expand=False,
            padding=(0, 2),
        ))
        console.print()
        _target    = _prompt_target()
        _objective = Prompt.ask(
            "[bold]Objective[/] [dim](what to investigate — Enter for full scan)[/]",
            default="",
        )
        console.print(
            "  [dim]Scopes:[/]  "
            "[cyan]osint[/] [dim]passive only[/]  ·  "
            "[cyan]ssl[/]  ·  "
            "[cyan]quick[/]  ·  "
            "[cyan]web[/]  ·  "
            "[cyan]network[/]  ·  "
            "[cyan]full[/] [dim]all tools[/]"
        )
        _scope = Prompt.ask("[bold]Scope[/]", default="full")

    run(_target, _objective, _scope)
