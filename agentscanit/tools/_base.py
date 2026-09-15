"""Shared helpers for all tool modules.

Naming note: the module-level function below is also called `_run`, which is the same
name as the BaseTool interface method that each tool class must implement. Within a tool
class method, `_run(cmd)` (no `self.`) calls this subprocess helper; `self._run(...)` would
call the class method itself. Python resolves the two correctly via scope, but readers
should be aware of this intentional name overlap — both follow the CrewAI `_run` convention.
"""

import subprocess
import threading
import time
from config import OUTPUT_LIMITS, TIMEOUT_DEFAULT

# ─── Aktive Subprozess-Registry (Ctrl+C-Fix, 2026-09-12) ──────────────────────
# Beobachtung: "Strg+C wirkt nicht" während langer Tool-Scans (dokumentiert seit
# Phase 7, nie gefixt). Root Cause: subprocess.run(..., timeout=...) blockiert in
# Popen.wait()/communicate() — läuft dieser Call in einem CrewAI-Worker-Thread
# (native Tool-Calling läuft nicht im Main-Thread), erreicht ein SIGINT dort NICHT
# den Python-Interpreter (Signal-Handler feuern in CPython nur im Main-Thread) —
# das Programm wartet weiter bis der Subprozess selbst fertig ist oder der
# Timeout greift, auch nach Strg+C. `kill -9` auf den Python-Prozess wirkt (Doku),
# weil das den Prozess (nicht nur den Signal-Handler) hart beendet.
# Fix: jeder laufende Subprozess wird hier registriert. Ein im Main-Thread
# installierter SIGINT-Handler (main.py) kann dadurch JEDEN aktiven Subprozess
# direkt per os-Signal beenden — das lässt den blockierenden communicate()-Call
# im Worker-Thread sofort zurückkehren (die Pipe des Kindes schließt), unabhängig
# davon in welchem Thread er hängt.
_active_procs: set[subprocess.Popen] = set()
_active_procs_lock = threading.Lock()


def _register_proc(proc: subprocess.Popen) -> None:
    with _active_procs_lock:
        _active_procs.add(proc)


def _unregister_proc(proc: subprocess.Popen) -> None:
    with _active_procs_lock:
        _active_procs.discard(proc)


def kill_all_active_procs() -> int:
    """Terminiert alle aktuell laufenden Tool-Subprozesse. Für den SIGINT-Handler
    in main.py — gibt die Anzahl beendeter Prozesse zurück."""
    with _active_procs_lock:
        procs = list(_active_procs)
    for proc in procs:
        try:
            proc.terminate()
        except Exception:
            pass
    return len(procs)

# Output patterns that indicate the tool printed a help/usage page instead of
# actual results — typically caused by an unknown CLI flag. We surface these
# as TOOL_ERROR so agents can skip and the trace records is_error=true.
_CLI_ERROR_PATTERNS = (
    "flag provided but not defined",
    "Error: unknown flag",
    "Error: unknown shorthand flag",
    "Usage:\n  ",         # most CLI tools start their help with this prefix
    "QUITTING!",          # nmap's fatal-error marker (bad port spec, bad target, etc.)
)


def _run(cmd: list[str], timeout: int = TIMEOUT_DEFAULT, cwd: str = None,
         stdin: str = None) -> str:
    """Run a command and return stdout.

    Errors are returned as '[TOOL_ERROR] tool: reason' so agents can detect
    failure and skip to the next tool instead of retrying.
    """
    # Deferred import avoids circular dependency at module load time
    # (trace.py is part of the tools package but must not be imported at the top level).
    from tools.trace import run_trace

    tool = cmd[0].split("/")[-1] if cmd else "unknown"
    t0 = time.time()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )
        _register_proc(proc)
        try:
            stdout, stderr = proc.communicate(input=stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        out = stdout.strip()
        stderr_s = stderr.strip()
        # BUG (2026-09-15, gmx.de-Live-Fund): stderr wurde bisher NUR benutzt wenn
        # stdout komplett leer war — ein Tool, das zuerst eine harmlose Banner-Zeile
        # nach stdout schreibt und DANACH mit einer Fehlermeldung auf stderr abbricht
        # (z.B. nmap: Startbanner auf stdout, dann "QUITTING!" auf stderr bei
        # ungültigem Port-Argument), rutschte durch — stdout war nicht leer, stderr
        # wurde komplett verworfen, kein [TOOL_ERROR] erkannt. Fix: die
        # Fehlermuster-Prüfung läuft jetzt immer gegen stdout+stderr kombiniert;
        # das bisherige "stdout leer -> stderr als Ergebnis nutzen"-Verhalten
        # (für Tools die normale Ausgaben auf stderr schreiben) bleibt unverändert.
        if not out and stderr_s:
            out = stderr_s
            check_text = out
        else:
            check_text = f"{out}\n{stderr_s}" if stderr_s else out
        if any(p in check_text for p in _CLI_ERROR_PATTERNS):
            out = f"[TOOL_ERROR] {tool}: invalid flags or arguments — {check_text[:200]}"
        run_trace.record_execution(cmd, out, time.time() - t0)
        return out
    except subprocess.TimeoutExpired:
        out = f"[TOOL_ERROR] {tool}: timeout after {timeout}s"
        run_trace.record_execution(cmd, out, time.time() - t0)
        return out
    except FileNotFoundError:
        out = f"[TOOL_ERROR] {tool}: binary not found — is it installed?"
        run_trace.record_execution(cmd, out, time.time() - t0)
        return out
    except Exception as e:
        # Hinweis Ctrl+C-Fall: kill_all_active_procs() (main.py-SIGINT-Handler)
        # ruft proc.terminate() extern auf — communicate() kehrt dadurch normal
        # zurück (kein Exception-Pfad hier), sobald der Subprozess beendet ist;
        # der Main-Thread beendet den ganzen Python-Prozess kurz danach ohnehin
        # per os._exit(). Dieser except-Zweig fängt echte Popen/communicate-Fehler.
        out = f"[TOOL_ERROR] {tool}: {e}"
        run_trace.record_execution(cmd, out, time.time() - t0)
        return out
    finally:
        if proc is not None:
            _unregister_proc(proc)


def _limit(text: str, key: str = "default") -> str:
    cap = OUTPUT_LIMITS.get(key, OUTPUT_LIMITS["default"])
    return text[:cap] if text else ""
