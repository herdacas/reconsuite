"""Shared helpers for all tool modules.

Naming note: the module-level function below is also called `_run`, which is the same
name as the BaseTool interface method that each tool class must implement. Within a tool
class method, `_run(cmd)` (no `self.`) calls this subprocess helper; `self._run(...)` would
call the class method itself. Python resolves the two correctly via scope, but readers
should be aware of this intentional name overlap — both follow the CrewAI `_run` convention.
"""

import subprocess
import time
from config import OUTPUT_LIMITS, TIMEOUT_DEFAULT

# Output patterns that indicate the tool printed a help/usage page instead of
# actual results — typically caused by an unknown CLI flag. We surface these
# as TOOL_ERROR so agents can skip and the trace records is_error=true.
_CLI_ERROR_PATTERNS = (
    "flag provided but not defined",
    "Error: unknown flag",
    "Error: unknown shorthand flag",
    "Usage:\n  ",         # most CLI tools start their help with this prefix
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
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=stdin,
        )
        out = result.stdout.strip()
        if not out and result.stderr.strip():
            out = result.stderr.strip()
        if any(p in out for p in _CLI_ERROR_PATTERNS):
            out = f"[TOOL_ERROR] {tool}: invalid flags or arguments — {out[:120]}"
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
        out = f"[TOOL_ERROR] {tool}: {e}"
        run_trace.record_execution(cmd, out, time.time() - t0)
        return out


def _limit(text: str, key: str = "default") -> str:
    cap = OUTPUT_LIMITS.get(key, OUTPUT_LIMITS["default"])
    return text[:cap] if text else ""
