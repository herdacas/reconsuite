"""
tools/trace.py — Run-level tracer for benchmark and manual validation.

Captures every tool execution during a crew run:
  - command/query actually sent out      (OPSEC: outgoing metadata)
  - agent-chosen parameters              (LLM decision quality)
  - raw output received                  (ground truth for report validation)
  - structured Pydantic output per phase (what ended up in the report)
  - timing per call and per phase

The gap between raw_output and structured_output reveals whether the agent
summarised correctly, dropped findings, or introduced information not present
in the raw data.

Output: logs/trace_<target>_<ts>.json

Usage (handled automatically by main.py / _base.py):
    from tools.trace import run_trace
    run_trace.activate(target, objective, scope, pipeline)
    # ... crew run ...
    run_trace.close_phase("blue")
    run_trace.set_phase_output("blue", pydantic_obj.model_dump())
    data = run_trace.to_dict()
    run_trace.reset()
"""

import time
from typing import Optional


class RunTrace:
    """Collects tool call data across a complete crew run.

    Lifecycle per run:
        activate()            — main.run(), before crew.kickoff()
        record_agent_action() — step_callback (AgentAction: LLM intent)
        record_execution()    — _base._run() or tool directly (actual execution)
        close_phase()         — _on_task_done() (attribute pending calls to phase)
        set_phase_output()    — _save_outputs() (add Pydantic output to phase)
        to_dict()             — _save_outputs() (serialise for JSON file)
        reset()               — _save_outputs() (clean up for next run)
    """

    def __init__(self):
        self._active:              bool            = False
        self._meta:                dict            = {}
        self._phases:              dict            = {}
        self._pending:             list            = []   # calls not yet attributed to a phase
        self._current_agent_call:  Optional[dict]  = None
        self._run_start:           float           = 0.0
        self._call_seq:            int             = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def activate(self, target: str, objective: str, scope: str, pipeline: list) -> None:
        """Start a new trace for a crew run."""
        self._active       = True
        self._meta         = {"target": target, "objective": objective,
                               "scope": scope,   "pipeline": pipeline}
        self._phases       = {p: {"tool_calls": [], "structured_output": None}
                               for p in pipeline}
        self._pending      = []
        self._current_agent_call = None
        self._run_start    = time.time()
        self._call_seq     = 0

    @property
    def is_active(self) -> bool:
        return self._active

    def reset(self) -> None:
        """Reset to blank state after a run completes."""
        self.__init__()

    # ── Recording ─────────────────────────────────────────────────────────────

    def record_agent_action(self, tool: str, tool_input) -> None:
        """Capture the LLM's intent just before a tool is called.

        Called from step_callback when step_output is an AgentAction.
        Stored temporarily and merged into the next record_execution() call.
        """
        if not self._active:
            return
        self._current_agent_call = {"tool_name": tool, "agent_params": tool_input}

    def record_execution(self, command, raw_output: str, duration_s: float) -> None:
        """Capture an actual tool execution.

        Args:
            command:    list[str] for subprocess calls, or a descriptive string/dict
                        for library calls (e.g. DdgSearch).
            raw_output: the full output before any _limit() truncation.
            duration_s: wall-clock seconds for the call.

        Called from _base._run() (subprocess tools) or directly from tools that
        use Python libraries instead of subprocesses (e.g. DdgSearchTool).
        """
        if not self._active:
            return
        self._call_seq += 1

        # Derive a human-readable binary/tool name from the command
        if isinstance(command, list) and command:
            tool_bin = command[0].split("/")[-1]
        elif isinstance(command, str):
            tool_bin = command
        else:
            tool_bin = "unknown"

        entry: dict = {
            "seq":              self._call_seq,
            "tool_bin":         tool_bin,
            "command":          command,
            # raw_output capped at 4000 chars — same ceiling as the largest OUTPUT_LIMIT.
            # raw_output_chars records the true length so the analyst knows if truncation occurred.
            "raw_output":       raw_output[:4000],
            "raw_output_chars": len(raw_output),
            "duration_s":       round(duration_s, 2),
            "is_error":         raw_output.startswith("[TOOL_ERROR]"),
        }

        # Merge with the most recent AgentAction if one was recorded just before this call.
        # This links the LLM's intent (tool_name, agent_params) to the actual execution.
        if self._current_agent_call:
            entry["tool_name"]    = self._current_agent_call["tool_name"]
            entry["agent_params"] = self._current_agent_call["agent_params"]
            self._current_agent_call = None
        else:
            entry["tool_name"]    = tool_bin
            entry["agent_params"] = None

        self._pending.append(entry)

    # ── Phase Management ──────────────────────────────────────────────────────

    def close_phase(self, phase: str) -> None:
        """Attribute all pending tool calls to a completed phase.

        Called from _on_task_done() immediately after a task finishes.
        Any calls in _pending belong to the phase that just ended.
        """
        if not self._active:
            return
        if phase not in self._phases:
            self._phases[phase] = {"tool_calls": [], "structured_output": None}
        self._phases[phase]["tool_calls"].extend(self._pending)
        self._pending.clear()

    def set_phase_output(self, phase: str, output: dict) -> None:
        """Store the Pydantic-structured output for a phase.

        Called from _save_outputs() after task_outputs are available.
        Enables direct comparison: raw_output (tool calls) vs structured_output (report input).
        """
        if not self._active or phase not in self._phases:
            return
        self._phases[phase]["structured_output"] = output

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return the complete trace as a JSON-serialisable dict."""
        total_calls = sum(len(p["tool_calls"]) for p in self._phases.values())
        error_calls = sum(
            1 for p in self._phases.values()
            for c in p["tool_calls"] if c.get("is_error")
        )
        return {
            **self._meta,
            "total_duration_s": round(time.time() - self._run_start, 1),
            "total_tool_calls": total_calls,
            "error_calls":      error_calls,
            "phases":           self._phases,
        }


# Module-level singleton — shared by _base.py, agents.py, and main.py
run_trace = RunTrace()
