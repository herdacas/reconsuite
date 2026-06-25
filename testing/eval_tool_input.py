#!/usr/bin/env python3
"""
eval_tool_input.py — Dimension 1: Tool-Input-Korrektheit

Prüft DETERMINISTISCH aus einem trace_*.json, ob jedes Tool valide Argumente bekam:
  - Target-Integrität: das Scan-Target (oder eine plausible Subdomain/IP) steht im command,
    nicht verstümmelt (kein '?', kein '://://', keine doppelten Schrägstriche).
  - Kein leeres / Platzhalter-Argument.
  - Tool-spezifische Flag-Plausibilität (nmap braucht ein Ziel, nuclei -u, nikto -h, ...).

Read-only — liest nur das Trace-Artefakt, ändert nichts am Framework.

Verwendung:
    python3 eval_tool_input.py logs/trace_<target>_<ts>.json
    → druckt input_valid_rate + Liste verdächtiger Calls; exit 0 wenn >= SCHWELLE.
"""
from __future__ import annotations
import json
import re
import sys
from dataclasses import dataclass, field

VALID_RATE_THRESHOLD = 0.95

# Muster die ein verstümmeltes/ungültiges Argument anzeigen (real beobachtet, siehe CLAUDE.md)
_GARBLE_PATTERNS = [
    r"://://",          # whatweb https://://?
    r"\?\s*$",          # Argument endet auf '?' (dnsrecon -d wenum?)
    r"<target>",        # unaufgelöster Platzhalter
    r"https?://\s*$",   # leeres URL-Schema
]

# Tool → minimale Plausibilitätsregel (callable(tokens) -> bool, True = plausibel)
def _has_nonflag_target(tokens: list[str]) -> bool:
    """mind. ein Nicht-Flag-Token nach dem Binary (= ein Ziel-Argument)."""
    return any(not t.startswith("-") for t in tokens[1:])

def _has_flag(flag: str):
    return lambda tokens: flag in tokens

_TOOL_RULES = {
    "nmap":          _has_nonflag_target,
    "nikto":         _has_flag("-h"),
    "nuclei":        _has_flag("-u"),
    "httpx":         lambda t: True,          # httpx liest Targets oft via stdin/-l
    "whatweb":       _has_nonflag_target,
    "sslscan":       _has_nonflag_target,
    "dig":           _has_nonflag_target,
    "whois":         _has_nonflag_target,
    "subfinder":     _has_flag("-d"),
    "dnsrecon":      _has_flag("-d"),
    "curl":          _has_nonflag_target,
    "ping":          _has_nonflag_target,
}


@dataclass
class InputEvalResult:
    trace_path: str
    target: str
    scope: str
    total_calls: int = 0
    valid_calls: int = 0
    issues: list[dict] = field(default_factory=list)

    @property
    def input_valid_rate(self) -> float:
        return self.valid_calls / self.total_calls if self.total_calls else 1.0

    @property
    def passed(self) -> bool:
        return self.input_valid_rate >= VALID_RATE_THRESHOLD


def _target_tokens(target: str) -> set[str]:
    """Akzeptable Host-Bestandteile: der Apex + (für Subdomains) die Registrable-Teile."""
    t = target.lower().strip()
    parts = {t}
    # Subdomains von target sind erlaubt → registrable-Anteil als Substring-Anker
    labels = t.split(".")
    if len(labels) >= 2:
        parts.add(".".join(labels[-2:]))   # 8com.de
    return parts


def evaluate_tool_input(trace_path: str) -> InputEvalResult:
    with open(trace_path) as f:
        trace = json.load(f)
    target = (trace.get("target") or "").lower()
    res = InputEvalResult(trace_path=trace_path, target=target, scope=trace.get("scope", "?"))
    anchors = _target_tokens(target)

    for phase, pdata in trace.get("phases", {}).items():
        for c in pdata.get("tool_calls", []):
            tool = c.get("tool_name", "?")
            tokens = c.get("command") or []
            cmd = " ".join(tokens) if isinstance(tokens, list) else str(tokens)
            cmd_l = cmd.lower()
            res.total_calls += 1
            problems = []

            # 1) Verstümmelungs-Muster
            for pat in _GARBLE_PATTERNS:
                if re.search(pat, cmd_l):
                    problems.append(f"garble:{pat}")

            # 2) Target-Integrität — nur für Tools die ein Netzwerk-Ziel als CLI-ARGUMENT
            #    brauchen. httpx/dnsx/katana bekommen Targets via stdin/Pipe (-l/stdin),
            #    nicht als Argument → kein Host im command erwartbar, korrekt.
            #    searchsploit/nvd_*/ddg nehmen Service-Namen, keinen Host.
            _stdin_tools = {"httpx", "dnsx", "katana"}
            net_tools = (set(_TOOL_RULES) | {"katana", "dnsx"}) - _stdin_tools
            if tool in net_tools:
                host_present = any(a in cmd_l for a in anchors) or bool(
                    re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", cmd_l)  # eine IP ist auch ok
                )
                if not host_present:
                    problems.append("no-target-host")

            # 3) Tool-spezifische Flag-Plausibilität
            rule = _TOOL_RULES.get(tool)
            if rule and isinstance(tokens, list) and not rule(tokens):
                problems.append("flag-implausible")

            if problems:
                res.issues.append({
                    "phase": phase, "tool": tool, "command": cmd[:100], "problems": problems,
                })
            else:
                res.valid_calls += 1
    return res


def print_result(res: InputEvalResult) -> None:
    print(f"=== Dim 1: Tool-Input — {res.trace_path.split('/')[-1]} ===")
    print(f"  target={res.target} scope={res.scope}")
    print(f"  input_valid_rate = {res.input_valid_rate:.3f} "
          f"({res.valid_calls}/{res.total_calls})  "
          f"{'PASS' if res.passed else 'FAIL'} (Schwelle {VALID_RATE_THRESHOLD})")
    if res.issues:
        print(f"  {len(res.issues)} verdächtige Calls:")
        for i in res.issues:
            print(f"    [{i['phase']}] {i['tool']}: {i['problems']}  «{i['command']}»")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: eval_tool_input.py <trace.json> [<trace.json> ...]")
        sys.exit(2)
    all_passed = True
    for path in sys.argv[1:]:
        r = evaluate_tool_input(path)
        print_result(r)
        all_passed &= r.passed
    sys.exit(0 if all_passed else 1)
