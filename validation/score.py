#!/usr/bin/env python3
"""validation/score.py — Phase 3: Scoring-Harness.

Muss mit venv/bin/python laufen (importiert agentscanit.tasks, das crewai
braucht). Für jedes Corpus-Target:
  1. Rehydriert den echten Session-Trace direkt in run_trace._phases (identisches
     Dict-Schema wie trace_*.json -> keine Re-Simulation nötig, 1:1 Ground Truth).
  2. Ruft die HEUTE gebauten/gefixten Guardrail-Funktionen direkt gegen den
     gespeicherten Report-Text auf — das ist gleichzeitig der in Phase 5
     geforderte Nachweis, dass jeder Fix über den GESAMTEN Corpus wirkt (nicht
     nur am ursprünglich beobachteten Einzelfall).
  3. Prüft CVE-Referenzen gegen den NVD-Oracle (FABRICATED-Klasse).
  4. Prüft Subdomains gegen den DNS-Oracle (ORACLE-Klasse).
  5. Prüft open_ports/tools_executed gegen den Trace selbst (Ground Truth,
     ORACLE-Klasse laut field_inventory.md — deterministisch, LLM-unabhängig).

Klassifikation je Feld/Finding: CORRECT, FALSE_POSITIVE, FABRICATED, WRONG_VALUE,
MISSING_VALUE, UNVERIFIABLE, AMBIGUOUS, STALE (siehe VALIDATION_SPEC.md Phase 3).
"""
import glob
import json
import os
import re
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "agentscanit"))
sys.path.insert(0, os.path.join(_ROOT, "validation", "oracles"))

from tools.trace import run_trace  # noqa: E402
import tasks as t  # noqa: E402

import dns_oracle  # noqa: E402
import cve_oracle  # noqa: E402

_CORPUS = os.path.join(_ROOT, "corpus", "fixtures")
_EXPECTED = os.path.join(_ROOT, "corpus", "expected")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


class _FakeTaskOutput:
    """Minimaler Stand-in für CrewAI's TaskOutput — genau die Attribute, die
    die Guardrail-Funktionen lesen (.raw, .pydantic)."""
    def __init__(self, raw, pydantic=None):
        self.raw = raw
        self.pydantic = pydantic


def _load_fixture(target_id: str) -> dict:
    fdir = os.path.join(_CORPUS, target_id)
    with open(os.path.join(fdir, "scanner_trace.json")) as f:
        trace = json.load(f)
    report_path = os.path.join(fdir, "report.md")
    report_text = open(report_path, encoding="utf-8", errors="ignore").read() if os.path.exists(report_path) else ""
    expected_path = os.path.join(_EXPECTED, f"{target_id}.yaml")
    expected_raw = open(expected_path, encoding="utf-8").read() if os.path.exists(expected_path) else ""
    return {"trace": trace, "report_text": report_text, "expected_raw": expected_raw, "fdir": fdir}


def _rehydrate_trace(trace: dict) -> None:
    """Setzt run_trace._phases direkt aus dem Fixture-Trace — 1:1 dasselbe
    Dict-Schema wie trace_*.json (RunTrace.close_phase() befüllt es identisch)."""
    run_trace._active = True
    run_trace._current_scope = trace.get("scope", "")
    run_trace._phases = trace.get("phases", {})
    run_trace._pending = []
    run_trace._guardrail_reject_count = 0


def score_report_guardrails(target_id: str, report_text: str) -> list[dict]:
    """Führt die 3 heute gebauten/erweiterten Report-Guardrails GEGEN DIESEN
    Corpus-Eintrag aus. Ergebnis pro Guardrail: CORRECT (kein Fund -> Report war
    schon sauber) oder FABRICATED (Guardrail hätte abgelehnt -> die Fixture
    enthält eine unbelegte Behauptung, die der Fix VOR seinem Commit-Datum
    nicht gefangen hätte)."""
    results = []
    for name, fn in (
        ("_confirmed_findings_tool_guardrail", t._confirmed_findings_tool_guardrail),
        ("_value_grounding_guardrail", t._value_grounding_guardrail),
    ):
        run_trace._guardrail_reject_count = 0  # jeder Guardrail unabhängig prüfen
        ok, feedback = fn(_FakeTaskOutput(report_text))
        results.append({
            "target": target_id, "check": name,
            "class": "CORRECT" if ok else "FABRICATED",
            "detail": None if ok else str(feedback)[:400],
        })
    return results


def score_tools_executed(target_id: str, trace: dict) -> list[dict]:
    """Prüft tools_executed (blue + red_scan) gegen die ECHTEN Calls DIESER
    Phase im Trace — exakt die Logik von _tools_executed_guardrail, hier gegen
    den kompletten Phasen-Trace (nicht nur _pending) angewendet, da wir offline
    gegen einen abgeschlossenen Trace prüfen."""
    results = []
    for phase_name in ("blue", "red_scan"):
        phase = trace.get("phases", {}).get(phase_name)
        if not phase:
            continue
        claimed = (phase.get("structured_output") or {}).get("tools_executed") or []
        real_used = {c.get("tool_name", "") for c in phase.get("tool_calls", []) if c.get("tool_name")}
        for tool in claimed:
            if not tool:
                continue
            low = tool.lower()
            grounded = any(low == r.lower() or low.startswith(r.lower()) for r in real_used)
            results.append({
                "target": target_id, "check": f"tools_executed[{phase_name}]",
                "field_value": tool,
                "class": "CORRECT" if grounded else "FABRICATED",
                "detail": None if grounded else f"kein Call zu '{tool}' im Trace (real: {sorted(real_used)})",
            })
    return results


def score_subdomains(target_id: str, trace: dict) -> list[dict]:
    """ORACLE-Klasse: jede behauptete Subdomain muss unabhängig via DNS auflösbar
    sein (dns_oracle, 3 unabhängige Resolver, siehe field_inventory.md)."""
    results = []
    research = trace.get("phases", {}).get("research", {})
    subs = (research.get("structured_output") or {}).get("subdomains") or []
    for sub in subs[:15]:  # Rate-Limit-Schonung — Stichprobe reicht für die Quote
        r = dns_oracle.fetch(sub)
        cls = {"RESOLVED": "CORRECT", "NXDOMAIN": "FALSE_POSITIVE",
               "AMBIGUOUS": "AMBIGUOUS"}.get(r["status"], "UNVERIFIABLE")
        results.append({
            "target": target_id, "check": "subdomains", "field_value": sub,
            "class": cls, "detail": r,
        })
    return results


def score_cve_references(target_id: str, trace: dict, report_text: str) -> list[dict]:
    """ORACLE-Klasse: jede CVE-ID im Trace UND im finalen Report muss gegen NVD
    auflösbar sein, sonst FABRICATED."""
    results = []
    ids = set()
    for phase in trace.get("phases", {}).values():
        so = phase.get("structured_output") or {}
        ids.update(so.get("cve_references") or [])
    ids.update(m.group(0).upper() for m in _CVE_RE.finditer(report_text))
    for cve_id in sorted(ids):
        r = cve_oracle.fetch(cve_id)
        cls = "CORRECT" if r["status"] == "EXISTS" else (
            "FABRICATED" if r["status"] == "FABRICATED" else "UNVERIFIABLE")
        results.append({
            "target": target_id, "check": "cve_references", "field_value": cve_id,
            "class": cls, "detail": {"cvss": r.get("cvss"), "severity": r.get("severity")},
        })
    return results


def score_open_ports(target_id: str, trace: dict) -> list[dict]:
    """CROSSCHECK/ORACLE: claimed open_ports (blue-Phase) gegen die tatsächlich
    im nmap-Rawoutput als 'open' markierten Ports (deterministisches Parsing,
    LLM-unabhängige Ground Truth)."""
    results = []
    blue = trace.get("phases", {}).get("blue", {})
    claimed = set((blue.get("structured_output") or {}).get("open_ports") or [])
    nmap_raw = "\n".join(
        c.get("raw_output", "") for c in blue.get("tool_calls", [])
        if c.get("tool_bin") == "nmap"
    )
    real_open = set(int(m.group(1)) for m in re.finditer(r"(\d+)/tcp\s+open", nmap_raw))
    if not nmap_raw:
        return results  # kein nmap-Call in dieser Phase -> nichts zu vergleichen
    for port in claimed:
        cls = "CORRECT" if port in real_open else "FALSE_POSITIVE"
        results.append({"target": target_id, "check": "open_ports", "field_value": port, "class": cls})
    for port in real_open - claimed:
        results.append({"target": target_id, "check": "open_ports", "field_value": port,
                         "class": "FALSE_NEGATIVE", "detail": "im nmap-Output offen, aber nicht gemeldet"})
    return results


def score_target(target_id: str) -> list[dict]:
    fx = _load_fixture(target_id)
    _rehydrate_trace(fx["trace"])
    out = []
    out += score_report_guardrails(target_id, fx["report_text"])
    out += score_tools_executed(target_id, fx["trace"])
    out += score_open_ports(target_id, fx["trace"])
    out += score_cve_references(target_id, fx["trace"], fx["report_text"])
    out += score_subdomains(target_id, fx["trace"])
    run_trace.reset()
    return out


def aggregate(all_results: list[dict]) -> dict:
    from wilson import wilson_ci
    by_check: dict[str, list[dict]] = {}
    for r in all_results:
        by_check.setdefault(r["check"], []).append(r)

    _COUNTS_AS_ERROR = {"FALSE_POSITIVE", "FALSE_NEGATIVE", "WRONG_VALUE",
                         "MISSING_VALUE", "MALFORMED", "FABRICATED"}
    _EXCLUDED = {"UNVERIFIABLE", "AMBIGUOUS", "STALE"}

    per_check = {}
    total_correct, total_n = 0, 0
    for check, rows in by_check.items():
        verifiable = [r for r in rows if r["class"] not in _EXCLUDED]
        correct = sum(1 for r in verifiable if r["class"] == "CORRECT")
        n = len(verifiable)
        ci = wilson_ci(correct, n)
        per_check[check] = {
            **ci,
            "n_total_incl_unverifiable": len(rows),
            "n_unverifiable": sum(1 for r in rows if r["class"] in _EXCLUDED),
            "classes": {c: sum(1 for r in rows if r["class"] == c)
                        for c in set(r["class"] for r in rows)},
        }
        total_correct += correct
        total_n += n

    overall = wilson_ci(total_correct, total_n)
    coverage = total_n / len(all_results) if all_results else None
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "overall": overall,
        "coverage_verifiable_fraction": round(coverage, 4) if coverage is not None else None,
        "n_raw_findings": len(all_results),
        "per_check": per_check,
    }


if __name__ == "__main__":
    targets = sorted(os.path.basename(p) for p in glob.glob(os.path.join(_CORPUS, "*")) if os.path.isdir(p))
    all_results = []
    for tid in targets:
        print(f"--- scoring {tid} ---", file=sys.stderr)
        all_results.extend(score_target(tid))

    report = aggregate(all_results)
    report["raw_findings"] = all_results
    out_path = os.path.join(_ROOT, "reports", "accuracy.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(json.dumps({k: v for k, v in report.items() if k != "raw_findings"}, indent=2, default=str))
    print(f"\n-> {out_path}")
