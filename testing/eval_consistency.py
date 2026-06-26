#!/usr/bin/env python3
"""
eval_consistency.py — Dimension 4: Konsistenz über N Wiederholungen (k-trial)

Aggregiert N Läufe DESSELBEN Targets/Scopes/Modells und misst die Varianz:
  - target_cve_consistency = Anteil der Läufe, die ALLE must_find_cves enthalten (Ziel 1.0)
                             — DAS ist das primäre Pass-Kriterium (die Ziel-CVE muss stabil
                             gefunden werden). Begleit-CVEs schwanken legitim (großer CPE-Pool
                             + NVD-Ranking) → die Gesamt-Jaccard darf NICHT allein entscheiden.
  - cve_jaccard       = mittlere paarweise Jaccard der GESAMT-CVE-Mengen — nur noch INFO,
                        nicht Pass-Kriterium (war zu streng, CLAUDE.md "Offene Harness-Schwachpunkte").
  - port_consistency  = Anteil identischer offene-Ports-Mengen (Ports deterministisch → Ziel 1.0)
  - grade_stddev      = Streuung des Scorecard-Gesamtscores (Ziel ≤ 5.0)

Read-only. Bekommt N (trace, report)-Paare. Grade via quality.score_scan (falls importierbar).

Verwendung:
    python3 eval_consistency.py --pairs trace1.json:report1.md ... [--must-find CVE-... CVE-...]
"""
from __future__ import annotations
import argparse
import itertools
import json
import os
import re
import statistics
import sys

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_PORT_RE = re.compile(r"\b(\d{1,5})/tcp\s+open\b")

# Schwellen (überschreibbar via targets.yaml consistency)
CVE_JACCARD_MIN = 0.8
PORT_CONSISTENCY_MIN = 1.0
GRADE_STDDEV_MAX = 5.0


def _cves_from_report(report_path: str) -> set[str]:
    if not os.path.exists(report_path):
        return set()
    return {m.upper() for m in _CVE_RE.findall(open(report_path, encoding="utf-8").read())}


def _ports_from_trace(trace_path: str) -> frozenset[int]:
    if not os.path.exists(trace_path):
        return frozenset()
    tr = json.load(open(trace_path))
    ports = set()
    for p in tr.get("phases", {}).values():
        for c in p.get("tool_calls", []):
            ports |= {int(m) for m in _PORT_RE.findall(c.get("raw_output", "") or "")}
    return frozenset(ports)


def _grade_score(trace_path: str) -> float | None:
    try:
        import sys as _s
        _s.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agentscanit"))
        from quality import score_scan
        return score_scan(trace_path).total_score
    except Exception:
        return None


def _mean_pairwise_jaccard(sets: list[set]) -> float:
    pairs = list(itertools.combinations(range(len(sets)), 2))
    if not pairs:
        return 1.0
    vals = []
    for i, j in pairs:
        a, b = sets[i], sets[j]
        union = a | b
        vals.append(len(a & b) / len(union) if union else 1.0)  # zwei leere Mengen = identisch
    return statistics.mean(vals)


def evaluate_consistency(pairs: list[tuple[str, str]],
                         must_find: list[str] | None = None) -> dict:
    cve_sets = [_cves_from_report(rep) for _, rep in pairs]
    port_sets = [_ports_from_trace(tr) for tr, _ in pairs]
    grades = [g for g in (_grade_score(tr) for tr, _ in pairs) if g is not None]

    cve_jaccard = _mean_pairwise_jaccard(cve_sets)
    port_consistency = (len(set(port_sets)) == 1) if port_sets else True
    grade_stddev = statistics.pstdev(grades) if len(grades) >= 2 else 0.0

    # Ziel-CVE-Konsistenz: Anteil der Läufe, die ALLE must_find_cves enthalten.
    # None bei TN/feature-Targets (kein must_find) → fließt nicht ins Pass.
    must = {c.upper() for c in (must_find or [])}
    if must:
        hits = sum(1 for s in cve_sets if must <= s)
        target_cve_consistency = hits / len(cve_sets) if cve_sets else None
    else:
        target_cve_consistency = None

    # Pass-Kriterium: Ports deterministisch + Grade stabil + (falls Ziel-CVEs definiert)
    # diese in JEDEM Lauf gefunden. Gesamt-Jaccard ist NICHT mehr Teil des Pass.
    passed = (
        (port_consistency >= PORT_CONSISTENCY_MIN if isinstance(port_consistency, (int, float))
         else port_consistency)
        and grade_stddev <= GRADE_STDDEV_MAX
        and (target_cve_consistency is None or target_cve_consistency >= 1.0)
    )
    return {
        "n_runs": len(pairs),
        "cve_sets": [sorted(s) for s in cve_sets],
        "target_cve_consistency": (round(target_cve_consistency, 3)
                                   if target_cve_consistency is not None else None),
        "must_find": sorted(must),
        "cve_jaccard": round(cve_jaccard, 3),  # nur INFO
        "port_sets": [sorted(s) for s in port_sets],
        "port_consistency": bool(port_consistency),
        "grades": grades,
        "grade_stddev": round(grade_stddev, 2),
        "passed": bool(passed),
    }


def print_result(r: dict) -> None:
    print(f"=== Dim 4: Konsistenz über {r['n_runs']} Läufe ===")
    tcc = r.get("target_cve_consistency")
    if tcc is not None:
        print(f"  Ziel-CVE-Konsistenz: {tcc}  (Ziel 1.0, must_find={r['must_find']})  "
              f"{'✓' if tcc >= 1.0 else '✗'}   [PRIMÄR]")
    else:
        print(f"  Ziel-CVE-Konsistenz: n/a (keine must_find_cves — TN/feature-Target)")
    print(f"  CVE-Jaccard (gesamt): {r['cve_jaccard']}  [nur INFO, nicht Pass-Kriterium]")
    print(f"  Port-Consistency: {r['port_consistency']}  (Ziel identisch)  "
          f"{'✓' if r['port_consistency'] else '✗'}")
    print(f"  Grade-StdDev:     {r['grade_stddev']}  (Ziel ≤ {GRADE_STDDEV_MAX})  "
          f"{'✓' if r['grade_stddev'] <= GRADE_STDDEV_MAX else '✗'}")
    print(f"  CVE-Mengen: {r['cve_sets']}")
    print(f"  Port-Mengen: {r['port_sets']}")
    print(f"  → {'PASS' if r['passed'] else 'FAIL'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", nargs="+", required=True,
                    help="trace.json:report.md Paare (mind. 2)")
    ap.add_argument("--must-find", nargs="*", default=[],
                    help="Ziel-CVE-IDs die in JEDEM Lauf vorkommen müssen (primäres Pass-Kriterium)")
    a = ap.parse_args()
    pairs = []
    for p in a.pairs:
        tr, _, rep = p.partition(":")
        pairs.append((tr, rep))
    r = evaluate_consistency(pairs, must_find=a.must_find)
    print_result(r)
    sys.exit(0 if r["passed"] else 1)
