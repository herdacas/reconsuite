#!/usr/bin/env python3
"""
eval_groundtruth.py — Dimension 3: Ground-Truth-Treffer (Recall / Precision-Proxy / TN)

Vergleicht den Report eines Scans gegen die Soll-Liste aus targets.yaml:
  - RECALL  = gefundene Soll-CVEs / alle Soll-CVEs  (Ziel: 1.0 für die designierten Ziel-CVEs)
  - FORBID-Check = keine der forbid_cves erscheint
  - TN-Check (kind=tn) = KEINE versions-verifizierte CVE im Report (CLEAN-Target)
  - PORTS = alle expected_ports tauchen im Report/Trace auf

Read-only. Liest final_report_*.md (bevorzugt) oder recon_report_*.md + trace_*.json (Ports).

Verwendung:
    python3 eval_groundtruth.py --target <id> --report <report.md> [--trace <trace.json>]
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys

import yaml

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_targets() -> dict:
    with open(os.path.join(_HERE, "targets.yaml")) as f:
        data = yaml.safe_load(f)
    return {t["id"]: t for t in data["targets"]}


def _report_cves(report_text: str) -> set[str]:
    """Alle CVE-IDs im Report (egal in welcher Sektion)."""
    return {m.upper() for m in _CVE_RE.findall(report_text)}


def _version_verified_cves(report_text: str) -> set[str]:
    """CVEs OBERHALB der '⚠️ ... OHNE Versions-Bestätigung'-Sektion (BUG-17).

    Für den TN-Check zählt nur, was als bestätigtes Finding dargestellt wird —
    versionslose/unbestätigte CVEs sind explizit als spekulativ markiert.
    """
    cut = re.split(r"⚠️.*?(OHNE Versions-Bestätigung|UNBESTÄTIGT)", report_text, maxsplit=1)
    confirmed_part = cut[0]
    return {m.upper() for m in _CVE_RE.findall(confirmed_part)}


def evaluate_groundtruth(target_id: str, report_path: str, trace_path: str | None = None) -> dict:
    targets = _load_targets()
    if target_id not in targets:
        raise SystemExit(f"Unbekanntes Target '{target_id}'. Bekannt: {list(targets)}")
    spec = targets[target_id]
    report = open(report_path, encoding="utf-8").read() if os.path.exists(report_path) else ""

    found = _report_cves(report)
    verified = _version_verified_cves(report)
    must = {c.upper() for c in spec.get("must_find_cves", [])}
    forbid = {c.upper() for c in spec.get("forbid_cves", [])}
    # allow_cves: bei TN-Targets bekannte, reale CVEs die toleriert werden (z.B. nginx:alpine
    # hat ein echtes, tool-bestätigtes CVE — kein Framework-Fehler). Dokumentiert die Realität,
    # statt das Target als "unsauber" zu werten. NUR explizit gelistete IDs sind erlaubt.
    allow = {c.upper() for c in spec.get("allow_cves", [])}

    recall_hits = must & found
    recall = len(recall_hits) / len(must) if must else None
    forbid_hits = forbid & found

    # Ports
    port_status = {}
    if trace_path and os.path.exists(trace_path):
        tr = json.load(open(trace_path))
        rawall = " ".join(c.get("raw_output", "") or ""
                          for p in tr.get("phases", {}).values()
                          for c in p.get("tool_calls", []))
        for port in spec.get("expected_ports", []):
            port_status[port] = (f"{port}/tcp" in rawall) or (str(port) in report)

    result = {
        "target": target_id, "kind": spec["kind"],
        "must_find": sorted(must), "found_required": sorted(recall_hits),
        "missing_required": sorted(must - found),
        "recall": recall,
        "forbid_violations": sorted(forbid_hits),
        "port_status": port_status,
    }

    if spec["kind"] == "tn":
        # True-Negative: keine versions-verifizierte CVE erlaubt — AUSSER explizit in
        # allow_cves gelistete, bekannte reale CVEs (z.B. nginx:alpine HTTP/3-UAF).
        unexpected = verified - allow
        result["tn_verified_cves"] = sorted(verified)
        result["tn_allowed_cves"] = sorted(verified & allow)
        result["tn_unexpected_cves"] = sorted(unexpected)
        result["tn_clean"] = (len(unexpected) == 0)
        result["passed"] = result["tn_clean"] and not forbid_hits
    else:
        result["passed"] = (recall == 1.0 if must else True) and not forbid_hits

    return result


def print_result(r: dict) -> None:
    print(f"=== Dim 3: Ground-Truth — {r['target']} (kind={r['kind']}) ===")
    if r["kind"] == "tn":
        allowed = r.get("tn_allowed_cves", [])
        unexpected = r.get("tn_unexpected_cves", r["tn_verified_cves"])
        allow_note = f", davon {len(allowed)} bekannt-erlaubt {allowed}" if allowed else ""
        print(f"  TN-Check: {len(r['tn_verified_cves'])} versions-verifizierte CVE(s){allow_note} "
              f"→ {'CLEAN' if r['tn_clean'] else 'VERLETZT (unerwartet): ' + str(unexpected)}")
    else:
        print(f"  Recall: {r['recall']}  gefunden={r['found_required']}  fehlt={r['missing_required']}")
    if r["forbid_violations"]:
        print(f"  ⚠️ Verbotene CVEs gefunden: {r['forbid_violations']}")
    if r["port_status"]:
        print(f"  Ports: " + ", ".join(f"{p}={'✓' if ok else '✗'}" for p, ok in r["port_status"].items()))
    print(f"  → {'PASS' if r['passed'] else 'FAIL'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--trace", default=None)
    a = ap.parse_args()
    r = evaluate_groundtruth(a.target, a.report, a.trace)
    print_result(r)
    sys.exit(0 if r["passed"] else 1)
