#!/usr/bin/env python3
"""validation/build_corpus.py — Phase 1: Corpus aus echten trace_*.json aufbauen.

Record-Replay (VALIDATION_SPEC.md Phase 1): nutzt bereits real durchgeführte
Scans dieser Session/dieses Projekts (keine neuen Live-Scans gegen die 7
Targets in scope.yaml). Für jedes Target:
  - meta.yaml           captured_at, target, kategorie, notizen
  - dns/*.json          dig/subfinder/dnsrecon-Rohcalls aus dem Trace
  - http/*.json         httpx/curl/nikto/whatweb-Rohcalls
  - tls/*.json          sslscan-Rohcalls
  - rdap/*.json         whois-Rohcalls (Whois-Freitext, kein echtes RDAP-JSON
                        verfügbar in diesem Projekt — als solches markiert)
  - other/*.json        alles Übrige (nmap, searchsploit, nvd_*, ddg, wafw00f, ...)
  - scanner_output.json der komplette Trace (Ground Truth für Team-1-Felder)
  - report.md           der recon_report/final_report dieses Laufs (Scanner-
                        Ausgabe UNTER TEST — das validiert score.py)

Read-only ggü. logs/ — kopiert nur, ändert nichts am Original.
"""
import json
import os
import shutil
import sys
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOGS = os.path.join(_ROOT, "logs")
_CORPUS = os.path.join(_ROOT, "corpus", "fixtures")

_CATEGORY_TOOLS = {
    "dns":  {"dig", "subfinder", "dnsrecon", "dnsx"},
    "http": {"httpx", "curl", "nikto", "whatweb", "katana", "nuclei", "wafw00f"},
    "tls":  {"sslscan", "testssl"},
    "rdap": {"whois"},
}


def _category_for(tool_bin: str) -> str:
    for cat, tools in _CATEGORY_TOOLS.items():
        if tool_bin in tools:
            return cat
    return "other"


def _newest(pattern_prefix: str, target: str, ext: str) -> str | None:
    import glob
    cands = glob.glob(os.path.join(_LOGS, f"{pattern_prefix}_{target}_*{ext}"))
    return max(cands, key=os.path.getmtime) if cands else None


def _ts_from_name(path: str) -> datetime | None:
    """Extrahiert den '<datum>_<zeit>'-Zeitstempel aus einem Dateinamen wie
    'trace_oldenburg.de_20260912_014331.json' -> datetime(2026,9,12,1,43,31)."""
    base = os.path.basename(path)
    parts = base.rsplit(".", 1)[0].split("_")
    for i in range(len(parts) - 1):
        cand = parts[i] + "_" + parts[i + 1]
        if len(cand) == 15 and cand[:8].isdigit() and cand[9:].isdigit():
            try:
                return datetime.strptime(cand, "%Y%m%d_%H%M%S")
            except ValueError:
                continue
    return None


def _find_session(target: str) -> dict:
    """Findet eine SELBSTKONSISTENTE Session (trace + recon_report exakt
    zeitgleich, final_report als der zeitlich NÄCHSTE danach) statt trace und
    final_report unabhängig voneinander per mtime zu wählen — das paarte sonst
    Dateien aus VERSCHIEDENEN Scan-Läufen (Bug gefunden 2026-09-12, oldenburg.de:
    neuester Trace hatte GAR KEINEN eigenen final_report, die naive mtime-Wahl
    griff den final_report einer älteren, unabhängigen Session).

    Bevorzugt die NEUESTE Session, die einen recon_report hat; ein final_report
    ist optional (manche Sessions erreichen Team 3 nicht) — wird nur übernommen
    wenn er innerhalb von 60 Minuten NACH dem Trace liegt (sonst falsch gepaart).
    """
    import glob
    traces = sorted(
        glob.glob(os.path.join(_LOGS, f"trace_{target}_*.json")),
        key=os.path.getmtime, reverse=True,
    )
    all_final_reports = glob.glob(os.path.join(_LOGS, f"final_report_{target}_*.md"))

    for trace_path in traces:
        t_ts = _ts_from_name(trace_path)
        if t_ts is None:
            continue
        recon_report = _newest("recon_report", target, ".md")
        # Exakt zeitgleicher recon_report (gleiche Session, gleicher Zeitstempel)
        recon_candidates = glob.glob(os.path.join(_LOGS, f"recon_report_{target}_*.md"))
        matching_recon = [r for r in recon_candidates if _ts_from_name(r) == t_ts]
        if not matching_recon:
            continue  # dieser Trace hat keinen eigenen recon_report -> Session verwerfen

        # Nächstgelegener final_report NACH diesem Trace (max. 60 Minuten Fenster)
        best_final, best_delta = None, None
        for fr in all_final_reports:
            fr_ts = _ts_from_name(fr)
            if fr_ts is None or fr_ts < t_ts:
                continue
            delta = (fr_ts - t_ts).total_seconds()
            if delta <= 3600 and (best_delta is None or delta < best_delta):
                best_final, best_delta = fr, delta

        return {
            "trace": trace_path,
            "recon_report": matching_recon[0],
            "final_report": best_final,
        }
    return {"trace": None, "recon_report": None, "final_report": None}


def build_fixture(target_id: str, scan_target: str, category: str, notes: str) -> dict:
    """Baut eine Fixture für ein Target aus dem NEUESTEN vorhandenen Trace.

    target_id: Verzeichnisname (z.B. 'example-com' — Domains mit '.' sind als
                Verzeichnisname unpraktisch, daher normalisiert).
    scan_target: der echte Zielstring wie er in den Dateinamen steht (z.B.
                'example.com' oder '172.17.0.2').
    """
    session = _find_session(scan_target)
    trace_path = session["trace"]
    if not trace_path:
        return {"target_id": target_id, "status": "NO_TRACE_FOUND"}

    # final_report (Team 3, angereichert) bevorzugt, sonst recon_report (Team 1) —
    # aber IMMER aus derselben Session wie der Trace, nie mtime-basiert fremdgepaart.
    report_path = session["final_report"] or session["recon_report"]
    # crew_<target>_<ts>.json trägt denselben Zeitstempel wie trace_<target>_<ts>.json
    # (beide vom selben Team-1-Lauf geschrieben) -> direkt aus dem Trace-Dateinamen ableiten.
    crew_path = os.path.join(_LOGS, os.path.basename(trace_path).replace("trace_", "crew_", 1))
    if not os.path.exists(crew_path):
        crew_path = None

    fdir = os.path.join(_CORPUS, target_id)
    for sub in ("dns", "http", "tls", "rdap", "other"):
        os.makedirs(os.path.join(fdir, sub), exist_ok=True)

    with open(trace_path) as f:
        trace = json.load(f)

    # Rohcalls nach Kategorie sortieren
    per_cat: dict[str, list] = {"dns": [], "http": [], "tls": [], "rdap": [], "other": []}
    for phase_name, phase in trace.get("phases", {}).items():
        for call in phase.get("tool_calls", []):
            entry = dict(call)
            entry["phase"] = phase_name
            per_cat[_category_for(call.get("tool_bin", ""))].append(entry)

    for cat, entries in per_cat.items():
        out_path = os.path.join(fdir, cat, "calls.json")
        with open(out_path, "w") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)

    # Vollständiger Trace = Ground Truth für Team-1-Felder (tools_executed, open_ports, ...)
    shutil.copy(trace_path, os.path.join(fdir, "scanner_trace.json"))
    if report_path:
        shutil.copy(report_path, os.path.join(fdir, "report.md"))
    if crew_path:
        shutil.copy(crew_path, os.path.join(fdir, "crew_output.json"))

    meta = {
        "target_id":     target_id,
        "scan_target":   scan_target,
        "category":      category,
        "captured_at":   datetime.fromtimestamp(
            os.path.getmtime(trace_path), tz=timezone.utc
        ).isoformat(),
        "source_trace":  os.path.basename(trace_path),
        "source_report": os.path.basename(report_path) if report_path else None,
        "notes":         notes,
        "n_tool_calls":  trace.get("total_tool_calls", sum(len(v) for v in per_cat.values())),
        "scope":         trace.get("scope"),
        "pipeline":      trace.get("pipeline"),
    }
    with open(os.path.join(fdir, "meta.yaml"), "w") as f:
        # Kein YAML-Lib-Zwang — einfaches, valides YAML von Hand (nur scalare Werte + eine Liste)
        for k, v in meta.items():
            if isinstance(v, list):
                f.write(f"{k}:\n")
                for item in v:
                    f.write(f"  - {item}\n")
            else:
                f.write(f"{k}: {json.dumps(v, ensure_ascii=False)}\n")

    return {"target_id": target_id, "status": "OK", "trace": trace_path,
            "report": report_path, "n_calls": meta["n_tool_calls"]}


TARGETS = [
    # (target_id, scan_target, category, notes)
    ("example-com",      "example.com",        "external_readonly",
     "IANA-reserviert, seit Session-Beginn wiederholt als Test-Target genutzt."),
    ("scanme-nmap-org",  "scanme.nmap.org",     "external_readonly",
     "Nmap-Projekt-eigenes, explizit für Scans freigegebenes Ziel. Ground Truth "
     "(CLAUDE.md, 2026-06-18): OpenSSH 6.6.1p1 + Apache httpd 2.4.7 (Ubuntu 2014) "
     "→ CVE-2018-15473, CVE-2016-10009/10010."),
    ("oldenburg-de",     "oldenburg.de",        "external_readonly",
     "Im Projekt wiederholt gescannt (deutsche Kommune, CLAUDE.md-Historie)."),
    ("westerstede-de",   "westerstede.de",      "external_readonly",
     "Im Projekt wiederholt gescannt (deutsche Kommune, CLAUDE.md-Historie)."),
    ("rastede-de",       "rastede.de",          "external_readonly",
     "Ground Truth (CLAUDE.md, 2026-09-11): OpenSSH 9.6p1 → CVE-2024-6387 "
     "(regreSSHion, CVSS 8.1) real zutreffend."),
    ("cloudflare-com",   "www.cloudflare.com",  "external_readonly",
     "Heute in dieser Session gescannt (Test-Matrix-Nachtrag) — deckte den "
     "tools_executed-Fabrikationsfall (wafw00f) auf."),
    ("nginx-baseline",   "172.17.0.2",          "lab_networks",
     "Docker-Container nginx:alpine, testing/targets.yaml#nginx-clean-baseline. "
     "TN-Baseline: erwartet minimale Angriffsfläche (Port 80 only)."),
]

if __name__ == "__main__":
    results = [build_fixture(*t) for t in TARGETS]
    for r in results:
        print(r)
    n_ok = sum(1 for r in results if r["status"] == "OK")
    print(f"\n{n_ok}/{len(results)} Fixtures gebaut.")
    sys.exit(0 if n_ok == len(results) else 1)
