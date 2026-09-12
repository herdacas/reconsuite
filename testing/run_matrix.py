#!/usr/bin/env python3
"""
run_matrix.py — Orchestrierung des Truth-&-Consistency-Testharness

Pro Target: Container-Lifecycle (start → ready-probe → N Scans → stop) bzw. live-Scan,
dann alle eval_*.py über die erzeugten Artefakte. Schreibt einen Matrix-Report
(JSON + Markdown) nach testing/results/.

WICHTIG:
- Container laufen über snap-Docker → Pfade müssen unter /root liegen (siehe CLAUDE.md).
- Läuft im aktuell konfigurierten Modus (REMOTE wenn ollama_api_key gesetzt, sonst LOCAL).
- scanme.nmap.org: max. 12 Scans/Tag — bei N=4 sparsam (Skript warnt).

Verwendung:
    python3 run_matrix.py --smoke                 # 1 Target × 1 Lauf (Container-Test)
    python3 run_matrix.py --targets tomcat-cve-2017-12615 nginx-clean-baseline --runs 4
    python3 run_matrix.py --all --runs 4          # volle Matrix
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_LOGS = os.path.join(_ROOT, "logs")
_RESULTS = os.path.join(_HERE, "results")
_VENV_PY = os.path.join(_ROOT, "venv", "bin", "python3")

sys.path.insert(0, _HERE)
import yaml  # noqa: E402


def _load() -> dict:
    return yaml.safe_load(open(os.path.join(_HERE, "targets.yaml")))


def _sh(cmd: str, timeout: int = 60) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def _probe(url: str, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=5)
            return True
        except Exception as e:
            # 4xx/5xx zählt auch als "Server antwortet"
            if hasattr(e, "code"):
                return True
            time.sleep(3)
    return False


def _container_ip(name: str) -> str | None:
    rc, out = _sh("docker inspect -f "
                  "'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + name)
    ip = out.strip()
    return ip if rc == 0 and ip else None


def container_up(spec: dict) -> tuple[bool, str | None]:
    """Startet den Container. Gibt (ok, scan_target) zurück.

    scan_target ist die Container-IP wenn use_container_ip gesetzt ist (Isolation:
    nur der Container ist sichtbar, keine Host-Dienste), sonst spec.scan_target.
    """
    name = spec.get("container_name")
    if not name:
        return True, spec.get("scan_target")
    _sh(f"docker rm -f {name} 2>/dev/null")
    img = spec.get("docker_image", "")
    if img and "/" in img and ":" in img:
        if _sh(f"docker image inspect {img}")[0] != 0:
            print(f"    pull {img} ...")
            _sh(f"docker pull {img}", timeout=600)
    print(f"    start {name} ...")
    rc, out = _sh(spec["docker_run_cmd"], timeout=600)
    if rc != 0:
        print(f"    ✗ start fehlgeschlagen: {out[:200]}")
        return False, None

    scan_target = spec.get("scan_target")
    if spec.get("use_container_ip"):
        time.sleep(3)
        ip = _container_ip(name)
        if not ip:
            print("    ✗ Container-IP nicht ermittelbar")
            return False, None
        scan_target = ip
        print(f"    Container-IP: {ip} (isoliert — nur Container sichtbar)")

    probe = spec.get("ready_probe")
    if spec.get("use_container_ip") and not probe:
        probe = f"http://{scan_target}/"      # Container-IP-Probe dynamisch
    if probe:
        ok = _probe(probe, spec.get("ready_timeout_s", 60))
        print(f"    ready-probe {probe}: {'✓' if ok else '✗ timeout'}")
        return ok, scan_target
    return True, scan_target


def container_down(spec: dict) -> None:
    name = spec.get("container_name")
    if name:
        _sh(f"docker rm -f {name} 2>/dev/null")
        print(f"    stop {name}")


def _newest(pattern_target: str, prefix: str, ext: str, after_ts: float) -> str | None:
    """Neueste Datei prefix_<safe_target>_*.ext die NACH after_ts erstellt wurde.

    Robust: exakter Match auf den safe-formatierten Target-String (wie main.py:
    re.sub(r'[^\\w.-]','_',target)) + Zeitschranke. Für llm_debug (Target=PID/leer)
    wird auf reinen Prefix-Match + Zeit zurückgefallen.
    """
    import glob, re
    cands = []
    if pattern_target:
        safe = re.sub(r"[^\w.-]", "_", pattern_target)
        glob_pat = os.path.join(_LOGS, f"{prefix}_{safe}_*{ext}")
    else:
        glob_pat = os.path.join(_LOGS, f"{prefix}_*{ext}")
    for f in glob.glob(glob_pat):
        if os.path.getmtime(f) >= after_ts - 2:
            cands.append(f)
    return max(cands, key=os.path.getmtime) if cands else None


def run_scan(target: str, scope: str, objective: str = "matrix-scan") -> dict:
    """Einen Scan ausführen, Pfade der erzeugten Artefakte zurückgeben.

    objective steuert objective-getriggerte Tools (API-Erkennung, Misconfig-Checks) —
    feature-Targets setzen es passend (z.B. 'API-Services erkennen')."""
    t0 = time.time()
    env = dict(os.environ, RECON_LLM_DEBUG="1")
    cmd = [_VENV_PY, os.path.join(_ROOT, "main.py"), target, objective, scope]
    p = subprocess.run(cmd, cwd=_ROOT, env=env, capture_output=True, text=True, timeout=2400)
    return {
        "trace": _newest(target, "trace", ".json", t0),
        "report": (_newest(target, "final_report", ".md", t0)
                   or _newest(target, "recon_report", ".md", t0)),
        "crew": _newest(target, "crew", ".json", t0),
        "debug": _newest(str(os.getpid()), "llm_debug", ".jsonl", t0)
                 or _newest("", "llm_debug", ".jsonl", t0),
        "exit": p.returncode,
        "dur_s": round(time.time() - t0, 1),
        # 2026-09-12-Fund: bei exit!=0 wurde stdout/stderr bisher nirgends
        # ausgegeben — ein Fehlschlag ließ sich nur durch manuelle Reproduktion
        # diagnostizieren (siehe CLAUDE.md, waf-cloudflare-Matrixlauf). Letzte
        # 2000 Zeichen genügen für die üblichen Traceback/ValidationError-Fälle.
        "tail": (p.stdout + p.stderr)[-2000:] if p.returncode != 0 else "",
    }


def _eval(script: str, args: list[str]) -> dict:
    cmd = [_VENV_PY, os.path.join(_HERE, script)] + args
    p = subprocess.run(cmd, cwd=os.path.join(_ROOT, "agentscanit"),
                       capture_output=True, text=True, timeout=300)
    return {"passed": p.returncode == 0, "output": (p.stdout + p.stderr).strip()}


def evaluate_run(target_id: str, spec: dict, artifacts: dict) -> dict:
    out = {}
    tr, rep, crew = artifacts.get("trace"), artifacts.get("report"), artifacts.get("crew")
    if tr:
        out["dim1_input"] = _eval("eval_tool_input.py", [tr])
    if tr and crew:
        out["dim2_output"] = _eval("eval_tool_output.py", [tr, crew])
    # feature-Targets (WAF/API/Misconfig) haben keine CVE-Ground-Truth → kein Dim3-Recall,
    # stattdessen: erscheint die erwartete Feature-Signatur im Report ODER Trace?
    if spec.get("kind") == "feature":
        out["feature"] = _eval_feature(spec, tr, rep)
    elif rep:
        gargs = ["--target", target_id, "--report", rep] + (["--trace", tr] if tr else [])
        out["dim3_groundtruth"] = _eval("eval_groundtruth.py", gargs)
    return out


def _eval_feature(spec: dict, trace: str | None, report: str | None) -> dict:
    """Deterministisch: jede in expect_signatures gelistete Zeichenkette muss im
    Report ODER im Trace-Roh-Output vorkommen. Kein LLM. Read-only."""
    sigs = spec.get("expect_signatures", [])
    haystack = ""
    for path in (report, trace):
        if path and os.path.exists(path):
            haystack += open(path, encoding="utf-8", errors="ignore").read()
    found = {s: (s in haystack) for s in sigs}
    passed = bool(sigs) and all(found.values())
    out = "=== Feature-Check: " + spec["id"] + " ===\n"
    for s, ok in found.items():
        out += f"  {'✓' if ok else '✗'} '{s}'\n"
    out += f"  → {'PASS' if passed else 'FAIL'}"
    return {"passed": passed, "output": out}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true", help="1 Target × 1 Lauf")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--targets", nargs="*", default=[])
    ap.add_argument("--runs", type=int, default=None)
    a = ap.parse_args()

    cfg = _load()
    by_id = {t["id"]: t for t in cfg["targets"]}
    n_runs = a.runs or cfg["consistency"]["n_runs"]

    if a.smoke:
        sel, n_runs = ["nginx-clean-baseline"], 1
    elif a.all:
        sel = list(by_id)
    elif a.targets:
        sel = a.targets
    else:
        print("Nichts ausgewählt. --smoke / --all / --targets ...")
        sys.exit(2)

    os.makedirs(_RESULTS, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    matrix = {"timestamp": ts, "n_runs": n_runs, "targets": {}}

    for tid in sel:
        spec = by_id[tid]
        print(f"\n### Target: {tid} ({spec['kind']}, {spec['lifecycle']}, n={n_runs}) ###")
        if spec.get("rate_limit_note"):
            print(f"  ⚠️ {spec['rate_limit_note']}")

        is_docker = spec["lifecycle"].startswith("docker")
        scan_target = spec.get("scan_target")
        if is_docker:
            ok, scan_target = container_up(spec)
            if not ok:
                matrix["targets"][tid] = {"error": "container_start_failed"}
                container_down(spec)
                continue

        runs = []
        try:
            for i in range(n_runs):
                print(f"  Lauf {i+1}/{n_runs} (target={scan_target}) ...")
                art = run_scan(scan_target, spec["scope"],
                               objective=spec.get("objective", "matrix-scan"))
                # exit≠0-Filter: bei fehlgeschlagenem Scan NICHT evaluieren — sonst greift
                # _newest auf einen alten Report aus einem früheren Lauf und verfälscht Dim3.
                if art["exit"] == 0:
                    ev = evaluate_run(tid, spec, art)
                    failed = False
                else:
                    ev = {}
                    failed = True
                runs.append({"artifacts": art, "eval": ev, "failed": failed})
                print(f"    exit={art['exit']} dur={art['dur_s']}s "
                      f"trace={'✓' if art['trace'] else '✗'} report={'✓' if art['report'] else '✗'}"
                      f"{'  [FAILED → nicht ausgewertet]' if failed else ''}")
                if failed and art.get("tail"):
                    print(f"    ↳ letzte Ausgabe:\n" + "\n".join(
                        f"      {ln}" for ln in art["tail"].splitlines()[-15:]
                    ))
        finally:
            if is_docker:
                container_down(spec)

        # Dim 4 Konsistenz über die N Läufe — NUR erfolgreiche Läufe (exit==0),
        # sonst würde ein alter Report aus einem Fehllauf die Jaccard-Konsistenz verfälschen.
        pairs = [f"{r['artifacts']['trace']}:{r['artifacts']['report']}"
                 for r in runs
                 if not r.get("failed")
                 and r["artifacts"]["trace"] and r["artifacts"]["report"]]
        consistency = None
        if len(pairs) >= 2:
            cons_args = ["--pairs"] + pairs
            must = spec.get("must_find_cves") or []
            if must:
                cons_args += ["--must-find"] + must
            consistency = _eval("eval_consistency.py", cons_args)

        matrix["targets"][tid] = {"kind": spec["kind"], "runs": runs,
                                  "consistency": consistency}

    out_json = os.path.join(_RESULTS, f"matrix_{ts}.json")
    json.dump(matrix, open(out_json, "w"), indent=2, default=str)
    print(f"\n✓ Matrix-Report: {out_json}")
    _print_summary(matrix)


def _print_summary(matrix: dict) -> None:
    print("\n" + "=" * 60)
    print(f"MATRIX-ZUSAMMENFASSUNG  (N={matrix['n_runs']})")
    print("=" * 60)
    for tid, data in matrix["targets"].items():
        if "error" in data:
            print(f"  {tid}: ❌ {data['error']}")
            continue
        runs = data["runs"]
        oks = sum(1 for r in runs if r["artifacts"]["exit"] == 0)
        # Dimensions-Pass-Rate NUR über erfolgreiche Läufe (failed-Läufe wurden nicht evaluiert).
        ok_runs = [r for r in runs if not r.get("failed")]
        def drate(dim):
            vals = [r["eval"].get(dim, {}).get("passed") for r in ok_runs if dim in r["eval"]]
            return f"{sum(bool(v) for v in vals)}/{len(vals)}" if vals else "-"
        cons = data.get("consistency")
        cons_s = ("PASS" if cons and cons["passed"] else "FAIL") if cons else "-"
        if data["kind"] == "feature":
            print(f"  {tid} ({data['kind']}): scans {oks}/{len(runs)} | "
                  f"Dim1 {drate('dim1_input')} Dim2 {drate('dim2_output')} "
                  f"Feature {drate('feature')} | Konsistenz {cons_s}")
        else:
            print(f"  {tid} ({data['kind']}): scans {oks}/{len(runs)} | "
                  f"Dim1 {drate('dim1_input')} Dim2 {drate('dim2_output')} "
                  f"Dim3 {drate('dim3_groundtruth')} | Konsistenz {cons_s}")


if __name__ == "__main__":
    main()
