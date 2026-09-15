#!/usr/bin/env python3
"""Test für zwei zusammenhängende Fixes — Live-Fund 2026-09-15 (gmx.de quick).

Befund: der Agent rief nmap mit ports='top100' auf. NmapTool._run() erkannte nur
den exakten String 'top1000' als Preset — 'top100' fiel ungeprüft in den -p-Zweig
durch ('-p top100'), was nmap nicht kennt ('QUITTING!', kein einziger Port
gescannt). Der Fehler blieb unsichtbar, weil tools/_base.py::_run() stderr nur
nutzte wenn stdout LEER war — nmap schreibt aber immer zuerst seine Startbanner-
Zeile nach stdout, bevor es auf stderr abbricht. Der finale Report interpretierte
das fälschlich als "gescannt, keine offenen Ports (CDN/LB-Filterung)".

Zwei Fixes, beide hier verifiziert:
1. tools/active_scanning.py::NmapTool._run() — erkennt jetzt 'top<N>'/'top-<N>'
   (case-insensitive) generisch als --top-ports N, nicht nur 'top1000' exakt.
2. tools/_base.py::_run() — Fehlermuster-Prüfung läuft jetzt gegen stdout+stderr
   kombiniert (nicht nur stdout), plus neues nmap-Muster 'QUITTING!'.

Nutzt echte Subprocess-Calls (kein Mock) — Muster wie der Rest des Projekts
(z.B. testing/test_sigint_fix.py).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from tools._base import _run  # noqa: E402
from tools.active_scanning import NmapTool  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


# --- Fix 2: 1:1-Reproduktion des echten gmx.de-Bugs (_base.py) ---
out = _run(["nmap", "-T4", "-Pn", "-p", "top100", "--open", "127.0.0.1"], timeout=30)
check("Reproduktion: 'nmap -p top100' wird jetzt als [TOOL_ERROR] erkannt",
      out.startswith("[TOOL_ERROR] nmap:"))
check("Reproduktion: Fehlermeldung enthält 'QUITTING!'", "QUITTING!" in out)

# --- Fix 2, Negativkontrollen (_base.py, echte Subprocess-Calls) ---
out_empty_stdout = _run(["sh", "-c", 'echo "only stderr" >&2'])
check("Regression: leeres stdout + harmloses stderr -> stderr wird weiterhin genutzt (unveraendert)",
      out_empty_stdout == "only stderr")

out_clean = _run(["sh", "-c", 'echo "real result"; echo "benign warning" >&2'])
check("Regression: stdout mit Inhalt + harmloses stderr -> Ergebnis bleibt sauber (kein TOOL_ERROR, kein stderr-Anhang)",
      out_clean == "real result")

out_err = _run(["sh", "-c", 'echo "Starting tool..."; echo "QUITTING!" >&2; exit 1'])
check("Fehlermuster auf stderr wird trotz nicht-leerem stdout erkannt (allgemeiner Fall)",
      out_err.startswith("[TOOL_ERROR]") and "QUITTING!" in out_err)

# --- Fix 1: NmapTool erkennt 'top<N>'-Varianten und scannt tatsächlich (127.0.0.1, real) ---
t = NmapTool()
for variant in ("top100", "top-100", "TOP-500", "top1000"):
    result = t._run(target="127.0.0.1", ports=variant)
    check(f"NmapTool ports='{variant}': kein [TOOL_ERROR], echter Scan lief",
          not result.startswith("[TOOL_ERROR]") and "Nmap done" in result)

# --- Fix 1, Negativkontrolle: unveraendertes Verhalten fuer Nicht-Preset-Werte ---
result_range = t._run(target="127.0.0.1", ports="1-1024")
check("NmapTool ports='1-1024' (Rohbereich) laeuft weiterhin unveraendert als -p-Wert",
      not result_range.startswith("[TOOL_ERROR]") and "Nmap done" in result_range)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
