#!/usr/bin/env python3
"""Deterministischer Test für den Ctrl+C-Fix (2026-09-12).

Simuliert exakt das reale Problem: _run() läuft in einem Worker-Thread (wie bei
CrewAI's nativem Tool-Calling), ein SIGINT-Handler im Main-Thread muss den
Subprozess trotzdem sofort beenden können. Kein CrewAI/Ollama nötig.

Positivkontrolle: normaler _run()-Aufruf liefert weiterhin korrektes Ergebnis.
Negativkontrolle (das eigentliche Bug-Szenario): ein _run()-Aufruf, der einen
30s-Sleep im Worker-Thread startet, wird nach ~1s durch kill_all_active_procs()
(simuliert den SIGINT-Handler) von AUSSERHALB dieses Threads beendet — muss in
deutlich unter 30s zurückkehren, sonst wäre der Bug weiterhin vorhanden.
"""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agentscanit"))

from tools._base import _run, kill_all_active_procs  # noqa: E402

passed = 0
failed = 0


def check(name, ok):
    global passed, failed
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    if ok:
        passed += 1
    else:
        failed += 1


# --- Positivkontrolle: normaler, kurzer _run()-Aufruf funktioniert weiterhin ---
out = _run(["echo", "hello-recon-suite"])
check(f"normaler _run()-Aufruf liefert korrektes Ergebnis (out={out!r})", out == "hello-recon-suite")

# --- Negativkontrolle / eigentlicher Bug-Fix-Test ---
# _run() läuft in einem Worker-Thread (wie CrewAI's Tool-Executor), ruft
# "sleep 30" auf. Nach 1s simulieren wir den SIGINT-Handler von main.py
# (kill_all_active_procs()) — OHNE dass der Worker-Thread selbst irgendein
# Signal empfängt. Der Worker-Thread muss trotzdem in << 30s zurückkehren.
result = {}


def worker():
    t0 = time.time()
    out = _run(["sleep", "30"], timeout=60)
    result["dur"] = time.time() - t0
    result["out"] = out


t = threading.Thread(target=worker)
t.start()
time.sleep(1.0)  # dem Subprozess Zeit geben, wirklich zu starten
n_killed = kill_all_active_procs()
t.join(timeout=10)

check(f"kill_all_active_procs() fand genau 1 aktiven Subprozess (n={n_killed})", n_killed == 1)
check(f"Worker-Thread kehrte NICHT nach _run() blockiert zurück (thread alive={t.is_alive()})", not t.is_alive())
check(
    f"_run()-Aufruf kehrte in << 30s zurück statt den vollen Sleep abzuwarten (dur={result.get('dur', 999):.1f}s)",
    result.get("dur", 999) < 10,
)

# --- Registry ist nach Abschluss wieder leer (kein Leak) ---
check("Registry ist nach Abschluss leer (kein Leak)", kill_all_active_procs() == 0)

print(f"\n{'='*40}\nPASS: {passed}/{passed+failed}")
sys.exit(0 if failed == 0 else 1)
