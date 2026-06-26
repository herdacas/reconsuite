#!/usr/bin/env python3
"""
run_timed.py — Startet flow.py mit phasenbasiertem Timeout.
Bricht mit SIGKILL ab wenn die nächste Phase nicht innerhalb von
PHASE_TIMEOUT Sekunden startet.

Usage:
    python3 debugging/run_timed.py [target] [scope] [phase_timeout_s]
"""
import subprocess, time, os, signal, glob, sys, json
from pathlib import Path
from datetime import datetime

TARGET        = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"
SCOPE         = sys.argv[2] if len(sys.argv) > 2 else "quick"
PHASE_TIMEOUT = int(sys.argv[3]) if len(sys.argv) > 3 else 60
MAX_TOTAL     = 600  # 10 Minuten absolutes Maximum

REPO      = Path(__file__).parent.parent
LOGS      = REPO / "logs"
CKPT_GLOB = str(LOGS / "checkpoints" / f"*{TARGET.split('.')[0]}*" / "main" / "*.json")
VENV_PY   = str(REPO / "venv" / "bin" / "python3")

TOOL_BINS = {"nmap","nikto","nuclei","sslscan","testssl","testssl.sh","ffuf",
             "whatweb","httpx","naabu","subfinder","amass","dnsrecon","dig",
             "theharvester","dnsx","katana","waybackurls","gau","searchsploit"}

def ts():
    return datetime.now().strftime("%H:%M:%S")

def kill_tree(pid: int):
    """Tötet die komplette Prozessgruppe mit SIGKILL."""
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGKILL)
        print(f"[{ts()}] SIGKILL → PGID {pgid}")
    except ProcessLookupError:
        pass
    except Exception as e:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

def count_checkpoints() -> int:
    files = glob.glob(CKPT_GLOB)
    if not files:
        # Breiterer Glob
        files = glob.glob(str(LOGS / "checkpoints" / "**" / "main" / "*.json"), recursive=True)
    return len(files)

def any_tool_running() -> str | None:
    """Gibt Tool-Namen zurück wenn ein Security-Tool-Prozess läuft."""
    try:
        out = subprocess.check_output(
            ["ps", "-eo", "comm", "--no-headers"],
            text=True, timeout=2,
        )
        for name in out.splitlines():
            n = name.strip().split("/")[-1]
            if n in TOOL_BINS:
                return n
    except Exception:
        pass
    return None

def read_latest_checkpoint_phases() -> list[str]:
    """Liest abgeschlossene Phasen aus dem neuesten Checkpoint."""
    files = sorted(glob.glob(CKPT_GLOB), key=os.path.getmtime)
    if not files:
        files = sorted(
            glob.glob(str(LOGS / "checkpoints" / "**" / "main" / "*.json"), recursive=True),
            key=os.path.getmtime,
        )
    if not files:
        return []
    try:
        with open(files[-1]) as f:
            d = json.load(f)
        crew = next((e for e in d.get("entities",[]) if e.get("entity_type")=="crew"), {})
        agents = {a["id"]: a.get("role","?") for a in crew.get("agents",[])}
        ROLE_MAP = {
            ("OSINT and Reconnaissance Specialist", 0): "research",
            ("Blue Team Security Analyst",          0): "blue",
            ("OSINT and Reconnaissance Specialist", 1): "findings",
            ("Blue Team Security Analyst",          1): "red_scan",
            ("Attack Surface Analyst",              0): "red",
            ("Security Automation Developer",       0): "coding",
            ("Pentest Recon Report Writer",         0): "report",
        }
        rc, done = {}, []
        for t in crew.get("tasks",[]):
            aid  = (t.get("agent") or {}).get("id","?")
            role = agents.get(aid,"?")
            idx  = rc.get(role, 0); rc[role] = idx + 1
            if t.get("output"):
                done.append(ROLE_MAP.get((role, idx), role))
        return done
    except Exception:
        return []


# ─── Start ────────────────────────────────────────────────────────────────────

print(f"[{ts()}] Starte: flow.py {TARGET} {SCOPE}  "
      f"(phase_timeout={PHASE_TIMEOUT}s, max={MAX_TOTAL}s)")

proc = subprocess.Popen(
    [VENV_PY, "flow.py", TARGET, "", SCOPE],   # empty objective so scope is 3rd arg
    cwd=str(REPO),
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
    preexec_fn=os.setsid,  # eigene Prozessgruppe → sauberer SIGKILL
)

start_time        = time.time()
research_done_at  = None  # set ONLY from stdout "✓ Research" line
blue_seen         = False
last_ckpt_count   = count_checkpoints()  # snapshot at start — ignore pre-existing
last_tool_seen_at = None
last_output_at    = time.time()
output_lines: list[str] = []

print(f"[{ts()}] Pre-existing checkpoints ignored: {last_ckpt_count}")

import threading, queue as _queue

# Stdout in separatem Thread lesen — verhindert dass readline() den Timeout blockiert
_out_q: _queue.Queue = _queue.Queue()

def _reader():
    try:
        for line in proc.stdout:
            _out_q.put(line)
    except Exception:
        pass
    _out_q.put(None)  # EOF sentinel

_t = threading.Thread(target=_reader, daemon=True)
_t.start()

try:
    while True:
        now     = time.time()
        elapsed = now - start_time

        # Alle verfügbaren Zeilen aus der Queue lesen
        while True:
            try:
                line = _out_q.get_nowait()
            except _queue.Empty:
                break
            if line is None:
                # EOF → Prozess fertig
                break
            stripped = line.rstrip()
            if stripped:
                print(f"[scan] {stripped}")
                output_lines.append(stripped)
                last_output_at = time.time()
                # Research-Checkpoint aus stdout-Ausgabe detektieren
                if "✓" in stripped and ("Research" in stripped or "OSINT" in stripped):
                    if research_done_at is None:
                        research_done_at = time.time()
                        print(f"[{ts()}] ✓ Research done (stdout) → warte {PHASE_TIMEOUT}s auf Blue")
                if "✓" in stripped and ("Active Scanning" in stripped or "Scanning" in stripped):
                    if not blue_seen:
                        blue_seen = True
                        print(f"[{ts()}] ✓ Blue abgeschlossen — Scan läuft weiter")

        # Prozess beendet?
        if proc.poll() is not None:
            print(f"\n[{ts()}] Prozess beendet (exit={proc.returncode})")
            break

        # Absolutes Maximum
        if elapsed > MAX_TOTAL:
            print(f"\n[{ts()}] MAX_TOTAL {MAX_TOTAL}s erreicht → SIGKILL")
            kill_tree(proc.pid)
            sys.exit(1)

        # Checkpoint-Fortschritt (Fallback wenn stdout keine ✓ Zeichen hat)
        # last_ckpt_count is initialized to pre-existing count — only NEW checkpoints trigger
        ckpt_n = count_checkpoints()
        if ckpt_n > last_ckpt_count:
            new_phases = read_latest_checkpoint_phases()
            print(f"\n[{ts()}] New checkpoint: {ckpt_n} total ({ckpt_n - last_ckpt_count} new) — {new_phases}")
            last_ckpt_count = ckpt_n

            if "blue" in new_phases and not blue_seen:
                blue_seen = True
                print(f"[{ts()}] ✓ Blue abgeschlossen (checkpoint)")

        # Laufendes Tool?
        tool = any_tool_running()
        if tool:
            if last_tool_seen_at is None:
                print(f"\n[{ts()}] ► Tool aktiv: {tool}")
            last_tool_seen_at = now

        # Phase-Timeout überwachen
        if research_done_at and not blue_seen:
            phase_elapsed = now - research_done_at

            # Tool läuft → Timer zurücksetzen
            if last_tool_seen_at and (now - last_tool_seen_at) < 5:
                research_done_at = now - 5  # kleinen Puffer lassen
            elif phase_elapsed > PHASE_TIMEOUT:
                print(f"\n[{ts()}] PHASE TIMEOUT: {phase_elapsed:.0f}s "
                      f"— Blue hat nie gestartet → SIGKILL")
                print(f"[{ts()}] Letzte Ausgabe: {output_lines[-3:] if output_lines else 'keine'}")
                kill_tree(proc.pid)
                sys.exit(1)
            elif int(phase_elapsed) % 10 == 0:
                remaining = PHASE_TIMEOUT - phase_elapsed
                print(f"[{ts()}] Warte auf Blue: {phase_elapsed:.0f}s/{PHASE_TIMEOUT}s "
                      f"(noch {remaining:.0f}s)  "
                      f"[letzte Ausgabe vor {now - last_output_at:.0f}s]")

        time.sleep(3)

except KeyboardInterrupt:
    print(f"\n[{ts()}] Ctrl+C → SIGKILL")
    kill_tree(proc.pid)
    sys.exit(1)

print(f"\n[{ts()}] Fertig nach {time.time()-start_time:.0f}s")
