#!/usr/bin/env python3
"""
diagnose_hang.py — Reproduziert den research→blue Hang und dumpt den Stack.

Strategie (evidenzbasiert):
  1. Startet flow.py quick in eigener Prozessgruppe.
  2. Liest stdout in einem Thread, erkennt "✓ Research".
  3. Nach Research: wartet bis BLUE_TIMEOUT auf Blue-Start
     (Tool-Prozess ODER "✓ Active Scanning" ODER neuer Output).
  4. Wenn Blue nicht startet → py-spy dump ALLER Threads des Prozessbaums.
     DAS ist der Beweis wo der Prozess hängt.
  5. Danach SIGKILL.

Usage:
    python3 debugging/diagnose_hang.py [target] [scope] [blue_timeout_s]
"""
import subprocess, time, os, signal, sys, threading, queue as _queue
from pathlib import Path
from datetime import datetime

TARGET      = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"
SCOPE       = sys.argv[2] if len(sys.argv) > 2 else "quick"
BLUE_TIMEOUT= int(sys.argv[3]) if len(sys.argv) > 3 else 90
MAX_TOTAL   = 420

REPO    = Path(__file__).parent.parent
VENV_PY = str(REPO / "agentscanit" / "venv" / "bin" / "python3")
PYSPY   = str(REPO / "agentscanit" / "venv" / "bin" / "py-spy")

TOOL_BINS = {"nmap","nikto","nuclei","sslscan","testssl","testssl.sh","ffuf",
             "whatweb","httpx","naabu","subfinder","amass","dnsrecon","dig",
             "theharvester","dnsx","katana","waybackurls","gau","searchsploit",
             "ping","curl","enum4linux","whois","sublist3r","assetfinder"}

def ts():
    return datetime.now().strftime("%H:%M:%S")

def child_pids(root_pid: int) -> list[int]:
    """Alle PIDs im Prozessbaum (root + Nachkommen) via /proc."""
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,ppid", "--no-headers"], text=True)
    except Exception:
        return [root_pid]
    children: dict = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            try:
                pid, ppid = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            children.setdefault(ppid, []).append(pid)
    result, stack = [], [root_pid]
    while stack:
        p = stack.pop()
        result.append(p)
        stack.extend(children.get(p, []))
    return result

def any_tool_running() -> str | None:
    try:
        out = subprocess.check_output(["ps","-eo","comm","--no-headers"], text=True, timeout=2)
        for name in out.splitlines():
            n = name.strip().split("/")[-1]
            if n in TOOL_BINS:
                return n
    except Exception:
        pass
    return None

def pyspy_dump(pid: int) -> str:
    """py-spy dump auf einen Python-Prozess. Gibt den Dump-Text zurück.

    Versucht zuerst mit --locals (zeigt Lock-Objekte), fällt auf plain zurück.
    """
    for args in (["--locals"], []):
        try:
            out = subprocess.check_output(
                [PYSPY, "dump", "--pid", str(pid)] + args,
                text=True, stderr=subprocess.STDOUT, timeout=30,
            )
            return out
        except subprocess.CalledProcessError as e:
            last = f"(py-spy CalledProcessError pid={pid}): {(e.output or '')[:400]}"
            continue
        except Exception as e:
            last = f"(py-spy failed pid={pid}): {e}"
            continue
    return last

def kill_tree(pid: int):
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
        print(f"[{ts()}] SIGKILL → PGID {os.getpgid(pid)}")
    except Exception:
        try: os.kill(pid, signal.SIGKILL)
        except Exception: pass


# ─── Start ──────────────────────────────────────────────────────────────────
print(f"[{ts()}] Starte flow.py {TARGET} {SCOPE} (blue_timeout={BLUE_TIMEOUT}s)")

proc = subprocess.Popen(
    [VENV_PY, "flow.py", TARGET, "", SCOPE],
    cwd=str(REPO),
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    text=True, bufsize=1, preexec_fn=os.setsid,
)

_out_q: _queue.Queue = _queue.Queue()
def _reader():
    try:
        for line in proc.stdout:
            _out_q.put(line)
    except Exception:
        pass
    _out_q.put(None)
threading.Thread(target=_reader, daemon=True).start()

start_time       = time.time()
research_done_at = None
blue_seen        = False
last_output_at   = time.time()
tool_ever_seen   = False
dumped           = False

try:
    while True:
        now = time.time()

        # stdout abarbeiten
        drained_eof = False
        while True:
            try:
                line = _out_q.get_nowait()
            except _queue.Empty:
                break
            if line is None:
                drained_eof = True
                break
            s = line.rstrip()
            if s:
                print(f"[scan] {s}")
                last_output_at = now
                if "✓" in s and ("Research" in s or "OSINT" in s) and research_done_at is None:
                    research_done_at = now
                    print(f"[{ts()}] >>> RESEARCH DONE — beobachte Blue-Start ({BLUE_TIMEOUT}s)")
                if "✓" in s and "Active Scanning" in s and not blue_seen:
                    blue_seen = True
                    print(f"[{ts()}] >>> BLUE COMPLETE")

        if proc.poll() is not None:
            print(f"\n[{ts()}] Prozess beendet (exit={proc.returncode})")
            break

        if now - start_time > MAX_TOTAL:
            print(f"\n[{ts()}] MAX_TOTAL erreicht")
            if not dumped:
                for p in child_pids(proc.pid):
                    print(f"\n===== py-spy dump PID {p} =====")
                    print(pyspy_dump(p))
            kill_tree(proc.pid)
            sys.exit(1)

        # Tool aktiv?
        tool = any_tool_running()
        if tool:
            if not tool_ever_seen:
                print(f"[{ts()}] ► Tool aktiv: {tool}")
            tool_ever_seen = True
            # nach research zählt ein Tool als Blue-Start (ping/nmap)
            if research_done_at and not blue_seen:
                # Reset blue timer solange Tools laufen — echte Arbeit
                research_done_at = now

        # Blue-Timeout: Research fertig, kein Blue, kein Tool, kein neuer Output
        if research_done_at and not blue_seen and not dumped:
            stalled = now - research_done_at
            idle    = now - last_output_at
            if stalled > BLUE_TIMEOUT and idle > BLUE_TIMEOUT:
                print(f"\n[{ts()}] !!! HANG: Blue startet nicht "
                      f"({stalled:.0f}s seit Research, {idle:.0f}s ohne Output)")
                print(f"[{ts()}] Erfasse Stack-Dumps des Prozessbaums...\n")
                pids = child_pids(proc.pid)
                print(f"[{ts()}] Prozessbaum-PIDs: {pids}")
                for p in pids:
                    print(f"\n===== py-spy dump PID {p} =====")
                    print(pyspy_dump(p))
                dumped = True
                print(f"\n[{ts()}] Dump fertig → SIGKILL")
                kill_tree(proc.pid)
                sys.exit(2)
            elif int(stalled) % 15 == 0:
                print(f"[{ts()}] warte auf Blue: {stalled:.0f}s/{BLUE_TIMEOUT}s "
                      f"(idle {idle:.0f}s, tool_seen={tool_ever_seen})")

        time.sleep(2)

except KeyboardInterrupt:
    print(f"\n[{ts()}] Ctrl+C")
    if not dumped:
        for p in child_pids(proc.pid):
            print(f"\n===== py-spy dump PID {p} =====")
            print(pyspy_dump(p))
    kill_tree(proc.pid)
    sys.exit(1)

print(f"\n[{ts()}] Fertig nach {time.time()-start_time:.0f}s")
