#!/usr/bin/env python3
"""
watch_scan.py — Echtzeit-Monitor für laufende Scans.

Zeigt in Echtzeit:
  - Welches Security-Tool gerade läuft (nmap, nikto, nuclei, ...)
  - Wie lange es schon läuft + Kommando-Args
  - Welche Phasen abgeschlossen sind (aus Checkpoint-JSON, agent-role-basiert)
  - Ob main.py / flow.py noch läuft + Laufzeit

Läuft in einem SEPARATEN Terminal während der Scan in einem anderen läuft.

Usage:
    cd /opt/projects/agentic-ai/recon-suite
    python3 debugging/watch_scan.py
    python3 debugging/watch_scan.py testphp.vulnweb.com
"""
import subprocess, time, os, sys, json, glob
from pathlib import Path
from datetime import datetime

TARGET  = sys.argv[1] if len(sys.argv) > 1 else None
LOGS    = Path("logs")
REFRESH = 2  # Sekunden

TOOL_BINS = {
    # Active Scanning (blue_agent)
    "nmap", "nikto", "nuclei", "sslscan", "testssl", "testssl.sh",
    "ffuf", "whatweb", "httpx", "naabu", "enum4linux", "enum4linux-ng",
    # Passive Recon (research_agent)
    "subfinder", "amass", "assetfinder", "dnsrecon", "dig",
    "theharvester", "theHarvester", "sublist3r", "dnsx", "katana",
    "waybackurls", "gau", "searchsploit",
}

# (agent_role, occurrence_index) → Phase-Label
# research_agent: task[0]=research, task[1]=findings
# blue_agent:     task[0]=blue,     task[1]=red_scan
ROLE_TO_PHASE = {
    ("OSINT and Reconnaissance Specialist", 0): "Research & OSINT",
    ("Blue Team Security Analyst",          0): "Active Scanning",
    ("OSINT and Reconnaissance Specialist", 1): "CVE Analysis",
    ("Blue Team Security Analyst",          1): "Targeted Follow-up",
    ("Attack Surface Analyst",              0): "Exploitability",
    ("Security Automation Developer",       0): "Script Generation",
    ("Pentest Recon Report Writer",         0): "Report",
}


def fmt(s: int) -> str:
    s = int(s)
    if s < 60:   return f"{s}s"
    m, sec = divmod(s, 60)
    if m < 60:   return f"{m}m{sec:02d}s"
    h, m2 = divmod(m, 60)
    return f"{h}h{m2:02d}m"


# ── Active tool subprocesses ──────────────────────────────────────────────────

def get_active_tools() -> list:
    """(tool_name, pid, elapsed_s, args_preview)"""
    try:
        raw = subprocess.check_output(
            ["ps", "-eo", "pid,etimes,comm,cmd", "--no-headers"],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
    except Exception:
        return []

    results = []
    for line in raw.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        pid, etimes_str, comm = parts[0], parts[1], parts[2]
        full_cmd = parts[3] if len(parts) > 3 else comm

        name    = comm.split("/")[-1]
        cmdbin  = full_cmd.split()[0].split("/")[-1] if full_cmd else ""
        matched = name if name in TOOL_BINS else (cmdbin if cmdbin in TOOL_BINS else None)
        if not matched:
            continue

        try:
            elapsed = int(etimes_str)
        except ValueError:
            elapsed = 0

        args = " ".join(full_cmd.split()[1:])[:72]
        results.append((matched, pid, elapsed, args))

    return sorted(results, key=lambda x: -x[2])  # längste zuerst


# ── Scan main process ─────────────────────────────────────────────────────────

def get_scan_proc() -> tuple:
    """(cmd_preview, elapsed_s) oder ('', 0)"""
    try:
        raw = subprocess.check_output(
            ["ps", "-eo", "pid,etimes,cmd", "--no-headers"],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
    except Exception:
        return "", 0

    for line in raw.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, etimes_str, cmd = parts
        if ("main.py" in cmd or "flow.py" in cmd) and "python" in cmd \
                and "watch_scan" not in cmd and "grep" not in cmd:
            try:
                elapsed = int(etimes_str)
            except ValueError:
                elapsed = 0
            return cmd.strip()[:80], elapsed

    return "", 0


# ── Phase progress from checkpoint JSON ───────────────────────────────────────

def get_phase_progress(target=None) -> tuple:
    """(completed: list[str], all_phases: list[str]) aus neuestem Checkpoint."""
    glob_pat = str(
        LOGS / "checkpoints"
        / ("*" if not target else f"*{target.replace('.', '*')}*")
        / "main" / "*.json"
    )
    files = sorted(glob.glob(glob_pat), key=os.path.getmtime)

    # Kein Match mit Target → alle Checkpoints prüfen (letzter zuerst)
    if not files:
        glob_all = str(LOGS / "checkpoints" / "*" / "main" / "*.json")
        files = sorted(glob.glob(glob_all), key=os.path.getmtime)

    if not files:
        return [], []

    # Neuestes File aus dem aktuellsten Checkpoint-Ordner
    latest_dir  = Path(files[-1]).parent.parent
    dir_files   = sorted((latest_dir / "main").glob("*.json"), key=os.path.getmtime)
    if not dir_files:
        return [], []

    try:
        with open(dir_files[-1]) as f:
            data = json.load(f)
    except Exception:
        return [], []

    crew = next(
        (e for e in data.get("entities", []) if e.get("entity_type") == "crew"),
        {}
    )
    agents_by_id = {
        a["id"]: a.get("role", "?")
        for a in crew.get("agents", [])
    }

    role_count: dict = {}
    completed:  list = []
    all_phases: list = []

    for task in crew.get("tasks", []):
        aid   = (task.get("agent") or {}).get("id", "?")
        role  = agents_by_id.get(aid, "?")
        idx   = role_count.get(role, 0)
        role_count[role] = idx + 1

        label = ROLE_TO_PHASE.get((role, idx), f"{role[:20]}#{idx+1}")
        all_phases.append(label)
        if task.get("output"):
            completed.append(label)

    return completed, all_phases


# ── Model info ────────────────────────────────────────────────────────────────

def get_model_info() -> str:
    try:
        sys.path.insert(0, "agentscanit")
        from config import ACTIVE_ANALYSIS, ACTIVE_RESEARCH, ACTIVE_BASE_URL
        base = ACTIVE_BASE_URL.replace("https://", "").replace("http://", "").split("/")[0]
        if ACTIVE_ANALYSIS == ACTIVE_RESEARCH:
            return f"{ACTIVE_ANALYSIS}  @{base}"
        return f"analysis={ACTIVE_ANALYSIS}  research={ACTIVE_RESEARCH}  @{base}"
    except Exception:
        return "?"


# ── Render ────────────────────────────────────────────────────────────────────

def render(tools, scan_cmd, scan_el, completed, all_phases, model_info):
    os.system("clear")
    ts     = datetime.now().strftime("%H:%M:%S")
    status = "RUNNING" if scan_cmd else "STOPPED"

    print(f"\n  ╔══  Scan Monitor  {ts}  [{status}]")
    if TARGET:
        print(f"  Target : {TARGET}")
    print(f"  Model  : {model_info}")
    if scan_cmd:
        print(f"  Process: {scan_cmd}  ({fmt(scan_el)} running)")
    else:
        print(f"  Process: (not running)")

    # ── Active Tools ──────────────────────────────────────────────────
    print(f"\n  ── Active Security Tools ──────────────────────────────────")
    if tools:
        for name, pid, elapsed, args in tools:
            warn = "  ⚠ LONG" if elapsed > 300 else ""
            print(f"    ► {name:16s}  {fmt(elapsed):>7s}  PID {pid}{warn}")
            if args:
                print(f"      {args}")
    elif scan_cmd:
        print("    (none — LLM arbeitet oder zwischen Tool-Calls)")
    else:
        print("    (none)")

    # ── Phase Progress ────────────────────────────────────────────────
    total = len(all_phases) or "?"
    print(f"\n  ── Phase Progress  ({len(completed)}/{total} abgeschlossen) ────────")
    if all_phases:
        active_shown = False
        for label in all_phases:
            if label in completed:
                print(f"    ✓  {label}")
            elif not active_shown and scan_cmd:
                print(f"    ► {label}  ← aktiv")
                active_shown = True
            else:
                print(f"    ○  {label}")
    else:
        print("    (noch kein Checkpoint — erste Task läuft noch)")

    print(f"\n  [Ctrl+C zum Beenden  |  refresh alle {REFRESH}s]\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    model_info = get_model_info()
    print(f"\n  watch_scan.py — starte Monitor, Ctrl+C zum Beenden\n")
    time.sleep(0.3)

    while True:
        tools               = get_active_tools()
        scan_cmd, scan_el   = get_scan_proc()
        completed, all_ph   = get_phase_progress(TARGET)
        render(tools, scan_cmd, scan_el, completed, all_ph, model_info)
        time.sleep(REFRESH)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Gestoppt.")
