#!/usr/bin/env python3
"""
check_pipeline.py — Automatische Diagnose des research→blue Hangs.

Testet jeden Schritt zwischen den Phasen isoliert in einem Subprocess mit
Timeout. Sobald der hängende Schritt gefunden ist, wird der Fix automatisch
angewendet.

Tests (alle ohne API-Call wenn möglich):
  1. Embedding  — nomic-embed-text via localhost:11434 (lokal, kein API-Key)
  2. Memory Save — _crew_memory.save() mit kurzem Text
  3. Memory Recall — _crew_memory.recall() auf aktuelle DB
  4. Blue + Memory — blue_agent mit memory=_crew_memory (API-Call nötig)
  5. LLM Timeout — prüft ob timeout-Parameter auf LLM-Instanz wirkt

Usage:
    cd /opt/projects/agentic-ai/recon-suite
    python3 debugging/check_pipeline.py
    python3 debugging/check_pipeline.py testphp.vulnweb.com
"""
import sys, os, subprocess, time, textwrap
from pathlib import Path

TARGET = sys.argv[1] if len(sys.argv) > 1 else "testphp.vulnweb.com"
REPO   = Path(__file__).parent.parent
PY     = sys.executable

TIMEOUT_LOCAL = 20   # Sekunden für lokale Tests (embedding, LanceDB)
TIMEOUT_API   = 90   # Sekunden für Tests mit API-Call

# ── Farben ────────────────────────────────────────────────────────────────────
OK   = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
HANG = "\033[33m⏱ HANG\033[0m"
FIX  = "\033[36m→ FIX\033[0m"


def run_test(label: str, code: str, timeout: int) -> tuple[bool, str]:
    """Führt Python-Code in einem Subprocess mit Timeout aus."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            [PY, "-c", code],
            cwd=str(REPO),
            capture_output=True, text=True,
            timeout=timeout,
            env={**os.environ, "CREWAI_DISABLE_TELEMETRY": "true"},
        )
        elapsed = time.time() - t0
        if proc.returncode == 0:
            out = proc.stdout.strip()
            return True, f"{elapsed:.1f}s  {out}"
        else:
            err = (proc.stderr or proc.stdout or "").strip()[-200:]
            return False, f"ERROR {elapsed:.1f}s: {err}"
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        return None, f"{elapsed:.0f}s — did not complete within {timeout}s"


def print_result(n: int, label: str, ok, detail: str):
    if ok is True:
        icon = OK
    elif ok is False:
        icon = FAIL
    else:
        icon = HANG
    print(f"  [{n}] {icon}  {label:<40s}  {detail}")


def apply_fix(fix_name: str, fix_fn):
    print(f"\n  {FIX}  Applying fix: {fix_name}")
    try:
        fix_fn()
        print(f"       Applied — re-run scan to verify")
    except Exception as e:
        print(f"       FAILED: {e}")


# ─── Fix-Funktionen ───────────────────────────────────────────────────────────

def fix_disable_memory():
    """Setzt memory=False in crew.py — umgeht die hängende Memory-Operation."""
    crew_path = REPO / "agentscanit" / "crew.py"
    text = crew_path.read_text()

    # Ersetze memory=_crew_memory durch memory=False in beiden crew_kwargs Blöcken
    if "memory=_crew_memory" in text:
        text = text.replace("memory=_crew_memory", "memory=False")
        crew_path.write_text(text)
        print(f"       crew.py: memory=_crew_memory → memory=False")
    else:
        print(f"       crew.py: kein memory=_crew_memory gefunden — bereits deaktiviert?")


def fix_add_llm_timeout():
    """Fügt timeout=120 zu allen LLM-Instanzen in agents.py hinzu."""
    agents_path = REPO / "agentscanit" / "agents.py"
    text = agents_path.read_text()

    if "timeout=120" in text:
        print("       agents.py: timeout=120 bereits vorhanden")
        return

    # Füge timeout nach temperature ein
    old = "        temperature=temperature,\n    )\n    if OLLAMA_API_KEY:"
    new = "        temperature=temperature,\n        timeout=120,\n    )\n    if OLLAMA_API_KEY:"
    if old in text:
        text = text.replace(old, new)
        agents_path.write_text(text)
        print("       agents.py: timeout=120 zu _llm() hinzugefügt")
    else:
        print("       agents.py: Pattern nicht gefunden — manuell prüfen")


def fix_clear_lancedb():
    """Löscht die LanceDB und erstellt ein leeres Verzeichnis."""
    import shutil
    lancedb_path = REPO / "agentscanit" / "memory" / "lancedb"
    if lancedb_path.exists():
        shutil.rmtree(lancedb_path)
    lancedb_path.mkdir(parents=True, exist_ok=True)
    print(f"       LanceDB gelöscht: {lancedb_path}")


# ─── Test-Code-Snippets ───────────────────────────────────────────────────────

T1_EMBED = textwrap.dedent(f"""
import sys, time, requests
sys.path.insert(0, 'agentscanit')
from config import EMBED_BASE_URL, EMBED_MODEL
t0 = time.time()
resp = requests.post(
    f"{{EMBED_BASE_URL}}/api/embeddings",
    json={{"model": EMBED_MODEL, "prompt": "blue team security scan {TARGET}"}},
    timeout=15,
)
elapsed = time.time() - t0
if resp.status_code != 200:
    raise RuntimeError(f"HTTP {{resp.status_code}}: {{resp.text[:100]}}")
dims = len(resp.json().get("embedding", []))
print(f"dims={{dims}}")
""").strip()

T2_MEM_SAVE = textwrap.dedent(f"""
import sys, os, time
sys.path.insert(0, 'agentscanit')
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
from crew import _crew_memory
t0 = time.time()
_crew_memory.save(
    user_message="Research for {TARGET}: IP 44.228.249.3",
    agent_response="Found domain {TARGET} resolving to 44.228.249.3",
    metadata={{"agent_role": "OSINT", "target": "{TARGET}"}},
)
elapsed = time.time() - t0
print(f"saved in {{elapsed:.1f}}s")
""").strip()

T3_MEM_RECALL = textwrap.dedent(f"""
import sys, os, time
sys.path.insert(0, 'agentscanit')
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
from crew import _crew_memory
t0 = time.time()
results = _crew_memory.recall("{TARGET}", depth="shallow", limit=3)
elapsed = time.time() - t0
print(f"recalled {{len(results)}} items in {{elapsed:.1f}}s")
""").strip()

T4_BLUE_MEMORY = textwrap.dedent(f"""
import sys, os, time
sys.path.insert(0, 'agentscanit')
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
from crewai import Task, Crew, Process
from agents import blue_agent
from crew import _crew_memory
from config import EMBED_BASE_URL, EMBED_MODEL

_embedder = {{
    "provider": "ollama",
    "config": {{"url": f"{{EMBED_BASE_URL}}/api/embeddings", "model_name": EMBED_MODEL}},
}}

task = Task(
    description="Run ping on {TARGET}. Return what you found.",
    expected_output="Short factual summary.",
    agent=blue_agent,
)

crew = Crew(
    agents=[blue_agent],
    tasks=[task],
    process=Process.sequential,
    memory=_crew_memory,
    embedder=_embedder,
    verbose=False,
)

t0 = time.time()
result = crew.kickoff(inputs={{"target": "{TARGET}"}})
elapsed = time.time() - t0
print(f"completed in {{elapsed:.1f}}s")
""").strip()

T5_LLM_TIMEOUT = textwrap.dedent(f"""
import sys, time
sys.path.insert(0, 'agentscanit')
from config import ACTIVE_ANALYSIS, ACTIVE_BASE_URL, OLLAMA_API_KEY
from crewai import LLM

llm = LLM(
    model=f"ollama/{{ACTIVE_ANALYSIS}}",
    base_url=ACTIVE_BASE_URL,
    temperature=0.1,
    timeout=10,
    **(dict(api_key=OLLAMA_API_KEY) if OLLAMA_API_KEY else {{}}),
    extra_body={{"think": False, "keep_alive": "5m", "num_ctx": 4096}},
)

t0 = time.time()
resp = llm.call([{{"role": "user", "content": "Reply with one word: ready"}}])
elapsed = time.time() - t0
print(f"LLM responded in {{elapsed:.1f}}s")
""").strip()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\n  check_pipeline.py — Diagnose: research→blue Übergang")
    print(f"  Target: {TARGET}\n")

    results = {}

    # ── Test 1: Embedding (lokal) ──────────────────────────────────────────────
    print("  [1/5] Embedding (nomic-embed-text, lokal) ...")
    ok, detail = run_test("embedding", T1_EMBED, TIMEOUT_LOCAL)
    results["embed"] = ok
    print_result(1, "Embedding localhost:11434", ok, detail)

    # ── Test 2: Memory Save (lokal) ────────────────────────────────────────────
    print("  [2/5] Memory Save (LanceDB write, lokal) ...")
    ok, detail = run_test("memory_save", T2_MEM_SAVE, TIMEOUT_LOCAL)
    results["mem_save"] = ok
    print_result(2, "Memory Save (LanceDB)", ok, detail)

    # ── Test 3: Memory Recall (lokal) ──────────────────────────────────────────
    print("  [3/5] Memory Recall (LanceDB read, lokal) ...")
    ok, detail = run_test("memory_recall", T3_MEM_RECALL, TIMEOUT_LOCAL)
    results["mem_recall"] = ok
    print_result(3, "Memory Recall (LanceDB)", ok, detail)

    # ── Test 4: Blue + Memory (API nötig) ─────────────────────────────────────
    print(f"  [4/5] Blue Agent + Memory (API, {TIMEOUT_API}s timeout) ...")
    ok, detail = run_test("blue_memory", T4_BLUE_MEMORY, TIMEOUT_API)
    results["blue_mem"] = ok
    print_result(4, "Blue Agent + Memory (full cond.)", ok, detail)

    # ── Test 5: LLM Timeout-Param ─────────────────────────────────────────────
    print(f"  [5/5] LLM Timeout-Parameter (API) ...")
    ok, detail = run_test("llm_timeout", T5_LLM_TIMEOUT, 30)
    results["llm_to"] = ok
    print_result(5, "LLM timeout=10 respected", ok, detail)

    # ── Diagnose + Auto-Fix ───────────────────────────────────────────────────
    print("\n  ── Diagnose ──────────────────────────────────────────────────")

    if results["embed"] is None:
        print("  URSACHE: Embedding hängt → nomic-embed-text antwortet nicht")
        print("  Alle Memory-Operationen (Save + Recall) werden ebenfalls hängen.")
        apply_fix("Disable Memory in crew.py", fix_disable_memory)
        apply_fix("Add LLM timeout (safety net)", fix_add_llm_timeout)
        return

    if results["mem_save"] is None or results["mem_recall"] is None:
        which = "Save" if results["mem_save"] is None else "Recall"
        print(f"  URSACHE: Memory {which} hängt → LanceDB-Operation blockiert")
        print("  Embedding läuft — Problem ist in LanceDB selbst.")
        apply_fix("Clear LanceDB", fix_clear_lancedb)
        apply_fix("Disable Memory in crew.py", fix_disable_memory)
        apply_fix("Add LLM timeout (safety net)", fix_add_llm_timeout)
        return

    if results["blue_mem"] is None:
        print("  URSACHE: Blue Agent + Memory hängt")
        print("  Embedding + LanceDB einzeln OK → Problem beim ersten LLM-Call")
        print("  von blue_agent im Memory-Kontext (Connection-Hang zur remote API).")
        apply_fix("Add LLM timeout=120 to agents.py", fix_add_llm_timeout)
        apply_fix("Disable Memory (prevents pre-call overhead)", fix_disable_memory)
        return

    if results["llm_to"] is None:
        print("  URSACHE: LLM timeout-Parameter wird nicht respektiert")
        print("  → LLM-Calls hängen indefinit ohne Abbruch-Mechanismus.")
        apply_fix("Add LLM timeout=120 to agents.py", fix_add_llm_timeout)
        return

    if all(v is True for v in results.values()):
        print("  Alle 5 Tests bestanden — kein isolierbares Problem gefunden.")
        print("  Nächster Schritt: osint-Scan testen (research only, kein blue):")
        print("    python3 flow.py testphp.vulnweb.com osint")
    else:
        failed = [k for k, v in results.items() if v is False]
        print(f"  Fehler in: {', '.join(failed)}")
        print("  Details oben — Fix manuell prüfen.")

    print()


if __name__ == "__main__":
    main()
