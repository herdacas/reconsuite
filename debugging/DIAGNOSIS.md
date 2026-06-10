# Phase 7 — Evidenzbasierte Fehlerdiagnose

Stand: 2026-06-10. Methode: reproduzieren → lokalisieren → Beweise → Hypothese → verifizieren.

## Ausgangs-Symptom (User-Report)
- "Nach Phase OSINT & Research hängt das Programm, nicht mit Strg+C killbar, nur `kill`."
- "Phase 2 startet nicht."

## Reproduktion

### Test 1 — Blue-Agent isoliert
`check_agent.py blue` → **✓ completed 12.7s**, erreicht final answer.
→ Blue-Agent selbst ist NICHT defekt.

### Test 2 — Pipeline MIT Sandbox (`diagnose_hang.py`)
Research ✓ (28s) → ~6s später **exit=-9 (SIGKILL)**.
Beweise gegen OOM: `dmesg` leer, `memory.events oom_kill 0`, 48 GB frei, cgroup `memory.max=max`.
→ **SIGKILL kam vom Bash-Tool-Sandbox** (blockt Netzwerk-Scanner nmap/naabu), NICHT vom Bug.

### Test 3 — Pipeline OHNE Sandbox (`diagnose_hang.py`, dangerouslyDisableSandbox)
```
✓ Research & OSINT   18s
✓ Active Scanning   107s     ← Blue LÄUFT und schließt ab. KEIN Hang.
⚠ findings (CVE Analysis) → RuntimeError: Agent execution ended without reaching a final answer
⚠ Checkpoint-Resume failed: TypeError: Can't instantiate abstract class BaseKnowledgeSource
→ 3 Retries scheitern → exit=1 nach 160s
```

## Hypothesen

### H1 — "Hang research→blue" / "Phase 2 startet nicht"
- **VERWORFEN.** Beweis: Test 3 zeigt Blue startet + schließt in 107s ab.
- Die wahrgenommene "Hängen nach Research" = stille, lange Blue-Phase
  (naabu/nmap scannen minutenlang ohne Konsolen-Output) + Sandbox-SIGKILL maskierte das echte Verhalten.

### H2 — findings crasht wegen leerer gpt-oss-Antwort (Retry-on-empty)
- **VERWORFEN als Ursache.** War eine Zwischenhypothese.
- Indiz dafür: `check_reuse.py` (echter Executor) loggte einmal
  `Invalid response from LLM call - None or empty` → gpt-oss kann leere Antworten liefern.
- Beweise DAGEGEN:
  - Single-turn (12×) und synthetische Multi-turn (15×): **0% empty** — nicht reproduzierbar isoliert.
  - Ein Retry-on-empty-Fix (`OpenAICompletion.call`-Patch) wurde implementiert + unit-getestet
    und dann End-to-End geprüft (`logs/verify_fix_run.log`): die Pipeline **crashte trotzdem** bei
    findings, und das Retry-Log feuerte **NIE** → `call()` lieferte nie leer.
  - → Die leere Antwort ist NICHT der Pipeline-Crash-Pfad. Fix wurde komplett zurückgenommen.

### H4 — Checkpoint-Write nach blue korrumpiert findings  ← **ROOT CAUSE**
- **BESTÄTIGT (deterministischer A/B-Test).**
  - MIT Checkpoint: findings crasht "ended without reaching a final answer" (3× → exit 1).
  - OHNE Checkpoint (`DISABLE_CHECKPOINT=1`): Pipeline läuft komplett durch
    (`✓ Research ✓ Active Scanning ✓ CVE Analysis ✓ Report → Assessment Complete`).
- Mechanismus (Code-belegt):
  - `event_bus.emit()` (event_bus.py:567) submittet den sync-Checkpoint-Handler an einen
    `ThreadPoolExecutor` und gibt das Future zurück OHNE darauf zu warten.
  - `_do_checkpoint` (checkpoint_listener.py:144) ruft `state.model_dump()` →
    `RuntimeState._serialize` (runtime.py:196) serialisiert `self.root` (crew/agent/task-Entities)
    im Hintergrund-Thread, WÄHREND der Main-Thread bereits die findings-Task startet und die
    Entities mutiert → Pydantic-Rust-Serializer iteriert ein dict das sich ändert →
    PyO3-Panic "dict changed size during iteration" → Thread-Local-Korruption → nächster
    findings-LLM-Call schlägt fehl.
  - Der frühere Fix patcht nur `EventRecord.model_dump` mit `r_locked()` — schützt das
    `event_record`, aber NICHT die Entities (`self.root`). Verifiziert: Patch aktiv + RWLock korrekt,
    Crash bleibt → Lücke sind die Entities.

### H3 — Checkpoint-Resume zusätzlich defekt
- **BESTÄTIGT (deterministisch).**
  `TypeError: Can't instantiate abstract class BaseKnowledgeSource ('aadd','add','validate_content')`.
- Ursache: `knowledge_sources` werden in den Checkpoint serialisiert; bei `Crew.from_checkpoint()`
  deserialisiert Pydantic die abstrakte Basisklasse statt `StringKnowledgeSource`.
- Folge: Selbst wenn man H4 abfinge, wäre Recovery unmöglich → Feature aktuell wertlos.

## Umgesetzter Fix (Root Cause H4)
- **Intra-Crew-Checkpointing standardmäßig deaktiviert** (`agentscanit/main.py`):
  `checkpoint_dir = None` außer `ENABLE_CHECKPOINT=1` gesetzt. Begründung im Code-Kommentar.
- Retry-Resume-Block gegen `checkpoint_dir is None` abgesichert (sonst `None / "main"` TypeError).
- Zwischen-Team-Resume bleibt über `@persist(SQLiteFlowPersistence)` (Flow-Ebene) erhalten.
- H2-Retry-on-empty + zugehörige Skripte wurden vollständig zurückgenommen (kein Bezug zur Ursache).
- **Offen für später:** korrekte Checkpoint-Reparatur (synchrone Serialisierung gegen Entity-Race
  + knowledge_sources beim Restore neu anhängen) — dann `ENABLE_CHECKPOINT=1` wieder Standard.

## E2E-Verifikation
- `DISABLE_CHECKPOINT=1`-Lauf (= neuer Default): komplette quick-Pipeline grün, exit 0.
- Nach dem Default-Flip: erneuter Lauf ohne Env-Var muss identisch durchlaufen.
