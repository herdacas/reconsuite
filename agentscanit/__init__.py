"""
agentscanit — Team 1: Active Recon & Enumeration

Standalone:  python3 agentscanit/main.py example.com
Als Package: from agentscanit import AgentScanITCrew
"""
import sys
import os

# Stelle sicher dass interne absolute Imports (from crew import ...) funktionieren
# wenn das Package von der recon-suite Ebene aus importiert wird.
_dir = os.path.dirname(os.path.abspath(__file__))
if _dir not in sys.path:
    sys.path.insert(0, _dir)

from crew import AgentScanITCrew, VALID_SCOPES, PHASE_LABEL  # noqa: E402

__all__ = ["AgentScanITCrew", "VALID_SCOPES", "PHASE_LABEL"]
