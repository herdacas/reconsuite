"""
interpret_agent/nvd.py — thin shim

Delegates to agentscanit.tools.nvd (single source of truth for NVD API v2).
interpret_flow.py uses `from nvd import fetch_cves` — this shim keeps that
import working without duplicating the implementation.
"""

from agentscanit.tools.nvd import lookup_cve, fetch_cves, search_nvd  # noqa: F401
