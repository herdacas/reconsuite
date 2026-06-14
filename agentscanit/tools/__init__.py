"""
tools/ — AgentScanIT tool package

Active scanning  (blue_agent)    → tools/active_scanning.py   (8 active tools after Phase 9.1)
Passive recon    (research_agent) → tools/passive_recon.py    (9 active tools after Phase 9.1)
CPE mapping                       → tools/cpe_map.py          (deterministic, no LLM)
NVD                               → tools/nvd.py              (keyword fallback + CPE tool)
Shared helpers                   → tools/_base.py
"""

from tools.active_scanning import (
    nmap_tool, nikto_tool, whatweb_tool, sslscan_tool, testssl_tool,
    curl_tool, ping_tool, nuclei_tool, ffuf_tool, enum4linux_tool,
    httpx_tool, naabu_tool,
)

from tools.passive_recon import (
    ddg_search_tool, theharvester_tool, sublist3r_tool, subfinder_tool,
    dnsrecon_tool, dig_tool, whois_tool, amass_tool, assetfinder_tool,
    dnsx_tool, katana_tool, waybackurls_tool, gau_tool, searchsploit_tool,
)

from tools.nvd import nvd_tool, nvd_cpe_tool

__all__ = [
    # active scanning (all exported for reversibility; agents.py controls what's active)
    "nmap_tool", "nikto_tool", "whatweb_tool", "sslscan_tool", "testssl_tool",
    "curl_tool", "ping_tool", "nuclei_tool", "ffuf_tool", "enum4linux_tool",
    "httpx_tool", "naabu_tool",
    # passive recon (all exported for reversibility; agents.py controls what's active)
    "ddg_search_tool", "theharvester_tool", "sublist3r_tool", "subfinder_tool",
    "dnsrecon_tool", "dig_tool", "whois_tool", "amass_tool", "assetfinder_tool",
    "dnsx_tool", "katana_tool", "waybackurls_tool", "gau_tool", "searchsploit_tool",
    # nvd
    "nvd_tool", "nvd_cpe_tool",
]
