"""
tools/cpe_map.py — Deterministic banner → CPE vendor/product mapping

No LLM in this path. Input: raw service banner string.
Output: (vendor, product) tuple for NVD CPE API, or None if no match.

Lookup order: longest/most-specific keyword first to avoid partial matches
(e.g. "oracle weblogic" before "oracle").
"""

from __future__ import annotations

# Banner substring → (vendor, product) per NVD CPE 2.3 naming
# Keys are lowercase; matched against banner.lower()
# Order matters: more specific entries must come before shorter prefixes.
CPE_MAP: list[tuple[str, tuple[str, str]]] = [
    # Application servers
    ("oracle weblogic admin httpd", ("oracle", "weblogic_server")),  # exact nmap banner
    ("oracle weblogic",        ("oracle",      "weblogic_server")),
    ("weblogic",               ("oracle",      "weblogic_server")),
    ("glassfish",              ("oracle",      "glassfish_server")),
    ("jboss",                  ("redhat",      "jboss_enterprise_application_platform")),
    ("wildfly",                ("redhat",      "wildfly")),
    ("websphere",              ("ibm",         "websphere_application_server")),
    # Web servers
    ("apache-coyote",          ("apache",      "tomcat")),
    ("apache tomcat",          ("apache",      "tomcat")),
    ("tomcat",                 ("apache",      "tomcat")),
    ("apache",                 ("apache",      "http_server")),
    ("nginx",                  ("nginx",       "nginx")),
    ("microsoft-iis",          ("microsoft",   "internet_information_services")),
    ("iis",                    ("microsoft",   "internet_information_services")),
    ("lighttpd",               ("lighttpd",    "lighttpd")),
    ("caddy",                  ("caddyserver", "caddy")),
    # SSH / network services
    ("openssh",                ("openbsd",     "openssh")),
    ("dropbear",               ("matt_johnston", "dropbear_ssh_server")),
    ("vsftpd",                 ("beasts",      "vsftpd")),
    ("proftpd",                ("proftpd_project", "proftpd")),
    ("pure-ftpd",              ("pureftpd",    "pure-ftpd")),
    ("postfix",                ("wietse_venema", "postfix")),
    ("dovecot",                ("dovecot",     "dovecot")),
    ("exim",                   ("exim",        "exim")),
    # Databases / message brokers
    ("redis",                  ("redis",       "redis")),
    ("memcached",              ("memcached",   "memcached")),
    ("activemq",               ("apache",      "activemq")),
    ("rabbitmq",               ("pivotal_software", "rabbitmq")),
    ("kafka",                  ("apache",      "kafka")),
    ("elasticsearch",          ("elastic",     "elasticsearch")),
    ("mongodb",                ("mongodb",     "mongodb")),
    ("mysql",                  ("mysql",       "mysql")),
    ("postgresql",             ("postgresql",  "postgresql")),
    ("mariadb",                ("mariadb",     "mariadb")),
    # CMS / frameworks
    ("wordpress",              ("wordpress",   "wordpress")),
    ("joomla",                 ("joomla",      "joomla\\!")),
    ("drupal",                 ("drupal",      "drupal")),
    ("typo3",                  ("typo3",       "typo3")),
    ("magento",                ("adobe",       "magento")),
    ("shopify",                ("shopify",     "shopify")),
    # TLS / crypto
    ("openssl",                ("openssl",     "openssl")),
    # Languages / runtimes
    ("php",                    ("php",         "php")),
    ("python",                 ("python",      "python")),
    ("ruby",                   ("ruby-lang",   "ruby")),
    ("node",                   ("nodejs",      "node.js")),
    # Frontend libs (from whatweb/httpx headers)
    ("jquery",                 ("jquery",      "jquery")),
    ("bootstrap",              ("getbootstrap","bootstrap")),
    ("angular",                ("google",      "angular")),
    ("react",                  ("facebook",    "react")),
    # Misc admin / monitoring
    ("webmin",                 ("webmin",      "webmin")),
    ("nagios",                 ("nagios",      "nagios")),
    ("zabbix",                 ("zabbix",      "zabbix")),
    ("grafana",                ("grafana_labs","grafana")),
    ("kibana",                 ("elastic",     "kibana")),
]


# Notable CVEs per (vendor, product) that are actively exploited and relevant
# for pentest targets but may not appear in the top-N CVSS sort because many
# higher-CVSS entries exist for the same product. These are fetched directly
# via cveId API in cpe_search_nvd() and merged into the result pool.
NOTABLE_CVES: dict[tuple[str, str], list[str]] = {
    ("oracle",  "weblogic_server"): ["CVE-2023-21839", "CVE-2020-14882", "CVE-2019-2725"],
    ("redis",   "redis"):           ["CVE-2022-0543"],
    ("apache",  "http_server"):     ["CVE-2021-41773", "CVE-2021-42013"],
    ("apache",  "log4j"):           ["CVE-2021-44228"],
}


def banner_to_cpe(banner: str) -> tuple[str, str] | None:
    """Map a service banner/header string to (vendor, product) CPE components.

    Returns the first match (most specific wins — table is ordered longest-first).
    Returns None if no mapping found.

    Robust against LLM-mangled input: strips whitespace-runs and ellipsis
    artifacts (e.g. "Oracle   ...  ...  httpd" → still matches "oracle weblogic"
    via token-level check).
    """
    import re as _re
    # Normalise whitespace and strip common LLM artefacts (…, ..., ·, —)
    cleaned = _re.sub(r'[…\.]{2,}', ' ', banner)
    cleaned = _re.sub(r'\s+', ' ', cleaned).strip()
    lower = cleaned.lower()

    for keyword, cpe in CPE_MAP:
        if keyword in lower:
            return cpe

    # Token-level fallback: check if all words of multi-word keywords appear
    # anywhere in the banner (handles "Oracle   admin httpd" → weblogic match
    # when the banner is partially mangled).
    tokens = set(lower.split())
    for keyword, cpe in CPE_MAP:
        kw_tokens = set(keyword.split())
        if len(kw_tokens) > 1 and kw_tokens.issubset(tokens):
            return cpe

    return None


def banners_to_cpes(banners: list[str]) -> list[tuple[str, str]]:
    """Map multiple banner strings, deduplicate, skip unknowns."""
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for b in banners:
        mapped = banner_to_cpe(b)
        if mapped and mapped not in seen:
            seen.add(mapped)
            result.append(mapped)
    return result
