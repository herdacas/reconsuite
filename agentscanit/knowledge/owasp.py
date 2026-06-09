"""OWASP Top 10 (2021) Knowledge Source — aktiviert in Phase 7 (Compliance Mapper).

Genutzt von compliance_agent als Knowledge Source für das OWASP-Mapping.
"""

from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource

OWASP_TOP10_TEXT = """
# OWASP Top 10 — 2021

A01:2021 – Broken Access Control
Previously ranked #5. Access control enforces policy such that users cannot
act outside of their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of all data.
Key CWEs: CWE-200, CWE-201, CWE-352
Common findings: IDOR, missing auth on admin endpoints, CORS misconfiguration,
  directory traversal, privilege escalation.

A02:2021 – Cryptographic Failures
Previously known as "Sensitive Data Exposure". Focus on failures related to
cryptography which often lead to sensitive data exposure or system compromise.
Key CWEs: CWE-259, CWE-327, CWE-331
Common findings: Weak TLS (SSLv3/TLS 1.0/1.1), self-signed certs, HTTP instead
  of HTTPS, weak cipher suites, hardcoded secrets, insecure hashing (MD5/SHA1).

A03:2021 – Injection
SQL, NoSQL, OS, LDAP injection. An application is vulnerable when user-supplied
data is not validated, filtered, or sanitized by the application.
Key CWEs: CWE-79, CWE-89, CWE-73
Common findings: SQL injection, XSS (reflected/stored), command injection,
  template injection, XXE.

A04:2021 – Insecure Design
New category focusing on risks related to design and architectural flaws.
Key CWEs: CWE-209, CWE-256, CWE-501, CWE-522
Common findings: Missing rate limiting, insecure password recovery, business
  logic flaws, missing security controls by design.

A05:2021 – Security Misconfiguration
Includes XML External Entities (XXE). Missing hardening, unnecessary features
enabled, default accounts/passwords, error handling revealing too much information.
Key CWEs: CWE-16, CWE-611
Common findings: Default credentials, directory listing enabled, verbose error
  messages, unnecessary open ports/services, missing security headers.

A06:2021 – Vulnerable and Outdated Components
Previously "Using Components with Known Vulnerabilities". Libraries, frameworks,
and other software modules run with the same privileges as the application.
Key CWEs: CWE-1104
Common findings: Apache Tomcat CVE, jQuery CVE, OpenSSL CVE, outdated CMS,
  outdated server software (Apache, Nginx, IIS), unpatched OS.

A07:2021 – Identification and Authentication Failures
Previously "Broken Authentication". Confirmation of the user's identity,
authentication, and session management is critical.
Key CWEs: CWE-297, CWE-287, CWE-384
Common findings: Weak passwords permitted, no MFA, session fixation, insecure
  session tokens, brute force possible, credential stuffing.

A08:2021 – Software and Data Integrity Failures
New category focusing on assumptions related to software updates, critical data,
and CI/CD pipelines without verifying integrity.
Key CWEs: CWE-829, CWE-494, CWE-502
Common findings: Insecure deserialization, unsigned updates, SRI missing on CDN
  resources, CI/CD without integrity checks.

A09:2021 – Security Logging and Monitoring Failures
Previously "Insufficient Logging & Monitoring". Without logging and monitoring,
breaches cannot be detected.
Key CWEs: CWE-778, CWE-117, CWE-223, CWE-532
Common findings: No audit log, login failures not logged, no alerting on
  suspicious activity, log injection possible.

A10:2021 – Server-Side Request Forgery (SSRF)
New category. SSRF flaws occur whenever a web application is fetching a remote
resource without validating the user-supplied URL.
Key CWEs: CWE-918
Common findings: URL parameter that fetches remote content, webhooks without
  allowlist, cloud metadata endpoint accessible (169.254.169.254).

## Mapping Hints

TLS 1.0 / TLS 1.1 / SSLv3           → A02:2021
Self-signed certificate               → A02:2021
Weak cipher suite                     → A02:2021
CVE (outdated component)              → A06:2021
Default credentials                   → A05:2021 + A07:2021
Directory listing                     → A05:2021
Missing security headers (CSP, HSTS)  → A05:2021
Open redirect                         → A01:2021
XSS                                   → A03:2021
SQL injection                         → A03:2021
SSRF                                  → A10:2021
No rate limiting on login             → A07:2021
"""

owasp_knowledge = StringKnowledgeSource(
    content=OWASP_TOP10_TEXT,
    metadata={"framework": "OWASP", "version": "2021", "use": "compliance-mapping"},
)
