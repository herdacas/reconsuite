"""OWASP Top 10 (2021) Knowledge Source — Vorbereitung Phase 7 (Compliance Mapper).

Noch nicht aktiviert. Wird in Phase 7 auf den compliance_agent gesetzt.
Import in knowledge/__init__.py erst dann ergänzen.
"""

# OWASP_TOP10_TEXT = """
# # OWASP Top 10 — 2021
#
# A01:2021 – Broken Access Control
# Previously ranked #5. Access control enforces policy such that users cannot
# act outside of their intended permissions. Failures typically lead to unauthorized
# information disclosure, modification, or destruction of all data.
# Key CWEs: CWE-200, CWE-201, CWE-352
#
# A02:2021 – Cryptographic Failures
# Previously known as "Sensitive Data Exposure". Focus on failures related to
# cryptography which often lead to sensitive data exposure or system compromise.
# Key CWEs: CWE-259, CWE-327, CWE-331
#
# A03:2021 – Injection
# SQL, NoSQL, OS, LDAP injection. An application is vulnerable when user-supplied
# data is not validated, filtered, or sanitized by the application.
# Key CWEs: CWE-79, CWE-89, CWE-73
#
# A04:2021 – Insecure Design
# New category focusing on risks related to design and architectural flaws.
# Key CWEs: CWE-209, CWE-256, CWE-501, CWE-522
#
# A05:2021 – Security Misconfiguration
# Includes XML External Entities (XXE). Missing hardening, unnecessary features
# enabled, default accounts/passwords, error handling revealing too much information.
# Key CWEs: CWE-16, CWE-611
#
# A06:2021 – Vulnerable and Outdated Components
# Previously "Using Components with Known Vulnerabilities". Libraries, frameworks,
# and other software modules run with the same privileges as the application.
# Key CWEs: CWE-1104
#
# A07:2021 – Identification and Authentication Failures
# Previously "Broken Authentication". Confirmation of the user's identity,
# authentication, and session management is critical.
# Key CWEs: CWE-297, CWE-287, CWE-384
#
# A08:2021 – Software and Data Integrity Failures
# New category focusing on assumptions related to software updates, critical data,
# and CI/CD pipelines without verifying integrity.
# Key CWEs: CWE-829, CWE-494, CWE-502
#
# A09:2021 – Security Logging and Monitoring Failures
# Previously "Insufficient Logging & Monitoring". Without logging and monitoring,
# breaches cannot be detected.
# Key CWEs: CWE-778, CWE-117, CWE-223, CWE-532
#
# A10:2021 – Server-Side Request Forgery (SSRF)
# New category. SSRF flaws occur whenever a web application is fetching a remote
# resource without validating the user-supplied URL.
# Key CWEs: CWE-918
# """
