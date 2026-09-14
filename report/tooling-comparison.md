# VaultNotes — Tooling Comparison: Bandit (SAST) & OWASP ZAP (DAST)

**Purpose:** Compare automated tool findings against the 7 vulnerabilities identified through manual black-box and white-box testing (see `blackbox-findings-so-far.md` and `whitebox-findings-so-far.md`), to evaluate what automated scanning catches versus what still requires manual assessment.

---

## OWASP ZAP (DAST) — Scan Summary

**Target:** `vulnerable` branch, `http://127.0.0.1:5000`
**Policy:** Default Policy
**Authentication:** Form-based, scanned as an authenticated user (`alice`)
**Total endpoints discovered:** 39
**Alerts:** 3 High, 5 Medium, 3 Low, 5 Informational

### Alerts that confirm manual findings

| ZAP Alert | Risk | Maps to Manual Finding | Notes |
|---|---|---|---|
| SQL Injection | High | **Finding 3 — SQL Injection** | Confirmed on `/search?q=`. ZAP's evidence was a `500 Internal Server Error` triggered by a single `'` — the same signal used during manual black-box testing to first suspect injection. |
| Cross Site Scripting (Reflected) | High (4 instances) | **Finding 4 — Stored XSS** | Flagged on `/search`, `/notes/new`, and `/notes/<id>/edit`. ZAP classifies these as "Reflected" since it detected the payload echoed back in the immediate response; manual testing additionally confirmed the **stored/persistent** nature (payload survives and executes for other users on later visits), which ZAP separately flags below. |
| Cross Site Scripting (Persistent) | High (1 instance) | **Finding 4 — Stored XSS** | Flagged specifically on `/search`, since a stored payload from `/notes/new` was later reflected there — this is ZAP correctly distinguishing persistent XSS from reflected XSS as separate alert types. |

### Manual findings ZAP did NOT catch

| Manual Finding | Why ZAP missed it |
|---|---|
| **Finding 1 — Privilege Escalation (Mass Assignment)** | Requires knowing `is_admin` is a meaningful, security-sensitive hidden field. ZAP has no way to infer business meaning from a form field name — it can only test fields that are actually present in rendered forms/requests it observes, and even then has no concept of "this field grants administrative privilege." |
| **Finding 2 — IDOR** | Requires comparing responses **across two different authenticated user sessions** for the same resource ID — e.g. logging in as bob and requesting a note owned by alice. Default Policy Active Scan operates as a single authenticated user and has no built-in concept of resource ownership to violate. |
| **Finding 5 — SSRF** | Requires either out-of-band callback infrastructure (a separate listener to detect that the server made an outbound request) or recognizing that a "URL" parameter triggers a server-side fetch — neither was configured for this scan. |
| **Finding 6 — Broken Authentication (rate limiting)** | Not a code-pattern or single-response vulnerability; requires a sustained sequence of repeated requests and observing whether behavior changes over time/volume. Outside the scope of a standard Active Scan. |
| **Finding 7 — Stale Session Authorization** | Requires understanding *when* a privilege value is set into a session versus the current database state — a timing/business-logic property, not something detectable from any single request/response pair. |

**Takeaway for the report:** ZAP correctly and independently confirmed both injection-class vulnerabilities (SQLi, XSS) that were found manually, which is a meaningful validation of those findings using a second, independent method. However, it completely missed every **access-control and business-logic** vulnerability (mass assignment, IDOR, SSRF, broken auth, stale session) — none of which are single-request-detectable and all of which required either credential/session comparison across users or an understanding of what the application *should* do. This is a strong illustration of DAST's core limitation: it can find vulnerabilities that manifest as anomalous responses to malicious input, but not vulnerabilities that are actually correct-looking responses to requests that simply shouldn't have been authorized in the first place.

### Bonus findings — real issues outside original scope

ZAP surfaced several legitimate issues not part of the original 7, worth noting in the report as additional hardening opportunities discovered incidentally:

- **Absence of Anti-CSRF Tokens** (Medium, systemic) — no CSRF protection on any state-changing form (login, register, note edit/delete). Genuine gap; Flask apps typically address this with `Flask-WTF`'s CSRF protection.
- **Content Security Policy (CSP) Header Not Set** (Medium, systemic)
- **Missing Anti-clickjacking Header** (Medium, systemic) — no `X-Frame-Options` or CSP `frame-ancestors`
- **Cookie without SameSite Attribute** (Low, systemic) — the Flask session cookie doesn't set `SameSite`, which is also a relevant *defense-in-depth* layer against CSRF
- **Server Leaks Version Information** (Low, systemic) — the `Server` header exposes `Werkzeug/3.0.3 Python/3.14.5`, aiding an attacker in fingerprinting the stack
- **X-Content-Type-Options Header Missing** (Low, systemic)

### Likely false positives — worth flagging, not fixing blindly

- **Buffer Overflow** (Medium, 1 instance) and **Format String Error** (Medium, 1 instance) — both triggered on `/register` by long/format-string-style fuzzing input causing a `500` error. These ZAP rules were originally designed for C/C++-style memory-unsafe applications; Python is memory-safe and not susceptible to classic buffer overflows or format-string attacks in the way these CWEs describe. The real underlying issue is more likely an **unhandled exception on unexpected input** (e.g. a `500` instead of a clean validation error) — worth investigating as a minor robustness issue, but the "Buffer Overflow" / "Format String" labeling itself is a mismatch between ZAP's generic detection heuristic (server closed the connection / threw a 500) and the actual root cause in a Python/Flask context. Good example for the report of why automated tool output needs human interpretation rather than being trusted at face value.

---

## OWASP ZAP (DAST) — Re-Scan Against `main` (Patched)

**Target:** `main` branch, `http://127.0.0.1:5000`
**Policy:** Default Policy, same authenticated context/user as the `vulnerable` scan
**Alerts:** 0 High, 0 Medium, 1 Low, 3 Informational

| ZAP Alert | Risk | Status |
|---|---|---|
| SQL Injection | — | **Gone.** No longer detected — confirms the parameterized query fix (Finding 3) holds under independent DAST testing. |
| Cross Site Scripting (Reflected/Persistent) | — | **Gone.** No longer detected — confirms the `|safe` removal (Finding 4) holds. |
| Buffer Overflow / Format String Error | — | **Gone.** As expected, since these were false positives caused by an unhandled `500` on fuzzed input to `/register`, not fixed directly, but likely no longer triggering the same way. Worth a follow-up check on whether `/register` now handles malformed input more gracefully, or if this is incidental. |
| Cookie without SameSite Attribute | Low | Still present — not one of the original 7 findings, remains an open item (see below). |

**This is strong independent confirmation that Findings 3 and 4 are genuinely fixed**, not just passing the specific PoCs used during manual re-testing — a different tool, with different attack payloads, run against the live app, found nothing where it previously found high-severity issues.

### Notable observation: uncontrolled note creation during scanning

The patched-branch scan took significantly longer to complete than the vulnerable-branch scan, and the report shows **2,638 total endpoints discovered** (versus 39 on the initial scan) with note IDs climbing past 650. This happened because `/notes/new` creates a new database row on every POST with no deduplication or rate limiting — and ZAP's Active Scan sends many fuzzed variations of each form submission. Every fuzzed request to `/notes/new` created a new note, which became a newly discovered `/notes/<id>/edit` URL, which was then itself queued for fuzzing — producing a runaway feedback loop of ever-expanding scan scope.

This is not one of the original 7 findings, but it's a legitimate secondary observation worth documenting: **uncontrolled resource creation** on `/notes/new`. In a production context, this could be abused to flood a database with junk data (a form of resource-exhaustion/denial-of-service) with no authentication barrier beyond being logged in as any regular user. A reasonable mitigation would be applying the same rate-limiting pattern already built for Finding 6 to note creation as well, or adding basic per-user throttling on write-heavy endpoints.

---

*(See earlier session notes — re-run against `vulnerable` branch for direct comparison if not already done.)*

Bandit, run against the patched `main` branch, flagged:
- Hardcoded Flask `secret_key` (Low)
- `debug=True` in `app.run()` (High)

Neither of these were part of the original 7 findings, but both are legitimate. Like ZAP, Bandit did not catch any of the access-control/business-logic findings (1, 2, 5, 6, 7) — consistent with the same underlying limitation: static pattern-matching cannot reason about authorization logic.

---

## Overall Conclusion

| Category | Manual Testing | Bandit (SAST) | ZAP (DAST) — `vulnerable` | ZAP (DAST) — `main` (patched) |
|---|---|---|---|---|
| SQL Injection | ✅ | — (fixed before scan) | ✅ Detected | ✅ Gone after fix |
| Stored XSS | ✅ | — (fixed before scan) | ✅ Detected | ✅ Gone after fix |
| IDOR | ✅ | ❌ | ❌ | — |
| Mass Assignment / Priv. Esc. | ✅ | ❌ | ❌ | — |
| SSRF | ✅ | ❌ | ❌ | — |
| Broken Auth (rate limiting) | ✅ | ❌ | ❌ | — |
| Stale Session Authorization | ✅ | ❌ | ❌ | — |
| Hardcoded secret / debug mode | ❌ (not tested) | ✅ | — | — |
| CSRF / missing headers | ❌ (not tested) | — | ✅ | Cookie SameSite still open |
| Uncontrolled note creation | ❌ (not tested) | — | — | ✅ Discovered incidentally during patched-branch scan |

Automated tools (SAST and DAST alike) are effective at catching **injection-class vulnerabilities and configuration issues**, but structurally cannot detect **access-control and business-logic flaws** — these require a human tester who understands what the application is *supposed* to allow, not just what makes it behave unexpectedly. This is exactly why the job description for this type of role pairs "running SAST and DAST scans" with "reviewing system configurations" and "collaborating with engineers on remediation" — the tools cover one layer, and manual assessment covers the layer tools cannot reach.
