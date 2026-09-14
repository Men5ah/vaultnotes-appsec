# VaultNotes — Security Assessment Report

**Application:** VaultNotes (Flask + SQLite notes app)
**Assessment type:** Full-cycle security assessment — black-box testing, white-box code review, remediation, and independent tool verification
**Branches:** `vulnerable` (unpatched baseline, frozen) → `main` (remediated)
**Tester:** [your name]
**Date:** September 2026

---

## Executive Summary

Over the course of this assessment, VaultNotes — a deliberately built, intentionally vulnerable Flask application — was tested end-to-end using an industry-representative methodology: black-box behavioral testing, white-box source code review to establish root cause, remediation with re-verification against original proof-of-concepts, and independent confirmation using automated SAST (Bandit) and DAST (OWASP ZAP) tooling.

**7 vulnerabilities were identified, confirmed, root-caused, and remediated:**

| # | Finding | OWASP Category | Severity | Status |
|---|---|---|---|---|
| 1 | Privilege Escalation via Mass Assignment | Broken Access Control | High | ✅ Fixed |
| 2 | Insecure Direct Object Reference (IDOR) | Broken Access Control | High | ✅ Fixed |
| 3 | SQL Injection (search) | Injection | High | ✅ Fixed |
| 4 | Stored Cross-Site Scripting (XSS) | Injection | High | ✅ Fixed |
| 5 | Server-Side Request Forgery (SSRF) | SSRF | Medium–High | ✅ Fixed |
| 6 | Broken Authentication (no rate limiting) | Broken Authentication | Medium | ✅ Fixed |
| 7 | Stale Session Authorization | Broken Access Control | Low–Medium | ✅ Fixed |

Two additional issues were identified incidentally during automated tooling and are documented as known, unremediated gaps: **absence of CSRF protection** and **missing security headers** (CSP, X-Frame-Options, X-Content-Type-Options, cookie `SameSite`). A secondary observation — **uncontrolled resource creation** on the note-creation endpoint — was also discovered during DAST re-scanning and is noted for future hardening.

A key finding of this assessment, independent of any single vulnerability: **automated tooling (both SAST and DAST) reliably detected injection-class vulnerabilities (SQLi, XSS) but detected none of the access-control or business-logic vulnerabilities** (mass assignment, IDOR, SSRF, broken auth, stale sessions) — all 5 of which required manual testing to discover. This gap is the core justification for pairing automated scanning with manual assessment in any real security program.

---

## Methodology

1. **Black-box testing** — the application was tested purely through its exposed behavior (HTTP requests via `curl`), with no source code consulted, informed by the OWASP Top 10.
2. **White-box code review** — for each confirmed black-box finding, the source code was reviewed to identify exact root cause (file and line).
3. **Remediation** — fixes were implemented directly on `main`; the `vulnerable` branch was preserved unmodified as a frozen baseline for reproducibility.
4. **Re-verification** — each fix was re-tested against its original proof-of-concept to confirm closure.
5. **Independent tool verification** — Bandit (SAST) and OWASP ZAP (DAST) were run against both branches to cross-check manual findings and surface anything missed.

---

## Finding 1: Privilege Escalation via Mass Assignment

**Severity:** High | **OWASP Category:** Broken Access Control

**Description**
The registration endpoint (`/register`) only exposes `username`, `email`, and `password` in its rendered HTML form. However, the server accepted an additional, undocumented `is_admin` field from the raw POST body, granting the newly created account administrator privileges.

**Proof of Concept**
```
curl -i -c cookies.txt -X POST http://127.0.0.1:5000/register \
  -d "username=eve" -d "email=eva@test.com" \
  -d "password=Hello12345!" -d "is_admin=1"
```
Verified against the database: `sqlite3 vaultnotes.db "SELECT id, username, is_admin FROM users WHERE username='eve';"` → `6|eve|1`

**Root Cause**
`auth.py`, `register()`:
```python
is_admin = request.form.get("is_admin", "0") == "1"
```
The server trusted any field present in the request body with no allowlist restricting which fields a client may control — a classic mass-assignment vulnerability.

**Remediation**
```python
user = User.create(username, email, password, is_admin=False)
```
Client control of `is_admin` was removed entirely; all self-registered accounts are now created as non-admin by default.

**Verification**
Re-running the original PoC payload (`is_admin=1`) against the patched code resulted in the account being created with `is_admin=0` in the database — the field is now fully ignored.

---

## Finding 2: Insecure Direct Object Reference (IDOR)

**Severity:** High | **OWASP Category:** Broken Access Control

**Description**
Notes were retrieved, edited, and deleted using a numeric ID in the URL (`/notes/<id>`, `/notes/<id>/edit`, `/notes/<id>/delete`) with no verification that the requesting user owned the note or that it was public. Any authenticated user could view, modify, or delete any other user's notes, including private ones.

**Proof of Concept**
```
# Alice creates a private note, note its ID
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/new \
  -d "title=Alice Secret" -d "content=This should not be visible to bob"

# Bob views it directly
curl -b bob_cookies.txt http://127.0.0.1:5000/notes/4
# -> 200 OK, full private content returned

# Bob edits it
curl -b bob_cookies.txt -X POST http://127.0.0.1:5000/notes/4/edit \
  -d "title=Hacked by bob" -d "content=pwned"
# -> change persisted to the database
```

**Root Cause**
`notes.py`, `view_note()`, `edit_note()`, `delete_note()`: each fetched the note by ID and proceeded directly to act on it, with no comparison against the current user's ID.

**Remediation**
Added existence checks (first) followed by authorization checks (second) to all three routes — public-or-owner for viewing, owner-only for editing and deleting:
```python
note = Note.get_by_id(note_id)
if not note:
    flash("Note not found.")
    return redirect(url_for("notes.list_notes"))

if not (note.is_public or note.owner_id == current_user().id):  # view_note
    flash("You do not have permission to view this note.")
    return redirect(url_for("notes.list_notes"))
```
Edit/delete/list templates were also updated so Edit/Delete controls are only rendered for the note's owner (defense-in-depth; the server-side check remains the actual control).

**Verification**
Re-running the original PoC: bob's view request against alice's private note now returns a 302 redirect with no content leaked; his edit and delete attempts leave the note completely unchanged. Alice retains full access to her own notes.

---

## Finding 3: SQL Injection (Search)

**Severity:** High | **OWASP Category:** Injection

**Description**
The `/search` endpoint built its SQL query via direct string concatenation of user input, allowing an attacker to alter query logic and retrieve data that should not have matched the search term — including notes not owned by the requesting user.

**Discovery process**
An initial single-quote payload (`q=x'`) produced `sqlite3.OperationalError: unrecognized token`, revealing that input was inserted directly into SQL syntax and that the app wraps input in a `LIKE '%...%'` pattern. Payloads using `=` were defeated by the trailing `%` (a literal character in `=` comparisons); a payload using `LIKE` succeeded, since `%` is a wildcard in that context.

**Proof of Concept**
```
curl -b alice_cookies.txt -G http://127.0.0.1:5000/search \
  --data-urlencode "q=x' OR '1' LIKE '1"
```
Returned every note in the database, including notes owned by other users and unrelated to the search term.

**Root Cause**
`models.py`, `Note.search()`:
```python
sql = (
    "SELECT * FROM notes WHERE (title LIKE '%" + query
    + "%' OR content LIKE '%" + query + "%') ORDER BY created_at DESC"
)
rows = db.execute(sql).fetchall()
```
The only query in the file built via string concatenation rather than parameterization (every other method already used `?` placeholders correctly).

**Remediation**
```python
sql = "SELECT * FROM notes WHERE (title LIKE ? OR content LIKE ?) ORDER BY created_at DESC"
pattern = f"%{query}%"
rows = db.execute(sql, (pattern, pattern)).fetchall()
return [Note(r) for r in rows if r["is_public"] or r["owner_id"] == session.get("user_id")]
```
The query was parameterized, and an additional filter was added so search results respect the same public/private visibility rules as the rest of the app (a user's own private notes are searchable by them; other users' private notes are not).

**Verification**
The original injection payload no longer returns unrelated data. Normal search correctly excludes other users' private notes while still surfacing the searching user's own private notes.

---

## Finding 4: Stored Cross-Site Scripting (XSS)

**Severity:** High | **OWASP Category:** Injection

**Description**
Note content was rendered without sanitization or output encoding, allowing submitted HTML/JavaScript to be stored and later executed in the browser of any user who viewed the note — including other users, since notes can be marked public.

**Proof of Concept**
```
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/new \
  --data-urlencode "title=XSS Test" \
  --data-urlencode "content=<script>alert(1)</script>" \
  -d "is_public=on"
```
The raw HTML response contained the unescaped tag; viewing the note in a real browser produced a genuine JavaScript alert.

**Root Cause**
`templates/notes_list.html` and `templates/note_detail.html`, multiple locations:
```html
<p>{{ note.content|safe }}</p>
```
The `|safe` filter explicitly disabled Jinja2's default autoescaping on user-controlled content with no sanitization applied anywhere in the pipeline.

**Remediation**
Removed `|safe` from every occurrence in both templates, restoring Jinja2's default HTML-entity escaping:
```html
<p>{{ note.content }}</p>
```

**Verification**
The same payload now renders as inert, escaped text (`&lt;script&gt;...`); no alert fires in the browser.

---

## Finding 5: Server-Side Request Forgery (SSRF)

**Severity:** Medium–High | **OWASP Category:** SSRF

**Description**
The `/notes/preview` endpoint performed a server-side HTTP fetch of any user-supplied URL, with no validation of scheme or destination host, and no binding to note ownership or existence.

**Proof of Concept**
```
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/preview \
  --data-urlencode "url=http://127.0.0.1:5000/admin"
# -> 200, server successfully issued the internal request

curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/preview \
  --data-urlencode "url=file:///etc/passwd"
# -> rejected, but only because the requests library lacks a file:// handler,
#    not due to any validation in the application
```

**Root Cause**
`notes.py`, `url_preview()`:
```python
url = request.form.get("url", "")
resp = requests.get(url, timeout=5)
```
Fully attacker-controlled input flowed directly into an outbound request with no scheme or host validation.

**Remediation**
```python
def safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        ip = socket.gethostbyname(parsed.hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
    except Exception:
        return False
    return True
```
Called before `requests.get()`; rejects unsafe URLs before any request is attempted.

**Verification**
Legitimate external URLs still succeed; loopback/localhost targets and non-http(s) schemes are now rejected pre-flight.

---

## Finding 6: Broken Authentication — No Rate Limiting

**Severity:** Medium | **OWASP Category:** Broken Authentication

**Description**
The `/login` endpoint had no mechanism to throttle or lock out repeated failed login attempts, permitting unrestricted brute-force or credential-stuffing attacks against any known username.

**Proof of Concept**
20 consecutive failed login attempts against `alice` all returned identical behavior; the correct password still succeeded immediately afterward with no obstruction.

**Root Cause**
`auth.py`, `login()` — no counting, lockout, delay, or CAPTCHA mechanism existed anywhere in the function.

**Remediation**
A rudimentary in-memory rate limiter was implemented: a per-username failed-attempt counter and lockout timestamp, checked before credential verification and reset on successful login:
```python
if username in locked_until and time.time() < locked_until[username]:
    flash("Account is locked. Please try again later.")
    return render_template("login.html")

user = User.get_by_username(username)
if user and user.check_password(password):
    ...
    if username in failed_attempts: del failed_attempts[username]
    if username in locked_until: del locked_until[username]
    return redirect(url_for("notes.list_notes"))

failed_attempts[username] = failed_attempts.get(username, 0) + 1
if failed_attempts[username] > 4:
    locked_until[username] = time.time() + 300
    flash("Too many failed login attempts. Please try again later.")
```
**Known limitation:** state is held in an in-process Python dictionary — it resets on app restart and would not synchronize correctly across multiple worker processes. A production deployment would use a shared store (e.g. Redis) or an established library such as `Flask-Limiter`.

**Verification**
5 failed attempts are permitted; the 6th triggers a lockout. During the lockout window, even the correct password is rejected. A fresh (never-failed) account can log in successfully with no false-positive lockout.

---

## Finding 7: Stale Session Authorization

**Severity:** Low–Medium | **OWASP Category:** Broken Access Control

**Description**
A user's admin status was read from the database and cached into the session only at login time. Subsequent requests trusted this cached value rather than the user's current database state, meaning privilege changes (grants or revocations) did not take effect until the affected user logged out and back in.

**Proof of Concept**
A newly escalated account (Finding 1) did not gain working admin access using its registration-time session; a fresh login was required before `/admin` access was granted, despite `is_admin=1` already being present in the database.

**Root Cause**
`auth.py`, `login()`: `session["is_admin"] = user.is_admin` (cached once, at login)
`admin.py`, `admin_required()`: `if not session.get("is_admin"):` (trusted the cached value indefinitely)

**Remediation**
```python
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            flash("Admin access required.")
            return redirect(url_for("notes.list_notes"))
        return view(*args, **kwargs)
    return wrapped
```
`admin_required` now re-fetches the user from the database on every request via `current_user()`, rather than trusting a session-cached flag.

**Verification**
A user's `is_admin` flag was flipped directly in the database mid-session (no re-login): admin access was granted on the very next request. Flipping it back to non-admin revoked access immediately, same session — confirming both grant and revocation now take effect in real time.

---

## Independent Tool Verification

### Bandit (SAST)

Run against the patched `main` branch, Bandit flagged two issues outside the original 7 findings:
- **Hardcoded Flask `secret_key`** (Low) — a static string in `app.py`, allowing session-cookie forgery by anyone with source access.
- **`debug=True`** (High) — exposes the interactive Werkzeug debugger, which permits arbitrary code execution if reached.

Bandit did not detect any of the 7 original findings — all require understanding of business/authorization logic, which static pattern-matching cannot evaluate.

### OWASP ZAP (DAST)

**Against `vulnerable`:** 3 High, 5 Medium, 3 Low, 5 Informational alerts. Independently confirmed **SQL Injection** and both **Reflected and Persistent XSS** (Findings 3 and 4) via a completely different testing method than manual black-box testing — strong cross-validation. ZAP also surfaced legitimate issues outside the original scope: absence of CSRF tokens, missing CSP/clickjacking/`X-Content-Type-Options` headers, missing cookie `SameSite` attribute, and server version disclosure. Two alerts (**Buffer Overflow**, **Format String Error**) were assessed as false positives — legacy ZAP heuristics designed for memory-unsafe languages, misfiring on an unhandled `500` error in Python, which is not susceptible to either underlying vulnerability class.

**Against `main` (patched):** 0 High, 0 Medium, 1 Low, 3 Informational. SQLi and XSS alerts were **gone**, independently confirming Findings 3 and 4 are genuinely remediated rather than only passing their original PoCs. The cookie `SameSite` issue remains open (not one of the original 7; documented as a known gap). The patched-branch scan also surfaced an unplanned secondary observation: **uncontrolled note creation** — `/notes/new` has no deduplication or rate limiting, and ZAP's fuzzing of that form during Active Scan created hundreds of junk notes, ballooning the scan's discovered-endpoint count from 39 to 2,638. This is a legitimate resource-exhaustion-adjacent issue worth future hardening (e.g. applying the Finding 6 rate-limiting pattern to note creation as well).

**Critically: ZAP detected none of the 5 access-control/business-logic findings** (mass assignment, IDOR, SSRF, broken auth, stale session) — consistent with Bandit's blind spot and reinforcing the report's core conclusion below.

---

## Conclusion

| Category | Manual Testing | Bandit (SAST) | ZAP (DAST) — vulnerable | ZAP (DAST) — main |
|---|---|---|---|---|
| SQL Injection | ✅ | — | ✅ | ✅ Gone after fix |
| Stored XSS | ✅ | — | ✅ | ✅ Gone after fix |
| IDOR | ✅ | ❌ | ❌ | — |
| Mass Assignment / Priv. Esc. | ✅ | ❌ | ❌ | — |
| SSRF | ✅ | ❌ | ❌ | — |
| Broken Auth (rate limiting) | ✅ | ❌ | ❌ | — |
| Stale Session Authorization | ✅ | ❌ | ❌ | — |
| Hardcoded secret / debug mode | ❌ | ✅ | — | — |
| CSRF / missing headers | ❌ | — | ✅ | Cookie SameSite still open |
| Uncontrolled note creation | ❌ | — | — | ✅ Discovered incidentally |

All 7 identified vulnerabilities were confirmed via black-box testing, root-caused via white-box code review, remediated on `main`, and re-verified both against original proof-of-concepts and via independent automated tooling. Automated SAST and DAST tools reliably caught injection-class vulnerabilities but detected **none** of the access-control or business-logic findings — reinforcing that meaningful application security assessment requires manual testing informed by an understanding of intended application behavior, not automated scanning alone.

**Known open items, out of scope for this remediation pass:**
- Absence of CSRF protection on state-changing forms
- Missing security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Missing cookie `SameSite` attribute
- Hardcoded Flask `secret_key`
- `debug=True` in application entrypoint
- Uncontrolled resource creation on `/notes/new`
