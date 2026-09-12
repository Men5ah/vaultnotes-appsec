# VaultNotes — White-Box Root Cause Analysis (In Progress)

**Tester:** [your name]
**Date:** September 2026
**Scope:** VaultNotes v1 source code (`auth.py`, `notes.py`, `models.py`, `admin.py`, templates)
**Method:** Source code review, performed after black-box testing (see `blackbox-findings-so-far.md`) to confirm the exact root cause of each previously-identified vulnerability. Findings are numbered to match the black-box report.

---

## Finding 1: Privilege Escalation via Mass Assignment — Root Cause

**File:** `auth.py`
**Function:** `register()`

**Vulnerable line:**
```python
is_admin = request.form.get("is_admin", "0") == "1"
```

**Root cause**
The registration handler reads an `is_admin` value directly from the client-submitted form data, with no restriction on who may set it and no allowlist limiting which fields the client is permitted to control. The HTML registration form never renders this field, so it is invisible through normal use of the UI, but the server places no server-side authorization check around it — it simply trusts whatever value is present in the POST body, defaulting to `"0"` only if the field is entirely absent.

This is a textbook **mass assignment** vulnerability: a security-sensitive attribute (`is_admin`) is bound directly from untrusted client input rather than being explicitly controlled by server-side logic.

**Remediation direction**
Remove client control of `is_admin` entirely from the registration path — new accounts should always be created as non-admin by default. If admin account creation needs to remain possible, it should be a separate, protected action performed by an existing administrator (e.g. a dedicated `/admin/users/promote` route gated by the existing `admin_required` check), never something a self-registering user can influence.

---

---

## Finding 2: IDOR — Root Cause

**File:** `notes.py`
**Functions:** `view_note()`, `edit_note()`, `delete_note()`

**Vulnerable pattern (present in all three routes):**
```python
note = Note.get_by_id(note_id)
# ...proceeds directly to return / modify / delete the note,
# with no check against the current user
```

**Root cause**
`Note.get_by_id()` itself is not the bug — it correctly fetches a note by ID and is used appropriately elsewhere in the app. The vulnerability is what's **missing** immediately after the fetch in each of these three routes: no comparison between `note.owner_id` and the currently authenticated user's ID before the route proceeds to return, modify, or delete the note. The app correctly authenticates *who* the user is (via the `login_required` decorator) but never authorizes *what* that user is allowed to act on.

This is present identically across all three routes, but the correct fix differs slightly by route:
- **`view_note`** should allow access if the note is public (`note.is_public`) OR the requester owns it
- **`edit_note`** / **`delete_note`** should only ever allow access if the requester owns the note — public visibility does not imply edit/delete rights

**Remediation direction**
Add an explicit authorization check immediately after the fetch in each route, e.g.:
```python
if note.owner_id != current_user().id:
    abort(403)
```
for `edit_note`/`delete_note`, and
```python
if not (note.is_public or note.owner_id == current_user().id):
    abort(403)
```
for `view_note`.

---

---

## Finding 3: SQL Injection — Root Cause

**File:** `models.py`
**Function:** `Note.search()`

**Vulnerable code:**
```python
sql = (
    "SELECT * FROM notes WHERE (title LIKE '%"
    + query
    + "%' OR content LIKE '%"
    + query
    + "%') ORDER BY created_at DESC"
)
rows = db.execute(sql).fetchall()
```

**Root cause**
The `query` parameter is inserted directly into the SQL string via Python string concatenation, rather than being passed as a bound/parameterized value. This means user input becomes part of the SQL syntax itself rather than being treated as inert data — which is what allowed a single quote in the black-box testing (Finding 3, black-box report) to close the intended string literal early and inject additional logic (`OR '1' LIKE '1`) into the WHERE clause.

Note that the use of `LIKE` itself is not the problem — the issue is exclusively how the query string is constructed. This is also the only query in `models.py` built via string concatenation; every other method in the file (`get_by_id`, `get_by_owner`, etc.) already uses parameterized `?` placeholders correctly, making `search()` an isolated inconsistency rather than a systemic pattern across the codebase.

**Remediation direction**
Use parameterized queries (bound placeholders), which keep SQL structure and user data completely separate at the database-driver level — a stronger and more reliable fix than attempting to sanitize or escape input manually:

```python
sql = "SELECT * FROM notes WHERE (title LIKE ? OR content LIKE ?) ORDER BY created_at DESC"
like_pattern = f"%{query}%"
rows = db.execute(sql, (like_pattern, like_pattern)).fetchall()
```

With this change, the `%` wildcard characters are part of the parameter *value*, not the SQL string, so no character in `query` — including quotes — can ever be interpreted as SQL syntax.

---

---

## Finding 4: Stored XSS — Root Cause

**Files:** `templates/notes_list.html`, `templates/note_detail.html`
**Pattern (appears in multiple places across both files):**
```html
<p>{{ note.content|safe }}</p>
```

**Root cause**
Jinja2 autoescapes template variables by default — converting characters like `<`, `>`, and `"` into HTML entities so that any HTML/JavaScript in a variable is rendered as inert, visible text rather than executed markup. The `|safe` filter explicitly disables this protection for the given variable, telling Jinja to render its value as raw, trusted HTML.

`note.content` originates directly from user input (via `notes.py`'s `new_note`/`edit_note` routes) with no server-side sanitization applied anywhere in the pipeline. Combining unsanitized user input with `|safe` means any HTML or `<script>` content a user submits is rendered verbatim and executed in the browser of anyone who later views that note — this is what allowed the `<script>alert(1)</script>` payload from black-box testing to execute.

This pattern appears in more than one location (both `notes_list.html` and `note_detail.html`), so the fix needs to be applied everywhere it occurs, not just once.

**Remediation direction**
Remove the `|safe` filter and let Jinja2's default autoescaping handle note content as plain text:
```html
<p>{{ note.content }}</p>
```
If limited HTML formatting in notes is a desired feature, use a dedicated sanitization library (e.g. `bleach`) to strip dangerous tags/attributes server-side before storage or rendering, rather than disabling escaping outright.

---

---

## Finding 5: SSRF — Root Cause

**File:** `notes.py`
**Function:** `url_preview()`

**Vulnerable lines:**
```python
url = request.form.get("url", "")
...
resp = requests.get(url, timeout=5)
```

**Root cause**
`url` is fully attacker-controlled input read directly from the request body. It flows unmodified into `requests.get(url, timeout=5)`, which performs a server-side outbound HTTP request to whatever value was supplied — with no validation of scheme (only `http`/`https` should ever be legitimate for a link-preview feature) and no check against the destination host. Nothing in the function prevents the target from being an internal or loopback address (`127.0.0.1`, `localhost`) or a private IP range.

This is the classic shape of an SSRF root cause: untrusted input reaching a sensitive sink (an outbound network request) with no validation in between. The two lines work together — the first captures fully attacker-controlled input, the second is the dangerous sink that acts on it unchecked.

**Remediation direction**
Before calling `requests.get()`:
- Validate that the URL scheme is `http` or `https` only
- Resolve the host and reject requests targeting private/internal IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`) and `localhost`
- Consider an allowlist of permitted domains if the feature's legitimate use case is narrow, which is more robust than a denylist

---

---

## Finding 6: Broken Authentication (No Rate Limiting) — Root Cause

**File:** `auth.py`
**Function:** `login()`

**Root cause**
Unlike the other findings, this is not caused by a specific flawed line but by an **absence**: nowhere in the `login()` function is there any mechanism to count failed attempts, apply a lockout, introduce a delay, or otherwise throttle repeated authentication attempts against the same account. Every login attempt — success or failure — is processed identically regardless of how many prior failed attempts preceded it:

```python
user = User.get_by_username(username)
if user and user.check_password(password):
    session["user_id"] = user.id
    session["is_admin"] = user.is_admin
    return redirect(url_for("notes.list_notes"))
```

This confirmed the black-box observation that 20 consecutive failed attempts produced no change in behavior, and the correct password still succeeded immediately afterward.

**Remediation direction**
Introduce rate limiting on the login endpoint — options include a fixed lockout after N failed attempts within a time window (tracked per-account and/or per-IP), an increasing delay between attempts, or a library such as `Flask-Limiter`. A CAPTCHA after a threshold of failures is another common complementary control.

---

## Finding 7: Stale Session Authorization — Root Cause

**Files:** `auth.py` (`login`), `admin.py` (`admin_required`)

**Vulnerable lines:**

`auth.py`, inside `login()`:
```python
session["is_admin"] = user.is_admin
```

`admin.py`, inside `admin_required()`:
```python
if not session.get("is_admin"):
    flash("Admin access required.")
    return redirect(url_for("notes.list_notes"))
```

**Root cause**
A user's admin status is read from the database and cached into the session **only at the moment of login**. Every subsequent request that checks admin access — via `admin_required` — trusts this cached session value rather than re-querying the database for the user's *current* `is_admin` status. This means privilege changes (in either direction) do not take effect for an already-active session until that user logs out and back in, which is what caused the black-box finding where a freshly-escalated account (Finding 1) did not gain admin access until a new login occurred.

**Remediation direction**
Re-check the user's current admin status from the database on each request requiring admin access, rather than relying solely on a value cached in the session at login time — e.g. `admin_required` should call `User.get_by_id(session.get("user_id"))` and check `.is_admin` fresh, rather than reading `session.get("is_admin")`. This also ensures that revoking admin access takes effect immediately rather than only on the affected user's next login.

---

## Summary

All 7 black-box findings now have confirmed root causes at the code level:

| # | Finding | Root Cause Location |
|---|---|---|
| 1 | Privilege Escalation (Mass Assignment) | `auth.py` — `register()` |
| 2 | IDOR | `notes.py` — `view_note()`, `edit_note()`, `delete_note()` |
| 3 | SQL Injection | `models.py` — `Note.search()` |
| 4 | Stored XSS | `templates/notes_list.html`, `templates/note_detail.html` |
| 5 | SSRF | `notes.py` — `url_preview()` |
| 6 | Broken Authentication | `auth.py` — `login()` |
| 7 | Stale Session Authorization | `auth.py` — `login()`, `admin.py` — `admin_required()` |

## Next Steps

- [ ] Apply remediations on `main` branch
- [ ] Re-test each fix against its original black-box PoC to confirm it's closed
- [ ] Optionally run Bandit (SAST) and OWASP ZAP (DAST) for a tooling comparison against manual findings