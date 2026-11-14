# SecureShop — CSSECDV S30C machine project

A deliberately small web app graded against a DLSU secure-web-development checklist.
Requirements live in `docs/specifications/` (specs PDF, checklist PDF, Canvas deliverable formats, rubric).
The checklist item numbers (2.1.1 … 2.4.7) are the vocabulary used everywhere: code comments, docs, tests.

## Hard rules

- **Never use global Python.** Only `C:\Apps\convert-markdown\.venv\Scripts\python.exe`.
- **Standard library only** for the app. Ask the user before installing any pip package
  (`python-docx` is already in the venv and is used only by `docs/build_docx.py`).
- python-docx reference docs are at `D:\Dev\docs\python-docx`.
- The user has allowed autonomous commits and pushes for this repo (no force-pushes).

## Commands

- Run: `C:\Apps\convert-markdown\.venv\Scripts\python.exe app.py` → http://127.0.0.1:8000 (`SHOP_PORT`, `SHOP_DB` override).
- Gate: `C:\Apps\convert-markdown\.venv\Scripts\python.exe test_app.py` must print `ALL TESTS PASSED`.
- Rebuild Word docs: `C:\Apps\convert-markdown\.venv\Scripts\python.exe docs\build_docx.py`.
- Reset demo state: delete `data/` (git-ignored; holds `shop.db` and `error.log`).

## Layout

- `app.py` — the whole app: validators, password hashing, `ROUTES` table, `dispatch()`, handlers, seed.
- `static/style.css` — only static file. No JavaScript, no inline styles (CSP `default-src 'self'`).
- `test_app.py` — plain assert script against a temp DB.
- `docs/*.md` — source of truth for the three Canvas deliverables; `docs/*.docx` are generated, never hand-edited.

## Invariants (do not break; the docs and graders rely on them)

- All requests go through `dispatch()`; role checks exist only in `authorize()` + the `ROUTES` table. Handlers never check roles. A new route = a new `ROUTES` row with an explicit role set. Deny by default.
- Input is validated with the `v_*` helpers and **rejected** via `ValidationError` — never stripped, truncated or otherwise sanitized. `dispatch()` logs every `ValidationError`.
- Every dynamic value in HTML goes through `html.escape`. SQL is always parameterized.
- Passwords and security answers: scrypt + per-secret salt (`hash_secret` / `verify_secret`). Never log secrets.
- Auth failure messages are fixed strings ("Invalid username and/or password.", "Password reset failed.", "Password change failed."); reasons go to the audit log only.
- `log()` is the only writer of `audit_log`; `/admin/logs` (admin-only) is the only reader. No route edits or deletes log rows.
- Errors: clients see generic custom pages; tracebacks go to `data/error.log` only.
- Roles: `admin` (Website Administrator), `manager` (Product Manager), `customer`. Admin has no product/order access.

## When behaviour changes

Update all of: `docs/SECURITY_DOCUMENTATION.md`, `docs/ACCESS_CONTROL_MATRIX.md`, `docs/TEST_CASES.md`, `README.md`,
then rebuild the `.docx` files. Limits, routes and messages are quoted verbatim in those docs.
