# SecureShop — CSSECDV Machine Project (Web App)

CSSECDV S30C, AY 2026–2027 Term 1. A small product catalog and ordering web application built to
demonstrate the secure web development checklist: authentication, authorization, data validation,
and error handling and logging.

- **Language:** Python 3 (developed on 3.14), **standard library only** — nothing to `pip install` for the app.
- **Storage:** SQLite (`data/shop.db`, created on first run).
- **Layout:** the whole application is `app.py`; `static/style.css` is the only static file.

## Running

Use the project's Python interpreter (never the global one):

```
C:\Apps\convert-markdown\.venv\Scripts\python.exe app.py
```

Then open <http://127.0.0.1:8000/>. Set `SHOP_PORT` to use another port and `SHOP_DB` to use another
database file. Delete the `data` folder to reset everything to the seeded state.

## Demo accounts

Created automatically when the database is empty. **Demo only — change them anywhere else.**

| Role | Username | Password |
|---|---|---|
| Website Administrator | `admin` | `Admin#Secure2026!` |
| Product Manager | `manager` | `Manager#Secure2026!` |
| Customer | `customer` | `Customer#Secure2026!` |

Security answer for all three: `Mrs. Evangelista-Santos`.

## Roles

| Role | Can do |
|---|---|
| Administrator | Create / delete / re-assign Administrator and Product Manager accounts; view and filter the audit log (read-only). |
| Product Manager | Add / edit / delete products; view all orders; mark pending orders fulfilled or cancelled. |
| Customer | Register; view products; place, edit and cancel their own pending orders. |

Everyone who is logged in can change their own password. The full mapping is in
[docs/ACCESS_CONTROL_MATRIX.md](docs/ACCESS_CONTROL_MATRIX.md).

## Security controls at a glance

| Area | How |
|---|---|
| Access control | One `ROUTES` table + `authorize()` inside `dispatch()`; deny by default. |
| Passwords | scrypt (N=2^14, r=8, p=1) with a 16-byte random salt per password; 12–128 chars with upper, lower, digit and special. |
| Lockout | 5 failed attempts → locked for 15 minutes. |
| Password rules | No re-use of any previous password; minimum age one day; current password required to change. |
| Reset | Fixed list of high-entropy security questions; answers stored hashed. |
| Sessions | Random token (SHA-256 stored), `HttpOnly; SameSite=Strict`, 30-minute idle timeout, CSRF token on every POST. |
| Validation | Allow-list validators that reject (never sanitize); parameterized SQL; HTML-encoded output. |
| Errors | Custom 400/403/404/405/413/500 pages; tracebacks only in `data/error.log`. |
| Logging | `audit_log` table recording successes and failures of auth, access control, validation, data and admin events; admin-only, read-only viewer with filters. |

Details per checklist item: [docs/SECURITY_DOCUMENTATION.md](docs/SECURITY_DOCUMENTATION.md).

## Tests

```
C:\Apps\convert-markdown\.venv\Scripts\python.exe test_app.py
```

Starts the server on a random port with a temporary database and prints `ALL TESTS PASSED`.
The manual demo script is [docs/TEST_CASES.md](docs/TEST_CASES.md).

## Documentation

| File | Purpose |
|---|---|
| `docs/specifications/` | Project specifications, checklist and Canvas submission format / rubric. |
| `docs/SECURITY_DOCUMENTATION.md` / `.docx` | Canvas deliverable: requirement, vulnerability, impact, security control. |
| `docs/ACCESS_CONTROL_MATRIX.md` / `.docx` | Canvas deliverable: every feature mapped to every role. |
| `docs/TEST_CASES.md` / `.docx` | Canvas deliverable: control group, test scenario, expected outcome. |
| `docs/build_docx.py` | Regenerates the `.docx` files from the Markdown sources (needs `python-docx`). |

The Markdown files are the source of truth. After editing them, rebuild the Word documents:

```
C:\Apps\convert-markdown\.venv\Scripts\python.exe docs\build_docx.py
```

## Known limitations

- Plain HTTP on localhost for the demo (no TLS, so no `Secure` cookie flag).
- Accounts created by an administrator have no security question, so they cannot self-reset a password.
