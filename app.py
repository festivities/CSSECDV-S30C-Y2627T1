"""SecureShop: a small, locked-down web shop. Python standard library only.

Run with:  python app.py   (SHOP_PORT overrides 8000, SHOP_DB overrides data/shop.db)
"""
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("SHOP_DB") or os.path.join(BASE_DIR, "data", "shop.db")
ERROR_LOG = os.path.join(os.path.dirname(DB_PATH), "error.log")
STYLE_PATH = os.path.join(BASE_DIR, "static", "style.css")

TS_FMT = "%Y-%m-%d %H:%M:%S"
MAX_BODY = 10_000
FORM_TYPE = "application/x-www-form-urlencoded"
SESSION_IDLE = timedelta(minutes=30)
LOCK_AFTER = 5
LOCK_FOR = timedelta(minutes=15)
PAGE_SIZE = 50
USERNAME_RE = r"[A-Za-z0-9_]{3,30}"
DATE_RE = r"\d{4}-\d{2}-\d{2}"
LOG_CATEGORIES = ["AUTH", "ACCESS", "VALIDATION", "DATA", "ADMIN", "ERROR"]
LOGIN_FAIL = "Invalid username and/or password."
RESET_FAIL = "Password reset failed."
DENIED = "You do not have permission to do that."
GENERIC_500 = "Something went wrong. Please try again later."
ONLY_PENDING = "Only pending orders can be changed."
ROLE_NAMES = {"admin": "Website Administrator", "manager": "Product Manager", "customer": "Customer"}
SECURITY_QUESTIONS = [
    "What was the name of your first-grade teacher?",
    "What was the license plate of your family's first car?",
    "What is the full name of your childhood best friend?",
    "What was the street name and number of your first home?",
    "What was the model of your first mobile phone?",
]
SEED_ANSWER = "Mrs. Evangelista-Santos"
SEED_USERS = [
    ("admin", "Admin#Secure2026!", "admin"),
    ("manager", "Manager#Secure2026!", "manager"),
    ("customer", "Customer#Secure2026!", "customer"),
]
SEED_PRODUCTS = [
    ("Wireless Keyboard", "Compact 2.4 GHz keyboard with long battery life.", 2499, 25),
    ("USB-C Hub", "Seven-in-one hub with HDMI and card readers.", 1899, 40),
    ("Noise-Cancelling Headset", "Over-ear headset with a detachable microphone.", 4590, 10),
]
SECURITY_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    # Not "no-referrer": that makes browsers send "Origin: null" on same-site form posts,
    # which the Origin check in handle() would reject.
    ("Referrer-Policy", "same-origin"),
    ("Cache-Control", "no-store"),
]
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE COLLATE NOCASE NOT NULL,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    sec_question INTEGER,
    sec_answer_hash TEXT,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    pw_changed_at TEXT NOT NULL,
    last_use_at TEXT,
    last_use_ok INTEGER,
    last_use_ip TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pw_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    prev_use TEXT,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    stock INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL,
    product_name TEXT NOT NULL,
    unit_price_cents INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'fulfilled', 'cancelled')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    username TEXT,
    ip TEXT,
    category TEXT NOT NULL,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT
);
"""


class ValidationError(Exception):
    """Input rejected. The message is shown to the user."""


class Abort(Exception):
    """Stop the request with an error page (no validation audit row)."""

    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


# ---------------------------------------------------------------- helpers

def now_utc():
    return datetime.now(timezone.utc)


def ts(moment=None):
    return (moment or now_utc()).strftime(TS_FMT)


def parse_ts(text):
    return datetime.strptime(text, TS_FMT).replace(tzinfo=timezone.utc)


def e(value):
    return html.escape(str(value), quote=True)


def matches(pattern, value):
    return re.fullmatch(pattern, value, re.ASCII) is not None


def money(cents):
    return f"{cents // 100}.{cents % 100:02d}"


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def cookie_value(header, name):
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return ""


def who(r):
    return r.session["username"] if r.session else None


def log_trace(context):
    logger = logging.getLogger("shop")
    if not logger.handlers:
        logger.addHandler(logging.FileHandler(ERROR_LOG, encoding="utf-8"))
        logger.propagate = False
    logger.exception("%s", context)


# ---------------------------------------------------------------- crypto

def _scrypt(secret, salt):
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def hash_secret(secret):
    salt = secrets.token_bytes(16)
    return f"scrypt${salt.hex()}${_scrypt(secret, salt).hex()}"


def verify_secret(secret, stored):
    _, salt_hex, hash_hex = stored.split("$")
    return hmac.compare_digest(_scrypt(secret, bytes.fromhex(salt_hex)), bytes.fromhex(hash_hex))


DUMMY_HASH = hash_secret("timing-filler-never-matches")


# ---------------------------------------------------------------- database

def connect():
    # ponytail: BEGIN IMMEDIATE serializes all requests; fine for a demo, per-row locking if load matters.
    db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = connect()
    try:
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            seed(db)
        db.commit()
    finally:
        db.close()


def seed(db):
    old = ts(now_utc() - timedelta(days=2))
    for username, password, role in SEED_USERS:
        create_user(db, username, password, role, 0, SEED_ANSWER, changed=old)
    db.executemany("INSERT INTO products (name, description, price_cents, stock) VALUES (?, ?, ?, ?)", SEED_PRODUCTS)


def log(db, category, event, outcome, detail="", username=None, ip=None):
    db.execute("INSERT INTO audit_log (ts, username, ip, category, event, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (ts(), username, ip, category, event, outcome, str(detail)))


def find_user(db, username):
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def create_user(db, username, password, role, question=None, answer=None, changed=None):
    now = ts()
    pw_hash = hash_secret(password)
    answer_hash = hash_secret(answer.casefold()) if answer is not None else None
    try:
        cur = db.execute(
            "INSERT INTO users (username, pw_hash, role, sec_question, sec_answer_hash, pw_changed_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, pw_hash, role, question, answer_hash, changed or now, now))
    except sqlite3.IntegrityError:
        raise ValidationError("Registration failed. Choose a different username.")
    db.execute("INSERT INTO password_history (user_id, pw_hash, created_at) VALUES (?, ?, ?)",
               (cur.lastrowid, pw_hash, now))
    return cur.lastrowid


def store_password(db, user_id, password):
    pw_hash = hash_secret(password)
    now = ts()
    db.execute("UPDATE users SET pw_hash = ?, pw_changed_at = ?, failed_count = 0, locked_until = NULL WHERE id = ?",
               (pw_hash, now, user_id))
    db.execute("INSERT INTO password_history (user_id, pw_hash, created_at) VALUES (?, ?, ?)", (user_id, pw_hash, now))


def was_used(db, user_id, password):
    rows = db.execute("SELECT pw_hash FROM password_history WHERE user_id = ?", (user_id,)).fetchall()
    return any(verify_secret(password, row["pw_hash"]) for row in rows)


def is_locked(row, moment):
    return bool(row["locked_until"]) and parse_ts(row["locked_until"]) > moment


def count_failure(db, row, reason):
    """Count one failed check (password or security answer). Returns the audit reason."""
    if row["failed_count"] + 1 >= LOCK_AFTER:
        db.execute("UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?",
                   (ts(now_utc() + LOCK_FOR), row["id"]))
        return "lockout triggered"
    db.execute("UPDATE users SET failed_count = failed_count + 1 WHERE id = ?", (row["id"],))
    return reason


def describe_prev(row):
    if not row["last_use_at"]:
        return "No previous activity recorded."
    kind = "successful login" if row["last_use_ok"] else "unsuccessful login attempt"
    return f"{row['last_use_at']} UTC — {kind} from {row['last_use_ip']}"


def load_session(db, token):
    if not token:
        return None
    th = token_hash(token)
    row = db.execute(
        "SELECT s.token_hash, s.csrf, s.prev_use, s.last_seen, u.id AS user_id, u.username, u.role "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (th,)).fetchone()
    if row is None:
        return None
    now = now_utc()
    if now - parse_ts(row["last_seen"]) > SESSION_IDLE:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
        return None
    db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (ts(now), th))
    return {key: row[key] for key in row.keys()}


# ---------------------------------------------------------------- validation

def v_str(form, name, min_len, max_len, pattern=None):
    val = form.get(name)
    if val is None or not min_len <= len(val) <= max_len or (pattern and not matches(pattern, val)):
        raise ValidationError(f"Invalid {name}.")
    return val


def v_int(form, name, lo, hi):
    val = form.get(name, "")
    if not matches(r"\d{1,9}", val):
        raise ValidationError(f"Invalid {name}.")
    if not lo <= int(val) <= hi:
        raise ValidationError(f"{name.capitalize()} must be between {lo} and {hi}.")
    return int(val)


def v_price(form, name):
    val = form.get(name, "")
    if not matches(r"\d{1,7}(\.\d{1,2})?", val):
        raise ValidationError("Invalid price.")
    whole, _, frac = val.partition(".")
    cents = int(whole) * 100 + int((frac + "00")[:2])
    if not 1 <= cents <= 100_000_000:
        raise ValidationError("Price must be between 0.01 and 1000000.00.")
    return cents


def v_choice(form, name, choices):
    val = form.get(name)
    if val not in choices:
        raise ValidationError(f"Invalid {name}.")
    return val


def v_password(form, name):
    pw = form.get(name, "")
    if not (12 <= len(pw) <= 128 and re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw)
            and re.search(r"[0-9]", pw) and re.search(r"[^A-Za-z0-9]", pw)):
        raise ValidationError("Password must be 12-128 characters and include an uppercase letter, "
                              "a lowercase letter, a digit and a symbol.")
    return pw


def v_opt(form, name, pattern):
    """Optional filter: empty means no filter."""
    val = form.get(name, "")
    if val and not matches(pattern, val):
        raise ValidationError(f"Invalid {name}.")
    return val


def parse_fields(text):
    try:
        raw = urllib.parse.parse_qs(text, keep_blank_values=True, max_num_fields=50)
    except ValueError:
        raise ValidationError("Too many form fields.")
    for name, values in raw.items():
        if len(values) > 1:
            raise ValidationError(f"Field {name} was given more than once.")
    return {name: values[0] for name, values in raw.items()}


# ---------------------------------------------------------------- dispatcher

def redirect(location, *cookies):
    return 302, "", [("Location", location)] + [("Set-Cookie", c) for c in cookies]


ERROR_TITLES = {400: "Request rejected", 403: "Access denied", 404: "Page not found", 405: "Method not allowed",
                413: "Request too large", 500: "Something went wrong"}
# Where "Go back" leads after a rejected request: the page holding the form (first matching prefix wins).
BACK_PAGES = [("/orders/new", "/products"), ("/forgot", "/forgot"), ("/login", "/login"), ("/register", "/register"),
              ("/password", "/password"), ("/orders", "/orders"), ("/manage/products", "/manage/products"),
              ("/manage/orders", "/manage/orders"), ("/admin/users", "/admin/users"), ("/admin/logs", "/admin/logs")]


def error_page(status, msg, session, path=""):
    back = "/"
    if status == 400:  # fixed destinations only; nothing from the request goes into the link
        back = next((dest for prefix, dest in BACK_PAGES if path.startswith(prefix)), "/")
    body = f'<p class="error">{e(msg)}</p><p><a href="{e(back)}">Go back</a></p>'
    return status, page(ERROR_TITLES.get(status, "Error"), body, session), []


def fail(r, status, msg, commit, audit=None):
    """Error response. Commits what the request already wrote (lockout counters, audit rows)."""
    if r.db is not None:
        if not commit:
            r.db.rollback()
        if audit:
            log(r.db, audit[0], audit[1], "FAILURE", audit[2], who(r), r.ip)
        r.db.commit()
    return error_page(status, msg, r.session, r.path)


def find_route(method, path):
    path_known = False
    for route_method, pattern, fn, roles in ROUTES:
        m = pattern.fullmatch(path)
        if m is None:
            continue
        if route_method == method:
            return m.groups(), fn, roles
        path_known = True
    if path_known:
        raise Abort(405, "Method not allowed.")
    raise Abort(404, "Page not found.")


def authorize(r, roles):
    """Deny by default. Returns None when allowed, otherwise the finished response."""
    if "public" in roles:
        return None
    if r.session is None:
        log(r.db, "ACCESS", "unauthenticated", "FAILURE", r.path, None, r.ip)
        return redirect("/login")
    if r.session["role"] not in roles:
        log(r.db, "ACCESS", "role", "FAILURE", f"{r.path} role={r.session['role']}", who(r), r.ip)
        return error_page(403, DENIED, r.session)
    return None


def handle(h, r):
    raw_len = h.headers.get("Content-Length", "0")
    if not raw_len.isdigit():
        raise Abort(400, "Invalid request.")
    if int(raw_len) > MAX_BODY:
        h.close_connection = True
        raise Abort(413, "Request is too large.")
    body = h.rfile.read(int(raw_len))
    url = urllib.parse.urlsplit(h.path)
    r.path = url.path
    r.query = parse_fields(url.query)
    if body and h.headers.get("Content-Type", "").split(";")[0].strip().lower() == FORM_TYPE:
        try:
            r.form = parse_fields(body.decode("utf-8"))
        except UnicodeDecodeError:
            raise ValidationError("Invalid form encoding.")

    token = cookie_value(h.headers.get("Cookie", ""), "sid")
    try:
        r.session = load_session(r.db, token)
    except Exception:
        log_trace("session load")
        raise Abort(403, DENIED)

    args, fn, roles = find_route(r.method, r.path)
    r.args = args
    try:
        denied = authorize(r, roles)
    except Exception:
        log_trace("authorize")
        raise Abort(403, DENIED)
    if denied is not None:
        return denied

    if r.method == "POST":
        origin = h.headers.get("Origin")
        if origin is not None and origin != f"http://{r.host}":
            log(r.db, "ACCESS", "csrf", "FAILURE", f"bad origin on {r.path}", who(r), r.ip)
            raise Abort(403, DENIED)
        sent = r.form.get("csrf", "").encode("utf-8")
        if r.session and not hmac.compare_digest(sent, r.session["csrf"].encode("utf-8")):
            log(r.db, "ACCESS", "csrf", "FAILURE", f"bad token on {r.path}", who(r), r.ip)
            raise Abort(403, DENIED)
    return fn(r)


def dispatch(h, method):
    r = SimpleNamespace(db=None, session=None, method=method, path="", query={}, form={}, args=(),
                        ip=h.client_address[0], host=h.headers.get("Host", ""))
    try:
        r.db = connect()
        r.db.execute("BEGIN IMMEDIATE")
        result = handle(h, r)
        r.db.commit()
    except Abort as ex:
        result = fail(r, ex.status, str(ex), commit=True)
    except ValidationError as ex:
        result = fail(r, 400, str(ex), commit=False, audit=("VALIDATION", "validation", f"{ex} {r.path}"))
    except Exception as ex:
        log_trace(f"{method} {r.path}")
        result = fail(r, 500, GENERIC_500, commit=False, audit=("ERROR", "exception", type(ex).__name__))
    finally:
        if r.db is not None:
            r.db.close()
    send(h, *result)


def send(h, status, body, headers):
    data = body.encode("utf-8") if isinstance(body, str) else body
    headers = list(headers)
    if not any(k == "Content-Type" for k, _ in headers):
        headers.append(("Content-Type", "text/html; charset=utf-8"))
    h.send_response(status)
    for k, v in headers + [("Content-Length", str(len(data)))] + SECURITY_HEADERS:
        h.send_header(k, v)
    h.end_headers()
    h.wfile.write(data)


# ---------------------------------------------------------------- layout

def csrf_field(session):
    if not session:
        return ""
    return f'<input type="hidden" name="csrf" value="{e(session["csrf"])}">'


def nav_html(session):
    if not session:
        return '<a href="/login">Log in</a> <a href="/register">Register</a>'
    role = session["role"]
    links = [("/", "Home"), ("/password", "Change password")]
    if role == "customer":
        links += [("/products", "Shop"), ("/orders", "My orders")]
    elif role == "manager":
        links += [("/products", "Catalog"), ("/manage/products", "Manage products"), ("/manage/orders", "Orders")]
    else:
        links += [("/admin/users", "Users"), ("/admin/logs", "Audit log")]
    items = " ".join(f'<a href="{e(href)}">{e(label)}</a>' for href, label in links)
    return (f'{items} <form method="post" action="/logout" class="inline">{csrf_field(session)}'
            '<button type="submit">Log out</button></form>')


def page(title, body, session=None):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} | SecureShop</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<header><h1>SecureShop</h1><nav>{nav_html(session)}</nav></header>
<main><h2>{e(title)}</h2>
{body}
</main>
</body>
</html>"""


def html_resp(r, title, body, status=200):
    return status, page(title, body, r.session), []


def table(headers, rows):
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    return f'<div class="wrap"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def select(name, pairs, selected=""):
    options = "".join(
        f'<option value="{e(value)}"{" selected" if value == selected else ""}>{e(label)}</option>'
        for value, label in pairs)
    return f'<select name="{e(name)}">{options}</select>'


def product_inputs(session, p=None):
    name, desc = (p["name"], p["description"]) if p else ("", "")
    price = money(p["price_cents"]) if p else ""
    stock = p["stock"] if p else 0
    return (csrf_field(session)
            + f'<label>Name <input name="name" required value="{e(name)}"></label>'
            + f'<label>Description <input name="description" value="{e(desc)}"></label>'
            + f'<label>Price <input name="price" required inputmode="decimal" value="{e(price)}"></label>'
            + f'<label>Stock <input name="stock" type="number" min="0" max="100000" required value="{e(stock)}"></label>')


# ---------------------------------------------------------------- public pages

def static_css(r):
    with open(STYLE_PATH, "rb") as f:
        return 200, f.read(), [("Content-Type", "text/css; charset=utf-8")]


def login_form(r):
    body = f"""<form method="post" action="/login">{csrf_field(r.session)}
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Log in</button>
</form>
<p><a href="/forgot">Forgot password?</a> | <a href="/register">Create an account</a></p>"""
    return html_resp(r, "Log in", body)


def login_post(r):
    username = r.form.get("username", "")
    password = r.form.get("password", "")
    valid_name = matches(USERNAME_RE, username)
    if not (valid_name and 1 <= len(password) <= 128):
        log(r.db, "AUTH", "login", "FAILURE", "invalid format", username if valid_name else None, r.ip)
        raise Abort(400, LOGIN_FAIL)

    row = find_user(r.db, username)
    if row is None:
        verify_secret(password, DUMMY_HASH)  # same cost as a real check
        log(r.db, "AUTH", "login", "FAILURE", "unknown user", username, r.ip)
        raise Abort(400, LOGIN_FAIL)

    now = now_utc()
    locked = is_locked(row, now)
    pw_ok = verify_secret(password, row["pw_hash"])
    ok = pw_ok and not locked
    r.db.execute("UPDATE users SET last_use_at = ?, last_use_ok = ?, last_use_ip = ? WHERE id = ?",
                 (ts(now), int(ok), r.ip, row["id"]))
    if ok:
        if r.session:
            r.db.execute("DELETE FROM sessions WHERE token_hash = ?", (r.session["token_hash"],))
        token = secrets.token_urlsafe(32)
        r.db.execute("UPDATE users SET failed_count = 0 WHERE id = ?", (row["id"],))
        r.db.execute("INSERT INTO sessions (token_hash, user_id, csrf, prev_use, last_seen) VALUES (?, ?, ?, ?, ?)",
                     (token_hash(token), row["id"], secrets.token_urlsafe(32), describe_prev(row), ts(now)))
        log(r.db, "AUTH", "login", "SUCCESS", "successful login", row["username"], r.ip)
        return redirect("/", f"sid={token}; HttpOnly; SameSite=Strict; Path=/")

    reason = "account locked" if locked else count_failure(r.db, row, "wrong password")
    log(r.db, "AUTH", "login", "FAILURE", reason, row["username"], r.ip)
    raise Abort(400, LOGIN_FAIL)


def register_form(r):
    questions = select("sec_question", [(str(i), q) for i, q in enumerate(SECURITY_QUESTIONS)])
    body = f"""<form method="post" action="/register">{csrf_field(r.session)}
<label>Username <input name="username" required></label>
<p class="hint">3-30 letters, digits or underscores.</p>
<label>Password <input name="password" type="password" autocomplete="new-password" required></label>
<p class="hint">12-128 characters with an uppercase letter, a lowercase letter, a digit and a symbol.</p>
<label>Confirm password <input name="confirm" type="password" autocomplete="new-password" required></label>
<label>Security question {questions}</label>
<label>Security answer <input name="sec_answer" required></label>
<p class="hint">6-100 characters. Used to reset your password.</p>
<button type="submit">Register</button>
</form>"""
    return html_resp(r, "Register", body)


def register_post(r):
    f = r.form
    username = v_str(f, "username", 3, 30, USERNAME_RE)
    password = v_password(f, "password")
    if f.get("confirm") != password:
        raise ValidationError("Passwords do not match.")
    question = int(v_choice(f, "sec_question", [str(i) for i in range(len(SECURITY_QUESTIONS))]))
    answer = v_str(f, "sec_answer", 6, 100)
    create_user(r.db, username, password, "customer", question, answer)
    log(r.db, "AUTH", "register", "SUCCESS", "customer account created", username, r.ip)
    return redirect("/login")


def forgot_form(r):
    body = f"""<form method="post" action="/forgot">{csrf_field(r.session)}
<label>Username <input name="username" required></label>
<button type="submit">Continue</button>
</form>"""
    return html_resp(r, "Forgot password", body)


def forgot_post(r):
    username = v_str(r.form, "username", 3, 30, USERNAME_RE)
    row = find_user(r.db, username)
    if row is not None and row["sec_question"] is not None:
        question = SECURITY_QUESTIONS[row["sec_question"]]
    else:  # decoy: same question for the same unknown name every time
        question = SECURITY_QUESTIONS[sum(username.casefold().encode()) % len(SECURITY_QUESTIONS)]
    body = f"""<p>Security question:</p>
<p class="question">{e(question)}</p>
<form method="post" action="/forgot/reset">{csrf_field(r.session)}
<input type="hidden" name="username" value="{e(username)}">
<label>Security answer <input name="sec_answer" required></label>
<label>New password <input name="password" type="password" autocomplete="new-password" required></label>
<label>Confirm new password <input name="confirm" type="password" autocomplete="new-password" required></label>
<button type="submit">Reset password</button>
</form>"""
    return html_resp(r, "Reset password", body)


def reset_post(r):
    f = r.form
    username = f.get("username", "")
    answer = f.get("sec_answer", "")
    valid_name = matches(USERNAME_RE, username)
    row = find_user(r.db, username) if valid_name else None
    if row is None or row["sec_answer_hash"] is None:
        verify_secret(answer, DUMMY_HASH)
        log(r.db, "AUTH", "password reset", "FAILURE", "unknown user or no security question",
            username if valid_name else None, r.ip)
        raise Abort(400, RESET_FAIL)
    if is_locked(row, now_utc()):
        log(r.db, "AUTH", "password reset", "FAILURE", "account locked", row["username"], r.ip)
        raise Abort(400, RESET_FAIL)
    if not verify_secret(answer.casefold(), row["sec_answer_hash"]):
        reason = count_failure(r.db, row, "wrong security answer")
        log(r.db, "AUTH", "password reset", "FAILURE", reason, row["username"], r.ip)
        raise Abort(400, RESET_FAIL)

    password = v_password(f, "password")
    if f.get("confirm") != password:
        raise ValidationError("Passwords do not match.")
    if was_used(r.db, row["id"], password):
        raise ValidationError("Password was used before.")
    store_password(r.db, row["id"], password)
    r.db.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
    log(r.db, "AUTH", "password reset", "SUCCESS", "password reset", row["username"], r.ip)
    return redirect("/login")


# ---------------------------------------------------------------- signed-in pages

def home(r):
    s = r.session
    body = (f"<p>Welcome, <strong>{e(s['username'])}</strong>.</p>"
            f"<p>Role: {e(ROLE_NAMES[s['role']])}</p>"
            f"<p>Last account use: {e(s['prev_use'] or 'No previous activity recorded.')}</p>")
    return html_resp(r, "Home", body)


def logout_post(r):
    r.db.execute("DELETE FROM sessions WHERE token_hash = ?", (r.session["token_hash"],))
    log(r.db, "AUTH", "logout", "SUCCESS", "logged out", r.session["username"], r.ip)
    return redirect("/login", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")


def password_form(r):
    body = f"""<form method="post" action="/password">{csrf_field(r.session)}
<label>Current password <input name="current" type="password" autocomplete="current-password" required></label>
<label>New password <input name="new" type="password" autocomplete="new-password" required></label>
<label>Confirm new password <input name="confirm" type="password" autocomplete="new-password" required></label>
<p class="hint">Once every 24 hours at most. You cannot reuse any earlier password.</p>
<button type="submit">Change password</button>
</form>"""
    return html_resp(r, "Change password", body)


def password_post(r):
    f = r.form
    row = find_user_by_id(r.db, r.session["user_id"])
    if not verify_secret(f.get("current", ""), row["pw_hash"]):
        log(r.db, "AUTH", "password change", "FAILURE", "re-auth failed", row["username"], r.ip)
        raise Abort(400, "Password change failed.")
    if parse_ts(row["pw_changed_at"]) > now_utc() - timedelta(days=1):
        raise ValidationError("Password was changed less than one day ago.")
    password = v_password(f, "new")
    if f.get("confirm") != password:
        raise ValidationError("Passwords do not match.")
    if was_used(r.db, row["id"], password):
        raise ValidationError("Password was used before.")
    store_password(r.db, row["id"], password)
    r.db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (row["id"], r.session["token_hash"]))
    log(r.db, "AUTH", "password change", "SUCCESS", "password changed", row["username"], r.ip)
    return redirect("/")


def find_user_by_id(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# ---------------------------------------------------------------- customer and manager

def products_page(r):
    rows = r.db.execute("SELECT * FROM products ORDER BY id").fetchall()
    is_customer = r.session["role"] == "customer"
    headers = ["Name", "Description", "Price", "Stock"] + (["Order"] if is_customer else [])
    trs = []
    for p in rows:
        cells = (f"<td>{e(p['name'])}</td><td>{e(p['description'])}</td>"
                 f"<td>{e(money(p['price_cents']))}</td><td>{e(p['stock'])}</td>")
        if is_customer:
            cells += (f'<td><form method="post" action="/orders/new" class="inline">{csrf_field(r.session)}'
                      f'<input type="hidden" name="product_id" value="{e(p["id"])}">'
                      '<input name="quantity" type="number" min="1" max="100" value="1"> '
                      '<button type="submit">Order</button></form></td>')
        trs.append(f"<tr>{cells}</tr>")
    return html_resp(r, "Products", table(headers, trs))


def adjust_stock(db, product_id, change):
    """stock += change. A decrease fails when not enough stock is left (or the product is gone)."""
    cur = db.execute("UPDATE products SET stock = stock + ? WHERE id = ? AND stock + ? >= 0",
                     (change, product_id, change))
    if cur.rowcount == 0 and change < 0:
        exists = db.execute("SELECT 1 FROM products WHERE id = ?", (product_id,)).fetchone()
        raise ValidationError("Insufficient stock." if exists else "Product no longer exists.")


def set_order_status(db, o, status):
    if o["status"] != "pending":
        raise ValidationError(ONLY_PENDING)
    if status == "cancelled":
        adjust_stock(db, o["product_id"], o["quantity"])  # give the stock back
    db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, o["id"]))


def order_new(r):
    pid = v_int(r.form, "product_id", 1, 999999999)
    qty = v_int(r.form, "quantity", 1, 100)
    p = r.db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if p is None:
        raise ValidationError("Product does not exist.")
    adjust_stock(r.db, pid, -qty)
    r.db.execute("INSERT INTO orders (user_id, product_id, product_name, unit_price_cents, quantity, status, created_at) "
                 "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                 (r.session["user_id"], pid, p["name"], p["price_cents"], qty, ts()))
    log(r.db, "DATA", "order create", "SUCCESS", f"product {pid} x{qty}", who(r), r.ip)
    return redirect("/orders")


def orders_page(r):
    rows = r.db.execute("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (r.session["user_id"],)).fetchall()
    trs = []
    for o in rows:
        actions = ""
        if o["status"] == "pending":
            actions = (f'<form method="post" action="/orders/{e(o["id"])}/edit" class="inline">{csrf_field(r.session)}'
                       f'<input name="quantity" type="number" min="1" max="100" value="{e(o["quantity"])}"> '
                       '<button type="submit">Change quantity</button></form> '
                       f'<form method="post" action="/orders/{e(o["id"])}/cancel" class="inline">{csrf_field(r.session)}'
                       '<button type="submit">Cancel</button></form>')
        trs.append(f"<tr><td>{e(o['id'])}</td><td>{e(o['product_name'])}</td>"
                   f"<td>{e(money(o['unit_price_cents']))}</td><td>{e(o['quantity'])}</td>"
                   f"<td>{e(o['status'])}</td><td>{e(o['created_at'])}</td><td>{actions}</td></tr>")
    headers = ["#", "Product", "Unit price", "Qty", "Status", "Placed", ""]
    return html_resp(r, "My orders", table(headers, trs))


def own_order(r):
    row = r.db.execute("SELECT * FROM orders WHERE id = ?", (int(r.args[0]),)).fetchone()
    if row is None:
        raise Abort(404, "Order not found.")
    if row["user_id"] != r.session["user_id"]:
        log(r.db, "ACCESS", "not owner", "FAILURE", r.path, who(r), r.ip)
        raise Abort(403, DENIED)
    return row


def order_edit(r):
    o = own_order(r)
    if o["status"] != "pending":
        raise ValidationError(ONLY_PENDING)
    qty = v_int(r.form, "quantity", 1, 100)
    adjust_stock(r.db, o["product_id"], o["quantity"] - qty)
    r.db.execute("UPDATE orders SET quantity = ? WHERE id = ?", (qty, o["id"]))
    log(r.db, "DATA", "order edit", "SUCCESS", f"order {o['id']} qty {qty}", who(r), r.ip)
    return redirect("/orders")


def order_cancel(r):
    o = own_order(r)
    set_order_status(r.db, o, "cancelled")
    log(r.db, "DATA", "order cancel", "SUCCESS", f"order {o['id']}", who(r), r.ip)
    return redirect("/orders")


def read_product(f):
    name = v_str(f, "name", 1, 100)
    description = v_str(f, "description", 0, 500)
    price = v_price(f, "price")
    stock = v_int(f, "stock", 0, 100000)
    return name, description, price, stock


def manage_products(r):
    rows = r.db.execute("SELECT * FROM products ORDER BY id").fetchall()
    cards = []
    for p in rows:
        pid = e(p["id"])
        cards.append(f"""<div class="card">
<form method="post" action="/manage/products/{pid}/edit">{product_inputs(r.session, p)}
<button type="submit">Save</button></form>
<form method="post" action="/manage/products/{pid}/delete" class="inline">{csrf_field(r.session)}
<button type="submit">Delete</button></form>
</div>""")
    body = (f'<h3>Add product</h3><form method="post" action="/manage/products/new">{product_inputs(r.session)}'
            '<button type="submit">Add product</button></form>'
            '<h3>Products</h3>' + "".join(cards))
    return html_resp(r, "Manage products", body)


def product_new(r):
    name, description, price, stock = read_product(r.form)
    r.db.execute("INSERT INTO products (name, description, price_cents, stock) VALUES (?, ?, ?, ?)",
                 (name, description, price, stock))
    log(r.db, "DATA", "product create", "SUCCESS", f"{name} stock {stock}", who(r), r.ip)
    return redirect("/manage/products")


def product_edit(r):
    pid = int(r.args[0])
    if r.db.execute("SELECT 1 FROM products WHERE id = ?", (pid,)).fetchone() is None:
        raise Abort(404, "Product not found.")
    name, description, price, stock = read_product(r.form)
    r.db.execute("UPDATE products SET name = ?, description = ?, price_cents = ?, stock = ? WHERE id = ?",
                 (name, description, price, stock, pid))
    log(r.db, "DATA", "product edit", "SUCCESS", f"id {pid} {name}", who(r), r.ip)
    return redirect("/manage/products")


def product_delete(r):
    pid = int(r.args[0])
    p = r.db.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if p is None:
        raise Abort(404, "Product not found.")
    if r.db.execute("SELECT 1 FROM orders WHERE product_id = ? AND status = 'pending'", (pid,)).fetchone():
        raise ValidationError("Product has pending orders.")
    r.db.execute("DELETE FROM products WHERE id = ?", (pid,))
    log(r.db, "DATA", "product delete", "SUCCESS", f"id {pid} {p['name']}", who(r), r.ip)
    return redirect("/manage/products")


def manage_orders(r):
    rows = r.db.execute("SELECT o.*, u.username FROM orders o JOIN users u ON u.id = o.user_id "
                        "ORDER BY o.id DESC").fetchall()
    trs = []
    for o in rows:
        actions = ""
        if o["status"] == "pending":
            actions = (f'<form method="post" action="/manage/orders/{e(o["id"])}/status" class="inline">'
                       f'{csrf_field(r.session)}'
                       '<button name="status" value="fulfilled" type="submit">Mark fulfilled</button> '
                       '<button name="status" value="cancelled" type="submit">Cancel</button></form>')
        trs.append(f"<tr><td>{e(o['id'])}</td><td>{e(o['username'])}</td><td>{e(o['product_name'])}</td>"
                   f"<td>{e(money(o['unit_price_cents']))}</td><td>{e(o['quantity'])}</td>"
                   f"<td>{e(o['status'])}</td><td>{e(o['created_at'])}</td><td>{actions}</td></tr>")
    headers = ["#", "Customer", "Product", "Unit price", "Qty", "Status", "Placed", ""]
    return html_resp(r, "Orders", table(headers, trs))


def manager_order_status(r):
    order_id = int(r.args[0])
    o = r.db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if o is None:
        raise Abort(404, "Order not found.")
    status = v_choice(r.form, "status", ["fulfilled", "cancelled"])
    set_order_status(r.db, o, status)
    log(r.db, "DATA", "order status", "SUCCESS", f"order {order_id} {status}", who(r), r.ip)
    return redirect("/manage/orders")


# ---------------------------------------------------------------- admin

def reauth_admin(r, event):
    row = find_user_by_id(r.db, r.session["user_id"])
    if not verify_secret(r.form.get("admin_password", ""), row["pw_hash"]):
        log(r.db, "AUTH", event, "FAILURE", "re-auth failed", who(r), r.ip)
        raise Abort(400, "Re-authentication failed.")


def admin_target(r):
    uid = int(r.args[0])
    row = find_user_by_id(r.db, uid)
    if row is None:
        raise Abort(404, "User not found.")
    if uid == r.session["user_id"]:
        raise ValidationError("You cannot modify your own account.")
    if row["role"] not in ("admin", "manager"):
        raise ValidationError("Only admin and manager accounts can be changed here.")
    return row


def admin_users(r):
    rows = r.db.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
    role_pick = select("role", [("manager", "manager"), ("admin", "admin")], "manager")
    trs = []
    for u in rows:
        actions = ""
        if u["role"] != "customer" and u["id"] != r.session["user_id"]:
            uid = e(u["id"])
            actions = (f'<form method="post" action="/admin/users/{uid}/role" class="inline">{csrf_field(r.session)}'
                       f'{role_pick} <input name="admin_password" type="password" required placeholder="Your password"> '
                       '<button type="submit">Change role</button></form> '
                       f'<form method="post" action="/admin/users/{uid}/delete" class="inline">{csrf_field(r.session)}'
                       '<input name="admin_password" type="password" required placeholder="Your password"> '
                       '<button type="submit">Delete</button></form>')
        trs.append(f"<tr><td>{e(u['username'])}</td><td>{e(u['role'])}</td><td>{e(u['created_at'])}</td>"
                   f"<td>{actions}</td></tr>")
    create = f"""<h3>Create admin or manager account</h3>
<form method="post" action="/admin/users/new">{csrf_field(r.session)}
<label>Username <input name="username" required></label>
<label>Role {select("role", [("manager", "manager"), ("admin", "admin")], "manager")}</label>
<label>Password <input name="password" type="password" autocomplete="new-password" required></label>
<label>Confirm password <input name="confirm" type="password" autocomplete="new-password" required></label>
<label>Your password (re-authentication) <input name="admin_password" type="password" required></label>
<p class="hint">Staff accounts have no security question, so they cannot use the forgot-password flow.</p>
<button type="submit">Create account</button>
</form>"""
    return html_resp(r, "Users", create + "<h3>All accounts</h3>" + table(["Username", "Role", "Created", ""], trs))


def admin_user_new(r):
    reauth_admin(r, "user create")
    f = r.form
    username = v_str(f, "username", 3, 30, USERNAME_RE)
    role = v_choice(f, "role", ["admin", "manager"])
    password = v_password(f, "password")
    if f.get("confirm") != password:
        raise ValidationError("Passwords do not match.")
    create_user(r.db, username, password, role)
    log(r.db, "ADMIN", "user create", "SUCCESS", f"{username} as {role}", who(r), r.ip)
    return redirect("/admin/users")


def admin_user_role(r):
    reauth_admin(r, "user role")
    target = admin_target(r)
    role = v_choice(r.form, "role", ["admin", "manager"])
    r.db.execute("UPDATE users SET role = ? WHERE id = ?", (role, target["id"]))
    log(r.db, "ADMIN", "user role", "SUCCESS", f"{target['username']} -> {role}", who(r), r.ip)
    return redirect("/admin/users")


def admin_user_delete(r):
    reauth_admin(r, "user delete")
    target = admin_target(r)
    r.db.execute("DELETE FROM users WHERE id = ?", (target["id"],))
    log(r.db, "ADMIN", "user delete", "SUCCESS", f"{target['username']} ({target['role']})", who(r), r.ip)
    return redirect("/admin/users")


def logs_link(keep, page_no, label):
    query = urllib.parse.urlencode({**keep, "page": page_no})
    return f'<a href="/admin/logs?{e(query)}">{e(label)}</a>'


def admin_logs(r):
    q = r.query
    category = v_opt(q, "category", "|".join(LOG_CATEGORIES))
    outcome = v_opt(q, "outcome", "SUCCESS|FAILURE")
    username = v_opt(q, "username", USERNAME_RE)
    date_from = v_opt(q, "date_from", DATE_RE)
    date_to = v_opt(q, "date_to", DATE_RE)
    page_no = v_int(q, "page", 1, 100000) if q.get("page") else 1
    rows = r.db.execute(
        "SELECT ts, username, ip, category, event, outcome, detail FROM audit_log "
        "WHERE (? = '' OR category = ?) AND (? = '' OR outcome = ?) AND (? = '' OR username = ?) "
        "AND (? = '' OR substr(ts, 1, 10) >= ?) AND (? = '' OR substr(ts, 1, 10) <= ?) "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        (category, category, outcome, outcome, username, username, date_from, date_from, date_to, date_to,
         PAGE_SIZE + 1, (page_no - 1) * PAGE_SIZE)).fetchall()

    keep = {k: v for k, v in (("category", category), ("outcome", outcome), ("username", username),
                              ("date_from", date_from), ("date_to", date_to)) if v}
    filters = f"""<form method="get" action="/admin/logs">
<label>Category {select("category", [("", "(any)")] + [(c, c) for c in LOG_CATEGORIES], category)}</label>
<label>Outcome {select("outcome", [("", "(any)"), ("SUCCESS", "SUCCESS"), ("FAILURE", "FAILURE")], outcome)}</label>
<label>Username <input name="username" value="{e(username)}"></label>
<label>From <input name="date_from" type="date" value="{e(date_from)}"></label>
<label>To <input name="date_to" type="date" value="{e(date_to)}"></label>
<button type="submit">Filter</button>
</form>"""
    trs = []
    for row in rows[:PAGE_SIZE]:
        cells = [row["ts"], row["username"] or "-", row["ip"] or "-", row["category"],
                 row["event"], row["outcome"], row["detail"] or ""]
        trs.append("<tr>" + "".join(f"<td>{e(c)}</td>" for c in cells) + "</tr>")
    nav = []
    if page_no > 1:
        nav.append(logs_link(keep, page_no - 1, "Newer"))
    if len(rows) > PAGE_SIZE:
        nav.append(logs_link(keep, page_no + 1, "Older"))
    body = filters + table(["Time (UTC)", "User", "IP", "Category", "Event", "Outcome", "Detail"], trs)
    body += f'<p>Page {e(page_no)}. {" | ".join(nav)}</p>'
    return html_resp(r, "Audit log", body)


# ---------------------------------------------------------------- routes

PUBLIC = frozenset({"public"})
ANY_USER = frozenset({"customer", "manager", "admin"})
SHOPPER = frozenset({"customer", "manager"})
CUSTOMER = frozenset({"customer"})
MANAGER = frozenset({"manager"})
ADMIN = frozenset({"admin"})

# (method, path regex, handler, allowed roles). The only access-control table in the app.
ROUTES = [
    ("GET", re.compile(r"/static/style\.css"), static_css, PUBLIC),
    ("GET", re.compile(r"/login"), login_form, PUBLIC),
    ("POST", re.compile(r"/login"), login_post, PUBLIC),
    ("GET", re.compile(r"/register"), register_form, PUBLIC),
    ("POST", re.compile(r"/register"), register_post, PUBLIC),
    ("GET", re.compile(r"/forgot"), forgot_form, PUBLIC),
    ("POST", re.compile(r"/forgot"), forgot_post, PUBLIC),
    ("POST", re.compile(r"/forgot/reset"), reset_post, PUBLIC),
    ("GET", re.compile(r"/"), home, ANY_USER),
    ("POST", re.compile(r"/logout"), logout_post, ANY_USER),
    ("GET", re.compile(r"/password"), password_form, ANY_USER),
    ("POST", re.compile(r"/password"), password_post, ANY_USER),
    ("GET", re.compile(r"/products"), products_page, SHOPPER),
    ("POST", re.compile(r"/orders/new"), order_new, CUSTOMER),
    ("GET", re.compile(r"/orders"), orders_page, CUSTOMER),
    ("POST", re.compile(r"/orders/([0-9]{1,9})/edit"), order_edit, CUSTOMER),
    ("POST", re.compile(r"/orders/([0-9]{1,9})/cancel"), order_cancel, CUSTOMER),
    ("GET", re.compile(r"/manage/products"), manage_products, MANAGER),
    ("POST", re.compile(r"/manage/products/new"), product_new, MANAGER),
    ("POST", re.compile(r"/manage/products/([0-9]{1,9})/edit"), product_edit, MANAGER),
    ("POST", re.compile(r"/manage/products/([0-9]{1,9})/delete"), product_delete, MANAGER),
    ("GET", re.compile(r"/manage/orders"), manage_orders, MANAGER),
    ("POST", re.compile(r"/manage/orders/([0-9]{1,9})/status"), manager_order_status, MANAGER),
    ("GET", re.compile(r"/admin/users"), admin_users, ADMIN),
    ("POST", re.compile(r"/admin/users/new"), admin_user_new, ADMIN),
    ("POST", re.compile(r"/admin/users/([0-9]{1,9})/role"), admin_user_role, ADMIN),
    ("POST", re.compile(r"/admin/users/([0-9]{1,9})/delete"), admin_user_delete, ADMIN),
    ("GET", re.compile(r"/admin/logs"), admin_logs, ADMIN),
]


class Handler(BaseHTTPRequestHandler):
    server_version = "SecureShop"
    sys_version = ""
    # Used by http.server itself for malformed requests / unsupported methods (never reaches dispatch).
    error_message_format = "<!doctype html><title>Error</title><p>The request could not be processed.</p>"

    def do_GET(self):
        dispatch(self, "GET")

    def do_POST(self):
        dispatch(self, "POST")

    def log_message(self, fmt, *args):  # keep the console quiet
        pass


def make_server(port):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    init_db()
    server = make_server(int(os.environ.get("SHOP_PORT", "8000")))
    print(f"SecureShop listening on http://127.0.0.1:{server.server_address[1]}")
    server.serve_forever()
