"""Plain-script tests for app.py. Run with the project venv python: python test_app.py"""
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

TMP = tempfile.mkdtemp(prefix="shop-test-")
os.environ["SHOP_DB"] = os.path.join(TMP, "test.db")  # must be set before importing app

import app  # noqa: E402

STRONG = "Correct#Horse2026"
ADMIN_PW = "Admin#Secure2026!"
MANAGER_PW = "Manager#Secure2026!"
CUSTOMER_PW = "Customer#Secure2026!"
NEW1 = "Customer#Secure2027!"
NEW2 = "Customer#Secure2028!"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


class Client:
    """Tiny cookie-keeping client. Picks up the csrf token from any page that shows one."""

    def __init__(self, base):
        self.base = base
        self.sid = None
        self.csrf = None

    def request(self, method, path, form=None, headers=None):
        hdrs = dict(headers or {})
        if method == "POST":
            hdrs.setdefault("Origin", self.base)  # browsers send this on form posts
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if self.sid:
            hdrs["Cookie"] = f"sid={self.sid}"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            resp = OPENER.open(req, timeout=10)
        except urllib.error.HTTPError as err:
            resp = err
        body = resp.read().decode("utf-8")
        for cookie in resp.headers.get_all("Set-Cookie") or []:
            if cookie.startswith("sid="):
                self.sid = cookie.split(";")[0][4:] or None
        found = re.search(r'name="csrf" value="([^"]+)"', body)
        if found:
            self.csrf = found.group(1)
        return resp.code, body, resp.headers

    def get(self, path):
        status, body, _ = self.request("GET", path)
        return status, body

    def post(self, path, form=None):
        return self.request("POST", path, {"csrf": self.csrf or "", **(form or {})})


def db_query(sql, args=()):
    conn = sqlite3.connect(app.DB_PATH)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def stock_of(product_id):
    return db_query("SELECT stock FROM products WHERE id = ?", (product_id,))[0][0]


def register(base, username, password):
    status, _, _ = Client(base).request("POST", "/register", {
        "username": username, "password": password, "confirm": password,
        "sec_question": "0", "sec_answer": "a long enough answer"})
    return status


def login(client, username, password):
    status, _, _ = client.request("POST", "/login", {"username": username, "password": password})
    client.get("/")  # loads a csrf token for later POSTs
    return status


def new_customer(base, username):
    assert register(base, username, STRONG) == 302
    client = Client(base)
    assert login(client, username, STRONG) == 302
    return client


def staff(base, username, password):
    client = Client(base)
    assert login(client, username, password) == 302, username
    return client


LOGIN_FAIL = app.LOGIN_FAIL


def test_public_and_routing(base):
    c = Client(base)
    status, _, headers = c.request("GET", "/products")
    assert status == 302 and headers["Location"] == "/login", status
    assert c.get("/nope")[0] == 404
    assert c.get("/static/../app.py")[0] == 404
    assert c.request("POST", "/products")[0] == 405
    status, body = c.get("/static/style.css")
    assert status == 200 and "font-family" in body


def test_login_messages(base):
    s1, b1, _ = Client(base).request("POST", "/login", {"username": "customer", "password": "Wrong#Password2026!"})
    s2, b2, _ = Client(base).request("POST", "/login", {"username": "no_such_user", "password": "Wrong#Password2026!"})
    assert s1 == s2 == 400, (s1, s2)
    assert b1 == b2 and LOGIN_FAIL in b1
    assert '<a href="/login">Go back</a>' in b1 and "Request rejected" in b1  # back to the form, not a status code


def test_lockout(base):
    assert register(base, "locker_01", STRONG) == 302
    c = Client(base)
    for _ in range(5):
        assert c.request("POST", "/login", {"username": "locker_01", "password": "Wrong#Attempt9"})[0] == 400
    status, body, _ = c.request("POST", "/login", {"username": "locker_01", "password": STRONG})
    assert status == 400 and LOGIN_FAIL in body, status
    assert db_query("SELECT locked_until FROM users WHERE username = 'locker_01'")[0][0]


def test_register_and_home(base):
    c = Client(base)
    weak = {"username": "newbie_01", "password": "Short#1", "confirm": "Short#1",
            "sec_question": "0", "sec_answer": "a long enough answer"}
    assert c.request("POST", "/register", weak)[0] == 400
    assert register(base, "newbie_01", STRONG) == 302
    assert register(base, "newbie_01", STRONG) == 400  # duplicate username
    assert login(c, "newbie_01", STRONG) == 302
    status, body = c.get("/")
    assert status == 200 and "Last account use:" in body and "No previous activity recorded." in body


def test_roles(base):
    cust = new_customer(base, "shopper_01")
    assert cust.get("/admin/logs")[0] == 403
    assert cust.get("/manage/products")[0] == 403
    mgr = staff(base, "manager", MANAGER_PW)
    assert mgr.get("/admin/users")[0] == 403
    adm = staff(base, "admin", ADMIN_PW)
    status, body = adm.get("/admin/logs")
    assert status == 200 and "ACCESS" in body
    assert db_query("SELECT COUNT(*) FROM audit_log WHERE category = 'ACCESS' AND outcome = 'FAILURE'")[0][0] >= 3


def test_csrf(base):
    cust = new_customer(base, "shopper_02")
    assert cust.request("POST", "/orders/new", {"product_id": "1", "quantity": "1"})[0] == 403
    assert cust.request("POST", "/logout", {"csrf": "forged"})[0] == 403
    assert cust.request("POST", "/logout", {"csrf": cust.csrf}, headers={"Origin": "http://evil.example"})[0] == 403
    assert cust.get("/")[0] == 200  # session survived the forged requests


def test_orders(base):
    alice = new_customer(base, "alice_01")
    bob = new_customer(base, "bob_01")
    before = stock_of(1)
    assert alice.post("/orders/new", {"product_id": "1", "quantity": "0"})[0] == 400
    assert alice.post("/orders/new", {"product_id": "1", "quantity": "101"})[0] == 400
    assert alice.post("/orders/new", {"product_id": "1", "quantity": "2"})[0] == 302
    assert stock_of(1) == before - 2
    order_id = db_query("SELECT MAX(id) FROM orders WHERE user_id = "
                        "(SELECT id FROM users WHERE username = 'alice_01')")[0][0]
    assert bob.post(f"/orders/{order_id}/cancel")[0] == 403
    assert alice.post(f"/orders/{order_id}/cancel")[0] == 302
    assert stock_of(1) == before


def test_password_change(base):
    cust = staff(base, "customer", CUSTOMER_PW)  # seeded: password changed 2 days ago
    assert cust.post("/password", {"current": "Wrong#Password2026!", "new": NEW1, "confirm": NEW1})[0] == 400
    assert cust.post("/password", {"current": CUSTOMER_PW, "new": CUSTOMER_PW, "confirm": CUSTOMER_PW})[0] == 400
    assert cust.post("/password", {"current": CUSTOMER_PW, "new": NEW1, "confirm": NEW1})[0] == 302
    status, body, _ = cust.request("POST", "/password", {"csrf": cust.csrf, "current": NEW1,
                                                         "new": NEW2, "confirm": NEW2})
    assert status == 400 and "less than one day ago" in body, status
    assert login(Client(base), "customer", NEW1) == 302


def test_password_storage(base):
    rows = db_query("SELECT username, pw_hash FROM users")
    assert rows
    for username, pw_hash in rows:
        assert pw_hash.startswith("scrypt$"), username
        for plain in (ADMIN_PW, MANAGER_PW, CUSTOMER_PW, NEW1, STRONG):
            assert plain not in pw_hash, username


def test_forced_error(base):
    alice = Client(base)
    assert login(alice, "alice_01", STRONG) == 302
    idx = next(i for i, route in enumerate(app.ROUTES) if route[2] is app.products_page)
    method, pattern, _, roles = app.ROUTES[idx]

    def boom(r):
        raise RuntimeError("forced failure for test")

    app.ROUTES[idx] = (method, pattern, boom, roles)
    try:
        status, body = alice.get("/products")
    finally:
        app.ROUTES[idx] = (method, pattern, app.products_page, roles)
    assert status == 500, status
    assert "Traceback" not in body and "forced failure" not in body
    assert "Something went wrong" in body
    with open(app.ERROR_LOG, encoding="utf-8") as f:
        assert "Traceback" in f.read()


def test_body_limit(base):
    status, _, _ = Client(base).request("POST", "/login", {"username": "x", "password": "y" * 11000})
    assert status == 413, status


TESTS = [test_public_and_routing, test_login_messages, test_lockout, test_register_and_home,
         test_roles, test_csrf, test_orders, test_password_change, test_password_storage,
         test_forced_error, test_body_limit]

if __name__ == "__main__":
    app.init_db()
    server = app.make_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    for test in TESTS:
        test(base_url)
        print("ok  ", test.__name__)
    server.shutdown()
    logging.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)
    print("ALL TESTS PASSED")
