# Test Cases

**Course:** CSSECDV (S30C), AY 2026–2027 Term 1 — Machine Project (Web App)

**Application:** SecureShop

**Group Members:** _(fill in before submission)_

## 1. Setup

1. Delete the `data` folder (if present) so the demo accounts are freshly seeded.
2. Start the server: `C:\Apps\convert-markdown\.venv\Scripts\python.exe app.py`
3. Open `http://127.0.0.1:8000/`.

| Role | Username | Password |
|---|---|---|
| Website Administrator | `admin` | `Admin#Secure2026!` |
| Product Manager | `manager` | `Manager#Secure2026!` |
| Customer | `customer` | `Customer#Secure2026!` |

Security answer for all seeded accounts: `Mrs. Evangelista-Santos`.

Suggested order: run the tests top to bottom. Tests that lock an account use a throwaway account registered in test A-05, so the seeded accounts stay usable. The numbers in brackets are checklist items.

## 2. Test Cases

### 2.1 Authentication

| Control Group | Test Scenario | Expected Outcome |
|---|---|---|
| Authentication | A-01 [2.1.1] Without logging in, open `/products`, `/orders`, `/manage/products`, `/admin/users` and `/admin/logs`. | Each request is redirected to `/login`. No protected content is shown. |
| Authentication | A-02 [2.1.1] Without logging in, open `/login`, `/register` and `/forgot`. | The pages load; these are the only public pages. |
| Authentication | A-03 [2.1.4] Log in with username `nosuchuser` and any password. Then log in with username `customer` and a wrong password. | Both attempts show exactly "Invalid username and/or password." Nothing reveals which part was wrong. |
| Authentication | A-04 [2.1.5, 2.1.6] On `/register`, try the passwords `Short#1a` (too short), `alllowercase#2026` (no uppercase), `NoDigitsHere#abc` (no digit) and `NoSpecial2026abc` (no special character). | Each registration is rejected with an HTTP 400 error page. No account is created. |
| Authentication | A-05 [2.1.5, 2.1.6, 2.1.9] Register `demo_user` with password `Demo#Account2026!`, pick a security question from the list and give an answer of at least 6 characters. | Registration succeeds and redirects to the login page. The question can only be chosen from the fixed high-entropy list; no free-text question is possible. |
| Authentication | A-06 [2.1.7] Type into any password field on the login, register, change password, reset and admin pages. | Characters are displayed as dots. |
| Authentication | A-07 [2.1.3] Open `data/shop.db` with a SQLite viewer (or run `C:\Apps\convert-markdown\.venv\Scripts\python.exe -c "import sqlite3;print(sqlite3.connect('data/shop.db').execute('select username,pw_hash from users').fetchall())"`). | Each `pw_hash` has the form `scrypt$<salt>$<hash>`; salts differ per user; no plaintext passwords are stored. |
| Authentication | A-08 [2.1.12] Log in as `demo_user` with a wrong password once, then with the correct password. | The home page shows "Last account use: … — unsuccessful login attempt from 127.0.0.1". After logging out and in again, it shows the previous successful login. |
| Authentication | A-09 [2.1.8] Log out. Enter a wrong password for `demo_user` five times, then enter the correct password. | All attempts, including the sixth with the correct password, show "Invalid username and/or password." The account is locked for 15 minutes and then unlocks automatically. |
| Authentication | A-10 [2.1.2] While `demo_user` is locked, open `/orders` directly. Also, in the browser's developer tools, change the `sid` cookie to a random value and open `/products`. | Both are redirected to `/login`; no session exists. Authentication fails closed. |
| Authentication | A-11 [2.1.13] Log in as `customer`. Open "Change password", enter a wrong current password and a valid new password. | The change is rejected with "Password change failed." and the password stays the same. |
| Authentication | A-12 [2.1.10] As `customer`, change password with the correct current password and the new password `Customer#Secure2026!` (the same as the current one). | Rejected with "Password was used before." |
| Authentication | A-13 [2.1.13, 2.1.10] As `customer`, change password with the correct current password and new password `Customer#Changed2026!`. | The change succeeds. |
| Authentication | A-14 [2.1.11] Immediately try to change the password again (current `Customer#Changed2026!`, new `Customer#Third2026!`). | Rejected with "Password was changed less than one day ago." |
| Authentication | A-15 [2.1.9, 2.1.4] Log out. On `/forgot` enter `nosuchuser`. Then enter `manager`. | Both show a security question, so the page does not reveal whether a username exists. |
| Authentication | A-16 [2.1.9] On `/forgot` for `manager`, give a wrong answer with a valid new password. | "Password reset failed." The password is unchanged. |
| Authentication | A-17 [2.1.9, 2.1.10] On `/forgot` for `manager`, give the answer `Mrs. Evangelista-Santos` and new password `Manager#Secure2026!` (the current password). | Rejected — the password was used before. |
| Authentication | A-18 [2.1.9] On `/forgot` for `manager`, give the correct answer and new password `Manager#Reset2026!`. | Reset succeeds; logging in as `manager` with the new password works. |

### 2.2 Authorization / Access Control

| Control Group | Test Scenario | Expected Outcome |
|---|---|---|
| Authorization | Z-01 [2.2.1, 2.2.2] Log in as `customer` (`Customer#Changed2026!`). Open `/manage/products`, `/manage/orders`, `/admin/users` and `/admin/logs` by typing the URLs. | Each returns the custom 403 page. The navigation bar shows only customer links. |
| Authorization | Z-02 [2.2.1] Log in as `manager` (`Manager#Reset2026!`). Open `/admin/users`, `/admin/logs` and `/orders`. | Each returns the custom 403 page. |
| Authorization | Z-03 [2.2.1] Log in as `admin`. Open `/products`, `/orders` and `/manage/products`. | Each returns the custom 403 page — the administrator has no product or order permissions (least privilege). |
| Authorization | Z-04 [2.2.2] While logged in, open a URL that does not exist, e.g. `/admin/secret`. | Custom 404 page; nothing is exposed by default. |
| Authorization | Z-05 [2.2.3] As `customer`, place an order (order #1). Log out, register and log in as a second customer, and submit the cancel form for order #1 (e.g. place an own order, then use developer tools to change the form action to `/orders/1/cancel`). | 403 page. Order #1 is unchanged. |
| Authorization | Z-06 [2.2.3] As `customer`, try to order a quantity larger than the product's stock (but at most 100). | Rejected with "Insufficient stock." Stock is unchanged. |
| Authorization | Z-07 [2.2.3] As `manager`, mark order #1 as fulfilled on `/manage/orders`. Then as `customer`, try to edit or cancel order #1. | Rejected with "Only pending orders can be changed." |
| Authorization | Z-08 [2.2.3] As `manager`, try to delete a product that has a pending order. | Rejected with "Product has pending orders." |
| Authorization | Z-09 [2.1.13, 2.2.3] As `admin`, create a Product Manager account `manager2` with password `Manager2#Secure2026!`, entering a wrong administrator password. Repeat with the correct administrator password. | First attempt: "Re-authentication failed.", no account created. Second attempt: account created and listed. |
| Authorization | Z-10 [2.2.3] As `admin`, change `manager2`'s role to Administrator, then delete `manager2` (correct administrator password each time). | Role changes, then the account is removed from the list. |
| Authorization | Z-11 [2.2.3] As `admin`, try to change the role of, or delete, the `admin` account itself (use developer tools to post to `/admin/users/1/delete` if no button is shown). Try the same for a customer account's id. | Both rejected: "You cannot modify your own account." and a validation error for the customer account. |
| Authorization | Z-12 [2.2.1] As any logged-in user, use developer tools to remove the hidden `csrf` field from a form (e.g. logout) and submit. | 403 page; the action is not performed. |

### 2.3 Data Validation

| Control Group | Test Scenario | Expected Outcome |
|---|---|---|
| Data Validation | V-01 [2.3.2] As `customer`, order quantity `0`, then `101`, then `-1`, then `abc` (use developer tools to remove the input's constraints if the browser blocks them). | Each is rejected with a 400 error page; no order is created. |
| Data Validation | V-02 [2.3.2] As `manager`, add a product with price `0`, price `1000000.01`, price `-5`, and stock `100001`. | Each is rejected with a 400 error page; no product is created. |
| Data Validation | V-03 [2.3.3] As `manager`, add a product with a 101-character name, then one with a 501-character description. | Both are rejected with a 400 error page. |
| Data Validation | V-04 [2.3.3] Register with a 2-character username, then a 31-character username, then a 129-character password. | Each is rejected with a 400 error page. |
| Data Validation | V-05 [2.3.1] Register with username `<script>alert(1)</script>` and with username `admin' OR '1'='1`. | Rejected outright (400). The input is not cleaned up and stored. |
| Data Validation | V-06 [2.3.1] As `manager`, add a product named `<b>Bold</b> & "quotes"` (valid: any characters, length 1–100). | The product is stored exactly as typed and displayed as literal text — not altered, and not interpreted as HTML. |
| Data Validation | V-07 [2.3.1] As `admin`, open `/admin/logs?category=NOPE` and `/admin/logs?date_from=14-11-2026`. | Each is rejected with a 400 error page. |

### 2.4 Error Handling

| Control Group | Test Scenario | Expected Outcome |
|---|---|---|
| Error Handling | E-01 [2.4.2] Open `/doesnotexist` while logged in. | Custom 404 page in the site layout, with a generic message. |
| Error Handling | E-02 [2.4.2] Trigger a 403 (Z-01) and a 400 (V-01). | Custom error pages in the site layout, with generic messages. |
| Error Handling | E-03 [2.4.1] Stop the server, rename the `products` table (`C:\Apps\convert-markdown\.venv\Scripts\python.exe -c "import sqlite3;c=sqlite3.connect('data/shop.db');c.execute('alter table products rename to p2');c.commit()"`), start the server and open `/products` as `customer`. Rename the table back afterwards. | Generic 500 page: "Something went wrong. Please try again later." No stack trace, SQL or file path is shown. The traceback is in `data/error.log` only. |
| Error Handling | E-04 [2.4.1] Inspect the response headers of any page in the browser's developer tools. | The `Server` header shows only `SecureShop`; no Python or library version. |

### 2.5 Logging

| Control Group | Test Scenario | Expected Outcome |
|---|---|---|
| Logging | L-01 [2.4.4] As `customer` and then as `manager`, open `/admin/logs`. | 403 page for both. |
| Logging | L-02 [2.4.4] As `admin`, open "Audit log". | The log is displayed, newest first. There are no edit or delete controls. |
| Logging | L-03 [2.4.6, 2.4.3] As `admin`, filter the log by category `AUTH`. | Entries for every login attempt in section 2.1: `SUCCESS` rows for logins, logouts, registration, password change and reset; `FAILURE` rows with details such as "unknown user", "wrong password", "lockout triggered", "account locked", "re-auth failed". |
| Logging | L-04 [2.4.7] Filter by category `ACCESS`. | `FAILURE` rows for the unauthenticated requests (A-01), the 403s (Z-01 to Z-03, L-01), the "not owner" attempt (Z-05) and the CSRF failure (Z-12), with username, IP and path. |
| Logging | L-05 [2.4.5] Filter by category `VALIDATION`. | `FAILURE` rows for every rejected input in section 2.3, naming the rule that failed. No passwords appear. |
| Logging | L-06 [2.4.3] Filter by outcome `SUCCESS`, then by category `DATA` and `ADMIN`. | Successful product, order and account operations are listed. |
| Logging | L-07 [2.4.3] Filter by username `demo_user`, and by a date range covering today. | Only matching rows are shown. |
| Logging | L-08 [2.4.1] Filter by category `ERROR`. | The 500 from E-03 appears with the exception class name only. |

## 3. Automated Checks

`test_app.py` runs a subset of the above against a temporary database:

```
C:\Apps\convert-markdown\.venv\Scripts\python.exe test_app.py
```

It prints `ALL TESTS PASSED` on success.
