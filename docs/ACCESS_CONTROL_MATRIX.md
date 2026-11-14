# Access Control Matrix

**Course:** CSSECDV (S30C), AY 2026–2027 Term 1 — Machine Project (Web App)

**Application:** SecureShop

**Group Members:** _(fill in before submission)_

## 1. Roles

| Role | Description |
|---|---|
| Unregistered | Any visitor without a valid session. |
| Customer (Role B) | Self-registered user. Works only with their own orders. |
| Product Manager (Role A) | Manages the product catalog and the fulfilment of all customers' orders. |
| Administrator | Website Administrator. Manages Administrator and Product Manager accounts and reads the audit log. Has no access to products or orders (least privilege). |

The matrix is enforced by a single component: the `ROUTES` table and `authorize()` in `app.py`. Anything not listed is denied (HTTP 404, or 403 / redirect to login).

## 2. Matrix

| Feature / Resource | Unregistered | Customer | Product Manager | Administrator |
|---|---|---|---|---|
| View login page and log in (`/login`) | Yes | Yes | Yes | Yes |
| Register a new Customer account (`/register`) | Yes | Yes | Yes | Yes |
| Reset a forgotten password via security question (`/forgot`, `/forgot/reset`) | Yes | Yes | Yes | Yes |
| Load the stylesheet (`/static/style.css`) | Yes | Yes | Yes | Yes |
| View home page with last-account-use notice (`/`) | No | Yes | Yes | Yes |
| Log out (`/logout`) | No | Yes | Yes | Yes |
| Change own password, with re-authentication (`/password`) | No | Yes | Yes | Yes |
| View product catalog (`/products`) | No | Yes | Yes | No |
| Place an order (`/orders/new`) | No | Yes | No | No |
| View own orders (`/orders`) | No | Yes | No | No |
| Edit quantity of own pending order (`/orders/<id>/edit`) | No | Yes | No | No |
| Cancel own pending order (`/orders/<id>/cancel`) | No | Yes | No | No |
| View, edit or cancel another customer's order | No | No | No | No |
| View product management page (`/manage/products`) | No | No | Yes | No |
| Add a product (`/manage/products/new`) | No | No | Yes | No |
| Edit a product (`/manage/products/<id>/edit`) | No | No | Yes | No |
| Delete a product (`/manage/products/<id>/delete`) | No | No | Yes | No |
| View all customers' orders (`/manage/orders`) | No | No | Yes | No |
| Mark a pending order fulfilled or cancelled (`/manage/orders/<id>/status`) | No | No | Yes | No |
| View list of user accounts (`/admin/users`) | No | No | No | Yes |
| Create Administrator / Product Manager account (`/admin/users/new`) | No | No | No | Yes |
| Change role of an Administrator / Product Manager account (`/admin/users/<id>/role`) | No | No | No | Yes |
| Delete an Administrator / Product Manager account (`/admin/users/<id>/delete`) | No | No | No | Yes |
| Modify or delete a Customer account | No | No | No | No |
| Modify or delete one's own account from the admin page | No | No | No | No |
| View and filter the audit log, read-only (`/admin/logs`) | No | No | No | Yes |
| Edit or delete audit log entries | No | No | No | No |
| Any URL not listed above | No | No | No | No |

## 3. Notes

- **Unique permissions per role.** Customer: placing and managing own orders. Product Manager: product catalog CRUD and order fulfilment for all customers. Administrator: account management and audit log.
- **Public routes for logged-in users.** The login, registration and reset pages remain reachable while logged in; logging in again replaces the existing session.
- **Object-level rules.** "Own" is decided on the server by comparing the order's `user_id` with the session user; a mismatch returns 403 and is logged.
- **State rules.** Order edits, cancellations and status changes apply to `pending` orders only.
- **Re-authentication.** Password change and all three administrator account operations require the acting user's current password in addition to the role shown above.
