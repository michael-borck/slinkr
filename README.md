<!-- BADGES:START -->
[![css](https://img.shields.io/badge/-css-1572b6?style=flat-square)](https://github.com/topics/css) [![flask](https://img.shields.io/badge/-flask-000000?style=flat-square)](https://github.com/topics/flask) [![flask-bcrypt](https://img.shields.io/badge/-flask--bcrypt-blue?style=flat-square)](https://github.com/topics/flask-bcrypt) [![flask-login](https://img.shields.io/badge/-flask--login-blue?style=flat-square)](https://github.com/topics/flask-login) [![html](https://img.shields.io/badge/-html-e34f26?style=flat-square)](https://github.com/topics/html) [![python](https://img.shields.io/badge/-python-3776ab?style=flat-square)](https://github.com/topics/python) [![qr-code-generator](https://img.shields.io/badge/-qr--code--generator-blue?style=flat-square)](https://github.com/topics/qr-code-generator) [![tinydb](https://img.shields.io/badge/-tinydb-blue?style=flat-square)](https://github.com/topics/tinydb) [![url-expansion](https://img.shields.io/badge/-url--expansion-blue?style=flat-square)](https://github.com/topics/url-expansion) [![url-shortener](https://img.shields.io/badge/-url--shortener-blue?style=flat-square)](https://github.com/topics/url-shortener)
<!-- BADGES:END -->

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-username/slinkr/ci.yml?branch=main)](https://github.com/your-username/slinkr/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

# Slinkr  
**Stretch. Shrink. Share.**

> A sleek, Flask-powered web app for shortening, expanding, QR-coding, and validating URLs.

---

## 📋 Table of Contents

1. [Demo](#-demo)  
2. [Features](#-features)  
3. [Tech Stack](#-tech-stack)  
4. [Getting Started](#-getting-started)  
   - [Configuration](#configuration)  
   - [Run Locally](#run-locally)  
5. [Usage Examples](#-usage-examples)  
6. [Deployment](#-deployment)  
7. [Contributing](#-contributing)  
8. [License](#-license)

---

## 📷 Demo

![Slinkr Interface](./assets/demo.gif)

---

## 🚀 Features

### Public (No Account Required)
- **Expand URLs** – Reveal full links.  
- **QR Code Generator** – PNG/SVG output, logo optional.

### Verified Users
- **URL Shortener** – Create branded short links (`/abc123`).  
- **Basic Link Checker** – HTTP status & reachability tests.

### Admin-Only
- **User Management** – View, verify, or delete users via `/admin/users`.  
- **Link Health Dashboard** – Monitor, check, and delete links via `/admin/links`.  
- **Dead-Link Cleanup** – Automatic background sweeps purge links after repeated failed checks (audit-logged).  
- **Rate Limiting Controls** – Fine-tune abuse protection.

---

## 🛠 Tech Stack

- **Backend:** Flask, TinyDB, Flask-Login, Flask-Bcrypt, Flask-Limiter  
- **Frontend:** TailwindCSS, Vanilla JS  
- **QR Codes:** `qrcode` + Pillow  
- **Utilities:** `requests`, `shortuuid`

---

## 📦 Getting Started

### Configuration

Create a `.env` file in your project root:

```dotenv
SECRET_KEY=your_super_secret_key
APP_BASE_URL=http://localhost:5000
````

### Run Locally

```bash
git clone https://github.com/your-username/slinkr.git
cd slinkr
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

First user to register becomes an **admin** and is auto-verified. Subsequent users require admin approval.

---

## 💻 Usage Examples

### Headless API (build scripts / automation)

`/api/shorten` and `/api/check` require a verified account. For scripts, set a
service key so you can authenticate with a header instead of a browser session:

```bash
# In the deployment .env (next to docker-compose.prod.yml):
SLINKR_API_KEY=$(openssl rand -hex 32)   # any strong secret
# Optional: attribute created links to a specific user (email or id).
# Defaults to the first admin when unset.
SLINKR_API_USER=you@example.com
```

The key is sent as `Authorization: Bearer <key>` or `X-API-Key: <key>`. It is
**opt-in**: with `SLINKR_API_KEY` unset the header is ignored and only the
browser session works. Requests bodies are **JSON**.

* **Shorten a URL**

  ```bash
  curl -X POST "$APP_BASE_URL/api/shorten" \
    -H "Authorization: Bearer $SLINKR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"url":"https://example.com"}'
  # → {"short_url":"https://.../Ab3XyZ"}
  # Idempotent: the same long URL always returns the same short code.
  ```

  **Custom alias (optional).** Add `"alias"` to request a memorable slug instead of a
  random code. The alias becomes the short code itself.

  ```bash
  curl -X POST "$APP_BASE_URL/api/shorten" \
    -H "Authorization: Bearer $SLINKR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"url":"https://example.com","alias":"my-link"}'
  # → {"short_url":"https://.../my-link","alias":"my-link"}
  ```

  - Aliases are **lowercased** and must be 2–64 chars of letters, digits, `-` or `_`
    (else `400`). Names that collide with the app's own routes (`api`, `admin`,
    `login`, …) are reserved (`400`).
  - **Clash handling.** A free alias is created. An alias already pointing at the
    **same** URL is returned unchanged (idempotent, so build scripts can re-run
    safely). An alias pointing at a **different** URL is refused with **`409`** — an
    existing link is never silently repointed. Pick another alias, or omit `alias`
    for a random code.

* **Check a Link**

  ```bash
  curl -X POST "$APP_BASE_URL/api/check" \
    -H "X-API-Key: $SLINKR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"url":"https://example.com"}'
  ```

* **Generate a QR Code** (public, no key needed)

  ```bash
  curl "$APP_BASE_URL/api/qrcode?url=https://example.com" \
    --output qr.png
  ```

### Dead-link cleanup

A background thread **inside the app** keeps the link table healthy — no cron
or external maintenance script needed. Every `LINK_CHECK_INTERVAL_MINUTES`
(default 60) one worker sweeps up to `LINK_CHECK_BATCH` (default 25) of the
*stalest* links, skipping any checked within the last
`LINK_CHECK_RECHECK_HOURS` (default 24). A link that fails
`DEAD_LINK_THRESHOLD` (default 3) consecutive checks — necessarily spread ≥24h
apart — is deleted, freeing its alias, with an audit record kept in the
`purged_links` table (visible on `/admin/links`). Sites that merely block bots
(401/403/429) are marked *inconclusive*, never dead. Set
`LINK_CHECK_AUTOPURGE=0` to record failures without ever auto-deleting.

The same machinery is exposed over the API (admin session or `SLINKR_API_KEY`):

* **List links with health status**

  ```bash
  curl "$APP_BASE_URL/api/links" -H "X-API-Key: $SLINKR_API_KEY"
  # ?dead=1 → only links at/over the threshold; ?mine=1 → only the service user's
  ```

* **Run a sweep batch now**

  ```bash
  curl -X POST "$APP_BASE_URL/api/links/check" \
    -H "X-API-Key: $SLINKR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"limit": 50, "purge": true}'
  # → {"checked":50,"alive":47,"dead":2,"blocked":1,"skipped":0,"purged":[...]}
  ```

* **Purge dead links** (`dry_run` previews without deleting)

  ```bash
  curl -X POST "$APP_BASE_URL/api/links/purge-dead" \
    -H "X-API-Key: $SLINKR_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"dry_run": true}'
  ```

* **Delete a single link** (owners can delete their own; admin/key can delete any)

  ```bash
  curl -X DELETE "$APP_BASE_URL/api/links/my-link" \
    -H "X-API-Key: $SLINKR_API_KEY"
  ```

---

## 🚀 Deployment

### Docker (recommended)

```bash
cp .env.example .env
# Edit .env: set SECRET_KEY (openssl rand -hex 32), APP_BASE_URL,
# RESEND_API_KEY + EMAIL_FROM for login emails, AUTO_VERIFY_DOMAINS,
# and optionally ADMIN_EMAIL to pre-create the admin account
docker compose up -d --build
```

The app listens on `127.0.0.1:8000` (via gunicorn) with data persisted in the
`slinkr_data` volume (`/data` in the container, SQLite in WAL mode). A Redis
sidecar provides shared rate-limit storage. Put Nginx or Caddy in front for
HTTPS, keep `TRUST_PROXY=1`, and set `SESSION_COOKIE_SECURE=1` once HTTPS is
live.

Login is passwordless: users enter their email, receive a six-digit code
(sent via [Resend](https://resend.com)), and are logged in — accounts are
created automatically on first login. Domains listed in `AUTO_VERIFY_DOMAINS`
are verified immediately; everyone else needs admin approval in
`/admin/users` before they can shorten links or run health checks. Without
a `RESEND_API_KEY`, codes are printed to the container logs (dev mode).

Existing TinyDB data (`slinkr_data.json`) is migrated into SQLite automatically
on first start if present in the data directory.

### Pull from GHCR

Pushes to `main` (and `v*` tags) build a multi-arch image via GitHub Actions
and publish it to GitHub Container Registry. On your VPS, edit
`docker-compose.yml` to use the image instead of building:

```yaml
services:
  slinkr:
    image: ghcr.io/<your-github-username>/slinkr:latest
```

If the package is private, log in first:
`echo $GH_PAT | docker login ghcr.io -u <username> --password-stdin`
(PAT needs the `read:packages` scope.)

### Manual

* Use Gunicorn + Nginx or Caddy.
* **Do not** run `app.py` with `debug=True` in production.
* Swap TinyDB for PostgreSQL/SQLite for higher scale.
* Configure `Flask-Limiter` with Redis:

  ```python
  limiter = Limiter(app, storage_uri="redis://localhost:6379")
  ```

---

## 🤝 Contributing

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) first, then:

1. Fork the repo
2. Create a feature branch
3. Run tests: `pytest`
4. Open a Pull Request

---

## 📄 License

MIT © Michael Borck

