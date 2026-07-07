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

* **Shorten a URL**

  ```bash
  curl -X POST "$APP_BASE_URL/api/shorten" \
    -H "Authorization: Bearer $TOKEN" \
    -d "url=https://example.com"  
  # → {"short_url":"http://.../Ab3XyZ"}
  ```

* **Generate a QR Code**

  ```bash
  curl "$APP_BASE_URL/api/qrcode?url=https://example.com" \
    --output qr.png
  ```

* **Check a Link**

  ```bash
  curl -X POST "$APP_BASE_URL/api/check" \
    -H "Authorization: Bearer $TOKEN" \
    -d "url=https://example.com"
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

