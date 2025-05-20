# Slinkr - URL Utility Hub

**Tagline:** "Your smart, simple hub for links, QR codes, and more."

## Overview

Slinkr is a web application built with Flask (Python) that provides several useful URL utilities. It features a single-page interface for ease of use and includes user registration with an admin verification system to manage access to certain features.

## Features

- **URL Shortener:** Create short, unique links (e.g., `your-app.com/abc123`) from long URLs. (Requires verified user account)
- **URL Expander:** Discover the original long URL associated with a Slinkr short link. (Open access by default)
- **QR Code Generator:** Generate standard QR codes for any valid URL. (Open access by default)
- **QR Code Generator with Logo:** Embed an optional logo (uploaded by the user) into the center of the QR code. (Open access by default)
- **Basic Link Checker:** Check the HTTP status code and reachability of any URL. (Requires verified user account)
- **User Authentication:** Users can register and log in.
- **Admin Verification:** New user accounts must be verified by an admin user before they can access features like shortening and link checking. The first registered user automatically becomes an admin.
- **Admin User Management:** Admins can view all users, manually verify/unverify accounts, and delete users via the `/admin/users` page.
- **Rate Limiting:** Basic protection against simple automated abuse for API endpoints.

## Tech Stack

- **Backend:** Python 3, Flask
- **Frontend:** HTML, TailwindCSS (via CDN), Vanilla JavaScript
- **Database:** TinyDB (lightweight JSON-based database)
- **Authentication:** Flask-Login, Flask-Bcrypt
- **QR Codes:** `qrcode` library (with Pillow for logo embedding)
- **HTTP Requests:** `requests` library
- **Rate Limiting:** Flask-Limiter
- **Other:** `shortuuid` for short code generation

## Setup Instructions

1.  **Clone the Repository (or download the files):**

    ```bash
    # If using git
    git clone <your-repo-url>
    cd slinkr-project-directory
    ```

2.  **Create a Virtual Environment (Recommended):**

    ```bash
    python -m venv venv
    # Activate the virtual environment
    # On Windows:
    # venv\Scripts\activate
    # On macOS/Linux:
    # source venv/bin/activate
    ```

3.  **Install Dependencies:**
    Ensure you have the `requirements.txt` file (provided in a separate artifact). Then run:

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables (Optional but Recommended):**
    The application uses environment variables for sensitive or deployment-specific settings. Create a `.env` file in the project root (ensure this file is **not** committed to version control if it contains secrets):

    ```dotenv
    # .env file
    SECRET_KEY='your_very_strong_and_secret_key_here' # IMPORTANT: Change this for production!
    # Optional: Set the base URL if deploying or using a custom domain
    # APP_BASE_URL='[https://your-slinkr-domain.com](https://your-slinkr-domain.com)'
    ```

    - `SECRET_KEY`: Used by Flask for session management and security. Make it long and random.
    - `APP_BASE_URL`: The base URL used for generating short links. Defaults to `http://127.0.0.1:5000` if not set.

## Running the Application

1.  **Ensure your virtual environment is activated.**

2.  **Run the Flask development server:**

    ```bash
    python app.py
    ```

3.  **First Run - Create Admin User:**
    If no admin user exists in the `slinkr_data.json` database, the script will prompt you in the terminal to create the first admin user when you run `python app.py`. Follow the prompts to set the username, email, and password. This first user will be automatically verified.
    Alternatively, the _first user to register_ via the web interface (`/register`) will automatically be designated as the admin and verified.

4.  **Access Slinkr:**
    Open your web browser and navigate to `http://127.0.0.1:5000` (or the `APP_BASE_URL` if you configured it).

## Admin Verification Process

1.  New users register via the `/register` page.
2.  Their account is created but marked as `is_verified = False`.
3.  An existing admin user must log in.
4.  The admin navigates to the `/admin/users` page.
5.  The admin finds the new user in the list and clicks the "Verify" button next to their name.
6.  Once verified, the user can log in and use all features, including URL shortening and link checking.

## Deployment Notes

- For production, **DO NOT** run with `debug=True`. Set `debug=False` in `app.py` or manage it via environment variables.
- Use a production-grade WSGI server like Gunicorn or uWSGI behind a reverse proxy like Nginx or Caddy.
- Ensure the `SECRET_KEY` environment variable is set to a strong, unique value.
- Set the `APP_BASE_URL` environment variable to your actual domain.
- Consider using a more robust database (like PostgreSQL or SQLite) instead of TinyDB for larger scale.
- Configure `Flask-Limiter` to use a persistent storage backend like Redis (`storage_uri="redis://localhost:6379"`) instead of `memory://` for production.
- Ensure the `uploads` directory has appropriate write permissions for the user running the WSGI server, or consider using cloud storage for
