import os
import io
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import shortuuid
import requests
import datetime # Needed for user creation timestamp

from flask import (
    Flask, request, jsonify, render_template, redirect, url_for,
    send_file, Response, flash, session, abort, g
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required,
    current_user
)
from flask_wtf.csrf import CSRFProtect, CSRFError, validate_csrf
from wtforms import ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from urllib.parse import urlparse
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from qrcode.image.styles.colormasks import SolidFillColorMask
from PIL import Image

# --- Configuration ---
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000") # Use env var or default
DATA_DIR = os.environ.get("DATA_DIR", ".") # Directory for DB + uploads (mount a volume here in Docker)
DB_FILE = os.path.join(DATA_DIR, 'slinkr.db') # SQLite database
LEGACY_TINYDB_FILE = os.path.join(DATA_DIR, 'slinkr_data.json') # Old TinyDB file (migrated on first run)
LOGO_UPLOAD_FOLDER = os.path.join(DATA_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Passwordless login (email codes via Resend)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "") # Empty = dev mode (codes printed to logs)
EMAIL_FROM = os.environ.get("EMAIL_FROM", "Slinkr <login@slinkr.link>")
# Users whose email domain is listed here are verified automatically on first login;
# everyone else can log in but needs admin approval for shortening/checking.
AUTO_VERIFY_DOMAINS = {
    d.strip().lower() for d in os.environ.get("AUTO_VERIFY_DOMAINS", "curtin.edu.au").split(",") if d.strip()
}
LOGIN_CODE_TTL_MINUTES = 10
LOGIN_CODE_RESEND_SECONDS = 60
LOGIN_CODE_MAX_ATTEMPTS = 5

# Headless API access (for build scripts / automation). Empty = disabled, so
# existing session-based auth is the only path unless this is explicitly set.
# When set, a request bearing this key (Authorization: Bearer <key> or the
# X-API-Key header) is authenticated as the service user below.
SLINKR_API_KEY = os.environ.get("SLINKR_API_KEY", "")
# The user that API-key requests act as (short links are attributed to them).
# An email or numeric id; defaults to the first admin when unset.
SLINKR_API_USER = os.environ.get("SLINKR_API_USER", "")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # Fall back to an ephemeral random key: sessions won't survive a restart,
    # but nobody can forge session cookies with a known default key.
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set; using an ephemeral key. "
          "All sessions will be invalidated on restart. Set SECRET_KEY in production.")

# --- Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = LOGO_UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_TIME_LIMIT'] = None # Token valid for the whole session (page may stay open a long time)
if os.environ.get("SESSION_COOKIE_SECURE", "0") == "1": # Enable when served over HTTPS
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Respect X-Forwarded-* headers when running behind a reverse proxy (nginx/caddy/traefik).
# Required for correct client IPs in rate limiting. Only enable when a trusted proxy fronts the app.
if os.environ.get("TRUST_PROXY", "0") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# --- Database (SQLite) ---
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL DEFAULT '', -- Legacy column; login is passwordless

    is_admin INTEGER NOT NULL DEFAULT 0,
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    short_code TEXT UNIQUE NOT NULL,
    long_url TEXT NOT NULL,
    user_id INTEGER,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_links_long_url ON links(long_url);
CREATE TABLE IF NOT EXISTS login_codes (
    email TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
"""

def _connect():
    """Opens a new SQLite connection with sensible defaults."""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn

def get_db():
    """Returns the per-request database connection, opening it if needed."""
    if '_db' not in g:
        g._db = _connect()
    return g._db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('_db', None)
    if db is not None:
        db.close()

def migrate_from_tinydb(conn):
    """One-time import of data from the old TinyDB JSON file, preserving IDs."""
    if not os.path.exists(LEGACY_TINYDB_FILE):
        return
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return # Already have data; never overwrite
    try:
        with open(LEGACY_TINYDB_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"WARNING: could not read legacy TinyDB file for migration: {e}")
        return
    for doc_id, u in (data.get('users') or {}).items():
        conn.execute(
            "INSERT OR IGNORE INTO users (id, username, email, password_hash, is_admin, is_verified, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (int(doc_id), u.get('username'), u.get('email'), u.get('password_hash'),
             int(bool(u.get('is_admin'))), int(bool(u.get('is_verified'))),
             u.get('created_at') or utcnow_iso())
        )
    for doc_id, l in (data.get('links') or {}).items():
        conn.execute(
            "INSERT OR IGNORE INTO links (id, short_code, long_url, user_id, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (int(doc_id), l.get('short_code'), l.get('long_url'), l.get('user_id'),
             l.get('created_at') or utcnow_iso())
        )
    conn.commit()
    migrated = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if migrated:
        print(f"Migrated {migrated} user(s) and their links from {LEGACY_TINYDB_FILE} to {DB_FILE}.")

def utcnow_iso():
    """Current UTC time as an ISO-8601 string (timezone-aware)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def init_db():
    conn = _connect()
    conn.execute("PRAGMA journal_mode = WAL") # Safe concurrent reads + single-writer across processes
    conn.executescript(SCHEMA)
    migrate_from_tinydb(conn)
    conn.commit()
    conn.close()

init_db()

# Security & Auth
csrf = CSRFProtect(app)
login_manager = LoginManager(app)

@login_manager.unauthorized_handler
def handle_unauthorized():
    """Sends unauthenticated users to the home page with the login modal open."""
    if request.path.startswith('/api/') or request.path.startswith('/auth/'):
        return jsonify({"error": "Login required"}), 401
    flash("Please log in to continue.", "info")
    return redirect(url_for('index', login=1))

# Rate Limiting (set RATELIMIT_STORAGE_URI=redis://host:6379/0 in production
# so limits are shared across workers and survive restarts)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour", "10 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


# --- User Model ---
class User(UserMixin):
    """Represents a user in the system for Flask-Login."""
    def __init__(self, user_row):
        self.id = user_row['id']
        self.username = user_row['username']
        self.email = user_row['email']
        self.is_admin = bool(user_row['is_admin'])
        self.is_verified = bool(user_row['is_verified'])
        self.created_at = user_row['created_at']

    # Required by Flask-Login
    def get_id(self):
        """Returns the user's ID as a string."""
        return str(self.id)

# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    """Loads a user object from the database given their ID."""
    try:
        row = get_db().execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if row:
            return User(row)
    except ValueError: # Handle cases where user_id might not be an integer
        pass
    return None


def request_api_key():
    """Return the API key presented on the current request, or ''.
    Accepts either `Authorization: Bearer <key>` or the `X-API-Key` header."""
    presented = request.headers.get("X-API-Key", "")
    if not presented:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[len("Bearer "):]
    return presented.strip()


def request_has_valid_api_key():
    """True when the request carries the configured service API key.
    Always False when SLINKR_API_KEY is unset, so the feature is opt-in."""
    if not SLINKR_API_KEY:
        return False
    presented = request_api_key()
    return bool(presented) and hmac.compare_digest(presented, SLINKR_API_KEY)


def service_user():
    """The verified user that API-key requests act as. SLINKR_API_USER (email or
    id) if set and found, otherwise the first admin. None if neither exists."""
    db = get_db()
    ident = SLINKR_API_USER.strip()
    row = None
    if ident:
        if ident.isdigit():
            row = db.execute("SELECT * FROM users WHERE id = ?", (int(ident),)).fetchone()
        else:
            row = db.execute("SELECT * FROM users WHERE lower(email) = ?", (ident.lower(),)).fetchone()
    if row is None:
        row = db.execute(
            "SELECT * FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1"
        ).fetchone()
    return User(row) if row else None


@login_manager.request_loader
def load_user_from_request(req):
    """Stateless auth for headless clients (build scripts, automation).
    Enabled only when SLINKR_API_KEY is set. A matching key authenticates as the
    service user; a browser session (loaded via the cookie) still takes
    precedence over this, so interactive use is unaffected."""
    if request_has_valid_api_key():
        return service_user()
    return None


def enforce_csrf_unless_api_key():
    """CSRF-protect session/cookie clients, but not API-key clients (which send
    no cookie, so CSRF does not apply). Call at the top of a state-changing API
    view that has been marked @csrf.exempt. Returns a JSON error response to
    return, or None when the request may proceed."""
    if request_has_valid_api_key():
        return None
    try:
        validate_csrf(request.headers.get("X-CSRFToken"))
    except (ValidationError, CSRFError):
        return jsonify({"error": "CSRF token missing or invalid"}), 400
    return None

# --- Helper Functions ---

def is_valid_url(url):
    """Checks if a given string is a valid URL, allowing for missing schemes for some uses."""
    if not isinstance(url, str):
        return False
    try:
        result = urlparse(url)
        # Allow URLs without scheme only if they have a netloc (e.g., "example.com")
        if result.netloc:
             return True
        # Require scheme and netloc for full validation (e.g., "http://example.com")
        if result.scheme and result.netloc:
            return True
    except ValueError:
        return False
    return False

def is_public_url(url):
    """Resolves the URL's host and rejects private/loopback/link-local/reserved
    addresses so the link checker can't be used to probe internal services (SSRF)."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if not ip.is_global:
                return False
        return True
    except (socket.gaierror, ValueError, OSError):
        return False

def allowed_file(filename):
    """Checks if the uploaded file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Passwordless Login Helpers ---

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def normalize_email(email):
    return (email or '').strip().lower()

def hash_login_code(email, code):
    """Codes are stored as an HMAC keyed by SECRET_KEY, never in plain text."""
    return hmac.new(SECRET_KEY.encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()

def is_auto_verified(email):
    return email.rsplit('@', 1)[-1] in AUTO_VERIFY_DOMAINS

def unique_username(db, email):
    """Derives a display name from the email local part, deduping if taken."""
    base = re.sub(r'[^a-zA-Z0-9._-]', '', email.split('@')[0])[:30] or 'user'
    candidate = base
    n = 1
    while db.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)).fetchone():
        n += 1
        candidate = f"{base}{n}"
    return candidate

def send_login_code(email, code):
    """Sends the login code via Resend. Without an API key (dev mode) the code
    is printed to the server log instead."""
    if not RESEND_API_KEY:
        print(f"[DEV] Login code for {email}: {code}")
        return True
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": EMAIL_FROM,
                "to": [email],
                "subject": f"{code} is your Slinkr login code",
                "text": (f"Your Slinkr login code is: {code}\n\n"
                         f"It expires in {LOGIN_CODE_TTL_MINUTES} minutes. "
                         "If you didn't request this, you can ignore this email."),
                "html": (f"<div style='font-family:sans-serif;max-width:420px'>"
                         f"<h2 style='color:#1f2937'>Your Slinkr login code</h2>"
                         f"<p style='font-size:2rem;letter-spacing:0.3em;font-weight:700;"
                         f"color:#059669;margin:16px 0'>{code}</p>"
                         f"<p style='color:#4b5563'>It expires in {LOGIN_CODE_TTL_MINUTES} minutes. "
                         f"If you didn't request this, you can ignore this email.</p></div>"),
            },
            timeout=10,
        )
        if resp.status_code >= 400:
            print(f"Resend API error {resp.status_code}: {resp.text[:300]}")
            return False
        return True
    except requests.exceptions.RequestException as e:
        print(f"Resend request failed: {e}")
        return False

def generate_qr_code_base64(url, logo_path=None, error_correction=qrcode.constants.ERROR_CORRECT_H):
    """Generates a QR code (optionally with a logo) and returns it as a base64 encoded string."""
    try:
        # Initialize QR code generator with high error correction for logo embedding
        qr = qrcode.QRCode(
            version=1, # Auto-adjusts version based on data size
            error_correction=error_correction,
            box_size=10, # Size of each QR code box
            border=4, # Border width around the QR code
        )
        qr.add_data(url)
        qr.make(fit=True) # Fit the data into the smallest possible QR code version

        # Create the QR code image using a styled factory for rounded corners
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=RoundedModuleDrawer(), # Use rounded modules
            color_mask=SolidFillColorMask(front_color=(0, 0, 0)) # Standard black QR code
        )

        # Embed logo if provided and valid
        if logo_path and os.path.exists(logo_path):
            try:
                logo = Image.open(logo_path).convert("RGBA") # Ensure logo has alpha channel

                # Calculate logo size relative to QR code size
                qr_width, qr_height = img.size
                max_logo_size = min(qr_width, qr_height) // 5 # Logo size (e.g., 1/5th)
                logo.thumbnail((max_logo_size, max_logo_size), Image.Resampling.LANCZOS) # Resize logo smoothly

                # Calculate position to place logo in the center
                pos = ((qr_width - logo.width) // 2, (qr_height - logo.height) // 2)

                # Create a white background slightly larger than the logo for better contrast/scannability
                bg_size = (logo.width + 10, logo.height + 10) # Add padding
                bg_pos = ((qr_width - bg_size[0]) // 2, (qr_height - bg_size[1]) // 2)
                background = Image.new("RGBA", bg_size, (255, 255, 255, 255)) # Opaque white background

                # Paste background first, then logo onto the QR code using alpha mask
                img.paste(background, bg_pos)
                img.paste(logo, pos, logo) # Use logo's alpha mask for transparency

            except Exception as e:
                print(f"Error processing logo: {e}")
                # Continue without logo if there's an error

        # Save QR code image to a bytes buffer
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        # Encode the image bytes to base64 string for embedding in HTML
        img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{img_str}"

    except Exception as e:
        print(f"Error generating QR code: {e}")
        return None

# --- Decorators ---
def admin_required(f):
    """Decorator to ensure user is logged in and is an admin."""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash("Admin access required.", "warning")
            # Handle API requests differently
            if request.endpoint and request.endpoint.startswith('api_'):
                 return jsonify({"error": "Admin access required"}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    # Preserve original function name and docstring for Flask/introspection
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

def verification_required(f):
    """Decorator to ensure user is logged in and verified."""
    @login_required
    def decorated_function(*args, **kwargs):
        # Admins bypass verification check
        if not current_user.is_verified and not current_user.is_admin:
            flash("Your account must be verified by an admin to perform this action.", "warning")
            # Return a specific JSON error for API calls
            if request.endpoint and request.endpoint.startswith('api_'):
                 return jsonify({"error": "Account not verified"}), 403
            return redirect(url_for('index')) # Redirect non-API requests
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function


# --- Main Routes ---

@app.route('/')
def index():
    """Renders the main single-page application."""
    # This route now correctly uses the template that expects 'current_user'
    return render_template('index_v2.html', base_url=APP_BASE_URL)

@app.route('/<short_code>')
@limiter.limit("100 per minute") # Limit redirection hits per IP
def redirect_to_long_url(short_code):
    """Redirects a short code to its corresponding long URL."""
    row = get_db().execute("SELECT long_url FROM links WHERE short_code = ?", (short_code,)).fetchone()

    if row:
        long_url = row['long_url']
        # Ensure the URL has a scheme for proper browser redirection
        if not urlparse(long_url).scheme:
             long_url = "http://" + long_url # Default to http if missing
        # Consider adding click tracking here later if needed
        return redirect(long_url, code=302) # Use 302 for temporary redirect
    else:
        # Render a 404 page if the short code is not found
        flash(f"Short link code '{short_code}' not found.", "warning")
        return render_template('404.html', short_code=short_code, base_url=APP_BASE_URL), 404

# --- API Endpoints ---

# Custom-alias support for /api/shorten.
# An alias becomes the short_code directly: aliases and random codes share the links
# table and its UNIQUE(short_code) constraint, which does all the clash enforcement.
# Aliases are lowercased so "6018-CH1" and "6018-ch1" cannot diverge. Reserved names
# are the app's own top-level routes; an alias there would be shadowed by the real page
# and never resolve, so we refuse them up front.
ALIAS_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{1,63}$')
RESERVED_ALIASES = {
    'api', 'admin', 'auth', 'login', 'logout', 'about', 'static',
    'favicon.ico', 'robots.txt',
}

@app.route('/api/shorten', methods=['POST'])
@csrf.exempt # CSRF is enforced below for session clients; API-key clients are exempt
@limiter.limit("5 per minute") # Limit shortening attempts per IP
@verification_required # Requires login and verification (or admin), or the API key
def api_shorten():
    """API endpoint to shorten a URL. Requires a verified account (session) or the
    service API key. Browser clients must send the CSRF token in X-CSRFToken.

    Optional `alias` requests a custom short code (a slug) instead of a random one.
    Clash rules: a free alias is created; an alias already pointing at the SAME url is
    returned unchanged (idempotent); an alias pointing at a DIFFERENT url is refused
    with 409 (we never repoint an existing link)."""
    csrf_error = enforce_csrf_unless_api_key()
    if csrf_error:
        return csrf_error
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    long_url = data.get('url')

    # Validate URL presence and basic format
    if not long_url:
        return jsonify({"error": "Missing URL"}), 400

    # Ensure URL has a scheme before storing/comparing
    parsed = urlparse(long_url)
    if not parsed.scheme and parsed.netloc: # e.g., example.com/path
        long_url = "http://" + long_url # Default to http if missing scheme but has domain
    elif not is_valid_url(long_url): # Check full validity if scheme exists or was added
        return jsonify({"error": "Invalid URL format"}), 400

    db = get_db()

    # Optional custom alias. If supplied, it IS the short code.
    alias = (data.get('url_alias') or data.get('alias') or '').strip().lower()
    if alias:
        if alias in RESERVED_ALIASES or not ALIAS_RE.match(alias):
            return jsonify({"error": "Invalid or reserved alias (use 2-64 chars: letters, digits, - or _)"}), 400
        row = db.execute("SELECT long_url FROM links WHERE short_code = ?", (alias,)).fetchone()
        if row is None:
            try:
                db.execute(
                    "INSERT INTO links (short_code, long_url, user_id, created_at) VALUES (?, ?, ?, ?)",
                    (alias, long_url, current_user.id, utcnow_iso())
                )
                db.commit()
            except sqlite3.IntegrityError:
                # Lost a race for this alias; re-read and fall through to the clash check.
                row = db.execute("SELECT long_url FROM links WHERE short_code = ?", (alias,)).fetchone()
        if row is not None and row['long_url'] != long_url:
            return jsonify({"error": f"Alias '{alias}' is already in use for a different URL"}), 409
        return jsonify({"short_url": f"{APP_BASE_URL}/{alias}", "alias": alias})

    # No alias: idempotent by URL, random 7-char code.
    # Check if this exact URL already exists
    existing = db.execute("SELECT short_code FROM links WHERE long_url = ?", (long_url,)).fetchone()
    if existing:
        short_code = existing['short_code']
    else:
        # Generate a unique short code; UNIQUE constraint guards against races
        while True:
            short_code = shortuuid.uuid()[:7] # Generate a 7-character short code
            try:
                db.execute(
                    "INSERT INTO links (short_code, long_url, user_id, created_at) VALUES (?, ?, ?, ?)",
                    (short_code, long_url, current_user.id, utcnow_iso())
                )
                db.commit()
                break
            except sqlite3.IntegrityError:
                continue # Collision — try another code

    # Construct the full short URL
    short_url = f"{APP_BASE_URL}/{short_code}"
    return jsonify({"short_url": short_url})

@app.route('/api/expand', methods=['POST'])
@csrf.exempt # Public, unauthenticated endpoint — safe to call without a token (e.g. curl)
@limiter.limit("30 per minute") # Allow more expands than shortens
def api_expand():
    """API endpoint to expand a Slinkr short URL."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    short_url_input = data.get('short_url', '').strip()

    if not short_url_input:
        return jsonify({"error": "Short URL cannot be empty"}), 400

    # Extract short code from input (could be full URL or just the code)
    try:
        parsed_url = urlparse(short_url_input)
        if parsed_url.netloc and parsed_url.path: # Looks like a full URL (e.g., http://app.com/abc)
             # Assuming the shortcode is the first part of the path
            short_code = parsed_url.path.strip('/')
            if '/' in short_code: # Handle potential trailing slashes or extra path parts
                short_code = short_code.split('/')[0]
        elif not parsed_url.scheme and not parsed_url.netloc and parsed_url.path: # Looks like just the code (e.g., abc)
            short_code = parsed_url.path.strip('/')
        else: # Unrecognized format
             return jsonify({"error": "Invalid short URL format"}), 400
    except Exception:
         return jsonify({"error": "Could not parse short URL"}), 400

    if not short_code:
         return jsonify({"error": "Could not extract short code from URL"}), 400

    # Find the corresponding long URL in the database
    row = get_db().execute("SELECT long_url FROM links WHERE short_code = ?", (short_code,)).fetchone()

    if row:
        return jsonify({"original_url": row['long_url']})
    else:
        return jsonify({"error": "Short URL not found"}), 404

@app.route('/api/qr', methods=['POST'])
@csrf.exempt # Public, unauthenticated endpoint — safe to call without a token (e.g. curl)
@limiter.limit("15 per minute") # Limit QR generation rate
def api_qr():
    """API endpoint to generate a QR code from a URL, optionally with a logo."""
    url = request.form.get('url')
    logo_file = request.files.get('logo')
    logo_path = None

    # Validate URL: must have scheme (http/https) and netloc for QR codes
    if not url:
         return jsonify({"error": "Missing URL for QR code"}), 400

    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
         # Try adding http:// if scheme is missing but netloc exists
         if parsed_url.netloc and not parsed_url.scheme:
             url = "http://" + url
             if not is_valid_url(url): # Check again after adding scheme
                 return jsonify({"error": "Invalid URL format for QR code (requires http/https)"}), 400
         else: # Invalid if scheme or netloc are missing
             return jsonify({"error": "Invalid URL format for QR code (requires http/https)"}), 400

    # Handle optional logo upload
    if logo_file:
        if allowed_file(logo_file.filename):
            try:
                # Save the logo temporarily with a unique name
                filename = f"logo_{shortuuid.uuid()[:8]}.{logo_file.filename.rsplit('.', 1)[1].lower()}"
                logo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                logo_file.save(logo_path)
            except Exception as e:
                print(f"Error saving logo: {e}")
                return jsonify({"error": "Could not save logo file"}), 500
        else:
            # Invalid file type for logo
            return jsonify({"error": "Invalid logo file type. Allowed: png, jpg, jpeg, gif"}), 400

    # Generate the QR code (with or without logo)
    qr_base64 = generate_qr_code_base64(url, logo_path)

    # Clean up the temporary logo file if it was created
    if logo_path and os.path.exists(logo_path):
        try:
            os.remove(logo_path)
        except Exception as e:
            # Log error but don't fail the request if cleanup fails
            print(f"Error removing temporary logo file {logo_path}: {e}")

    # Return the base64 encoded QR code image data
    if qr_base64:
        return jsonify({"qr_image_data": qr_base64})
    else:
        # Error occurred during QR generation
        return jsonify({"error": "Failed to generate QR code"}), 500

@app.route('/api/check', methods=['POST'])
@csrf.exempt # CSRF is enforced below for session clients; API-key clients are exempt
@limiter.limit("10 per minute") # Stricter limit for external requests
@verification_required # Requires login and verification (or admin), or the API key
def api_check():
    """API endpoint to check link status. Requires a verified account (session) or
    the service API key. Browser clients must send the CSRF token in X-CSRFToken."""
    csrf_error = enforce_csrf_unless_api_key()
    if csrf_error:
        return csrf_error
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    url_to_check = data.get('url')

    # Basic validation, allow URLs without scheme initially
    if not url_to_check:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Prepend http:// if no scheme is present for the request library
    parsed = urlparse(url_to_check)
    if not parsed.scheme:
        url_to_check = "http://" + url_to_check

    # Final validation after potentially adding scheme
    if not is_valid_url(url_to_check):
         return jsonify({"error": "Invalid URL format"}), 400

    # Block requests to internal/private addresses (SSRF protection)
    if not is_public_url(url_to_check):
        return jsonify({"error": "URL host is not publicly reachable", "status_indicator": "🚫"}), 400

    # Perform the HTTP request to check the URL status
    try:
        headers = {'User-Agent': 'SlinkrLinkChecker/1.0 (+https://your-app-url.com/about)'} # Identify the checker
        # Use HEAD request first for efficiency (doesn't download body)
        # Set timeout, allow redirects
        response = requests.head(url_to_check, allow_redirects=True, timeout=10, headers=headers)

        # If HEAD is disallowed (405 Method Not Allowed), try GET
        if response.status_code == 405:
             response = requests.get(url_to_check, allow_redirects=True, timeout=10, stream=True, headers=headers) # stream=True avoids downloading large files immediately

        status_code = response.status_code
        status_text = response.reason
        final_url = response.url # Get the final URL after any redirects

        # Close response body if using stream=True with GET to release connection
        if response.request.method == 'GET' and hasattr(response, 'close'):
            response.close()

        # Determine status indicator based on status code range
        if 200 <= status_code < 300: status_indicator = "✅" # Success
        elif 300 <= status_code < 400: status_indicator = "➡️" # Redirect
        elif 400 <= status_code < 500: status_indicator = "❌" # Client Error
        elif 500 <= status_code < 600: status_indicator = "⚠️" # Server Error
        else: status_indicator = "❓" # Unknown status

        return jsonify({
            "status_code": status_code,
            "status_text": status_text,
            "status_indicator": status_indicator,
            "final_url": final_url
        })

    # Handle specific request exceptions
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out", "status_indicator": "⏱️"}), 408 # Request Timeout status
    except requests.exceptions.SSLError:
         return jsonify({"error": "SSL certificate verification failed", "status_indicator": "🔒❌"}), 500 # Use 500 or a custom code
    except requests.exceptions.ConnectionError:
        # This can include DNS resolution errors, refused connections, etc.
        return jsonify({"error": "Could not connect to the server or resolve host", "status_indicator": "🔌"}), 503 # Service Unavailable
    except requests.exceptions.RequestException as e:
        # Catch other general request errors
        print(f"Link check error for {url_to_check}: {e}")
        # Avoid leaking potentially sensitive error details from the requests library
        error_message = "An unexpected error occurred during the request."
        # Provide more specific feedback for common issues if possible
        if "invalid URL" in str(e).lower() or "Name or service not known" in str(e):
             error_message = "Invalid URL format or host could not be resolved."

        return jsonify({"error": error_message, "status_indicator": "❓"}), 500 # Internal Server Error


# --- Authentication Routes ---

@app.route('/login')
def login():
    """Legacy URL — the login flow now lives in a modal on the home page."""
    return redirect(url_for('index', login=1))

@app.route('/auth/request-code', methods=['POST'])
@limiter.limit("5 per minute; 30 per hour")
def auth_request_code():
    """Step 1 of passwordless login: email a one-time code to the user."""
    if current_user.is_authenticated:
        return jsonify({"error": "Already logged in"}), 400
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Please enter a valid email address"}), 400

    db = get_db()
    now = datetime.datetime.now(datetime.timezone.utc)

    # Per-email resend throttle (in addition to the per-IP rate limit)
    row = db.execute("SELECT created_at FROM login_codes WHERE email = ?", (email,)).fetchone()
    if row:
        created = datetime.datetime.fromisoformat(row['created_at'])
        wait = LOGIN_CODE_RESEND_SECONDS - (now - created).total_seconds()
        if wait > 0:
            return jsonify({"error": f"Please wait {int(wait) + 1}s before requesting another code"}), 429

    code = f"{secrets.randbelow(1_000_000):06d}"
    expires = now + datetime.timedelta(minutes=LOGIN_CODE_TTL_MINUTES)
    db.execute(
        "INSERT INTO login_codes (email, code_hash, created_at, expires_at, attempts)"
        " VALUES (?, ?, ?, ?, 0)"
        " ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash,"
        " created_at = excluded.created_at, expires_at = excluded.expires_at, attempts = 0",
        (email, hash_login_code(email, code), now.isoformat(), expires.isoformat())
    )
    db.commit()

    if not send_login_code(email, code):
        return jsonify({"error": "Could not send the email. Please try again shortly."}), 502
    return jsonify({"ok": True})

@app.route('/auth/verify-code', methods=['POST'])
@limiter.limit("10 per minute")
def auth_verify_code():
    """Step 2 of passwordless login: verify the code, create the account if
    it's the user's first login, and start the session."""
    if current_user.is_authenticated:
        return jsonify({"error": "Already logged in"}), 400
    data = request.get_json(silent=True) or {}
    email = normalize_email(data.get('email'))
    code = (data.get('code') or '').strip()
    if not EMAIL_RE.match(email) or not re.fullmatch(r'\d{6}', code):
        return jsonify({"error": "Invalid email or code format"}), 400

    db = get_db()
    now = datetime.datetime.now(datetime.timezone.utc)
    row = db.execute("SELECT * FROM login_codes WHERE email = ?", (email,)).fetchone()

    generic_error = "That code is invalid or has expired. Please request a new one."
    if not row or datetime.datetime.fromisoformat(row['expires_at']) < now:
        return jsonify({"error": generic_error}), 400
    if row['attempts'] >= LOGIN_CODE_MAX_ATTEMPTS:
        db.execute("DELETE FROM login_codes WHERE email = ?", (email,))
        db.commit()
        return jsonify({"error": generic_error}), 400
    if not hmac.compare_digest(row['code_hash'], hash_login_code(email, code)):
        db.execute("UPDATE login_codes SET attempts = attempts + 1 WHERE email = ?", (email,))
        db.commit()
        return jsonify({"error": "Incorrect code. Please check and try again."}), 400

    # Code is valid — consume it
    db.execute("DELETE FROM login_codes WHERE email = ?", (email,))

    user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user_row:
        is_first_user = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        verified = is_first_user or is_auto_verified(email)
        db.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, is_verified, created_at)"
            " VALUES (?, ?, '', ?, ?, ?)",
            (unique_username(db, email), email, int(is_first_user), int(verified), utcnow_iso())
        )
        user_row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    elif not user_row['is_verified'] and is_auto_verified(email):
        # Domain was whitelisted after this account was created — upgrade it
        db.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (user_row['id'],))
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_row['id'],)).fetchone()
    db.commit()

    login_user(User(user_row), remember=True)
    return jsonify({"ok": True, "username": user_row['username'], "verified": bool(user_row['is_verified'])})

@app.route('/logout')
@login_required # User must be logged in to log out
def logout():
    """Logs the current user out."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Admin Routes ---

@app.route('/admin/users')
@admin_required # Uses custom decorator for admin access
def admin_users():
    """Displays list of users for admin management."""
    rows = get_db().execute(
        "SELECT * FROM users ORDER BY LOWER(username)"
    ).fetchall()
    users = [dict(r) for r in rows]
    return render_template('admin_users.html', users=users)

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
@admin_required
def admin_verify_user(user_id):
    """Admin action to toggle user verification status."""
    db = get_db()
    user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    # Cannot modify self (optional safeguard)
    if current_user.id == user_id:
         flash('Admins cannot change their own verification status.', 'warning')
         return redirect(url_for('admin_users'))

    # Toggle verification status
    new_status = 0 if user_row['is_verified'] else 1
    db.execute("UPDATE users SET is_verified = ? WHERE id = ?", (new_status, user_id))
    db.commit()

    action = "verified" if new_status else "unverified"
    flash(f'User {user_row["username"]} has been {action}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin action to delete a user."""
    db = get_db()
    user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    # Prevent admin from deleting themselves
    if current_user.id == user_id:
         flash('Admin cannot delete their own account.', 'warning')
         return redirect(url_for('admin_users'))

    username = user_row["username"]
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    # Also remove links associated with the deleted user
    db.execute("DELETE FROM links WHERE user_id = ?", (user_id,))
    db.commit()

    flash(f'User {username} and their associated links have been deleted.', 'success')
    return redirect(url_for('admin_users'))

# --- Optional: About Page ---
@app.route('/about')
def about():
    """Renders the about page."""
    # Reuse the existing about.html template
    return render_template('about.html', base_url=APP_BASE_URL)

# --- Error Handlers ---
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handles missing/invalid CSRF tokens."""
    if request.path.startswith('/api/'):
        return jsonify({"error": f"CSRF validation failed: {e.description}"}), 400
    flash("Your session expired or the form was invalid. Please try again.", "warning")
    return redirect(request.referrer or url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 Not Found errors."""
    # Pass the base_url if your 404 template uses it
    return render_template('404.html', base_url=APP_BASE_URL, error=e), 404

@app.errorhandler(403)
def forbidden(e):
     """Handles 403 Forbidden errors."""
     # Custom 403 page or redirect
     # Flash message might have already been set by decorators
     return render_template('403.html', base_url=APP_BASE_URL, error=e), 403

@app.errorhandler(429) # Rate limit exceeded
def ratelimit_handler(e):
    """Handles 429 Too Many Requests errors from Flask-Limiter."""
    # Return JSON response for API calls, potentially render template for others
    if request.endpoint and request.endpoint.startswith('api_'):
        return jsonify(error=f"Rate limit exceeded: {e.description}"), 429
    else:
        flash(f"Rate limit exceeded: {e.description}. Please try again later.", "warning")
        # Could render a specific rate limit template or redirect
        return redirect(url_for('index'))


@app.errorhandler(500)
def internal_server_error(e):
     """Handles 500 Internal Server errors."""
     # Log the error for debugging purposes
     # Be careful not to leak sensitive info in production logs
     print(f"Internal Server Error encountered: {e}")

     flash("An unexpected internal error occurred. Please try again later.", "danger")
     return render_template('500.html', base_url=APP_BASE_URL, error=e), 500


# --- Admin Bootstrap (non-interactive, for Docker/production) ---
def bootstrap_admin_from_env():
    """Creates the initial admin account from ADMIN_EMAIL (and optionally
    ADMIN_USERNAME) if no admin exists yet. Login is passwordless — the admin
    signs in with an emailed code like everyone else.
    (Alternatively, the very first user to log in becomes admin.)"""
    email = normalize_email(os.environ.get("ADMIN_EMAIL"))
    if not email:
        return
    if not EMAIL_RE.match(email):
        print("WARNING: ADMIN_EMAIL is not a valid email address; admin not created.")
        return
    conn = _connect()
    try:
        if conn.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone():
            return
        username = os.environ.get("ADMIN_USERNAME") or email.split('@')[0]
        conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, is_verified, created_at)"
            " VALUES (?, ?, '', 1, 1, ?)",
            (username, email, utcnow_iso())
        )
        conn.commit()
        print(f"Admin account '{username}' <{email}> created from environment variables.")
    except sqlite3.IntegrityError:
        pass # Another worker created it first — fine
    finally:
        conn.close()

bootstrap_admin_from_env()

# --- Run the App ---
if __name__ == '__main__':
    # No admin? Set ADMIN_EMAIL in the environment, or just log in —
    # the very first user to sign in becomes admin automatically.

    # --- Start Flask Development Server ---
    # Use 0.0.0.0 to make it accessible on the local network
    # Use environment variables for production configuration (host, port, debug)
    run_host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    run_port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    # Use FLASK_DEBUG=1 to enable debug mode for local development (never in production)
    is_debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    print(f"Starting Flask app on {run_host}:{run_port} (Debug: {is_debug})")
    app.run(host=run_host, port=run_port, debug=is_debug)
