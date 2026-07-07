import os
import io
import base64
import ipaddress
import json
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
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError
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
    password_hash TEXT NOT NULL,
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
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to /login if @login_required fails
login_manager.login_message_category = 'info' # Flash message category

# Used to equalize login timing when the username doesn't exist (prevents
# user enumeration via response-time differences).
DUMMY_PASSWORD_HASH = bcrypt.generate_password_hash("timing-equalization-dummy").decode('utf-8')

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
        self.password_hash = user_row['password_hash']
        self.is_admin = bool(user_row['is_admin'])
        self.is_verified = bool(user_row['is_verified'])
        self.created_at = user_row['created_at']

    def verify_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

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

@app.route('/api/shorten', methods=['POST'])
@limiter.limit("5 per minute") # Limit shortening attempts per IP
@verification_required # Requires login and verification (or admin)
def api_shorten():
    """API endpoint to shorten a URL. Requires verified account.
    Browser clients must send the CSRF token in the X-CSRFToken header."""
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
@limiter.limit("10 per minute") # Stricter limit for external requests
@verification_required # Requires login and verification (or admin)
def api_check():
    """API endpoint to check link status. Requires verified account.
    Browser clients must send the CSRF token in the X-CSRFToken header."""
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    # Redirect logged-in users away from registration page
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # --- Input Validation ---
        error = False
        if not username or not email or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            error = True
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            error = True
        if len(password) < 8:
             flash('Password must be at least 8 characters long.', 'danger')
             error = True
        # Basic email format check (more robust validation is possible)
        if '@' not in email or '.' not in email.split('@')[-1]:
             flash('Invalid email address format.', 'danger')
             error = True

        db = get_db()

        # --- Uniqueness Check (single generic message to limit account enumeration) ---
        if not error:
            taken = db.execute(
                "SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)
            ).fetchone()
            if taken:
                flash('That username or email is not available. Please choose another.', 'danger')
                error = True

        # --- Proceed if no errors ---
        if not error:
            # Hash password securely
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Determine if this is the very first user
            is_first_user = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0

            # Insert new user into the database
            try:
                db.execute(
                    "INSERT INTO users (username, email, password_hash, is_admin, is_verified, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (username, email, hashed_password,
                     int(is_first_user), # First user automatically becomes admin
                     int(is_first_user), # First user is automatically verified
                     utcnow_iso())
                )
                db.commit()
            except sqlite3.IntegrityError:
                # Race with a concurrent registration using the same username/email
                flash('That username or email is not available. Please choose another.', 'danger')
                return render_template('register.html')

            # Provide feedback to the user
            if is_first_user:
                 flash(f'Admin account created for {username}! You are automatically verified.', 'success')
            else:
                 flash(f'Account created for {username}! Please wait for admin verification to use all features.', 'info')

            return redirect(url_for('login')) # Redirect to login after successful registration

        # If there were errors, re-render the registration page (flashed messages will show)
        return render_template('register.html')

    # Handle GET request (show the registration form)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    # Redirect logged-in users away from login page
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False # Check if "remember me" is ticked

        # Find user by username in the database
        user_row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # Check if user exists and password is correct
        if user_row:
            user = User(user_row) # Create User object from database data
            if user.verify_password(password):
                # Password matches, log the user in
                login_user(user, remember=remember)
                flash(f'Welcome back, {user.username}!', 'success')

                # Redirect to the page the user was trying to access, or to index
                next_page = request.args.get('next')
                # Basic security check for open redirect vulnerability
                if next_page and urlparse(next_page).netloc == '':
                    return redirect(next_page)
                else:
                    return redirect(url_for('index'))
            else:
                # Password incorrect
                flash('Login Unsuccessful. Please check username and password.', 'danger')
        else:
            # User not found — still run a hash check so response timing
            # doesn't reveal whether the username exists
            bcrypt.check_password_hash(DUMMY_PASSWORD_HASH, password or '')
            flash('Login Unsuccessful. Please check username and password.', 'danger')

    # Handle GET request (show the login form)
    return render_template('login.html')

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
    """Creates the initial admin user from ADMIN_USERNAME / ADMIN_EMAIL /
    ADMIN_PASSWORD environment variables if no admin exists yet.
    (Alternatively, the first user to register via the web UI becomes admin.)"""
    username = os.environ.get("ADMIN_USERNAME")
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")
    if not (username and email and password):
        return
    conn = _connect()
    try:
        if conn.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone():
            return
        if len(password) < 8:
            print("WARNING: ADMIN_PASSWORD must be at least 8 characters; admin not created.")
            return
        conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, is_verified, created_at)"
            " VALUES (?, ?, ?, 1, 1, ?)",
            (username, email, bcrypt.generate_password_hash(password).decode('utf-8'), utcnow_iso())
        )
        conn.commit()
        print(f"Admin user '{username}' created from environment variables.")
    except sqlite3.IntegrityError:
        pass # Another worker created it first — fine
    finally:
        conn.close()

bootstrap_admin_from_env()

# --- Run the App ---
if __name__ == '__main__':
    # --- Initial Admin User Creation (Command-line prompt if none exist) ---
    # This runs only when the script is executed directly (python app.py)
    conn = _connect()
    if not conn.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone():
         print("------------------------------------------")
         print("No admin user found. Creating one now...")
         print("------------------------------------------")
         while True:
            admin_username = input("Enter admin username: ").strip()
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (admin_username,)).fetchone():
                print("Username already exists. Try again.")
            elif not admin_username:
                 print("Username cannot be empty. Try again.")
            else:
                break
         while True:
            admin_email = input("Enter admin email: ").strip()
            if conn.execute("SELECT 1 FROM users WHERE email = ?", (admin_email,)).fetchone():
                print("Email already exists. Try again.")
            elif '@' not in admin_email or '.' not in admin_email.split('@')[-1]:
                 print("Invalid email format. Try again.")
            else:
                 break
         while True:
            admin_password = input("Enter admin password (min 8 chars): ").strip()
            if len(admin_password) < 8:
                print("Password must be at least 8 characters long. Try again.")
            else:
                confirm_password = input("Confirm admin password: ").strip()
                if admin_password == confirm_password:
                    break
                else:
                    print("Passwords do not match. Try again.")

         # Hash the password and insert the admin user
         hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
         conn.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, is_verified, created_at)"
            " VALUES (?, ?, ?, 1, 1, ?)",
            (admin_username, admin_email, hashed_password, utcnow_iso())
         )
         conn.commit()
         print("------------------------------------------")
         print(f"Admin user '{admin_username}' created and verified successfully.")
         print("------------------------------------------")
    conn.close()

    # --- Start Flask Development Server ---
    # Use 0.0.0.0 to make it accessible on the local network
    # Use environment variables for production configuration (host, port, debug)
    run_host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    run_port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    # Use FLASK_DEBUG=1 to enable debug mode for local development (never in production)
    is_debug = os.environ.get("FLASK_DEBUG", "0") == "1"

    print(f"Starting Flask app on {run_host}:{run_port} (Debug: {is_debug})")
    app.run(host=run_host, port=run_port, debug=is_debug)
