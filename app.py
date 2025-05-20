import os
import io
import base64
import shortuuid
import requests
import datetime # Needed for user creation timestamp

from flask import (
    Flask, request, jsonify, render_template, redirect, url_for,
    send_file, Response, flash, session, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required,
    current_user
)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from tinydb import TinyDB, Query, where
from urllib.parse import urlparse
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from qrcode.image.styles.colormasks import SolidFillColorMask
from PIL import Image

# --- Configuration ---
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000") # Use env var or default
DB_FILE = 'slinkr_data.json' # Main DB file
LOGO_UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secret_key_change_me") # CHANGE FOR PRODUCTION!

# --- Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = LOGO_UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database
db = TinyDB(DB_FILE)
links_table = db.table('links')
users_table = db.table('users')

# Security & Auth
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to /login if @login_required fails
login_manager.login_message_category = 'info' # Flash message category

# Rate Limiting (adjust limits as needed)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour", "10 per minute"],
    storage_uri="memory://", # Use redis in production for better scaling
)


# --- User Model ---
class User(UserMixin):
    """Represents a user in the system for Flask-Login."""
    def __init__(self, user_data):
        self.id = user_data.doc_id # Use TinyDB document ID as user ID
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.password_hash = user_data.get('password_hash')
        self.is_admin = user_data.get('is_admin', False)
        self.is_verified = user_data.get('is_verified', False)
        self.created_at = user_data.get('created_at')

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
        user_doc = users_table.get(doc_id=int(user_id))
        if user_doc:
            return User(user_doc)
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
    Link = Query()
    result = links_table.search(Link.short_code == short_code)

    if result:
        long_url = result[0]['long_url']
        # Ensure the URL has a scheme for proper browser redirection
        if not urlparse(long_url).scheme:
             long_url = "http://" + long_url # Default to http if missing
        print(f"Redirecting {short_code} to {long_url}")
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
    """API endpoint to shorten a URL. Requires verified account."""
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


    # Check if this exact URL already exists
    Link = Query()
    existing = links_table.search(Link.long_url == long_url)
    if existing:
        short_code = existing[0]['short_code']
    else:
        # Generate a unique short code
        while True:
            short_code = shortuuid.uuid()[:7] # Generate a 7-character short code
            if not links_table.contains(Query().short_code == short_code):
                break # Found a unique code
        # Store the new mapping with user association and timestamp
        links_table.insert({
            'short_code': short_code,
            'long_url': long_url,
            'user_id': current_user.id, # Associate link with the logged-in user
            'created_at': datetime.datetime.utcnow().isoformat() # Store creation time
        })

    # Construct the full short URL
    short_url = f"{APP_BASE_URL}/{short_code}"
    return jsonify({"short_url": short_url})

@app.route('/api/expand', methods=['POST'])
@limiter.limit("30 per minute") # Allow more expands than shortens
# No verification required by default for expanding
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
    Link = Query()
    result = links_table.search(Link.short_code == short_code)

    if result:
        return jsonify({"original_url": result[0]['long_url']})
    else:
        return jsonify({"error": "Short URL not found"}), 404

@app.route('/api/qr', methods=['POST'])
@limiter.limit("15 per minute") # Limit QR generation rate
# No verification required by default for QR codes
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
    """API endpoint to check link status. Requires verified account."""
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

        # --- Uniqueness Check ---
        if not error:
            UserQuery = Query()
            if users_table.search(UserQuery.username == username):
                flash('Username already exists. Please choose another.', 'danger')
                error = True
            if users_table.search(UserQuery.email == email):
                flash('Email address already registered. Please use another.', 'danger')
                error = True

        # --- Proceed if no errors ---
        if not error:
            # Hash password securely
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Determine if this is the very first user
            is_first_user = users_table.count(UserQuery.username.exists()) == 0

            # Insert new user into the database
            users_table.insert({
                'username': username,
                'email': email,
                'password_hash': hashed_password,
                'is_admin': is_first_user, # First user automatically becomes admin
                'is_verified': is_first_user, # First user is automatically verified
                'created_at': datetime.datetime.utcnow().isoformat() # Record creation time
            })

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
        UserQuery = Query()
        user_doc = users_table.get(UserQuery.username == username)

        # Check if user exists and password is correct
        if user_doc:
            user = User(user_doc) # Create User object from database data
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
            # User not found
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
    all_users_data = users_table.all()
    # Convert raw data to list of dicts, adding the document ID as 'id'
    users = [dict(u, **{'id': u.doc_id}) for u in all_users_data]
    # Sort users, e.g., by username (case-insensitive)
    users.sort(key=lambda x: x['username'].lower())
    return render_template('admin_users.html', users=users)

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
@admin_required
def admin_verify_user(user_id):
    """Admin action to toggle user verification status."""
    user_doc = users_table.get(doc_id=user_id)
    if not user_doc:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    # Cannot modify self (optional safeguard)
    if current_user.id == user_id:
         flash('Admins cannot change their own verification status.', 'warning')
         return redirect(url_for('admin_users'))

    # Toggle verification status
    new_status = not user_doc.get('is_verified', False)
    users_table.update({'is_verified': new_status}, doc_ids=[user_id])

    action = "verified" if new_status else "unverified"
    flash(f'User {user_doc["username"]} has been {action}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin action to delete a user."""
    user_doc = users_table.get(doc_id=user_id)
    if not user_doc:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    # Prevent admin from deleting themselves
    if current_user.id == user_id:
         flash('Admin cannot delete their own account.', 'warning')
         return redirect(url_for('admin_users'))

    # Consider deleting associated links or reassigning them (more complex)
    # For now, just delete the user document
    username = user_doc["username"]
    users_table.remove(doc_ids=[user_id])
    # Also remove links associated with the deleted user (optional cleanup)
    links_table.remove(where('user_id') == user_id)

    flash(f'User {username} and their associated links have been deleted.', 'success')
    return redirect(url_for('admin_users'))

# --- Optional: About Page ---
@app.route('/about')
def about():
    """Renders the about page."""
    # Reuse the existing about.html template
    return render_template('about.html', base_url=APP_BASE_URL)

# --- Error Handlers ---
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
     # Optionally log the full traceback in production if needed
     # import traceback
     # print(traceback.format_exc())

     flash("An unexpected internal error occurred. Please try again later.", "danger")
     return render_template('500.html', base_url=APP_BASE_URL, error=e), 500


# --- Run the App ---
if __name__ == '__main__':
    # --- Initial Admin User Creation (Command-line prompt if none exist) ---
    # This runs only when the script is executed directly (python app.py)
    # Checks if an admin user already exists in the database
    if not users_table.contains(Query().is_admin == True):
         print("------------------------------------------")
         print("No admin user found. Creating one now...")
         print("------------------------------------------")
         while True:
            admin_username = input("Enter admin username: ").strip()
            if users_table.contains(Query().username == admin_username):
                print("Username already exists. Try again.")
            elif not admin_username:
                 print("Username cannot be empty. Try again.")
            else:
                break
         while True:
            admin_email = input("Enter admin email: ").strip()
            if users_table.contains(Query().email == admin_email):
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
         users_table.insert({
            'username': admin_username,
            'email': admin_email,
            'password_hash': hashed_password,
            'is_admin': True,
            'is_verified': True, # Admin is auto-verified
            'created_at': datetime.datetime.utcnow().isoformat()
         })
         print("------------------------------------------")
         print(f"Admin user '{admin_username}' created and verified successfully.")
         print("------------------------------------------")

    # --- Start Flask Development Server ---
    # Use 0.0.0.0 to make it accessible on the local network
    # Debug=True enables auto-reloading and detailed error pages (disable in production)
    # Use environment variables for production configuration (host, port, debug)
    run_host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    run_port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    # Use FLASK_DEBUG=0 or FLASK_DEBUG=1 environment variable in production/dev
    is_debug = os.environ.get("FLASK_DEBUG", "1") == "1"

    print(f"Starting Flask app on {run_host}:{run_port} (Debug: {is_debug})")
    app.run(host=run_host, port=run_port, debug=is_debug)

