import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv

# Load .env for local development only (file is gitignored)
load_dotenv()
import hashlib
import defusedxml.ElementTree as ET
import pickle
import jwt
import urllib3
from flask import Flask, request, escape
import json

# Flask application
app = Flask(__name__)

# 1. **Injection (SQL Injection)**
def get_user_data(user_id):
    connection = sqlite3.connect('example.db')
    cursor = connection.cursor()

    # Vulnerable to SQL Injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

# JWT secret from environment - must be strong (min 32 chars for HS256)
def _get_jwt_secret():
    secret = os.environ.get("JWT_SECRET")
    if not secret or len(secret) < 32:
        raise ValueError(
            "JWT_SECRET environment variable must be set with at least 32 characters. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return secret

# 2. **Broken Authentication**
# Credentials from env/secrets - never hardcoded (SOC2 CC6.1, CC6.7)
def _get_auth_users():
    """Load auth users from AUTH_USERS_FILE (path to JSON) or AUTH_USERS (JSON string)."""
    file_path = os.environ.get("AUTH_USERS_FILE")
    if file_path and Path(file_path).exists():
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    auth_json = os.environ.get("AUTH_USERS")
    if auth_json:
        return json.loads(auth_json)
    raise ValueError(
        "AUTH_USERS or AUTH_USERS_FILE must be set. "
        "Local dev: AUTH_USERS='{\"admin\":\"password123\",\"user\":\"userpass\"}' in .env. "
        "Production: Use AUTH_USERS_FILE pointing to secrets manager output."
    )

def login(username, password):
    # Insecure login mechanism (plain text password comparison)
    users = _get_auth_users()
    if username in users and users[username] == password:
        # Token signed with strong secret from environment
        token = jwt.encode({"user": username}, _get_jwt_secret(), algorithm="HS256")
        return f"Logged in, token: {token}"
    else:
        return "Invalid credentials"

# 3. **Sensitive Data Exposure**
def store_password(password):
    # Storing passwords using MD5, which is insecure
    return hashlib.md5(password.encode()).hexdigest()

# 4. **XML External Entities (XXE)**
# Max XML size to prevent DoS (1MB)
_MAX_XML_SIZE = 1 * 1024 * 1024

def parse_xml(xml_string):
    # Safe parsing: defusedxml prevents XXE, entity expansion, and XML bombs
    if xml_string is None or (hasattr(xml_string, '__len__') and len(xml_string) > _MAX_XML_SIZE):
        raise ValueError("Invalid or oversized XML input")
    tree = ET.fromstring(xml_string)
    name_elem = tree.find("name")
    return name_elem.text if name_elem is not None else None

# 5. **Broken Access Control**
def delete_user(user_id, current_user):
    # No authorization check: any user can delete any account
    print(f"User {user_id} deleted by {current_user}")

# 6. **Security Misconfiguration**
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")

@app.route('/')
def index():
    return "Welcome to the vulnerable app!"

# 7. **Cross-Site Scripting (XSS)**
@app.route('/greet')
def greet():
    name = request.args.get('name')
    # Vulnerable to XSS, input is reflected without validation or sanitization
    return f"Hello, {name}!"

# 8. **Insecure Deserialization**
def insecure_deserialize(data):
    import json  # Import required for safe deserialization
    return json.loads(data)

# 9. **Using Components with Known Vulnerabilities**
def use_vulnerable_library():
    # Using a vulnerable version of urllib3
    http = urllib3.PoolManager()
    response = http.request('GET', 'http://example.com')
    return response.data

# 10. **Insufficient Logging and Monitoring**
@app.route('/admin')
def admin():
    # No logging of access to sensitive areas like admin routes
    return "Welcome to the admin area!"

# Example vulnerable routes
@app.route('/get_user/<user_id>')
def get_user(user_id):
    return str(get_user_data(user_id))

@app.route('/login', methods=['POST'])
def login_route():
    # Credentials in request body only - never in URL (avoids logs, history, proxies)
    if request.is_json:
        data = request.get_json(silent=True) or {}
        username = data.get('username')
        password = data.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
    if not username or not password:
        return "Missing username or password", 400
    return login(username, password)

@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user_route(user_id):
    # Sensitive identity in body, not URL
    if request.is_json:
        data = request.get_json(silent=True) or {}
        current_user = data.get('current_user')
    else:
        current_user = request.form.get('current_user')
    delete_user(user_id, current_user)
    safe_user_id = escape(user_id)
    safe_current_user = escape(current_user) if current_user is not None else ''
    return f"User {safe_user_id} deleted by {safe_current_user}"

@app.route('/store_password', methods=['POST'])
def store_password_route():
    # Password in body only - never in URL path or query
    if request.is_json:
        data = request.get_json(silent=True) or {}
        password = data.get('password')
    else:
        password = request.form.get('password')
    if not password:
        return "Missing password", 400
    return store_password(password)

@app.route('/parse_xml', methods=['POST'])
def parse_xml_route():
    xml_string = request.data
    return parse_xml(xml_string)

@app.route('/deserialize', methods=['POST'])
def deserialize_route():
    data = request.data
    return insecure_deserialize(data)

@app.route('/vulnerable_library')
def vulnerable_library_route():
    return use_vulnerable_library()

# Example of vulnerable usage (do not run in production)
if __name__ == '__main__':
    # Example: SQL Injection Exploitation
    get_user_data("1' OR '1'='1")

    # Example: Safe XML parsing (XXE disabled)
    xml_data = '''<?xml version="1.0"?>
    <user>
        <name>test</name>
    </user>
    '''
    parse_xml(xml_data)

    # Example: Insecure Deserialization Exploitation
    payload = b'cos\nsystem\n(S"rm -rf /"\ntR.'  # Dangerous payload
    insecure_deserialize(payload)

    # Running the Flask app
    app.run()
