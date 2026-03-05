import os
import pickle
import yaml
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, redirect, send_file

app = Flask(__name__)

# VULN: Hardcoded secret key
app.secret_key = "hardcoded_secret_key_12345"

# VULN: Debug mode enabled in production
app.debug = True

DATABASE = "users.db"


def get_db():
    return sqlite3.connect(DATABASE)


# VULN: SQL Injection
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    db = get_db()
    # SQL injection - string formatting in query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor = db.execute(query)
    user = cursor.fetchone()
    if user:
        return "Login successful"
    return "Login failed", 401


# VULN: Server-Side Template Injection (SSTI)
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # SSTI - user input directly in template string
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# VULN: Command Injection
@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    # Command injection via shell=True
    result = subprocess.check_output(f"nslookup {domain}", shell=True)
    return result


# VULN: Insecure Deserialization
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    # Pickle deserialization of untrusted data
    obj = pickle.loads(data)
    return str(obj)


# VULN: Unsafe YAML loading
@app.route("/parse-yaml", methods=["POST"])
def parse_yaml():
    content = request.get_data(as_text=True)
    # Unsafe YAML load allows arbitrary code execution
    data = yaml.load(content)
    return str(data)


# VULN: Path Traversal
@app.route("/download")
def download():
    filename = request.args.get("file")
    # Path traversal - no sanitization
    filepath = os.path.join("/var/data", filename)
    return send_file(filepath)


# VULN: XSS - Reflected
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # XSS - unescaped user input
    return f"<html><body>Results for: {query}</body></html>"


# VULN: Open Redirect
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url")
    # Open redirect without validation
    return redirect(url)


# VULN: SSRF
@app.route("/fetch")
def fetch_url():
    import requests
    url = request.args.get("url")
    # SSRF - fetching user-supplied URL
    resp = requests.get(url)
    return resp.text


# VULN: Weak cryptography
@app.route("/hash")
def weak_hash():
    import hashlib
    data = request.args.get("data", "")
    # Using MD5 for hashing (weak/broken)
    hashed = hashlib.md5(data.encode()).hexdigest()
    return {"hash": hashed}


# VULN: Hardcoded database credentials
DB_HOST = "db.production.internal"
DB_USER = "root"
DB_PASS = "P@ssw0rd!"
DB_NAME = "production"


# VULN: XML External Entity (XXE)
@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    from lxml import etree
    content = request.get_data()
    # XXE - parsing XML without disabling external entities
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(content, parser)
    return etree.tostring(doc).decode()


if __name__ == "__main__":
    # VULN: Binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
