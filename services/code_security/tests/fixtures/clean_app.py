"""
Safe Python fixture -- the secure counterpart of the vulnerable Python
samples. Every function here is the CORRECT way to do something the
rule pack flags when done unsafely, and several deliberately still use
string concatenation, since that is the shape that produces false
positives in the other languages.

Used to measure the agent's false-positive rate (project doc 8.3).
"""

import hashlib  # noqa: F401 -- present but not used for passwords
import json
import subprocess
from urllib.parse import urlparse

import bcrypt
import requests
import yaml
from flask import render_template

ALLOWED_HOSTS = {"api.example.com", "api2.example.com"}


# Parameterized query -- concatenation used only for a static fragment.
def get_user(cursor, username):
    table_suffix = "main"
    query = "SELECT * FROM users_" + table_suffix + " WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()


# Argument list, no shell -- but the path is still built by concatenation.
def run_backup(target_dir, prefix="backup"):
    archive = prefix + ".tar.gz"
    subprocess.run(["tar", "-czf", archive, target_dir], shell=False, check=True)


# TLS verification left on.
def fetch_data(url):
    return requests.get(url, verify=True)


# Host allowlisted before the request -- URL still concatenated.
def proxy_request(host):
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get("https://" + host + "/api/data", verify=True)


# Same, via urlparse on a caller-supplied URL.
def fetch_validated(url):
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, verify=True)


# Structured parsing instead of eval().
def load_config(raw):
    return json.loads(raw)


# Safe YAML loader.
def load_yaml_config(raw):
    return yaml.safe_load(raw)


# Template file with Jinja2 autoescaping instead of render_template_string.
def show_message(user_input):
    return render_template("page.html", value=user_input)


# Constant-time hash verification instead of ==.
def check_login(input_password, stored_hash):
    return bcrypt.checkpw(input_password.encode(), stored_hash)


# Deliberate slow hashing with a salt.
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
