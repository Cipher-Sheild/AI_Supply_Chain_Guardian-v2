"""
Deliberately vulnerable Python fixture for the code_security agent.
Each function targets one rule in app/semgrep_rules/custom_rules.yml.
NOT production code -- test data only.
"""

import hashlib
import os
import pickle

import requests
import yaml
from flask import Markup, render_template_string


# python-sql-injection-string-concat  (CWE-89)
def get_user(cursor, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


# python-requests-tls-verification-disabled  (CWE-295)
def fetch_insecure(url):
    return requests.get(url, verify=False)


# python-os-system-command-injection  (CWE-78)
def run_backup(target_dir):
    cmd = "tar -czf backup.tar.gz " + target_dir
    os.system(cmd)


# python-eval-on-input  (CWE-95)
def load_config(raw):
    return eval(raw)


# python-flask-xss-render-template-string  (CWE-79)
def show_message(user_input):
    html = "<p>" + user_input + "</p>"
    return render_template_string(html)


# python-insecure-deserialization-pickle  (CWE-502)
def restore_session(data):
    return pickle.loads(data)


# python-insecure-yaml-load  (CWE-502)
def load_yaml_config(raw):
    return yaml.load(raw)


# python-ssrf-requests-user-controlled-url  (CWE-918)
def proxy_request(host):
    url = "https://" + host + "/api/data"
    return requests.get(url)


# python-plaintext-password-comparison  (CWE-287)
def check_login(password, stored_password):
    return password == stored_password


# python-weak-password-hashing  (CWE-916)
def hash_password(password):
    return hashlib.md5(password)