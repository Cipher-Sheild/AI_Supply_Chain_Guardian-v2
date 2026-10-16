"""
Real, reused test cases for the license_compliance baseline comparison.

Every case here is one we already demoed live against the running
service in Docker during development/testing (see the project's
testing walkthrough) -- nothing invented for this comparison. Each
case includes what's needed to (a) run our own agent's pipeline
directly, and (b) install the real package(s) so the baseline tools
have something to inspect, since both pip-licenses and license-checker
only report on packages that are ACTUALLY INSTALLED on disk -- unlike
our agent, which works directly from raw manifest text with no install
step at all. This difference is itself one of the findings -- see
RESULTS.md.
"""

TEST_CASES = [
    {
        "name": "pyspread (GPL-3.0-only, + transitive GPL-3.0-only PyQt6)",
        "ecosystem": "python",
        "manifest_filename": "requirements.txt",
        "manifest_content": "pyspread\n",
        "pip_install_targets": ["pyspread"],
        "notes": (
            "Real GPL-3.0-only PyPI package. Declares PyQt6 (also "
            "GPL-3.0-only) as a dependency -- tests whether each tool "
            "catches the transitive license too, not just the direct one."
        ),
    },
    {
        "name": "python-crontab (LGPL-3.0-only, requires our ScanCode fallback)",
        "ecosystem": "python",
        "manifest_filename": "requirements.txt",
        "manifest_content": "python-crontab==3.2.0\n",
        "pip_install_targets": ["python-crontab==3.2.0"],
        "notes": (
            "Registry metadata only says 'LGPLv3' as a raw string -- no "
            "OSI classifier, no PEP 639 license_expression. Our agent's "
            "fast path can't normalize this and falls back to "
            "ScanCode-toolkit's real license-detection engine, which "
            "correctly resolves it to LGPL-3.0-only."
        ),
    },
    {
        "name": "express (clean, MIT, npm)",
        "ecosystem": "node",
        "manifest_filename": "package.json",
        "manifest_content": '{"dependencies": {"express": "4.19.2"}}',
        "npm_install_targets": ["express@4.19.2"],
        "notes": "Widely used, clean MIT-licensed control case for the Node/npm path.",
    },
    {
        "name": "ccnetviz (real GPL-3.0 npm package)",
        "ecosystem": "node",
        "manifest_filename": "package.json",
        "manifest_content": '{"dependencies": {"ccnetviz": "1.0.19"}}',
        "npm_install_targets": ["ccnetviz@1.0.19"],
        "notes": (
            "Real, live-verified GPL-3.0-licensed npm package "
            "(confirmed directly against the npm registry before use, "
            "not assumed)."
        ),
    },
    {
        "name": "fake/hallucinated package (simulated AI-suggested dependency that doesn't exist)",
        "ecosystem": "python",
        "manifest_filename": "requirements.txt",
        "manifest_content": "ccnetviz-python-does-not-exist==1.0.0\n",
        "pip_install_targets": ["ccnetviz-python-does-not-exist==1.0.0"],
        "notes": (
            "Deliberately invalid package name. Tests graceful "
            "handling of an AI hallucination -- an AI-specific threat "
            "model this project exists to catch, not something "
            "traditional license-auditing tools were designed around. "
            "NOTE: a real `pip install` of this fails outright (the "
            "package doesn't exist), so pip-licenses never even gets a "
            "chance to run on it -- see RESULTS.md for why this "
            "matters structurally, not just as a quirky edge case."
        ),
    },
]

# The large, realistic 55-dependency scan used in the service's own
# load test, reused here as-is (not regenerated). Two packages are
# EXCLUDED from the baseline tools' real `pip install` only (not from
# our own agent's run, which needs no install step at all):
#   - psycopg2==2.9.9   -- fails to build from source without a system
#                          PostgreSQL dev toolchain (pg_config) present.
#                          Nothing to do with license compliance -- a
#                          real, unrelated environment/build failure
#                          that blocks pip-licenses from running on it
#                          at all. Our own agent is unaffected since it
#                          never builds/installs anything.
#   - ccnetviz-python-does-not-exist==1.0.0 -- doesn't exist, `pip
#                          install` fails outright (see above case).
LARGE_SCAN_REQUIREMENTS_TXT = """\
numpy==1.26.4
pandas==2.2.2
requests==2.31.0
flask==3.0.3
django==5.0.6
scipy==1.13.1
matplotlib==3.9.0
pillow==10.3.0
pytest==8.2.2
click==8.1.7
jinja2==3.1.4
sqlalchemy==2.0.30
boto3==1.34.128
pyyaml==6.0.1
cryptography==42.0.8
attrs==23.2.0
packaging==24.1
urllib3==2.2.2
idna==3.7
certifi==2024.6.2
charset-normalizer==3.3.2
six==1.16.0
setuptools==70.0.0
wheel==0.43.0
typing-extensions==4.12.2
cffi==1.16.0
pycparser==2.22
markupsafe==2.1.5
werkzeug==3.0.3
tornado==6.4.1
gunicorn==22.0.0
celery==5.4.0
redis==5.0.6
psycopg2==2.9.9
pymongo==4.7.3
aiohttp==3.9.5
httpx==0.27.0
fastapi==0.111.0
uvicorn==0.30.1
starlette==0.37.2
pydantic==2.7.4
tqdm==4.66.4
colorama==0.4.6
rich==13.7.1
black==24.4.2
flake8==7.1.0
mypy==1.10.0
isort==5.13.2
coverage==7.5.4
sphinx==7.3.7
docutils==0.21.2
babel==2.15.0
pyspread
python-crontab==3.2.0
ccnetviz-python-does-not-exist==1.0.0
"""

LARGE_SCAN_EXCLUDED_FROM_BASELINE_INSTALL = [
    "psycopg2==2.9.9",  # native build failure, unrelated to licensing
    "ccnetviz-python-does-not-exist==1.0.0",  # doesn't exist
]