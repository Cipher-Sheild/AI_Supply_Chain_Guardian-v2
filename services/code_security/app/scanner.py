"""
Semgrep subprocess wrapper.

We call Semgrep as a subprocess rather than using its Python library API
directly -- this keeps our process isolated from Semgrep's internals
(easier to upgrade Semgrep independently) and matches how Semgrep is
meant to be used: as a CLI tool with a JSON output contract.

Rules are bundled locally (app/semgrep_rules/) rather than pulled from
the semgrep.dev registry at request time, so this service has no runtime
dependency on an external service being reachable.
"""

import json
import shutil
import subprocess
import signal
import importlib.util
from functools import lru_cache
import yaml
import sys
import tempfile
import os
from pathlib import Path

from app.schemas import Finding, Severity

RULES_PATH = Path(__file__).parent / "semgrep_rules" / "custom_rules.yml"


def _resolve_semgrep_binary() -> str:
    """
    subprocess inherits the parent process's PATH, which does NOT
    automatically include a venv's bin/ directory unless that venv was
    actually `activate`d in the calling shell. We look in the same
    directory as the current Python interpreter first (covers venvs and
    Docker images where semgrep is installed alongside the app), then
    fall back to whatever `semgrep` resolves to on PATH.
    """
    package=importlib.util.find_spec("semgrep")
    if package and package.origin:
        core=Path(package.origin).parent/"bin"/"semgrep-core"
        if core.is_file():return str(core)
    candidate = Path(sys.executable).parent / "pysemgrep"
    if candidate.exists():
        return str(candidate)
    candidate = Path(sys.executable).parent / "semgrep"
    if candidate.exists():
        return str(candidate)

    found = shutil.which("semgrep")
    if found:
        return found

    raise RuntimeError(
        "semgrep binary not found. Ensure it's installed in the same "
        "environment as this app (pip install semgrep)."
    )


# Semgrep's own severity scale (ERROR/WARNING/INFO) doesn't match our
# shared low/medium/high/critical/info scale used across all 8 agents.
# ERROR findings here are all currently high-impact vuln classes
# (SQLi, command injection, eval, TLS bypass), so we map them to
# "high" by default.
SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.high,
    "WARNING": Severity.medium,
    "INFO": Severity.low,
}


# Rule severity is authoritative across languages; a future prior may affect confidence only.
def apply_language_weighting(severity: Severity, language: str) -> Severity:
    return severity


# Deterministic, per-rule remediation guidance. Keyed on the bare rule
# id (not the full check_id Semgrep returns, which is prefixed with the
# rule file's module path e.g. "app.semgrep_rules.<rule-id>"). Kept as
# a fixed lookup rather than generated per-finding, since the correct
# fix for a given rule doesn't depend on the specific code that triggered
# it -- only on which vulnerability class it is.
#
# Guidance is portable and also retained in details for older consumers.
REMEDIATION_MAP = {
    "python-sql-injection-string-concat": (
        "Use parameterized queries instead of string concatenation:\n"
        "  cursor.execute(\"SELECT * FROM users WHERE name = %s\", (user_input,))\n"
        "Never build SQL by concatenating or f-string-formatting raw input."
    ),
    "python-requests-tls-verification-disabled": (
        "Remove verify=False, or pass a CA bundle path explicitly:\n"
        "  requests.get(url, verify=True)\n"
        "  requests.get(url, verify='/path/to/ca-bundle.pem')"
    ),
    "python-os-system-command-injection": (
        "Use subprocess.run() with an argument list, no shell=True:\n"
        "  subprocess.run(['ls', user_input], shell=False)\n"
        "Avoid os.system() and shell=True entirely when any part of the "
        "command may contain external input."
    ),
    "python-eval-on-input": (
        "Avoid eval()/exec() on external input entirely. If parsing "
        "structured data, use json.loads() instead. If dynamic dispatch "
        "is the actual goal, use an explicit lookup dict of allowed "
        "functions rather than executing arbitrary code."
    ),
    "python-flask-xss-render-template-string": (
        "Use render_template() with a template file (Jinja2 autoescapes "
        "by default) instead of render_template_string() with concatenated "
        "HTML:\n"
        "  return render_template('page.html', value=user_input)\n"
        "If Markup() is unavoidable, escape the value first: "
        "Markup.escape(user_input)."
    ),
    "python-insecure-deserialization-pickle": (
        "Avoid unpickling data from any source you don't fully trust. "
        "Use a safe serialization format instead:\n"
        "  import json\n"
        "  data = json.loads(raw_bytes)\n"
        "If pickle is required, ensure the data source is authenticated "
        "and cannot be influenced by external input."
    ),
    "python-insecure-yaml-load": (
        "Use yaml.safe_load() instead of yaml.load():\n"
        "  data = yaml.safe_load(raw_yaml)\n"
        "If yaml.load() is required for a specific reason, pass "
        "Loader=yaml.SafeLoader explicitly."
    ),
    "python-ssrf-requests-user-controlled-url": (
        "Validate/allowlist the target host before making the request:\n"
        "  if urlparse(url).hostname not in ALLOWED_HOSTS:\n"
        "      raise ValueError('host not allowed')\n"
        "Never construct request URLs directly from unvalidated external input."
    ),
    "python-plaintext-password-comparison": (
        "Use a password hashing library's verify function instead of ==:\n"
        "  import bcrypt\n"
        "  bcrypt.checkpw(input_password.encode(), stored_hash)\n"
        "Never compare passwords directly, even if one side is hashed."
    ),
    "python-weak-password-hashing": (
        "Use a dedicated password-hashing function, not MD5/SHA1:\n"
        "  from werkzeug.security import generate_password_hash\n"
        "  hashed = generate_password_hash(password)\n"
        "MD5/SHA1 are too fast and lack salting for password storage."
    ),
    "js-sql-injection-string-concat": (
        "Use parameterized queries instead of string concatenation:\n"
        "  connection.query('SELECT * FROM users WHERE id = ?', [userId])\n"
        "Never build SQL by concatenating or template-literal-formatting raw input."
    ),
    "js-insecure-tls-verification-disabled": (
        "Remove rejectUnauthorized: false, or set it to true:\n"
        "  axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: true }) })"
    ),
    "js-command-injection": (
        "Use execFile() or spawn() with an argument array, not exec() with a string:\n"
        "  child_process.execFile('ls', [userInput])\n"
        "Avoid exec() entirely when any part of the command may contain external input."
    ),
    "js-eval-on-input": (
        "Avoid eval()/Function() on external input entirely. If parsing "
        "structured data, use JSON.parse() instead."
    ),
    "js-xss-dangerous-html": (
        "Use textContent for plain text, or sanitize with DOMPurify if HTML is required:\n"
        "  element.textContent = userInput;\n"
        "  // or: element.innerHTML = DOMPurify.sanitize(userInput);"
    ),
    "js-insecure-deserialization": (
        "Avoid node-serialize's unserialize() entirely -- it is a known RCE vector. "
        "Use JSON.parse() for structured data instead."
    ),
    "js-ssrf-user-controlled-url": (
        "Validate/allowlist the target host before making the request:\n"
        "  const { hostname } = new URL(url);\n"
        "  if (!ALLOWED_HOSTS.includes(hostname)) throw new Error('host not allowed');"
    ),
    "js-plaintext-password-comparison": (
        "Use a password hashing library's compare function instead of ===:\n"
        "  const bcrypt = require('bcrypt');\n"
        "  await bcrypt.compare(inputPassword, storedHash);"
    ),
    "js-weak-password-hashing": (
        "Use bcrypt, scrypt, or argon2 instead of MD5/SHA1:\n"
        "  const bcrypt = require('bcrypt');\n"
        "  const hash = await bcrypt.hash(password, 10);"
    ),
    "php-sql-injection-string-concat": (
        "Use prepared statements instead of string concatenation:\n"
        "  $stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');\n"
        "  $stmt->execute([$username]);"
    ),
    "php-insecure-tls-verification-disabled": (
        "Remove CURLOPT_SSL_VERIFYPEER, false, or set it to true:\n"
        "  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);"
    ),
    "php-command-injection": (
        "Escape each argument, or avoid shelling out entirely:\n"
        "  shell_exec('ls ' . escapeshellarg($userInput));"
    ),
    "php-eval-on-input": (
        "Avoid eval() on external input entirely. If parsing structured "
        "data, use json_decode() instead."
    ),
    "php-xss-unescaped-echo": (
        "Escape before output:\n"
        "  echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');"
    ),
    "php-insecure-deserialization": (
        "Use json_decode() for structured data instead of unserialize() "
        "on untrusted input."
    ),
    "php-ssrf-curl-user-controlled-url": (
        "Validate/allowlist the target host before making the request:\n"
        "  $host = parse_url($url, PHP_URL_HOST);\n"
        "  if (!in_array($host, $allowedHosts)) { throw new Exception('host not allowed'); }"
    ),
    "php-plaintext-password-comparison": (
        "Use password_verify() instead of ==/===:\n"
        "  if (password_verify($inputPassword, $storedHash)) { ... }"
    ),
    "php-weak-password-hashing": (
        "Use password_hash() instead of md5()/sha1():\n"
        "  $hash = password_hash($password, PASSWORD_BCRYPT);"
    ),
    "java-sql-injection-string-concat": (
        "Use PreparedStatement with bound parameters:\n"
        "  PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\");\n"
        "  stmt.setString(1, username);"
    ),
    "java-insecure-tls-verification-disabled": (
        "Remove ALLOW_ALL_HOSTNAME_VERIFIER; use the default strict verifier instead."
    ),
    "java-command-injection": (
        "Use the array-argument overload or ProcessBuilder with separate arguments:\n"
        "  new ProcessBuilder(\"ls\", userInput).start();"
    ),
    "java-scriptengine-eval-on-input": (
        "Avoid ScriptEngine.eval() on external input entirely."
    ),
    "java-xss-unescaped-response-write": (
        "Escape output before writing to the response, e.g. with OWASP Java Encoder:\n"
        "  writer.print(Encode.forHtml(request.getParameter(\"name\")));"
    ),
    "java-insecure-deserialization": (
        "Avoid deserializing untrusted data. Use a safe format like JSON instead "
        "(e.g. Jackson's ObjectMapper)."
    ),
    "java-ssrf-user-controlled-url": (
        "Validate/allowlist the target host before connecting:\n"
        "  if (!ALLOWED_HOSTS.contains(new URL(url).getHost())) { throw new SecurityException(); }"
    ),
    "java-plaintext-password-comparison": (
        "Use a password hashing library's verify function instead of .equals():\n"
        "  BCrypt.checkpw(inputPassword, storedHash);"
    ),
    "java-weak-password-hashing": (
        "Use BCrypt, SCrypt, or Argon2 instead of MD5/SHA-1:\n"
        "  String hash = BCrypt.hashpw(password, BCrypt.gensalt());"
    ),
}


def _bare_rule_id(check_id: str) -> str:
    """
    Semgrep's check_id is prefixed with the rule file's module path
    (e.g. "app.semgrep_rules.python-sql-injection-string-concat") when
    pointed at a local file rather than a registry rule. We only want
    the actual rule id for the remediation lookup.
    """
    return check_id.rsplit(".", 1)[-1]


EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".php": "php",
    ".java": "java",
}


def infer_language(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return EXTENSION_LANGUAGE_MAP.get(ext, "python")



class ScanFindings(list):
    partial=False

@lru_cache(maxsize=1)
def _rule_severities():
    rules=yaml.safe_load(RULES_PATH.read_text())["rules"]
    return {rule["id"]:rule["severity"] for rule in rules}

def _run_bounded(command, *, cwd, timeout):
    """Kill the scanner process group on timeout, including native workers."""
    process=subprocess.Popen(command,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        stdout,stderr=process.communicate(timeout=timeout)
    except BaseException:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(command,process.returncode,stdout,stderr)

def run_semgrep(content: str, filename: str, timeout_seconds: float | None = None) -> list[Finding]:
    """
    Writes `content` to a temp file (preserving the original extension so
    Semgrep can detect the language correctly), runs the bundled rule set
    against it, and maps the JSON output into our Finding schema.
    """
    suffix = Path(filename).suffix or ".py"
    language = infer_language(filename)

    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        binary=_resolve_semgrep_binary()
        if Path(binary).name == "semgrep-core":
            # Pinned local OSS core avoids CLI auth/metadata startup per snippet.
            command=[binary,"-rules",str(RULES_PATH),"-lang",language,"-j","1","-json_nodots","-timeout","5","-max_memory","256",tmp_path]
        else:
            command=[binary,"--config",str(RULES_PATH),"--json","--jobs","1","--quiet","--metrics=off","--disable-version-check","--no-git-ignore",tmp_path]
        result = _run_bounded(command,cwd=str(Path(tmp_path).parent),
            timeout=timeout_seconds if timeout_seconds is not None else min(7.5,float(os.getenv("SEMGREP_TIMEOUT_SECONDS","7.5"))))

        if not result.stdout:
            raise RuntimeError(f"Semgrep produced no output. stderr: {result.stderr}")

        if result.returncode != 0:
            raise RuntimeError(f"Semgrep engine exited with code {result.returncode}")
        payload = json.loads(result.stdout)

        # Semgrep exits 0 even with partial rule/parse failures, so errors
        # must be checked explicitly. But PartialParsing at warn level is NOT
        # a crash -- it's the normal case for AI-generated fragments, which
        # are often incomplete by the time we intercept them. Semgrep still
        # returns findings for the portion it parsed, so we keep those and
        # only treat genuine error-level failures as a scanner crash.
        fatal = [
            e for e in payload.get("errors", [])
            if e.get("level", e.get("severity")) not in ("warn", "warning")
        ]
        if fatal:
            raise RuntimeError(f"Semgrep reported errors: {fatal}")

        findings = ScanFindings()
        findings.partial = bool(payload.get("errors") or payload.get("skipped_rules"))
        for r in payload.get("results", []):
            semgrep_severity = r.get("extra", {}).get("severity") or _rule_severities().get(_bare_rule_id(r.get("check_id", "")), "WARNING")
            metadata = r.get("extra", {}).get("metadata", {})
            check_id = r.get("check_id", "")
            bare_id = _bare_rule_id(check_id)

            base_severity = SEMGREP_SEVERITY_MAP.get(semgrep_severity, Severity.medium)
            weighted_severity = apply_language_weighting(base_severity, language)

            findings.append(
                Finding(
                    category=metadata.get("category", "code_security"),
                    severity=weighted_severity,
                    confidence=0.85,  # static-rule matches are deterministic, not probabilistic
                    location=f"{filename}:{r['start']['line']}",
                    reason=r.get("extra", {}).get("message", "").strip(),
                    remediation=REMEDIATION_MAP.get(bare_id),
                    details={
                        "message": r.get("extra", {}).get("message", "").strip(),
                        "remediation": REMEDIATION_MAP.get(bare_id),
                        "rule_id": check_id,
                        "cwe": metadata.get("cwe"),
                        "end_line": r.get("end", {}).get("line"),
                        "language": language,
                        # Recorded so a de-escalated finding stays explainable
                        # rather than looking like the rule fired at a lower
                        # severity than it declares.
                        "base_severity": base_severity.value,
                        "language_weighted": weighted_severity is not base_severity,
                    },
                )
            )
        return findings

    finally:
        os.unlink(tmp_path)


def determine_status(findings: list[Finding]) -> str:
    """
    Maps our finding list to trust_engine's shared status vocabulary
    (pass/warn/fail/stub). Semgrep running successfully with zero
    findings is a clean "pass"; findings of high/critical severity are
    treated as "fail" so trust_engine weighs them accordingly; anything
    lower is a "warn".

    Actual scan errors are status="error" in main.py; this function
    receives findings only from a completed scan.
    """
    if not findings:
        return "pass"
    if any(f.severity in (Severity.high, Severity.critical) for f in findings):
        return "fail"
    return "warn"