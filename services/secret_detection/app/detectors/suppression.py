import re
import json
import os
from typing import Dict, Any, Tuple

RULES_PATH = os.path.join(os.path.dirname(__file__), '..', 'rules', 'allowlist.json')

class SuppressionFilter:
    def __init__(self, allowlist_path: str = RULES_PATH):
        self.allowlist = self._load_allowlist(allowlist_path)
        self.placeholders = [
            'example', 'test', 'dummy', 'changeme', 'xxxx', 'your_', 
            'placeholder', 'redacted', 'sample', 'fake'
        ]
        
        # specific nuanced examples
        self.known_public_examples = [
            'AKIAIOSFODNN7EXAMPLE'
        ]

    def _load_allowlist(self, path: str) -> Dict[str, list]:
        if not os.path.exists(path):
            return {"allowed_secrets": [], "allowed_paths": []}
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def evaluate(self, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Returns (is_suppressed, modified_finding)
        """
        secret_val = finding['secret_value']
        
        # 1. Allowlist by value
        if secret_val in self.allowlist.get("allowed_secrets", []):
            return True, finding
            
        # 2. Allowlist by path
        file_path = finding['file_path']
        if finding.get('match_context') not in {'vendor_regex','keyword_assignment','connection_string'} and any(file_path.endswith(p) for p in self.allowlist.get("allowed_paths", [])):
            return True, finding

        # 3. Min Length
        if len(secret_val) < 8 and finding.get("match_context") not in {"vendor_regex", "keyword_assignment", "connection_string"}:
            return True, finding

        # 4. Known public examples nuance
        if secret_val in self.known_public_examples:
            # Do NOT suppress. Downgrade confidence/severity.
            finding["confidence_boost"] = min(finding.get("confidence_boost", 0.0), 30.0)
            finding["is_public_example"] = True
            return False, finding

        # 5. URLs without embedded credentials
        if (secret_val.startswith('http://') or secret_val.startswith('https://')) and '@' not in secret_val:
            return True, finding

        if re.fullmatch(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*", secret_val):
            return True, finding

        # 6. Placeholders (case insensitive)
        secret_lower = secret_val.lower()
        if finding.get("match_context") != "vendor_regex" and (secret_lower in {"changeme", "redacted", "placeholder", "dummy", "this_is_a_test_password"} or re.fullmatch(r"x{3,}|your[_-].*|(?:test|example|sample|dummy|fake)[_-](?:key|token|password|secret)(?:[_-].*)?", secret_lower)):
            # If it's a structural assignment with a generic placeholder, it's a false positive
            return True, finding

        return False, finding
