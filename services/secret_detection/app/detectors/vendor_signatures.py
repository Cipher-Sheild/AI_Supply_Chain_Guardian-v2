import json
import os
import re
from typing import List, Dict, Any, Generator

RULES_PATH = os.path.join(os.path.dirname(__file__), '..', 'rules', 'vendor_patterns.json')

class VendorSignatureDetector:
    def __init__(self, rules_path: str = RULES_PATH):
        self.rules = self._load_rules(rules_path)
        self.compiled_rules = self._compile_rules()

    def _load_rules(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            return {}
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _compile_rules(self) -> Dict[str, re.Pattern]:
        compiled = {}
        for rule_id, rule_data in self.rules.items():
            flags = 0
            if "DOTALL" in rule_data.get("flags", []):
                flags |= re.DOTALL
            compiled[rule_id] = re.compile(rule_data["pattern"], flags)
        return compiled

    def scan(self, text: str, file_path: str) -> Generator[Dict[str, Any], None, None]:
        for rule_id, pattern in self.compiled_rules.items():
            for match in pattern.finditer(text):
                # Identify if there is a named group 'secret', else use whole match
                if 'secret' in pattern.groupindex:
                    secret_val = match.group('secret')
                    # Recalculate start for correct line number if needed, but for simplicity
                    # we just take the line of the overall match start
                    start_idx = match.start('secret')
                else:
                    secret_val = match.group(0)
                    start_idx = match.start()
                
                # AWS Access keys context check
                if rule_id == "aws_access_key":
                    prefixes = self.rules[rule_id].get("prefix_context", [])
                    if prefixes and not any(secret_val.startswith(p) for p in prefixes):
                        continue

                line_number = text.count('\n', 0, start_idx) + 1
                
                yield {
                    "detector_id": f"vendor_signature:{rule_id}",
                    "file_path": file_path,
                    "line_number": line_number,
                    "secret_value": secret_val, # Will be redacted later
                    "confidence_boost": 95.0, # High confidence for vendor signatures
                    "rule_description": self.rules[rule_id]["description"],
                    "match_context": "vendor_regex"
                }
