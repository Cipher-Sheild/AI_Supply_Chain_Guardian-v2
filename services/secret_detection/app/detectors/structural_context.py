import re
from typing import Generator, Dict, Any

class StructuralContextDetector:
    def __init__(self):
        # Match standard connection strings: scheme://user:password@host...
        # Extract the password group.
        self.conn_string_pattern = re.compile(
            r'[a-zA-Z][a-zA-Z0-9\+\-\.]*://[^:\s]+:(?P<password>.+)@[^@\s]+'
        )

        # Match suspicious assignments: KEYWORD = "VALUE"
        # Handles JSON/YAML colons as well: "KEYWORD": "VALUE"
        self.suspicious_keywords = [
            "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "API_KEY",
            "PRIVATE", "CREDENTIAL", "AUTH", "CONN_STR", "_URL"
        ]
        
        # Regex to capture keyword and value. Matches:
        # key = "value"
        # key: "value"
        # "key": "value"
        # Let's use a simpler heuristic for string literals.
        self.assignment_pattern = re.compile(
            r'''(?P<key>[a-zA-Z0-9_'"\-]+)\s*[:=]\s*(?P<quote>['"])(?P<value>.+?)(?P=quote)'''
        )
        
        self.unquoted_assignment = re.compile(r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*[:=]\s*(?P<value>[^\s#\"']+)\s*(?:#.*)?$", re.MULTILINE)

    def _is_suspicious_key(self, key: str) -> bool:
        key_upper = key.upper().strip("'\"")
        # Direct matches or substring
        for kw in self.suspicious_keywords:
            if kw in key_upper or key_upper.startswith('DB_'):
                return True
        return False

    def scan(self, text: str, file_path: str) -> Generator[Dict[str, Any], None, None]:
        # 1. Connection strings
        for match in self.conn_string_pattern.finditer(text):
            secret_val = match.group('password')
            start_idx = match.start('password')
            line_number = text.count('\n', 0, start_idx) + 1
            
            yield {
                "detector_id": "structural:connection_string",
                "file_path": file_path,
                "line_number": line_number,
                "secret_value": secret_val,
                "confidence_boost": 60.0,
                "rule_description": "Embedded credential in connection string",
                "match_context": "connection_string"
            }

        # 2. Keyword=Value assignments
        for match in self.assignment_pattern.finditer(text):
            key = match.group('key')
            if self._is_suspicious_key(key):
                secret_val = match.group('value')
                start_idx = match.start('value')
                line_number = text.count('\n', 0, start_idx) + 1
                
                clean_key = key.strip('"\'')
                yield {
                    "detector_id": "structural:keyword_assignment",
                    "file_path": file_path,
                    "line_number": line_number,
                    "secret_value": secret_val,
                    "confidence_boost": 40.0, # Will be boosted by entropy layer
                    "rule_description": f"Suspicious identifier '{clean_key}' assigned to string literal",
                    "match_context": "keyword_assignment"
                }

        # Environment files and unquoted YAML scalar assignments.
        for match in self.unquoted_assignment.finditer(text):
            if not self._is_suspicious_key(match.group("key")): continue
            value=match.group("value")
            if value.startswith(("${", "$", "os.environ", "process.env")) or value.lower() in {"null","none","true","false"}: continue
            yield {"detector_id":"structural:keyword_assignment", "file_path":file_path,
                "line_number":text.count("\n",0,match.start("value"))+1, "secret_value":value,
                "confidence_boost":40., "rule_description":"Credential assigned to an unquoted scalar", "match_context":"keyword_assignment"}
