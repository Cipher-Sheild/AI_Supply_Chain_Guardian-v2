"""Mask credential-shaped values in returned evidence; retain field structure.
This is output hygiene, not an alternative detector or proof of no secrets.
"""
import re
_URI=re.compile(r'([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@]+)(@)',re.I)
_CREDENTIAL_NAME=r'(?=[A-Za-z_])[A-Za-z0-9_-]{0,64}(?:password|passwd|pwd|api[_-]?key|secret|token|access[_-]?token|auth[_-]?token|private[_-]?key)[A-Za-z0-9_-]{0,64}'
_ASSIGN=re.compile(r'''(\b'''+_CREDENTIAL_NAME+r'''["']?\s*[:=]\s*)(["']?)([^\s"'`,;]+)(["']?)''',re.I)
_BEARER=re.compile(r'''(\b(?:authorization|proxy-authorization)\s*[:=]\s*["']?(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{8,})''',re.I)
_PRIVATE_KEY=re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----',re.S)
_VENDOR=re.compile(r'\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{35}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{36,}|pypi-[A-Za-z0-9_-]{150,}|xox[baprs]-[A-Za-z0-9-]{20,})\b')
_KEYS=re.compile(r'^(?:'+_CREDENTIAL_NAME+r'|authorization|proxy-authorization|cookie|set-cookie)$',re.I)

def redact_text(value):
    value=_PRIVATE_KEY.sub('[REDACTED PRIVATE KEY]',value)
    value=_BEARER.sub(lambda m:m.group(1)+'[REDACTED]',value)
    value=_URI.sub(lambda m:m.group(1)+'[REDACTED]'+m.group(3),value)
    value=_ASSIGN.sub(lambda m:m.group(1)+m.group(2)+'[REDACTED]'+m.group(4),value)
    return _VENDOR.sub('[REDACTED]',value)

def redact(value):
    if isinstance(value,str):return redact_text(value)
    if isinstance(value,list):return [redact(v) for v in value]
    if isinstance(value,dict):return {k:('[REDACTED]' if _KEYS.match(str(k)) and isinstance(v,str) else redact(v)) for k,v in value.items()}
    return value
