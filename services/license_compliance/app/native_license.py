"""Conservative license text matching against pinned SPDX data, not a scanner wrapper.

Whitespace and one-line copyright notices can vary. Modified clauses and unknown
texts stay unknown; this does not infer licenses from a project name or heading.
"""
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

ROOT=Path(__file__).parent/'data/spdx'


def normalize(text):
    # Only an isolated attribution may vary. Never discard arbitrary clauses
    # just because they begin with the word "copyright".
    notice = re.compile(r'^\s*copyright\s*(?:\(c\)\s*)?(?:<year>|\d{4}(?:\s*[-,]\s*\d{4})*)\s+[^\n]{1,120}$', re.I)
    obligation = re.compile(r'\b(?:must|shall|may|only|prohibit\w*|forbid\w*|restrict\w*|commercial|noncommercial|permission|condition\w*|require\w*|redistribut\w*|distribut\w*|reproduc\w*|derivative\w*|provided|unless|fee|pay|use)\b', re.I)
    lines=[line for line in text.splitlines() if not (notice.fullmatch(line) and not obligation.search(line))]
    return re.sub(r'\s+',' ','\n'.join(lines)).strip().casefold()


@lru_cache(maxsize=1)
def templates():
    manifest=json.loads((ROOT/'manifest.json').read_text())
    result={}
    for license_id,entry in manifest['files'].items():
        raw=(ROOT/f'{license_id}.txt').read_bytes()
        if hashlib.sha256(raw).hexdigest()!=entry['sha256']:
            raise ValueError('SPDX data checksum mismatch')
        result[license_id]=normalize(raw.decode('utf-8'))
    return result


@lru_cache(maxsize=1)
def template_index():
    result={}
    for identifier,canonical in templates().items():
        result.setdefault(canonical,[]).append(identifier)
    return result


def identify_text(text):
    if not text or not text.strip():return [],None,0.0,['No license text available.']
    normalized=normalize(text)
    try:
        matches=template_index().get(normalized,[])
    except (OSError,ValueError):
        return [],None,0.0,['Pinned license data unavailable or invalid.']
    if len(matches)!=1:
        return [],None,0.0,['License text does not exactly match a supported canonical license; review required.']
    return matches,None,0.9,[]
