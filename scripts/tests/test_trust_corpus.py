"""Corpus integrity checks protect labels/provenance before any training."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def test_corpus_groups_hashes_and_label_provenance():
    manifest=ROOT/'evaluation/trust_model/corpus/manifest.json'
    rows=json.loads(manifest.read_text())
    assert len(rows)==360 and len({r['sample_id'] for r in rows})==360
    groups={};hashes={}
    for row in rows:
        assert row['label'] in {'accept','review','reject'}
        assert row['rationale'] and row['provenance']=='project-authored synthetic construction'
        assert row['independent_review'] is False and row['human_reviewed'] is False
        content=(manifest.parent/row['path']).read_bytes()
        assert hashlib.sha256(content).hexdigest()==row['sha256']
        assert groups.setdefault(row['group'],row['split'])==row['split']
        assert hashes.setdefault(row['sha256'],row['split'])==row['split']
    assert {s:sum(r['split']==s for r in rows) for s in ['train','validation','test']}=={'train':180,'validation':90,'test':90}
