import importlib.util
from pathlib import Path
import pytest
spec=importlib.util.spec_from_file_location('review',Path(__file__).resolve().parents[1]/'apply_trust_label_review.py');review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)

def test_incomplete_review_cannot_be_claimed():
 with pytest.raises(ValueError):review.reviewed_manifest([{'sample_id':'a','sha256':'abc'}],[{'sample_id':'a'}])

def test_reviewed_label_is_explicit_and_preserves_original():
 rows=[{'sample_id':'a','sha256':'abc','label':'unreviewed'}]
 record={'sample_id':'a','artifact_sha256':'abc','reviewer_label':'review','review_scope':'supplied_text','review_rationale':'Needs context','reviewer_id':'human-reviewer','reviewed_date':'2026-10-18','independent_attestation':'yes'}
 result=review.reviewed_manifest(rows,[record])
 assert result[0]['independent_review'] is True and result[0]['target_trust']==65
 assert rows[0]['label']=='unreviewed'
 record['reviewer_id']='implementation-agent'
 with pytest.raises(ValueError):review.reviewed_manifest(rows,[record])
