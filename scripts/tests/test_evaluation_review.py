import importlib.util,json,hashlib
from pathlib import Path
import pytest,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
spec=importlib.util.spec_from_file_location('pilot',Path(__file__).resolve().parents[1]/'evaluate_trust_pilot.py');pilot=importlib.util.module_from_spec(spec);spec.loader.exec_module(pilot)

def manifest(tmp_path):
 artifact=tmp_path/'a.py';artifact.write_text('print(1)\n')
 rows=[{'sample_id':'one','path':'a.py','sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'label':'accept','independent_review':False}]
 path=tmp_path/'manifest.json';path.write_text(json.dumps(rows));return path,rows

def test_unreviewed_cannot_be_scored_as_reviewed_holdout(tmp_path):
 path,rows=manifest(tmp_path)
 assert len(pilot.validate_rows(path))==1
 with pytest.raises(ValueError,match='review'):pilot.validate_rows(path,True)
 rows[0].update(independent_review=True,reviewer_id='reviewer-two');path.write_text(json.dumps(rows))
 assert len(pilot.validate_rows(path,True))==1

def test_changed_artifact_fails_before_submission(tmp_path):
 path,_=manifest(tmp_path);(tmp_path/'a.py').write_text('changed')
 with pytest.raises(ValueError,match='hash'):pilot.validate_rows(path)

def test_duplicate_id_fails(tmp_path):
 path,rows=manifest(tmp_path);path.write_text(json.dumps(rows+rows))
 with pytest.raises(ValueError,match='Duplicate'):pilot.validate_rows(path)
