import csv
import json
import sys
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'evaluation'))
import guardian_cli
import run_labeled_corpus as runner
from latency_benchmark import percentile

def test_nearest_rank_boundary():
    assert percentile([10,20,30,40],50)==20
    assert percentile(list(range(1,21)),95)==19
    assert percentile([1,2,3],100)==3

@pytest.mark.parametrize('decision,score,status,expected',[('accept',90,'final',0),('accept',70,'final',2),('review',100,'final',2),('reject',100,'final',3),('accept',100,'provisional',4)])
def test_cli_policy_gates(decision,score,status,expected):
    assert guardian_cli.exit_code({'recommendation':decision,'trust_score':score,'scan_status':status},80)==expected

def test_corpus_runner_preserves_labels_and_maps_final_ids(tmp_path,monkeypatch):
    (tmp_path/'artifact.py').write_text('print(1)')
    manifest=tmp_path/'manifest.csv';manifest.write_text('sample_id,path,label,artifact_type\ns1,artifact.py,human-clean,code\n')
    monkeypatch.setattr(runner,'request_json',lambda *args:{'request_id':'req1','scan_status':'provisional'})
    monkeypatch.setattr(runner,'wait_final',lambda *args:{'request_id':'req1','scan_status':'final'})
    output=tmp_path/'mapping.csv'
    assert runner.main([str(manifest),'--output',str(output)])==0
    with output.open() as f: rows=list(csv.DictReader(f))
    assert rows[0]['label']=='human-clean' and rows[0]['request_id']=='req1' and rows[0]['scan_status']=='final'

def test_manifest_missing_labels_is_rejected(tmp_path):
    path=tmp_path/'manifest.json';path.write_text(json.dumps([{'sample_id':'s','path':'x'}]))
    with pytest.raises(ValueError):runner.read_manifest(path)

@pytest.mark.parametrize('score',[float('nan'),float('inf'),True,None,-1,101])
def test_cli_rejects_invalid_scores(score):
    assert guardian_cli.exit_code({'recommendation':'accept','trust_score':score,'scan_status':'final'},80)==4


def test_project_discovery_does_not_hide_unimplemented_source_languages(tmp_path):
    for filename in ('main.rs','main.cpp','main.cs','deploy.sh','LICENSE'):(tmp_path/filename).write_text('controlled source fixture')
    found=guardian_cli.discover([tmp_path])
    assert {path.name for path in found}=={'main.rs','main.cpp','main.cs','deploy.sh','LICENSE'}
