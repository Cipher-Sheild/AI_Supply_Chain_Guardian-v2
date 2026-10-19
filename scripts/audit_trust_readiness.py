#!/usr/bin/env python3
"""Re-evaluate an already reviewed cohort; never relabel it or train on it."""
import argparse, hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'services/trust_engine'))
from guardian_cli import deployment_config
from guardian_http import request_json, wait_final
from train_trust_model import state_from_response, Learned, metrics
from app.fusion import fuse
from app.scorers import WeightedSumScorer
from xgboost import XGBRegressor

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 args.output.mkdir(parents=True,exist_ok=True)
 manifest=json.loads((ROOT/'evaluation/trust_model/v3/external/human-reviewed-manifest-20261018.json').read_text())
 model=XGBRegressor();model.load_model(ROOT/'evaluation/trust_model/v4-clean-patterns/models/guardian.json')
 deployment_config(Path('/home/cipher/.config/guardian/demo-client.env'))
 rows=[];details=[]
 for sample in manifest:
  source=Path(sample['path']);content=source.read_bytes()
  if hashlib.sha256(content).hexdigest()!=sample['sha256']:raise ValueError('Changed source: '+sample['sample_id'])
  response=wait_final('http://127.0.0.1:18808',request_json('http://127.0.0.1:18808/analyze',{'filename':'readiness_audit/'+sample['sample_id']+'/'+sample['filename'],'content':content.decode()}),180)
  with (args.output/'fresh-responses.jsonl').open('a') as f:f.write(json.dumps({'sample_id':sample['sample_id'],'artifact_sha256':sample['sha256'],'response':response})+'\n')
  state=state_from_response(response);row={**sample,'artifact_type':source.suffix or 'license','state':state};rows.append(row)
  weighted=fuse(state.copy(),scorer=WeightedSumScorer());ml=fuse(state.copy(),scorer=Learned(model))
  raw=Learned(model).score(state,0)
  # A perfect raw score still cannot bypass deterministic safety gates.
  class OracleScore:
   def score(self,state,total_risk):return float(sample['target_trust'])
  gated=fuse(state.copy(),scorer=OracleScore())
  item={'sample_id':sample['sample_id'],'label':sample['label'],'weighted':weighted.recommendation,'ml':ml.recommendation,'ml_score':ml.trust_score,'raw_ml_score':raw,'target_score_with_gates':gated.recommendation,'label_blocked_even_with_target_score':gated.recommendation!=sample['label'],'detectors':[{'agent':a['agent_name'],'status':a['status'],'coverage':a['coverage'],'decision_floor':a.get('decision_floor'),'findings':[{'severity':v['severity'],'title':v.get('title'),'category':v.get('category'),'hard_block':v.get('hard_block')} for v in a['findings']]} for a in response['detector_results']]}
  details.append(item);print(json.dumps({k:v for k,v in item.items() if k!='detectors'}),flush=True)
 report={'scope':'Previously inspected project-team reviewed ten-file cohort. Fresh detector replay, not an independent holdout. No training or relabelling. Same detector evidence used for both scorers.','weighted':metrics(rows,WeightedSumScorer()),'ml_v4':metrics(rows,Learned(model)),'blocked_by_gates':sum(x['label_blocked_even_with_target_score'] for x in details),'production_promoted':False,'details':details}
 (args.output/'results.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
