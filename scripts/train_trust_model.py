#!/usr/bin/env python3
"""Train and compare a constrained scorer on real final detector responses.
Synthetic pilot results do not establish independent generalization or calibration.
"""
import argparse,hashlib,json,sys,os,importlib.metadata,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/trust_engine'))
import numpy as np
from sklearn.metrics import mean_absolute_error,accuracy_score,confusion_matrix
from xgboost import XGBRegressor,DMatrix
from app.ml.vector import FEATURE_NAMES,FEATURE_VERSION,MONOTONIC_CONSTRAINTS,vector_from_event
from app.features import feature_event
from app.routing import RoutingDecision
from app.state import AgentCallRecord
from app.schemas import AgentResult
from app.fusion import fuse
from app.scorers import WeightedSumScorer

def state_from_response(response):
    decisions=[RoutingDecision(**d) for d in response['routing']['routing']]
    if len(decisions)!=1:raise ValueError('training pilot requires one artifact per request')
    records=[AgentCallRecord(file=decisions[0].filename,agent=a['agent_name'],expected=True,agent_ran=a['status'] not in {'stub','error'},status=a['status'],result=AgentResult(**a)) for a in response['detector_results']]
    return {'request_id':response['request_id'],'routing':decisions,'results':records,'files':[{}],'pending_callbacks':[],'routing_notes':response['routing'].get('routing_notes',[])}

def metrics(rows,scorer):
    preds=[];truth=[];scores=[];targets=[]
    for row in rows:
        output=fuse(row['state'].copy(),scorer=scorer)
        preds.append(output.recommendation);truth.append(row['label']);scores.append(output.trust_score);targets.append(row['target_trust'])
    return {'n':len(rows),'accuracy':float(accuracy_score(truth,preds)),'mae':float(mean_absolute_error(targets,scores)),
        'false_accepts':sum(p=='accept' and t!='accept' for p,t in zip(preds,truth)),
        'confusion_labels':['accept','review','reject'],'confusion_matrix':confusion_matrix(truth,preds,labels=['accept','review','reject']).tolist(),
        'per_type':{kind:{'n':sum(r['artifact_type']==kind for r in rows),'accuracy':float(accuracy_score([t for r,t in zip(rows,truth) if r['artifact_type']==kind],[p for r,p in zip(rows,preds) if r['artifact_type']==kind]))} for kind in sorted({r['artifact_type'] for r in rows})}}

class Learned:
    def __init__(self,model):self.model=model
    def score(self,state,total_risk):
        vector=np.asarray([vector_from_event(feature_event(state))],dtype=np.float32)
        return float(np.clip(self.model.predict(vector)[0],0,100))

def training_versions():
    versions={p:importlib.metadata.version(p) for p in ['numpy','scikit-learn','shap']}
    # Both wheels expose the xgboost import, but their distribution names differ.
    for distribution in ('xgboost-cpu','xgboost'):
        try:
            versions['xgboost']=importlib.metadata.version(distribution)
            versions['xgboost_distribution']=distribution
            return versions
        except importlib.metadata.PackageNotFoundError:
            continue
    raise importlib.metadata.PackageNotFoundError('xgboost-cpu or xgboost')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,default=ROOT/'evaluation/trust_model/corpus/manifest.json');parser.add_argument('--responses',required=True,type=Path);parser.add_argument('--output',type=Path,default=ROOT/'services/trust_engine/models');parser.add_argument('--report-dir',type=Path,default=ROOT/'evaluation/trust_model');parser.add_argument('--model-version',default='synthetic-pilot-v1');args=parser.parse_args();args.report_dir.mkdir(parents=True,exist_ok=True)
    manifest=json.loads(args.manifest.read_text());raw_rows=[json.loads(l) for l in args.responses.read_text().splitlines() if l.strip()]
    if len({r['sample_id'] for r in raw_rows})!=len(raw_rows):raise ValueError('duplicate collected sample')
    collected={r['sample_id']:r for r in raw_rows}
    responses={sid:r['response'] for sid,r in collected.items()}
    rows=[];observations=[]
    if len({r['request_id'] for r in responses.values()})!=len(responses):raise ValueError('duplicate server request IDs')
    for sample in manifest:
        if sample['sample_id'] not in responses:raise ValueError('missing response: '+sample['sample_id'])
        source=args.manifest.parent/sample['path']
        if hashlib.sha256(source.read_bytes()).hexdigest()!=sample['sha256']:raise ValueError('corpus hash changed')
        if collected[sample['sample_id']].get('artifact_sha256')!=sample['sha256']:raise ValueError('submitted artifact hash mismatch')
        response=responses[sample['sample_id']]
        if response['scan_status']!='final':raise ValueError('provisional training row')
        state=state_from_response(response)
        event=feature_event(state)
        event.pop('outcome',None);event['observation_source']='reconstructed_final_response'
        for file in event['files']:
            for observation in file['agents'].values():
                if observation is not None:observation['elapsed_ms']=None
        observations.append(event)
        rows.append({**sample,'state':state,'vector':vector_from_event(event)})
    (args.report_dir/'training-features.jsonl').write_text(''.join(json.dumps(event,allow_nan=False)+'\n' for event in observations))
    split={s:[r for r in rows if r['split']==s] for s in ['train','validation','test']}
    groups={s:{r['group'] for r in rr} for s,rr in split.items()}
    if any(groups[a]&groups[b] for a,b in [('train','test'),('train','validation'),('validation','test')]):raise ValueError('group leakage')
    train=split['train'];X=np.asarray([r['vector'] for r in train],dtype=np.float32);y=np.asarray([r['target_trust'] for r in train],dtype=np.float32)
    candidates=[]
    for depth in [2,3,4]:
        model=XGBRegressor(n_estimators=100,max_depth=depth,learning_rate=.05,objective='reg:squarederror',monotone_constraints=tuple(MONOTONIC_CONSTRAINTS),random_state=56,n_jobs=1,tree_method='hist',device='cpu',subsample=1,colsample_bytree=1)
        model.fit(X,y)
        validation=metrics(split['validation'],Learned(model));candidates.append((validation['false_accepts'],validation['mae'],depth,model,validation))
    _,_,depth,model,validation=min(candidates,key=lambda c:(c[0],c[1],c[2]))
    args.output.mkdir(parents=True,exist_ok=True);path=args.output/'guardian.json';model.save_model(path)
    metadata={'model_version':args.model_version,'feature_version':FEATURE_VERSION,'feature_names':FEATURE_NAMES,'monotonic_constraints':MONOTONIC_CONSTRAINTS,'target':'trust_score_0_100','training_scope':'project-authored synthetic pilot; no independent human review','sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),'selected_depth':depth,'seed':56,'versions':training_versions()}
    path.with_suffix('.metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    baseline=metrics(split['test'],WeightedSumScorer());test=metrics(split['test'],Learned(model))
    # Verify SHAP library agrees with exact native TreeSHAP, in trust-point output space.
    import shap
    check=np.asarray([r['vector'] for r in split['test']],dtype=np.float32)
    library=shap.TreeExplainer(model).shap_values(check)
    native=model.get_booster().predict(DMatrix(check),pred_contribs=True)
    max_difference=float(np.max(np.abs(library-native[:,:-1])))
    if max_difference>.01:raise ValueError('SHAP implementations disagree')
    monotonic_violations=0;monotonic_checks=0
    for row in check:
        for j in range(len(row)):
            if np.isnan(row[j]):continue
            monotonic_checks+=1
            increased=row.copy();increased[j]+=1
            if float(model.predict(np.asarray([increased]))[0])>float(model.predict(np.asarray([row]))[0])+1e-4:monotonic_violations+=1
    if monotonic_violations:raise ValueError('monotonicity violated')
    ablations={}
    for agent in ['cipherguard','code_security','docker_security','license_compliance','prompt_injection','secret_detection','workflow_cicd']:
        indexes=[i for i,n in enumerate(FEATURE_NAMES) if n.startswith(agent+'.')]
        altered=[]
        for row in split['test']:
            state=dict(row['state']);state['results']=[r for r in state['results'] if r.agent!=agent]
            altered.append({**row,'state':state})
        ablations[agent]=metrics(altered,Learned(model))
    report={'scope':metadata['training_scope'],'sample_count':len(rows),'split_counts':{s:len(rr) for s,rr in split.items()},'group_counts':{s:len(g) for s,g in groups.items()},'label_counts':{l:sum(r['label']==l for r in rows) for l in ['accept','review','reject']},'validation_selected':validation,'weighted_test':baseline,'xgboost_test':test,'shap_max_difference':max_difference,'monotonic_violations':monotonic_violations,'monotonic_checks':monotonic_checks,'agent_ablations_with_uncertainty_gates':ablations,'production_promoted':False,'reason_not_promoted':'Synthetic corpus authored by implementation agent; no independent review or external held-out benchmark.','test_not_used_for_selection':True}
    (args.report_dir/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['sample_count','split_counts','weighted_test','xgboost_test','shap_max_difference','monotonic_violations','production_promoted']},indent=2))
if __name__=='__main__':main()
