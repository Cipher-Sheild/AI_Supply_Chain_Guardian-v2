"""Native JSON XGBoost inference and exact TreeSHAP, without pickle loading."""
import hashlib,json,math,threading
from pathlib import Path
from app.ml.vector import FEATURE_NAMES,FEATURE_VERSION,MONOTONIC_CONSTRAINTS,vector_from_state
class Predictor:
    def __init__(self,path):
        import xgboost as xgb
        self.path=Path(path)
        self.metadata=json.loads(self.path.with_suffix('.metadata.json').read_text())
        if self.metadata.get('feature_version')!=FEATURE_VERSION or self.metadata.get('feature_names')!=FEATURE_NAMES:
            raise ValueError('model feature schema mismatch')
        if hashlib.sha256(self.path.read_bytes()).hexdigest()!=self.metadata.get('sha256'):
            raise ValueError('model checksum mismatch')
        if any(not isinstance(self.metadata.get(key),str) or not self.metadata[key].strip() for key in ('model_version','training_scope')):raise ValueError('missing model provenance')
        if self.metadata.get('monotonic_constraints')!=MONOTONIC_CONSTRAINTS:raise ValueError('missing declared monotonic constraints')
        if self.metadata.get('target')!='trust_score_0_100':raise ValueError('unsupported model target')
        self.booster=xgb.Booster();self.booster.load_model(self.path)
        self.booster.set_param({'nthread':1,'device':'cpu'})
        if self.booster.num_features()!=len(FEATURE_NAMES):raise ValueError('model feature count mismatch')
        self.lock=threading.Lock()
    def infer(self,state):
        import numpy as np
        import xgboost as xgb
        row=vector_from_state(state)
        matrix=xgb.DMatrix(np.asarray([row],dtype=np.float32),feature_names=FEATURE_NAMES)
        with self.lock:
            raw=float(self.booster.predict(matrix)[0])
            contributions=self.booster.predict(matrix,pred_contribs=True)[0]
        if not math.isfinite(raw) or not all(math.isfinite(float(v)) for v in contributions):raise ValueError('nonfinite model output')
        if abs(float(sum(contributions))-raw)>0.01:raise ValueError('SHAP additivity failed')
        grouped={agent:0.0 for agent in ('cipherguard','code_security','docker_security','license_compliance','prompt_injection','secret_detection','workflow_cicd')}
        for name,value in zip(FEATURE_NAMES,contributions[:-1]):grouped[name.split('.')[0]]+=float(value)
        return {'method':'xgboost','model_version':self.metadata['model_version'],
            'feature_version':FEATURE_VERSION,'training_scope':self.metadata['training_scope'],
            'raw_model_score':raw,'model_score':max(0.,min(100.,raw)),
            'shap':{'method':'exact TreeSHAP','output_space':'trust score points before policy gates',
                'base_value':float(contributions[-1]),'agent_contributions':grouped,
                'agent_selected':{agent:any(agent in d.expected_agents for d in state.get('routing',[])) for agent in grouped},
                'features':[{ 'feature':name,'value':None if math.isnan(value) else value,'contribution':float(contribution)} for name,value,contribution in zip(FEATURE_NAMES,row,contributions[:-1])]}}
