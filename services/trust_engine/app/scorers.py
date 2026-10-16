"""Numerical scoring seam; fusion retains authoritative policy gates."""
from typing import Protocol
import logging,math,os,threading
class Scorer(Protocol):
    def score(self,state:dict,total_risk:float)->float: ...
class WeightedSumScorer:
    def score(self,state:dict,total_risk:float)->float:
        return round(max(0.,min(100.,100.-total_risk)),2)
class ConfiguredScorer:
    def __init__(self):self._predictor=None;self._path=None;self._lock=threading.Lock()
    def load_model(self):
        from pathlib import Path
        path=os.getenv('TRUST_MODEL_PATH',str(Path(__file__).resolve().parents[1]/'models'/'guardian.json'))
        with self._lock:
            if self._predictor is None or self._path!=path:
                from app.ml.predictor import Predictor
                self._predictor=Predictor(path);self._path=path
        return self._predictor
    def score(self,state,total_risk):
        fallback=WeightedSumScorer().score(state,total_risk)
        mode=os.getenv('TRUST_SCORER','weighted')
        if mode=='weighted':return fallback
        if mode!='ml':
            state['_model_scoring']={'method':'weighted_fallback','reason':'unsupported_scorer_configuration'}
            return fallback
        try:
            self.load_model()
            detail=self._predictor.infer(state)
            state['_model_scoring']=detail
            return round(detail['model_score'],2)
        except Exception as exc:
            logging.getLogger(__name__).warning('ML unavailable; weighted fallback: %s',type(exc).__name__)
            state['_model_scoring']={'method':'weighted_fallback','reason':type(exc).__name__}
            return fallback
DEFAULT_SCORER=ConfiguredScorer()
