"""Guardian-owned linear screening inference; JSON weights, no pickle or SDK.
The score identifies spans needing contextual assessment, not proof of an attack.
"""
import hashlib,json,math,os,threading
from pathlib import Path

class ClassifierUnavailable(ValueError):pass
_lock=threading.Lock();_model=None;_path=None


def load():
    global _model,_path
    path=Path(os.getenv('PROMPT_CLASSIFIER_PATH',str(Path(__file__).resolve().parents[1]/'models/semantic-classifier.json')))
    with _lock:
        if _model is not None and _path==path:return _model
        try:
            if path.stat().st_size>1048576:raise ValueError('classifier file budget exceeded')
            raw=path.read_bytes();data=json.loads(raw)
            metadata=json.loads(path.with_suffix('.metadata.json').read_text())
            if metadata['model_sha256']!=hashlib.sha256(raw).hexdigest():raise ValueError('classifier checksum mismatch')
            if metadata['embedding_revision']!=os.getenv('EMBEDDING_MODEL_REVISION','1110a243fdf4706b3f48f1d95db1a4f5529b4d41'):raise ValueError('classifier embedding revision mismatch')
            if data.get('schema_version')!='1.0' or data.get('feature_type')!='normalized_minilm_embedding' or data.get('feature_count')!=384:raise ValueError('classifier feature schema mismatch')
            weights=data['weights'];intercept=data['intercept'];threshold=data['review_threshold']
            if len(weights)!=384 or any(isinstance(value,bool) or not isinstance(value,(float,int)) or not math.isfinite(value) for value in [*weights,intercept,threshold]):raise ValueError('classifier coefficients invalid')
            if not 0<threshold<1:raise ValueError('classifier threshold invalid')
            _model=data;_path=path;return data
        except (OSError,ValueError,KeyError,TypeError) as error:
            raise ClassifierUnavailable('semantic classifier is unavailable or invalid') from error


def score_vectors(vectors):
    import numpy as np
    data=load();rows=np.asarray(vectors,dtype=float)
    if rows.ndim!=2 or rows.shape[1]!=384 or not np.isfinite(rows).all():raise ClassifierUnavailable('invalid semantic feature matrix')
    norms=np.linalg.norm(rows,axis=1,keepdims=True)
    normalized=rows/np.maximum(norms,1e-12)
    values=np.clip(normalized@np.asarray(data['weights'])+data['intercept'],-40,40)
    return (1/(1+np.exp(-values))).tolist()


def batch_probabilities(texts):
    if os.getenv('PROMPT_CLASSIFIER_ENABLED','true').lower()!='true':return [0.0]*len(texts)
    if not texts:return []
    from app.embeddings import get_model,_chunk_text
    model=get_model()
    if model is None:raise ClassifierUnavailable('verified embedding model unavailable')
    chunks=[];owners=[]
    for index,text in enumerate(texts):
        for chunk in _chunk_text(text):chunks.append(chunk);owners.append(index)
    vectors=model.encode(chunks,convert_to_numpy=True,batch_size=32)
    scores=score_vectors(vectors);result=[0.0]*len(texts)
    for owner,score in zip(owners,scores):result[owner]=max(result[owner],score)
    return result


def threshold():
    return load()['review_threshold'] if os.getenv('PROMPT_CLASSIFIER_ENABLED','true').lower()=='true' else 1.0
