"""Train Guardian's local semantic screening classifier on public training data.
Only the public train split selects the model and screening threshold. The public
116-row test split has already been inspected in a prior benchmark, so subsequent
measurements are disclosed as re-evaluation, not a new untouched holdout.
"""
import hashlib,json,os,sys
from pathlib import Path
import numpy as np
import pyarrow.parquet as parquet
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import confusion_matrix
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/prompt_injection'))
from app.embeddings import get_model
REVISION='4f61ecb038e9c3fb77e21034b22511b523772cdd'


def main():
    path=ROOT/'.data/production-pass/external-pi-train.parquet'
    rows=parquet.read_table(path).to_pylist()
    texts=[row['text'] for row in rows];y=np.asarray([row['label'] for row in rows])
    groups=[hashlib.sha256(' '.join(text.casefold().split()).encode()).hexdigest() for text in texts]
    model=get_model()
    if model is None:raise RuntimeError('verified embedding model unavailable')
    X=model.encode(texts,convert_to_numpy=True,normalize_embeddings=True,batch_size=32)
    splits=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=56)
    training,validation=next(splits.split(X,y,groups))
    candidates=[]
    for c in [.01,.1,1.,10.,100.]:
        classifier=LogisticRegression(C=c,class_weight='balanced',max_iter=3000,random_state=56)
        classifier.fit(X[training],y[training]);probabilities=classifier.predict_proba(X[validation])[:,1]
        for threshold in [.2,.25,.3,.35,.4,.45,.5,.55,.6,.65,.7,.75]:
            tn,fp,fn,tp=confusion_matrix(y[validation],probabilities>=threshold,labels=[0,1]).ravel()
            candidates.append((2*fn+fp,fn,fp,c,threshold,classifier,int(tp),int(tn)))
    _,fn,fp,c,threshold,classifier,tp,tn=min(candidates,key=lambda item:item[:5])
    # Refit the selected settings on the full training split, never test labels.
    classifier=LogisticRegression(C=c,class_weight='balanced',max_iter=3000,random_state=56).fit(X,y)
    artifact={'schema_version':'1.0','feature_type':'normalized_minilm_embedding','feature_count':int(X.shape[1]),
        'weights':classifier.coef_[0].tolist(),'intercept':float(classifier.intercept_[0]),'review_threshold':threshold}
    output=ROOT/'services/prompt_injection/models/semantic-classifier.json'
    output.write_text(json.dumps(artifact,allow_nan=False,separators=(',',':'))+'\n')
    metadata={'model_version':'guardian-pi-semantic-v1','model_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
        'embedding_repo':'sentence-transformers/all-MiniLM-L6-v2','embedding_revision':'1110a243fdf4706b3f48f1d95db1a4f5529b4d41',
        'dataset':'deepset/prompt-injections','dataset_revision':REVISION,'dataset_split_used':'train',
        'dataset_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'training_rows':len(rows),
        'source_attribution':'deepset, https://huggingface.co/datasets/deepset/prompt-injections',
        'license_note':'Pinned dataset card declares Apache-2.0 at top level and CC-BY-4.0 in dataset_info; preserve attribution and both declarations.',
        'validation_rows':len(validation),'group_overlap':len(set(np.asarray(groups)[training])&set(np.asarray(groups)[validation])),
        'validation_confusion':{'tp':tp,'tn':tn,'fp':int(fp),'fn':int(fn)},'selected_C':c,'review_threshold':threshold,
        'purpose':'Candidate screening for contextual judgment, not independent proof of maliciousness',
        'test_split_used_for_selection':False,'test_split_previously_observed':True}
    output.with_suffix('.metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    directory=ROOT/'evaluation/prompt_injection_external/classifier-validation';directory.mkdir(parents=True,exist_ok=True)
    (directory/'training.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps(metadata,indent=2))


if __name__=='__main__':main()
