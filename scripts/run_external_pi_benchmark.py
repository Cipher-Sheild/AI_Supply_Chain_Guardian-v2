"""Measure PI on deepset's pinned public test split, without changing labels/rules.
Direct prompts are embedded as README prose; this is a scoped external check,
not proof of full supply-chain generalization or unseen LLM training data.
"""
import argparse,hashlib,json,os,time
from pathlib import Path
from urllib.request import urlopen
from guardian_cli import deployment_config
from guardian_http import request_json,wait_final
ROOT=Path(__file__).resolve().parents[1]
REVISION='4f61ecb038e9c3fb77e21034b22511b523772cdd'
FILENAME='data/test-00000-of-00001-701d16158af87368.parquet'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',default='https://localhost:3343/api')
    parser.add_argument('--config',type=Path,default=ROOT/'.data/production-pass/compose.env')
    parser.add_argument('--ca-file',type=Path,default=ROOT/'.data/production-pass/tls/server.crt')
    parser.add_argument('--output',type=Path,default=ROOT/'evaluation/prompt_injection_external/results.json')
    parser.add_argument('--pace-seconds',type=float,default=0)
    args=parser.parse_args();deployment_config(args.config)
    if args.pace_seconds<0:parser.error('pace-seconds must be nonnegative')
    os.environ['GUARDIAN_CA_FILE']=str(args.ca_file.resolve())
    url=f'https://huggingface.co/datasets/deepset/prompt-injections/resolve/{REVISION}/{FILENAME}'
    with urlopen(url,timeout=30) as response:raw=response.read(10*1024*1024+1)
    if len(raw)>10*1024*1024:raise ValueError('dataset exceeds download budget')
    path=ROOT/'.data/production-pass/external-pi-test.parquet';path.write_bytes(raw)
    import pyarrow.parquet as parquet
    rows=parquet.read_table(path).to_pylist();results=[]
    for index,row in enumerate(rows):
        text=row['text'];label=int(row['label'])
        if label not in {0,1} or not isinstance(text,str):raise ValueError('invalid dataset row')
        response=wait_final(args.url,request_json(args.url+'/analyze',{'filename':'README.md','content':text}),180)
        detector=next(agent for agent in response['detector_results'] if agent['agent_name']=='prompt_injection')
        unknown=bool(detector['unresolved']) or detector['coverage']!='full'
        detected=bool(detector['findings'])
        results.append({'dataset_row':index,'source_text_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'label':label,'detected':detected,'unknown':unknown,'recommendation':response['recommendation'],
            'request_id':response['request_id'],'pi_status':detector['status'],
            'confirmed':any(item['category']=='prompt_injection' for item in detector['findings']),
            'requires_context_review':any(item['category']=='prompt_injection_uncertain' for item in detector['findings']),
            'llm_escalations':detector['evidence'].get('escalated_to_llm',0)})
        args.output.parent.mkdir(parents=True,exist_ok=True)
        # Save progress in the private runtime directory; final report comes below.
        (ROOT/'.data/production-pass/external-pi-progress.json').write_text(json.dumps(results)+'\n')
        if args.pace_seconds:time.sleep(args.pace_seconds)
        if (index+1)%20==0:print(f'External PI {index+1}/{len(rows)}',flush=True)
    known=[row for row in results if not row['unknown']]
    tp=sum(row['label']==1 and row['detected'] for row in known)
    fp=sum(row['label']==0 and row['detected'] for row in known)
    fn=sum(row['label']==1 and not row['detected'] for row in known)
    tn=sum(row['label']==0 and not row['detected'] for row in known)
    report={'source':'deepset/prompt-injections','source_url':url,'revision':REVISION,'split':'test','license':'CC-BY-4.0',
        'attribution':'deepset, prompt-injections dataset, https://huggingface.co/datasets/deepset/prompt-injections',
        'dataset_file_sha256':hashlib.sha256(raw).hexdigest(),'project_training_used_this_split':False,
        'test_split_previously_observed':True,'evaluation_role':'Re-evaluation after independent training-split model selection; not a new untouched holdout',
        'confirmed_attacks':sum(row['label']==1 and row['confirmed'] for row in results),
        'attack_rows_requiring_context_review':sum(row['label']==1 and row['requires_context_review'] for row in results),
        'scope':'Public direct prompts submitted as README prose; no full-chain generalization claim. LLM pretraining overlap is unknown.',
        'provider':'groq','model':'openai/gpt-oss-20b','samples':len(results),'known':len(known),'unknown':len(results)-len(known),
        'tp':tp,'fp':fp,'fn':fn,'tn':tn,'accuracy_known':(tp+tn)/len(known) if known else None,
        'recall_known':tp/(tp+fn) if tp+fn else None,'false_positive_rate_known':fp/(fp+tn) if fp+tn else None,
        'false_accepts':sum(row['label']==1 and row['recommendation']=='accept' for row in results),'rows':results}
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key!='rows'},indent=2))


if __name__=='__main__':main()
