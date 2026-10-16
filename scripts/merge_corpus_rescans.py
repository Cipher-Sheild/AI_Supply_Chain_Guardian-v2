#!/usr/bin/env python3
"""Replace explicitly recollected samples; preserve labels and submitted hashes."""
import argparse,csv,json
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,default=Path('docs/final-validation'));p.add_argument('--manifest',type=Path,default=Path('evaluation/trust_model/corpus/manifest.json'));a=p.parse_args()
    manifest=json.loads(a.manifest.read_text());expected={r['sample_id']:r for r in manifest};rows={};mappings={}
    for prefix in ['corpus','workflow-corrected','markdown-corrected']:
        response=a.directory/(prefix+'-responses.jsonl' if prefix=='corpus' else prefix+'.jsonl')
        mapping=a.directory/('corpus-mapping.csv' if prefix=='corpus' else prefix+'.csv')
        if not response.exists() or not mapping.exists():raise ValueError('missing collection '+prefix)
        for line in response.read_text().splitlines():
            if line.strip():
                row=json.loads(line);rows[row['sample_id']]=row
        with mapping.open(newline='') as stream:
            for row in csv.DictReader(stream):mappings[row['sample_id']]=row
    if set(rows)!=set(expected):raise ValueError('incomplete or unexpected collected IDs')
    for sid,row in rows.items():
        if row['artifact_sha256']!=expected[sid]['sha256']:raise ValueError('artifact hash mismatch: '+sid)
        if row['response']['scan_status']!='final':raise ValueError('provisional response')
        if mappings[sid]['label']!=expected[sid]['label'] or mappings[sid]['error']:raise ValueError('label/error mismatch')
        if mappings[sid]['request_id']!=row['response']['request_id']:raise ValueError('request join mismatch')
    (a.directory/'corpus-responses.jsonl').write_text(''.join(json.dumps(rows[r['sample_id']])+'\n' for r in manifest))
    with (a.directory/'corpus-mapping.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['sample_id','request_id','label','scan_status','error'],lineterminator='\n');writer.writeheader();writer.writerows(mappings[r['sample_id']] for r in manifest)
    print('Merged and validated',len(rows),'final hash-matched independently construction-labeled samples.')
if __name__=='__main__':main()
