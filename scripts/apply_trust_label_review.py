#!/usr/bin/env python3
"""Apply explicit reviewer attestations to a new manifest; never infer labels.
This validates a supplied review record, not the reviewer's identity or expertise.
"""
import argparse,csv,json,hashlib
from pathlib import Path

def reviewed_manifest(rows, reviews):
 by_id={r['sample_id']:r for r in reviews}
 if len(by_id)!=len(reviews) or set(by_id)!={r['sample_id'] for r in rows}:raise ValueError('Review IDs must match manifest exactly')
 output=[]
 for row in rows:
  review=by_id[row['sample_id']]
  if review.get('independent_attestation','').lower()!='yes' or not review.get('reviewer_id','').strip() or not review.get('review_rationale','').strip() or not review.get('reviewed_date','').strip():raise ValueError('Incomplete independent reviewer attestation')
  if review['reviewer_id'].strip() in {'implementation-agent',row.get('author_id','implementation-agent')}:raise ValueError('Author cannot attest independent review')
  if review.get('reviewer_label') not in {'accept','review','reject'} or review.get('review_scope') not in {'supplied_text','resolved_images'}:raise ValueError('Invalid reviewer label/scope')
  if review.get('artifact_sha256')!=row['sha256']:raise ValueError('Review artifact hash differs')
  output.append({**row,'label':review['reviewer_label'],'target_trust':{'accept':100,'review':65,'reject':0}[review['reviewer_label']],'label_scope':review['review_scope'],'independent_review':True,'human_reviewed':True,'reviewer_id':review['reviewer_id'].strip(),'review_rationale':review['review_rationale'],'reviewed_date':review['reviewed_date'],'review_attestation':'supplied_by_reviewer; identity not independently authenticated by this script'})
 return output

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('manifest',type=Path);p.add_argument('review_csv',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
 if args.output.exists():raise ValueError('Never overwrite prior labels')
 rows=json.loads(args.manifest.read_text())
 with args.review_csv.open(newline='') as f:result=reviewed_manifest(rows,list(csv.DictReader(f)))
 args.output.write_text(json.dumps(result,indent=2)+'\n');print(f'{len(result)} explicitly reviewed labels recorded; attestations retained.')
if __name__=='__main__':main()
