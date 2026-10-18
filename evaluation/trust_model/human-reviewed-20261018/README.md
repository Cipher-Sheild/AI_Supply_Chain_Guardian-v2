# Human-reviewed external evaluation — 18 October 2026

The user submitted guardian-review-external.csv with ten personal review attestations by Abdulelah. All sample IDs, file hashes, scope values and required fields validated. Eight files are Accept, two Review, none Reject. The original CSV and all rationales are retained without edits. The prior AI-assisted review is a separate record, not the source of these submitted human labels.

This is project-team human review, with independence self-attested. Identity, expertise and non-involvement in earlier label construction are not independently authenticated. AI suggestions were previously available in the project conversation, so this cannot be presented as a formally blinded study. The source files were already scanned; a fresh run does not make them untouched.

## Results

| Method | Prior saved observations | Fresh observations |
|---|---:|---:|
| Weighted | 3/10 (30%) | 3/10 (30%) |
| Frozen v2 ML replay | 3/10 (30%) | 3/10 (30%) |
| V3 ML candidate replay | 2/10 (20%) | 2/10 (20%) |

All ten fresh requests finalized with no scan failures. Fresh request IDs are distinct from old IDs. Model replay uses the same respective detector observations and authoritative policy gates; it is not an additional live ML API experiment. No training or threshold changes occurred. Full MAE/confusion/per-type results and per-case scan IDs are in the JSON/CSV files.

Weighted scoring blocked six of eight human-Accept cases: false-block rate 75% in that class. Neither human-Review case was accepted. With no Reject-labelled examples, malicious-case recall cannot be estimated. Two repositories and ten files are not enough for a broad production accuracy claim. No metric from this cohort replaces the 83.33% synthetic development figure, or vice versa.

## Interpretation and release decision

Dominant disagreements involve prompt uncertainty on benign text, canonical MIT notice matching, packaged-schema SQL execution, and the severity assigned to a tutorial development secret. The v3 model additionally rejects both licence files. SHAP additivity does not validate these predictions; the model remains a candidate and normal deployment remains weighted.

The ten-file human-review task is complete. Independent external blinded validation, review of the larger development/image sets and a new representative project/family holdout remain separate. Existing cases are now diagnostic development evidence. Targeted general fixes may follow, but tuning against these ten and calling their rescan untouched would be invalid. Current evidence does not support independently validated production readiness.

All ten fresh persisted scan responses match retrieval. Ten audit PDFs were downloaded and each extracted PDF text contains its matching full scan ID. See persistence-and-pdf-checks.json and audit-pdfs/.
