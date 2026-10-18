# Scope-explicit development evaluation, 18 October 2026

This directory contains a developer-inspected retest and a small, still-unreviewed external observation set. It is **not an independently reviewed final benchmark**. The earlier native-v2 66.67% result remains historical evidence in `../native-validation`; it has not been overwritten.

- `development-manifest.json`: 360 existing synthetic artifacts with SHA-256, explicit supplied-text label scope and original 180/90/90 grouping. Prior errors were inspected while fixing the system, so the 90 test-labelled cases are development retest cases for this iteration.
- `comparison.json`: weighted baseline, frozen v2 candidate and retrained v3 candidate evaluated on the **same fresh response set**.
- `development-results-ready/` and `models-ready/`: usable candidate results/model from healthy collection. No candidate was promoted as the normal default.
- `development-results/` and `models/`: superseded diagnostics from an initial isolated model-path setup failure. Never use these as final metrics; the full provenance is retained rather than hidden.
- `image-lock.json`: four resolved image index digests. `resolved-images/` contains separate operational fixtures. Images were inventoried without executing them.
- `runtime-lock.json`: detector/source/container identities. A digest records a snapshot; external advisory feeds and a hosted judge are not permanently frozen by this file.
- `external/`: ten real source/license files from two commit-pinned upstream repositories, with matching license notices and provenance. They are not used in training and have no accuracy claim until reviewed.
- `*-label-review.csv` and `REVIEW_GUIDE.md`: blank human-review records and scope rubric. Review status is pending.
- `verification-summary.json`: fresh collection counts, historical setup failures, admission retries, complete image results and remaining limitations.

## Measured development results

| Method on the same fresh 90 test-labelled cases | Accuracy | Score MAE | False accepts |
|---|---:|---:|---:|
| Weighted | 77.78% (70/90) | 19.5833 | 0 |
| Frozen native-v2 ML candidate | 83.33% (75/90) | 14.2267 | 0 |
| Retrained v3 ML candidate | 83.33% (75/90) | 13.1105 | 0 |

The retraining improves numerical error on this development set but does not improve classification over the frozen v2 model on the same fresh inputs. Comparing 83.33% directly with the older 66.67% cannot isolate a model-training benefit: detectors, observation time and container scope changed. All results remain against unreviewed construction labels.

Five true Accept-labelled Markdown variants still receive Review from screening/judge uncertainty. The known Review-labelled precedence instruction is now reviewed rather than accepted. Zero observed false accepts is not zero real-world risk. Reject-labelled SQL/Compose cases can still be held at Review rather than Reject; both block the configured write gate, but that distinction remains an exact-label error.

All 360 healthy-run records finalized; no detector returned status error. The initial concurrent collection hit 25 explicit capacity rejections, then separate retries filled those IDs. Ten external observations finalized after three admission retries, with no ground-truth metric assigned. The separate pinned Alpine/Debian/Python/Node inventory runs all completed with full requested coverage: Alpine Accept; the other three Reject with findings. Rejection is not a scanner failure.

Native/library SHAP contribution difference was zero in the checked test matrix; no violations occurred in 3,360 observed-feature monotonic checks. Those checks establish implementation properties on tested inputs, not calibration, causality or external predictive validity.

## Repeat and review

Use `scripts/evaluate_trust_pilot.py` with a fresh output directory, the private deployment configuration outside this corpus, an explicit scan scope and a healthy endpoint. The runner checks hashes, rejects scope mismatch, limits concurrency, and retries only an explicit capacity rejection that did not admit a scan. Use `--require-reviewed` for a reviewed holdout.

For retraining, use `scripts/train_trust_model.py --evaluation-role development_retest`; save models to a new candidate location and retain the model identity. Read `REVIEW_GUIDE.md` before converting completed reviewer attestations into a new manifest. No independent reviewer has been invented or contacted by the assistant.


## Submitted human review — 18 October 2026

Ten upstream files now have user-supplied labels and attestations by Abdulelah (8 Accept, 2 Review). IDs, scopes and SHA256 hashes validate. Fresh weighted agreement is 30% (3/10); frozen v2 ML replay 30%; v3 ML replay 20%. The cohort has no Reject labels and is not untouched or formally blinded. These results expose excessive blocking and do not supersede the different 83.33% synthetic development measurement. Full evidence: output/human-reviewed-evaluation-20261018/. This update supersedes earlier pending status only for these ten supplied human reviews; other review sets remain separate.
