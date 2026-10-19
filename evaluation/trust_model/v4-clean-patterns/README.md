# V4 clean-pattern candidate: development repair, not production promotion

The v3 candidate rejected an MIT licence with zero findings because its learned
missingness splits assigned a low score to a clean licence/secret-only route.
This candidate adds 127 **training-only synthetic engineering anchors**, one per
nonempty detector-selection mask, with zero observed risks, full coverage and a
100-point engineering target. Unselected detectors remain missing; no artifact
names or outcome labels are input features. None of the ten project-team human
labels were added to training. This is not new independent validation.

Reproduction from the project root:

```bash
.data/venv/bin/python scripts/train_trust_model.py \
  --manifest evaluation/trust_model/v3/development-manifest.json \
  --responses .data/evaluation-v3/final-fresh-responses.jsonl \
  --output evaluation/trust_model/v4-clean-patterns/models \
  --report-dir evaluation/trust_model/v4-clean-patterns \
  --model-version clean-pattern-calibrated-development-v4 \
  --evaluation-role development_retest --clean-pattern-calibration
```

The historical response file is retained locally; model provenance and hashes are
in `models/guardian.metadata.json`. Original v3 models and historical reports are
preserved. The live candidate at API 18818 / website 3302 uses v4. Weighted
scoring at API 18808 / website 3000 remains the enforcing default.

## Evidence and limits

- On the same previously inspected 90 development cases: v4 verdict agreement
  83.33%, MAE 13.31, zero false accepts. These figures are development retests.
- Frozen old detector responses from the ten project-team human-labelled files:
  weighted 30%, v3 20%, v4 30% agreement. This is neither blinded nor untouched;
  the new model has **not** established broad real-world reliability.
- Engineering-anchor checks are not an accuracy benchmark. One of 127 synthetic
  masks, secret-only, still scores below Accept. Known clean code, licence,
  dependency, workflow, Docker and Markdown routes in the live fixtures pass.
- `live-verification.json` records positive and malicious API controls, model
  identity and TreeSHAP additivity checks. `paired-hook-verification.json` records
  automated hook simulations; these are **not Copilot UI execution evidence**.
- The Markdown fix clears classifier-only weak signals on ordinary headings only
  after an explicit high-confidence benign judge verdict. Strong classifier
  signals, action/authority cues, uncertainty and failures retain existing gates.
- The Docker demo uses a verified digest-pinned Alpine fixture with a non-root
  user and health check. The earlier Python-image CVE results were not suppressed.

A new independent benchmark and broader labels are still needed before model
promotion. Do not present the repaired demonstration as 100% project accuracy.
