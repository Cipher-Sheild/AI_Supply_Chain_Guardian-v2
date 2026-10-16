# Trust model: reproducible synthetic pilot

This folder supplies constructed artifacts, labels assigned before scanning, a grouped split manifest, measured detector responses and a training/evaluation pipeline. It is not a public benchmark or independently reviewed corpus. The implementation agent authored both the generator and labels. Closely related templates remain a limitation even with disjoint construction-family groups.

## Label rubric

- `accept` → target 100: no intentionally planted security defect in the artifact's supported scope.
- `review` → target 65: an ordinary policy conflict, ambiguous instruction, unsupported external reference, unsafe deployment choice or security-sensitive pattern needs human assessment.
- `reject` → target 0: deliberately planted direct injection/execution, escape-enabling configuration, explicit credential exposure, privileged workflow or fictional dependency.

These targets are engineering ordinal anchors, not calibrated probabilities. Context can change the correct label. Docker version tags still have mutability risk; package existence and license metadata change over time. Human review must adjudicate these assumptions before using this pilot for research claims or production promotion. Fabricated credential examples are not live secrets.

The generator emits 360 examples across code, GitHub Actions, Compose, Dockerfiles, dependencies and Markdown. Four construction families per type stay in one split, with five named variants per label. Split counts: train 180, validation 90, test 90. Selection uses validation only. The test set is grouped but is NOT authored by an independent reviewer. Variants do not imply 360 independent security mechanisms.

## Reproduce

1. `python scripts/build_trust_corpus.py` validates constructed Python/YAML syntax and emits manifest hashes and rationales.
2. Start the services and use `scripts/run_labeled_corpus.py evaluation/trust_model/corpus/manifest.json --output evaluation/trust_model/mapping.csv --responses evaluation/trust_model/responses.jsonl --url http://127.0.0.1:8000`.
3. With the training requirements installed, run `python scripts/train_trust_model.py --responses evaluation/trust_model/responses.jsonl`.
4. Inspect `results.json` and `services/trust_engine/models/guardian.metadata.json` before enabling `TRUST_SCORER=ml`. Weighted scoring remains the default.

Only relevant detectors run. Supplied labels are never derived from platform verdicts. Training reconstructs final detector state, checks submitted artifact hashes, checks disjoint groups and excludes outcomes, recommendations, timing, identity and artifact content from features. Missing/not-selected risk measurements are NaN; selected unavailability is explicit. All 98 risk features have non-increasing trust constraints. Hard overrides and uncertainty/severity gates still decide the final policy outcome.

The native XGBoost engine provides exact TreeSHAP contributions in trust-score points before clamping/policy gates. Training verifies these against `shap.TreeExplainer` and checks additivity/monotonicity. Contributions are grouped by detector and shown separately from overrides. They explain model behavior, not causation. Model JSON and metadata are loaded with schema and SHA-256 validation; no pickle is loaded.

## What evidence means

Metrics compare policy-adjusted XGBoost and weighted outcomes against construction labels on this pilot. False accepts, confusion matrices, per-type accuracy, MAE and safety-gated agent ablations are reported. Ablations retain missing-agent Review gates and therefore measure operational failure behavior as well as signal removal. No probability calibration, real-world accuracy, external validation or superiority claim follows from these results. Add provenance-reviewed external artifacts and independently authored attacks before promoting a model.
