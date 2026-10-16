# Artifact labeling and review guide

The current corpus was authored by construction, not independently reviewed. `evaluation/trust_model/corpus/manifest.json` records labels, rationales, split/group, submitted SHA-256 and review flags. It contains fabricated credentials and constructed attacks that must never be executed/deployed. Detectors produce features only; their decisions are not labels.

Review an artifact in its stated context. Accept means no planted defect within supported scope; Review means an ambiguous/review-level security or license concern; Reject means a definite dangerous construction under the project policy. A broken scanner does not change the artifact's independent label, but operational uncertainty must still prevent Accept. This distinction explains some disagreement between artifact labels and gated platform outcomes.

Every reviewer should record sample_id, source/context, rationale, proposed label, reviewer identity/date, confidence and disputed assumptions. Use an independent second reviewer for ambiguous cases and keep adjudication notes. Do not mark `human_reviewed` or `independent_review` true merely because the generator or model accepted a row. Review fictional dependency existence and mutable registry/license assumptions when collecting live data.

Keep samples from a source repository/generator/construction template together across splits. Build an externally authored held-out set with provenance and appropriate licensing. Include clean controls, mixed risks, known misses and realistic unsupported/failure contexts. Do not let renamed or trivially modified attacks count as independent validation. Never tune on the final test set.

The pilot targets 100/65/0 are ordinal engineering anchors, not calibrated probabilities. Define a target/rubric before adding external data. Native TreeSHAP explains model prediction before gates; it does not justify relabeling a sample or overriding security policy. Promote a model only after a documented baseline comparison on independently reviewed data, including false accepts and per-type performance.
