# Independent label and scope review — pending

No independent review has been performed by the implementing assistant. The CSV sheets are blank for reviewer decisions. An automated check or another model's agreement would not substitute for the requested second person's review.

## Scope decision

Review each artifact under one named scope. Do not mix these labels in one accuracy denominator.

- **supplied_text**: inspect the provided source/configuration only. Container results do not establish image existence, image contents, CVEs, build success or runtime behavior. A full coverage result means the requested text scope completed.
- **resolved_images**: inspect supplied configuration plus supported OS-package inventory in the recorded image digest, with the actual platform and advisory snapshot. A configuration labelled clean under text scope may still require Review/Reject here. No claim covers language packages without their lockfiles or unsupported OS inventories.

Normal Trust Engine container requests still enable CVE checks by default. Explicit supplied-text requests do not silently redefine that default. Reports expose the selected scope. A final result and full requested coverage do not mean complete software assurance.

## How the second reviewer should work

1. Open the artifact listed in the CSV and check its SHA-256 against `artifact_sha256`.
2. Read the stated scope and label rationale. For development fixtures, `author_proposed_label` is the original proposal, not a required answer. For upstream files it is `unreviewed`.
3. Enter `reviewer_label` as accept/review/reject, `review_scope`, a concrete rationale, your own `reviewer_id`, date and `independent_attestation=yes` only after doing the review.
4. Use Accept only for the stated supported scope; use Review for unresolved context or uncertainty; use Reject for a supported confirmed policy violation. The score targets 100/65/0 are ordinal engineering anchors, not probabilities.
5. Resolve disputed labels before using them for training/evaluation. Record context and dissent in the rationale. Never change a label merely to match a detector verdict or increase accuracy.
6. Keep at least one new project/family split untouched until final evaluation. The 360 existing artifacts are a development retest because their prior errors were examined during implementation. They are no longer a pristine benchmark for this round of changes.
7. Real upstream files are NOT assumed safe because their projects are popular or permissively licensed. License identification and security labels are separate reviews.

Sheets: `development-label-review.csv` (360), `external-label-review.csv` (10), `images-label-review.csv` (4). Prefer review without consulting model predictions. Two repositories and ten upstream files are a small external observation set, not a broad attack benchmark.

## Record the review without overwriting history

Run from the repository root, after a person actually completes the whole corresponding sheet:

```bash
python3 scripts/apply_trust_label_review.py \
  evaluation/trust_model/v3/external/manifest.json \
  evaluation/trust_model/v3/external-label-review.csv \
  --output evaluation/trust_model/v3/external/reviewed-manifest.json
```

The script validates IDs, hashes and explicit attestations. It does not authenticate a person's identity or establish expertise. It refuses incomplete records and leaves the original labels unchanged.

Use `scripts/evaluate_trust_pilot.py ... --require-reviewed --scan-scope supplied_text` only when all records are adjudicated for that scope. The evaluation runner refuses mismatched label/scan scopes, changed content and incomplete independent-review records. A report should name the reviewer and review date only with their actual completed record.

## External-source licensing

The collection script saves commit-pinned source URLs, SHA-256, GitHub SPDX license identification and matching retained license notices. The license check covers the sampled upstream files at those commits; it is not legal advice, a transitive dependency-license audit, or permission to remove notices. Upstream code was never installed or executed.
