# Software requirements — local project scope

Version: final local implementation, 12 October 2026. Verification is reported separately in FINAL_PROJECT_DOCUMENTATION.md and final-validation/VERIFICATION.md.

| Requirement | Acceptance criterion |
|---|---|
| Artifact submission | Single and bounded multi-file requests validate types, names and byte limits. |
| Relevant scanning | Capability routing selects only applicable detectors; unsupported/unknown work reports partial/none coverage. |
| Evidence contract | Findings retain severity/confidence/location/remediation and recursively preserved details; credentials are masked in returned evidence. |
| Safe decisions | Errors, missing/unexecuted checks, pending and unresolved licenses never become confident Accept. Overrides remain authoritative. |
| Deterministic baseline | Finite [0,100] weighted score, documented score bands and policy floors. |
| Learned candidate | Reproducible constrained training, version/checksum validation, finite inference and visible weighted fallback. |
| Explanation | Original evidence plus weighted breakdown; exact TreeSHAP for an invoked trained model, with policy outcomes separated. |
| Durable lifecycle | Every scan retrievable; atomic/idempotent callbacks; overdue finalization; leased prompt journal/retry. |
| Persistence | Fractional scores and recorded per-file/model explanations survive reopening and model changes. |
| Developer interfaces | CLI/pre-commit, dashboard, audit PDF and explicit editor command support final/provisional states. |
| Resource bounds | Admission/body/work/worker/deadline bounds; timed-out scanner process trees are terminated. |
| Reproducibility | Direct pins, platform runtime lock, contract/runtime drift checks, service/script builds/tests and reproducible corpus provenance. |
| Honest reporting | Synthetic labels, unsupported coverage, unverified deployment/UI and benchmark limitations remain visible. |

Public multi-tenant operation, universal AI-assistant interception, whole-program security proof, full SBOM resolution, Go/GitLab specialist coverage and build-verified automatic remediation are outside this delivered local scope. The three-second target is measured separately and is not a guaranteed acceptance criterion.
