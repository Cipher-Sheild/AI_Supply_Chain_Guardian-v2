# Agent-by-agent review — final local run

Existing designs are retained where they match declared capabilities and passing evidence. Tests demonstrate behavior, not universal detection accuracy. Full current design and operating instructions are in FINAL_PROJECT_DOCUMENTATION.md.

| Component | Evidence | Validated responsibilities | Limits |
|---|---|---|---|
| cipherguard | 16 passed | Dependency parsing, existence/metadata/similarity and cache error handling | PyPI/npm only; no full resolved dependency graph. |
| code_security | 32 passed | Real 37-rule native Semgrep scans, language/suffix guards, errors/partial parsing and process cleanup | Python/JS/TS/PHP/Java; Go remains partial. |
| secret_detection | 29 passed in 0.43s | Vendor/context/entropy/suppression, confidence bounds, locations and masked previews | Detection coverage/calibration needs external artifacts. |
| docker_security | 41 passed | Docker/Compose rules, tool completion, image references, hardening labels and returned redaction | No actual hardening image build or full CVE-image proof. |
| workflow_cicd | 26 passed in 0.85s | GitHub YAML/action refs, permissions/triggers, remote shell and failure semantics | GitLab remains partial; rules are not comprehensive proof. |
| license_compliance | 39 passed in 1.25s | Registry/text fallback, SPDX expressions, unknowns, ordinary Review versus explicit denylist and cache | No full SBOM/source-archive/version-range resolution. |
| prompt_injection | 49 passed | Extraction/heuristics/embeddings/judge typing, journal/retry/cache/quorum/redirect behaviour | CPU judging can be slow; evasion/false positives remain; container restart unverified. |
| trust_engine | 207 passed | Routing/canonical dispatch, contract/fusion, unselected/unexecuted guards, persistence/PG row locks, interfaces and learned model/SHAP | Synthetic candidate optional; public multi-tenant deployment not delivered. |

## Changes justified by failures or missing functionality

- Semgrep CLI startup exceeded its budget. The pinned native OSS core retains rules/severities and passes the real-language regression suite; partial parse warnings now reduce coverage and process groups are killed on timeout.
- Fusion could consume explicitly unselected results or trust unexecuted clean claims. These are now ignored or held at Review as appropriate.
- Docker serialized legacy findings cannot be deserialized as legacy input. The redacted output boundary uses the public canonical contract, preserving every evidence field and avoiding response-validation failures.
- Credential-shaped values in tool/hardening evidence and public history are masked. This is output hygiene, not a claim to detect every credential format.
- Durable prompt delivery must not acknowledge HTTP redirects. Only actual 2xx confirms delivery; token-bearing redirects are not followed.
- Typed single-vote judge results may be cached for repeated exact spans; errors and multi-vote quorums bypass reuse. Generation/context/thread limits and a project alias reduce CPU oversubscription.
- Missing predictive work is now implemented: constructed labeled corpus, grouped training/evaluation, constrained model loading/fallback, exact TreeSHAP and persisted/public explanations. The model is not automatically promoted.

## Integration proof and interpretation

Native PostgreSQL/Redis HTTP scans, seven detector schema audits, per-file/history/PDF/model checks and a migrated PostgreSQL row-lock test pass. All declared supported scanners contain real logic; unsupported capabilities are honestly partial. A Docker socket denial prevents Compose/container assertions. Browser approval was declined, and VS Code interaction remains manual. No external held-out or human-reviewed label certification is claimed.

The synthetic test has 90 related rows: both scorers 77.8% accuracy, weighted false accepts 5 versus candidate 0, with 10 clean rows moved to Review by the candidate. These mismatches are measured limitations, not grounds to silently relabel data or overfit the test set. More detector coverage and independent review remain necessary for stronger security/novelty claims.
