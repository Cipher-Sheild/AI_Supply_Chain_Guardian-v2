# AI Supply Chain Guardian: Complete Project Documentation

**A Multi-Agent AI Platform with Predictive Trust Assessment for AI-Generated Software Artifacts**

B.Tech Capstone, Group 56, Department of Computer Science & Engineering, Symbiosis Institute of Technology, Pune
Document date: 11 October 2026

> **How to read this document.** It consolidates everything decided and built across the project conversations: the objective, the architecture, the specification of every agent, the routing logic, the Trust Engine and ML plan, the audit findings, the Checkpoint 1 results, what remains, and how to defend it. Labels used throughout:
> - **[Specified]**: stated in the Synopsis, Final Documentation, paper draft or CipherGuard report.
> - **[Recommended]**: guidance added where the written spec was silent. Confirm against the real code.
> - **[Built]**: confirmed by the implementation audit or the Checkpoint 1 report.
> - **[Decision]**: a choice taken during the project. Decisions marked *(assistant-proposed)* should be confirmed by the team.

---

## Table of contents

1. [Project objective and goal](#1-project-objective-and-goal)
2. [Problem, gap and novelty](#2-problem-gap-and-novelty)
3. [Team, ownership and working method](#3-team-ownership-and-working-method)
4. [System architecture](#4-system-architecture)
5. [The shared contract](#5-the-shared-contract)
6. [Agent specifications](#6-agent-specifications)
7. [Why the agents are deterministic (no ML)](#7-why-the-agents-are-deterministic-no-ml)
8. [Routing logic (final)](#8-routing-logic-final)
9. [Trust Engine: fusion, scoring and the ML plan](#9-trust-engine-fusion-scoring-and-the-ml-plan)
10. [Interfaces](#10-interfaces)
11. [Testing and evaluation plan](#11-testing-and-evaluation-plan)
12. [Project history: what happened, in order](#12-project-history-what-happened-in-order)
13. [Implementation audit (26 findings)](#13-implementation-audit-26-findings)
14. [Checkpoint 1: results and status](#14-checkpoint-1-results-and-status)
15. [What is left](#15-what-is-left)
16. [Documents vs build: inconsistencies to fix](#16-documents-vs-build-inconsistencies-to-fix)
17. [Viva preparation](#17-viva-preparation)
18. [Submission checklist](#18-submission-checklist)
19. [Open decisions](#19-open-decisions)
20. [Glossary](#20-glossary)

---

## 1. Project objective and goal

**One-line definition [Specified].** AI Supply Chain Guardian is a pre-acceptance security platform. It intercepts AI-generated artifacts (source code, dependency manifests, Dockerfiles, CI/CD workflows) before a developer accepts or commits them, runs the relevant specialist agents in parallel, and fuses their outputs into one explainable **0-100 Trust Score** with an **Accept / Review / Reject** recommendation.

**What we set out to achieve**
- Stop risky AI-generated artifacts from entering the codebase, instead of catching them after commit.
- Cover seven risk categories in one pipeline: hallucinated dependencies (slopsquatting), insecure code, leaked secrets, unsafe containers, risky CI/CD workflows, license conflicts, and prompt injection.
- Give developers a measurable, explainable trust score so a reviewer knows why something was accepted, flagged or blocked.
- Deliver it through IDE-agnostic interfaces: a CLI/pre-commit hook (primary), a VS Code extension, and a web dashboard, with scan history for audit.

**Expected outcomes [Specified]**
- Prevents insecure AI-generated artifacts from entering the codebase.
- Reduces security review time.
- Provides measurable trust scoring for AI-assisted development.
- A benchmarked CipherGuard module, a calibrated Trust Engine, and a complete academic report.

---

## 2. Problem, gap and novelty

### 2.1 The problem
AI coding assistants (GitHub Copilot, Cursor, Claude Code, Gemini) raise developer productivity but introduce supply-chain risks that traditional post-commit tools do not address:

| Risk | Description |
|---|---|
| Hallucinated dependencies (slopsquatting) | Models suggest plausible but non-existent package names that attackers can pre-register with malicious code. Spracklen et al. (USENIX Security 2025) measured 5.2-21.7% hallucination across 16 LLMs. |
| Insecure code | SQL injection, XSS, command injection and other OWASP Top 10 classes. |
| Secret leakage | Exposed API keys, tokens and credentials in generated code. |
| Unsafe containers | Vulnerable Dockerfiles, exposed ports, missing limits, root execution. |
| Risky CI/CD workflows | Unpinned third-party Actions, broad permissions, curl-to-shell patterns. |
| License violations | AI-suggested dependencies with copyleft or unknown licenses. |
| Prompt injection | Hidden instructions in comments, docstrings, strings or fetched content that can hijack downstream AI agents. |

### 2.2 Existing tools and their limit
Semgrep, Snyk, Trivy and Gitleaks are effective but **reactive**: they scan after the artifact is written or committed.

### 2.3 The gap
No existing implemented system we found fuses seven independent risk signals into one calibrated, explainable, artifact-level trust score **before acceptance**.

### 2.4 The novelty claim (use this exact framing)
- **Pre-acceptance interception** plus the **fusion and explainability layer** (the Trust Engine) is the contribution.
- It is **not** any single detector. Individual detectors already exist in open source, and several agents wrap mature tools.
- Always say "to our knowledge".
- We do not claim to beat ScanCode, zizmor, Gitleaks, Semgrep or similar tools on raw detection. In those categories the contribution is integration and consistent scoring.

---

## 3. Team, ownership and working method

### 3.1 Components and owners [Specified]

| # | Component | Function | Complexity rank | Owner |
|---|---|---|---:|---|
| 1 | CipherGuard | Hallucinated / typosquatted package detection | 2 | Dev A (AB00d) |
| 2 | Code Security | OWASP-style vulnerabilities (Semgrep) | 4 | Dev C |
| 3 | Secret Detection | Hardcoded keys and tokens | 8 (easiest) | Dev A (AB00d) |
| 4 | Docker Security | Unsafe Dockerfiles and Compose files | 5 | Floating (AB00d) |
| 5 | Workflow / CI-CD | Unpinned Actions, broad permissions, curl-to-bash | 6 | Dev C |
| 6 | License Compliance | Incompatible or unknown licenses | 7 | Dev B |
| 7 | Prompt Injection | Hidden instructions aimed at AI agents (LLM layer) | 3 | Dev B |
| 8 | Predictive AI Trust Engine | Router, fan-out, fusion, explanation | 1 (hardest) | Whole team, built last |

Within the Trust Engine, one teammate owns the router and LangGraph wiring (Item 3), another (Ali) owns fusion (Item 4), and the ML scoring layer (XGBoost and SHAP) is a follow-on piece owned by the Trust Engine developer.

### 3.2 Working method
- Microservices so three developers build without merge conflicts.
- Build the easy agent first to establish the shared schema pattern, then the harder one.
- Phased, verified builds: one module at a time, verified before moving on, no silent code dumps (the discipline set by Secret Detection and reused by CipherGuard).
- Honest benchmarking: report tradeoffs and shortfalls, never overclaim.

### 3.3 Planned roadmap [Specified]

| Phase | Weeks | Activities |
|---|---|---|
| 1. Planning and setup | 1-2 | Architecture, scaffold of all service folders and compose file, shared AgentResult schema |
| 2. Build individual agents | 3-10 | Each developer builds owned agents |
| 3. Integration | 11-14 | Router, LangGraph fan-out/fan-in, fusion logic |
| 4. UI and features | 15-17 | CLI/pre-commit hook, VS Code extension, dashboard |
| 5. Testing and optimization | 18-20 | Synthetic dataset, CipherGuard benchmark, latency tuning |
| 6. Documentation and presentation | 21-22 | Report, deck, demo video |

---

## 4. System architecture

### 4.1 Locked decisions [Specified]
- **Microservices, one container per agent** (revised from an initial modular monolith). 8 services plus PostgreSQL and Redis in Docker Compose. The frontend runs natively outside Docker.
- **`trust_engine` is the only public entry point** and the only service that touches PostgreSQL. Detectors are stateless, internal to the Compose network, and each exposes `POST /analyze` and `GET /health`.
- **Deterministic by default.** The only ML or LLM component is Prompt Injection's semantic layer. The Trust Score stays deterministic (rule overrides plus weighted scoring) unless and until a trained scorer is added under the safety layer.
- **Shared AgentResult/Finding schema**, originated by Secret Detection.
- **Free and local tooling:** ScanCode instead of FOSSA, Llama 3 via Ollama instead of the OpenAI API, cached registry calls with backoff.
- **Scoped latency claim:** six of seven agents complete synchronously in under 3 seconds; Prompt Injection resolves asynchronously and updates the score afterward. This is a target, not yet validated.

### 4.2 Six-layer pipeline

| Layer | Responsibility |
|---|---|
| Input | Capture AI assistant output before it is written or committed |
| Interface | CLI / pre-commit hook (primary), VS Code extension, web dashboard |
| Orchestration | LangGraph graph: Artifact Router, parallel dispatcher, fan-in |
| Agent | Seven detector microservices; only artifact-relevant agents run per request |
| Predictive Trust Engine | Fuse results into a score, explanation and decision |
| Data | PostgreSQL (history, audit) and Redis (cache, pending-scan state) |

### 4.3 Usage flow
1. A developer is about to accept an AI suggestion. The CLI hook or editor extension intercepts it and sends it to `trust_engine`.
2. The router classifies the artifact and dispatches only the relevant detectors in parallel.
3. Each detector returns a structured AgentResult. The Trust Engine fuses them into a score with an explanation and a decision.
4. The developer sees an inline warning (medium or high risk) or a silent pass, with full detail on the dashboard. Everything is logged for audit.
5. Two modes: **interactive** (IDE flags risk before acceptance) and **batch / CI gate** (pre-commit or pipeline step blocks merges below a configurable threshold).

### 4.4 Technology stack [Specified]

| Concern | Technology |
|---|---|
| Backend / API | FastAPI (per service, Python) |
| Frontend | React + TypeScript + Tailwind CSS (Vite) |
| Orchestration | LangGraph / LangChain |
| LLM (semantic checks) | Llama 3 via Ollama (local, free) |
| Scanners | Semgrep, Trivy, Hadolint, ScanCode-toolkit, Gitleaks/TruffleHog (as specified) |
| ML / scoring | scikit-learn / XGBoost, SHAP (planned) |
| Similarity | Levenshtein (the build uses `jellyfish`) |
| Database / cache | PostgreSQL, Redis |
| Containers | Docker, Docker Compose |
| IDE integration | CLI / pre-commit hook (primary), VS Code Extension API (secondary) |

### 4.5 Actual graph as built [Built, per audit]
`route -> call_agents -> fuse -> END`. Parallelism comes from `asyncio.gather` in dispatch. The graph is an orchestration skeleton: there are no autonomous agent-to-agent reasoning loops.

Public Trust Engine routes: `GET /health`, `POST /analyze`, `POST /callback/{callback_id}` (authenticated with a shared token), `GET /scans/{request_id}`.

---

## 5. The shared contract

### 5.1 AgentResult envelope
Every detector returns the same envelope so the Trust Engine fuses without per-agent special cases.

| Field | Meaning |
|---|---|
| `agent` / `agent_name` | Stable detector identifier |
| `status` | `pass`, `warn`, `fail`, `error`, `stub`, `pending` |
| `findings[]` | Finding objects: category, severity, confidence (0-1), location (file and line), details, plus agent-specific data in `details` |
| `score` | Agent-level risk value (CipherGuard uses 0-100 with bands 0-39 / 40-89 / 90-100) |
| `callback_id` | Prompt Injection only, returned with `pending` |

Meaning of the statuses:
- `error`: the agent could not decide (network, timeout, crash). Treated as **unknown**, never clean.
- `stub`: the artifact type is not supported by that agent.
- `pending`: the async result is not ready; an update arrives via authenticated callback.

### 5.2 Changes made during the project
- Trust Engine status literal originally had only pass/warn/fail/stub. `error` was added, and the transport-failure fallback was changed from `fail` to `error`.
- `pending` and an optional `callback_id` were added to `AgentResult`.
- All seven agents updated their own `AgentResult` literal to the same six values: `Literal["pass", "warn", "fail", "error", "stub", "pending"]`.
- The state model lives in `trust_engine/app/state.py` and imports `AgentResult` from `schemas.py` rather than redefining it. `agent_ran` is set by the orchestrator, not the detector.
- Checkpoint 1 added a versioned contract (`CONTRACT_V1.md`) with generated, drift-checked copies across services (`python3 scripts/sync_contracts.py --check`).

### 5.3 Per-(file, agent) record exchanged between router and fusion
`file`, `agent`, `expected`, `agent_ran`, `status`, `result`, `elapsed_ms`, `error_reason`, `callback_id`.

Per file: `artifact_type`, `routing_source`, `expected_agents`, `coverage`, `notes`. Per request: overall coverage, pending callbacks, routing notes.

### 5.4 Stub rule for all seven agents [Decision]
Keep each agent's own artifact-type guard as a safety net behind the router. An unsupported type returns `status="stub"` with `reason="unsupported_artifact_type"`, never `pass`. If the router expected the agent and got a stub, that is a routing/contract mismatch: `agent_ran=False`, coverage downgraded to `partial`, and fusion never counts it as clean.

---

## 6. Agent specifications

For each agent: purpose, how it works, rules, and what it was tested against. Spec and implementation differences are called out.

### 6.1 CipherGuard: slopsquatting detection (Dev A)

**Purpose.** Detect AI-suggested packages that do not exist (an attacker can pre-register them), typosquat and combosquat lookalikes, and suspiciously new or thin packages, before install.

**Scope v1.** `requirements.txt` and `package.json` (PyPI and npm only). Handles environment markers, PEP 508 direct references, scoped npm names (`@babel/core`), and skips non-registry specs (git/file URLs).

**Pipeline**
1. **Parse** dependencies.
2. **Existence check:** async PyPI/npm query returning existence and metadata in one call.
3. **Typosquat check:** normalized Levenshtein distance (`dist / max(len1, len2)`) against an independent 10,000-package reference corpus per ecosystem, using `jellyfish`. Requires distance of at least 1, so an exact match is never treated as a typo.
4. **Metadata risk:** age, maintainer count, monthly downloads.

**Architecture invariants (justified by benchmark evidence)**
- **Stages 3 and 4 always run**, even when the package exists. 222 hallucinated Python names collide with real obscure packages and were missed by both baseline tools.
- **Fail closed:** any registry error scores as high risk. 62 of the 222 misses were network failures silently treated as clean.
- **Heuristics alone can never hard-block:** the maximum heuristic score is 74 (32 + 25 + 8 + 9), below the 90 threshold. Only a 404 or fail-closed error reaches 100.
- The typosquat reference corpus stays independent of the scoring ground truth (a data-leakage bug was found and fixed).

**Scoring**

| Signal | Points |
|---|---:|
| Existence 404, or registry error (fail closed) | +100 |
| Typosquat signal (distance <= 0.20, or age-conditioned hybrid rule) | +32 |
| Age under 120 days | +25 |
| Single maintainer | +8 |
| Downloads under 100 per month | +9 |

Bands: 0-39 clean pass, 40-89 middle-band flag (developer review), 90-100 hard block.

**Dataset.** About 24,000 labeled records across seven categories, built from Spracklen et al. (PackageHallucination), LibHalluBench (EMNLP 2026), Trend Micro slopsquatting data, live npm registry corpora, the `npm-rank` list, and Node core modules. The benchmark run covered 23,192 packages.

**Benchmark: tools compared.** slopcheck, dep-hallucinator (its `ml_engine.py` contains no real ML), matt-slopcheck, slopguard.

**Locked results**

| Metric | Target | Result | Status |
|---|---|---|---|
| Python lenient recall | >= 98.00% | 97.05% | Short by 0.95 pt |
| Python lenient FPR | < 10.00% | 11.99% | Short by 1.99 pt |
| Python runtime | < 367.51 s | 317.02 s | Pass |
| JS lenient recall | >= 98.60% | 97.01% | Short by 1.59 pt |
| JS lenient FPR | < 10.00% | 1.51% | Pass |
| JS runtime | < 186.38 s | 124.50 s | Pass |
| Network errors (23,192 live requests) | 0 | 0 (dep-hallucinator: 942) | Pass |
| Blind-spot set (222 collisions) | maximize | 57/222 (25.7%) | Baselines: 0/222 |

**The recall/FPR tradeoff.** Pushing FPR down to 8.28% collapsed blind-spot catches from 105/222 to 5/222. The shipped hybrid rule (57/222 at 11.99% FPR) is a deliberate middle point.

**Engineering lessons**
- Switching to `asyncio.gather` first made runtime worse (507 s to 568.9 s) because of two bugs: `asyncio.to_thread` dispatching 16,784 microsecond-scale cached calls to a 32-worker pool (lock contention), and the semaphore being held during backoff sleeps. After fixing both (487.6 s), HTTP/2 multiplexing brought Python to 317 s and JS to 124.5 s.
- npm scoped URLs: keep `@` literal and percent-encode `/`.
- `age_days` is computed live, so a package at a threshold edge can flip category between runs. This is documented, not a bug.

**Code comparison (shipped code)**

| Tool | Core LOC | Typosquat corpus | Concurrency | ML |
|---|---:|---|---|---|
| slopcheck | ~1,760 | ~37 PyPI / ~32 npm (hardcoded) | ThreadPoolExecutor | None |
| dep-hallucinator | ~12,581 | curated list | asyncio | None (fake `ml_engine.py`) |
| matt-slopcheck | ~916 | none | Promise.all(10) | None |
| slopguard | ~913 | none | Promise.all(12) | None |
| **CipherGuard** | **~674** | **10,000 per ecosystem** | asyncio + HTTP/2 | None |

slopcheck's tiny corpus explains its false positives on legitimate names like `motor` and `flair`.

**Non-goals v1.** No ML or LLM, no instruction-file scanning (AGENTS.md, .cursorrules), no crates.io or Go. **Known scope limit:** hallucinations mostly appear as `import x` or `pip install x` inside code, which v1 does not parse. State this in the paper.

### 6.2 Secret Detection (Dev A)

**Purpose.** Find hardcoded credentials, API keys, tokens and connection strings.

**Spec [Specified].** Wrap Gitleaks or TruffleHog as a subprocess, add Shannon entropy as a second pass, filter placeholders with an allowlist engine, classify by secret type, assign severity. LLM-free.

**As built [Built].** The audit found a native deterministic scanner rather than a Gitleaks wrapper: vendor signatures (13 families), structural context (connection strings, quoted assignments), entropy scoring, suppression, and masked previews. This differs from the spec text, so the documents must describe what exists.

**Rules**
- Never return a full secret; masked previews only.
- High-confidence secret types are eligible for the engine's hard-block override.
- Output must carry `category` (the secret type), `location` (file and line), and `confidence` on a 0-1 scale.

**Known issues (audit F10, fixed in Checkpoint 1).** Blanket suppression of values containing "test", "sample" or "example" dropped real vendor-signature and context-confirmed secrets; credentials shorter than eight characters were suppressed; unquoted env/YAML assignments were missed; confidence came back as 30.0 instead of 0.3; category and location were not populated.

**Benchmarked against** Gitleaks, TruffleHog and Betterleaks. Not a novelty claim: it is the schema and Docker template for the other agents and contributes a signal to fusion.

### 6.3 Code Security (Dev C)

**Purpose.** Statically analyze AI-generated source for OWASP-style vulnerabilities.

**Spec [Specified].** Tree-sitter parsing, Semgrep with OWASP Top 10 rules plus custom rules for LLM-typical patterns, CWE mapping and severity, remediation per finding, Bandit for Python.

**As built [Built].** Semgrep subprocess with 37 bundled custom rules: Python 10, JS/TS 9, PHP 9, Java 9. **Go has no rules.** No Bandit, CodeQL or Tree-sitter integration.

**Languages to detect**
- **Specified minimum:** Python, JavaScript, Go (the evaluation dataset spans these three).
- **Recommended tiers:** Tier 1 Python, JavaScript, TypeScript; Tier 2 Go; Tier 3 optional Java and PHP.
- **Current reality:** Python, JS/TS, PHP and Java are covered; Go is intentionally reported as partial coverage. [Decision, assistant-proposed: do not add Go rules for now.]

**Vulnerability classes** (CWE mapping [Recommended]): SQL injection (89), XSS (79), OS command injection (78), path traversal (22), deserialization (502), weak crypto (327/328), hardcoded credentials (798), broken TLS verification (295), SSRF (918), XXE (611), open redirect (601), code injection (94).

**Custom LLM-pattern rules [Recommended]**
- Python: `shell=True` on user input, `pickle.loads`, `yaml.load` without SafeLoader, `eval`/`exec`, f-string SQL, md5/sha1 for passwords, `verify=False`, Flask `debug=True`.
- JS/TS: `child_process.exec` with concatenation, `innerHTML`/`dangerouslySetInnerHTML`, template-literal SQL, `eval`, `Math.random` for tokens, disabled TLS.
- Go: `exec.Command("sh","-c",...)`, `fmt.Sprintf` SQL, `InsecureSkipVerify`, `math/rand` for tokens.

**Rules.** Deterministic, no LLM. Analyze snippets and diffs, not only whole repos. Pin Semgrep and rule-pack versions. Unsupported language returns a stub, never a silent pass.

**Audit findings (fixed in Checkpoint 1).** JS/TS severities were downgraded below the severity floor (F16); `.jsx`, `.tsx`, `.mjs`, `.cjs` were routed but rejected by the agent (F07).

### 6.4 Docker Security (floating, AB00d)

**Purpose.** Analyze Dockerfiles and container configuration and produce hardening suggestions.

**Pipeline [Built].** Auto-detects Compose versus Dockerfile; custom Dockerfile and Compose rules; Hadolint; Trivy config; Docker Hub existence checks; optional Trivy image CVE scan (default off); hardening suggestions with a re-lint comparison.

**Checks.** Root user, unpinned or `:latest` base, exposed sensitive ports, embedded secrets, remote shell execution, TLS bypass, health checks, registry allowlist; Compose: privileged mode, docker socket and host mounts, namespaces, capabilities, resource limits, exposed database ports.

**Notes.** Trivy v0.74.0 JSON check IDs are hyphenated (for example `DS-0001`); pin the Trivy version. Cold Trivy CVE scans are a main latency risk, so the vulnerability database should be pre-baked and cached.

**Audit findings (fixed in Checkpoint 1).** Missing or failing Hadolint/Trivy produced empty (clean-looking) results (F04); image references like `alpine@sha256:...`, `localhost:5000/...` and stage aliases were parsed wrongly (F12); the hardener's output was not build-verified and mishandled Alpine, scratch images and multi-stage files (F11). Hardening is now labelled **suggested changes**, not verified fixes.

### 6.5 Workflow / CI-CD Security (Dev C)

**Purpose.** Validate GitHub Actions workflows for supply-chain risk.

**Rules [Built].** Safe YAML parsing with `on`/True normalization; actions not pinned to a full commit SHA; broad permissions combined with dangerous triggers (job-level and reusable workflows included); `curl | bash` and PowerShell equivalents. Fully rule-based for determinism.

**Suggested extra rules [Recommended].** `pull_request_target` with checkout of the PR head; untrusted `github.event.*` expressions in `run:` steps; self-hosted runners on public repos.

**Honest positioning.** zizmor already does this well. We claim integration and consistent scoring, not better detection.

**Limits.** GitLab CI is not supported (reported as partial coverage). Real basis: the 2025 tj-actions compromise.

**Audit findings (fixed).** Crashes and malformed expected workflows now return `error` (F17); GitLab files no longer get silent full coverage (F01).

### 6.6 License Compliance (Dev B)

**Purpose.** Identify license conflicts introduced by AI-suggested dependencies.

**Pipeline [Built].** Extract dependencies; registry license lookup (PyPI, npm) with ScanCode text fallback; policy modes (no-copyleft, permissive-only, custom); limited transitive check (one level, capped at 10); cache; findings only for conflicts and reviews.

**Rules.** An unknown or unresolved license **holds Review** regardless of confidence. License expressions are parsed as a full tree (AND, OR, WITH, nesting); an unresolved AND branch is never reduced to a permissive license.

**Decision [assistant-proposed, confirm].** A license conflict (for example GPL/AGPL under a no-copyleft policy) **holds Review**; only an explicit organization denylist rejects.

**Limits.** No full lockfile or SBOM graph; npm caret/tilde ranges are not resolved to installed versions; ScanCode only scans license metadata text, not package source archives.

### 6.7 Prompt Injection Detection (Dev B)

**Purpose.** Detect hidden or adversarial instructions in comments, docstrings, string literals and Markdown that could hijack a downstream AI agent. The only agent with an ML/LLM component.

**Design: layered funnel [Built].**
1. **Lexical heuristics** (instruction-override phrases, obfuscation: zero-width characters, base64/hex, ROT13, spacing tricks). Synchronous.
2. **Embedding similarity** against 60 known injection anchors, with a bag-of-words fallback if model weights are missing. Synchronous.
3. **LLM judge** (local Ollama Llama 3, with an OpenAI path in the agent's client) for borderline spans. Asynchronous: the service returns `pending` with a `callback_id`, runs the judge in the background, then posts an authenticated callback to the Trust Engine.

A partial gate lets stages 1-2 hard-block synchronously. Cross-span weak signals can be correlated.

**Rules.** Quarantine suspicious segments rather than silently accepting. Layered detection reduces but does not eliminate evasion (documented in arXiv:2504.11168). Normalize text (homoglyphs, zero-width) before heuristics.

**Audit findings (fixed or partly fixed).** The judge parser coerced `{}` into "not injection" and `"false"` into truthy (F13); ties favored "not injection". It now requires a strict typed verdict (boolean plus finite 0-1 confidence), and ties or failed quorums are unresolved. **Not yet fixed:** durable delivery. Background tasks live in process memory, so a restart loses them (F20).

### 6.8 The Trust Engine

Covered in section 9.

---

## 7. Why the agents are deterministic (no ML)

**CipherGuard** (the evidence-based case)
- The failures were deterministic bugs. 72% of the 222 blind-spot packages were name collisions (existence-only checks cannot tell "the package the AI meant" from an obscure real one), and 28% were registry errors treated as clean. Always running typosquat and metadata checks plus failing closed fixed both without a model.
- ML had nothing left to catch: the benchmark showed zero misses caused by subtle naming-plausibility tricks, the only thing an ML or LLM classifier would help with.
- **Explainability:** every flag traces to a rule and a point value.
- **Safety guarantee:** heuristics max out at 74, under the 90 hard-block threshold, so a legitimate new package is never auto-rejected without human review. A learned model cannot offer that kind of guarantee.
- **Reproducibility and speed:** repeatable results, no training data to leak or go stale, runtime targets met without inference.

**Other agents.** Secret Detection, Workflow, Docker, Code Security and License Compliance ask well-defined questions ("is this action pinned to a SHA?") that rules answer accurately and audibly. A model adds risk without adding coverage.

**Where ML belongs.** Prompt Injection's semantic layer, because indirect injection needs language understanding that regex cannot provide. It runs asynchronously so its latency does not block other agents.

**The honest tradeoff.** Determinism costs some recall (CipherGuard is 1-1.6 points below its original recall targets, and its Python FPR is 11.99% against a 10% target). This is a deliberate, documented choice.

---

## 8. Routing logic (final)

The router is a **pure, deterministic function**: no network calls, no LLM, no side effects. It is driven by a rule table checked in precedence order.

### 8.1 Type resolution (first match wins)
1. **Explicit `artifact_type`.** Validate against the enum (invalid returns HTTP 422). An explicit value wins; a conflict with filename inference adds a note.
2. **Path and filename rules.** Normalize `\` to `/`, case-insensitive; specific paths before generic extensions.
3. **Content sniff** (only with no filename, only when confident): `FROM` first line means Dockerfile; YAML with both `on:` and `jobs:` means workflow; JSON with `dependencies`/`devDependencies` means dependency manifest.
4. **Fallback:** `unknown`.

A generic `*.yml` outside a workflow path is `unknown`.

### 8.2 Routing table [as specified in the router spec]

| Type | Agents |
|---|---|
| code | Code Security, Secret Detection, Prompt Injection |
| dockerfile | Docker Security, Secret Detection |
| workflow | Workflow/CI-CD, Secret Detection |
| dependency | CipherGuard, License Compliance, Secret Detection |
| unknown | Secret Detection only, `coverage: partial` |
| lockfile, binary, oversized (over 1,000,000 bytes) | none, `coverage: none` |

Rules that go with the table:
- **Secret Detection runs on every text artifact** under the size limit.
- **CipherGuard only receives files its parser supports** (`requirements*.txt`, `package.json`). Lockfiles are not dependency manifests: treated as `unknown`, coverage `none`, and Secret Detection is skipped on them (hash-heavy content causes entropy false positives).
- **Prompt Injection** is on code by default. Widening it to other text formats depends on what Dev B's extractor supports.
- Unknown-type artifacts go to Secret Detection only. Because a clean result on an unknown file would otherwise yield a high score, **partial coverage floors the decision at Review**. The unrecognized-type note belongs in the engine's `routing` block, not in an agent's evidence.

### 8.3 Capability corrections made in Checkpoint 1
The audit showed the router sent things agents could not handle (and the opposite). Checkpoint 1 introduced **one capability matrix** that drives the router, API validation, detector guards, docs and tests:
- `docker-compose.yml` / `compose.yaml` now route to Docker Security.
- README / Markdown routes to Prompt Injection.
- `.java` and `.php` route to Code Security; `.jsx`, `.tsx`, `.mjs`, `.cjs` are accepted by Code Security.
- Go, GitLab CI, `pyproject.toml` and Pipfile report **partial coverage** rather than silent full coverage.
- After routing, the orchestrator forwards a canonical request (resolved type, ecosystem, original filename) so guards stop rejecting inferred types.

### 8.4 Multi-file requests
Treat every request as a list of files. Route each file separately and call each expected agent once per file in the existing single-file format, so **agent input contracts do not change**. Aggregate at fusion. Add a files-per-request cap and a concurrency semaphore. Prompt Injection may have several pending callbacks per request, so store one `callback_id` per (file, agent) pair.

### 8.5 LangGraph structure
State: `request_id`, `files`, `routing`, `results` (with an `operator.add` reducer so parallel branches append), `pending_callbacks`, `score`.

`ingest -> route -> conditional edge (one Send per (file, agent)) -> call_agent (parallel) -> fuse -> explain -> persist -> END`

- `call_agent` must never raise; a timeout or transport failure becomes `status="error"` with `agent_ran=True`.
- Prompt Injection: synchronous stages return inline; a pending stage produces a **provisional** score. A separate callback entry point re-runs fusion and updates the stored result.

### 8.6 Tests that guard routing
Table-driven checks for every row; precedence (`.github/workflows/a.yml` is workflow, `config.yml` is unknown, `Dockerfile.dev` is dockerfile, `Requirements-Dev.TXT` is a dependency manifest); explicit overrides inference; invalid type returns 422; unknown type gets Secret Detection only and Review; killed detector gives Review, never Accept; skipped agent has `agent_ran=False`; binary or oversized input has coverage none; mixed multi-file requests fan out correctly.

---

## 9. Trust Engine: fusion, scoring and the ML plan

### 9.1 What the engine does
It performs no detection. It routes, fans out, fuses and explains.

### 9.2 Fusion rules [Specified, as built after Checkpoint 1]
- **Only agents that ran contribute.** Normalization uses the weights of agents that ran, so skipped agents neither reward nor penalize.
- **Hard overrides first:** CipherGuard score of 90 or more, a confirmed high-severity secret, a Prompt Injection hard block, a critical Code Security finding, a Docker escape or invalid-image block, a Workflow critical finding. These Reject regardless of the weighted score.
- **Weighted base score:** `100 - sum(severity weight x confidence)`, floored at 0.
- **Fail closed:** `error`, `stub`, `pending`, unresolved licenses, partial or no coverage can never produce Accept; they hold at Review.
- **Provisional scores:** pending Prompt Injection returns a flagged provisional score until its callback resolves.
- **Decision bands (as built):** Accept at 80 or more, Review from 50, Reject below. High or critical severity findings also floor the decision at Review.

### 9.3 Scorer seam (built in Checkpoint 1)
`services/trust_engine/app/scorers.py` defines `Scorer.score(state, total_risk)` returning a finite float in [0, 100]. `WeightedSumScorer` is the default. `fuse(state, scorer=...)` is the injection point. Hard overrides run first and do not invoke the scorer; coverage, status, unresolved, license-review and severity floors stay outside the model and are authoritative.

### 9.4 Feature log for ML (built in Checkpoint 1)
`FEATURE_LOG_PATH` controls append-only JSONL observations (default `/tmp/guardian-features.jsonl`, empty disables). Each event: feature_version, contract_version, request_id, timestamp, phase (`initial` or `callback`), files, outcome. Per file: artifact type, routing source, routing coverage, and seven agent keys; unselected or missing agents are **null**, never zero. Completed results carry coverage, unresolved, decision floor, severity counts, max confidence, hard blocks, numerical agent-specific scores (including CipherGuard package scores) and elapsed time.

Privacy: the log excludes content, paths, package names, snippets, reasons, secrets and prompts, uses a numeric whitelist, and files are created with mode 0600. Training rows should use `callback`-phase rows where Prompt Injection went pending; initial rows are provisional.

### 9.5 The ML plan (teammate's piece)
The documented intent is a weighted-sum baseline, with a transition to a trained XGBoost or logistic-regression model once labeled data exists, and SHAP for per-agent contributions. Agreed constraints:
- Keep the hard overrides and uncertainty floors as the safety layer. ML can never accept something an override rejects.
- Use **monotonic constraints**: more severe findings, higher confidence, missing checks or more uncertainty can never raise the score.
- **Compare against the weighted baseline** and report honestly if the model does not win.
- **SHAP is only meaningful with a trained model.** For the weighted-sum scorer the per-agent contribution already is the explanation. Do not claim SHAP explanations for a scorer that is not a model.

### 9.6 The dataset
**No labeled fused dataset exists.** Existing data is per-agent (CipherGuard's 24k package records, small service fixtures, six hand-written Prompt Injection cases). The ML teammate builds one, with these rules:
- Unit is an **artifact**; label is the desired decision (Accept / Review / Reject, or a 0-3 severity).
- **Labels must not come from the detectors.** Assign them by construction (planted bug, secret, hallucinated package, injection) or by human review. Otherwise the model learns the rules back.
- Sources: clean files from well-known permissively licensed repos; seeded vulnerabilities; fabricated but realistic keys; hallucinated names from existing datasets; tj-actions-style workflows; public injection datasets; reviewed AI-generated artifacts.
- Size and balance: at least a few hundred artifacts across the five types and three labels. Critical cases will be rare, which is one reason overrides stay.
- Splits grouped by source repo or generator; a held-out set written by someone other than the rule author.
- The runner `scripts/run_labeled_corpus.py` (Checkpoint 2) reads a manifest, submits each artifact, waits for callbacks, and writes a CSV mapping `sample_id` to `request_id` and label, so the feature log can be joined with labels.

### 9.7 Explanation layer: unresolved choice
The Final Documentation says an LLM may write the explanation text; the paper says SHAP-rendered explanations. Pick one and make all documents agree. Recommended: deterministic per-agent contributions (and SHAP only with a trained model); an LLM may narrate verified results but never decide.

---

## 10. Interfaces

| Interface | Spec | Priority |
|---|---|---|
| CLI / pre-commit hook | Primary and IDE-agnostic. Prints score and top reasons; exits non-zero below a configurable threshold (CI gate); staged-file and snippet modes | Primary |
| Web dashboard | React + TypeScript + Tailwind. Submit artifact, score and decision, coverage, evidence cards, pending polling, history, audit PDF export. Requires same-origin proxy or scoped CORS | Secondary |
| VS Code extension | Inline diagnostics before acceptance; handles provisional-score updates | Secondary |
| LSP | JetBrains and Vim support | Future scope |

Current state: the frontend is a scaffold (a single heading); there is no CLI, hook or extension yet.

---

## 11. Testing and evaluation plan

### 11.1 Test data [Specified]
Synthetic AI-generated artifacts across Python, JavaScript and Go: hallucinated names, OWASP-style vulnerable snippets, secret-laden samples, unsafe Dockerfiles, risky workflows, license-conflict manifests, injection payloads, plus clean controls for false-positive rate and mixed artifacts for routing and partial-agent fusion.

### 11.2 Real-world basis per agent

| Agent | Basis |
|---|---|
| CipherGuard | Spracklen et al. (USENIX Security 2025); benchmark vs existing tools |
| Code Security | OWASP Top 10 |
| Secret Detection | Common leak patterns in AI-generated code |
| Docker | CIS Docker Benchmark |
| Workflow | 2025 tj-actions compromise |
| License | SPDX compatibility matrix |
| Prompt Injection | OWASP LLM Top 10 (#1); evasion literature |
| Trust Engine | Calibration against combined agent severity |

### 11.3 Metrics
Precision, recall and FPR per agent; per-agent latency p50/p95 (cold and warm separately); end-to-end synchronous latency (target under 3 s for six non-LLM agents, not yet validated); time-to-final for async Prompt Injection; Trust Score calibration (score versus labeled severity, with an ablation dropping each agent); router correctness; failure behaviour (a killed detector must degrade to Review).

### 11.4 Latency reality
Main risks: Prompt Injection LLM inference (1-3 s), cold Trivy CVE scans, ScanCode, and **cold Semgrep, whose first invocation exceeded the scanner's 8 s bound** in the Checkpoint 1 environment. Microservice network overhead is small (about 10-50 ms). The scoped claim stands: six agents synchronous, Prompt Injection asynchronous. Report measured numbers even if the target is missed.

### 11.5 Results
Paper Results tables (CipherGuard benchmark table, end-to-end latency, calibration) are still placeholders pending measurement.

---

## 12. Project history: what happened, in order

1. **Specification review.** The full project was reviewed from the Synopsis, Final Documentation, paper draft and CipherGuard report. A 16-page master specification PDF was produced covering scope, every agent, the Trust Engine, interfaces, testing, status and remaining work. Code Security languages were clarified (Python, JavaScript, Go minimum; recommended tiers).
2. **Routing design review.** A teammate proposed routing rules (Secret Detection on every artifact, Prompt Injection on code only, infer artifact type from filename, unknown type goes to Secret Detection). The logic was found sound, with five improvements: do not send lockfiles to CipherGuard, add a coverage indicator so unknown files cannot get a full-confidence Accept, make `artifact_type` optional but validated, record the routing source, and make Prompt Injection scope a Dev B decision. A final routing spec was written as `ROUTING_SPEC.md`.
3. **Interface agreement.** The router/orchestrator/fusion boundary was settled: per-file routing with no agent contract changes, one shared stub rule for all seven agents, and an explicit per-(file, agent) field list. This was delivered as a 2-page PDF.
4. **Status literal and state model.** The Trust Engine's status literal was missing `error` and `pending`; it was fixed along with `callback_id`. The shared state model was placed in `trust_engine/app/state.py`, importing `AgentResult` from `schemas.py`. All seven agents were updated to the six-value literal.
5. **Eight components done.** All agents, routing and the Trust Engine were reported built. The question "what is left" was answered (integration hardening, persistence, interfaces, evaluation, documents), alongside the rationale for deterministic agents.
6. **Implementation audit.** A coding agent audited the whole repository (205 files) and produced 26 findings (section 13).
7. **ML plan.** The Trust Engine developer proposed XGBoost plus SHAP under the existing hard overrides. The plan was approved with one change of order: fix the contract and fusion bugs first, because a model trained on the audit's defects would learn them. The data problem was clarified: no labeled fused dataset exists, so one must be built.
8. **Checkpoint 1.** A detailed prompt drove the agent through contract, routing, fusion and detector fixes plus ML readiness. It completed with 401 passing tests across eight suites (section 14).
9. **Next steps prepared.** A Checkpoint 2 prompt (latency, persistence, async reliability, interfaces, evaluation tooling, docs) and a teammate handoff message were prepared, with the agent permitted to push and write the message.

---

## 13. Implementation audit (26 findings)

Audit date 11 October 2026, over 205 tracked files. Verdict: all seven detectors contain real logic, but the product was not dependable end to end. Keep the microservices and the router/orchestrator/fusion separation; repair the contract first; do not rewrite agents.

### P0: verdict and coverage correctness
| ID | Finding |
|---|---|
| F01 | Expected `stub` results could yield Accept / 100 (for example GitLab CI, JSX/TSX, malformed workflows) |
| F02 | Unknown license findings contributed zero penalty at confidence 0, yielding Accept |
| F03 | CipherGuard emitted a finding for every clean package; 21 clean packages scored 49.6 and Rejected |
| F04 | Docker tool failures (missing binaries, timeouts) looked like zero findings; registry errors cached as "exists" |
| F05 | Detector finding fields were silently stripped at the Trust Engine boundary |
| F06 | Docker hard blocks were not preserved by fusion |

### P1: integration and scanner behavior
| ID | Finding |
|---|---|
| F07 | Real capabilities unreachable or mis-routed (Compose, Markdown, Java, PHP, JSX/TSX, Go) |
| F08 | Inferred artifact type not forwarded to detectors, so guards stubbed valid input |
| F09 | Malformed or unsupported manifests passed as clean |
| F10 | Secret suppression dropped real credentials |
| F11 | Docker hardener output not build-verified; Alpine, scratch and multi-stage mishandled |
| F12 | Image reference parsing broken (digest, registry port, stage aliases, non-Hub registries) |
| F13 | LLM judge output coerced permissively into a verdict |
| F14 | Detector timeout budgets do not fit the 10 s cap; no global worker bound |
| F15 | Cache implementations diverge from configuration; failures cached |
| F16 | JS/TS vulnerabilities downweighted below the severity floor |
| F17 | Workflow crashes reported `fail` with no findings, which fusion accepted |
| F18 | Partial license expressions lost obligations (`MIT AND Proprietary` became `MIT`) |

### P1/P2: API, state and operations
| ID | Finding |
|---|---|
| F19 | Schemas lacked invariants (unbounded confidence, pending without callback, no agent-name check) |
| F20 | Async Prompt Injection work is not durable (in-memory tasks, no overdue finalization) |
| F21 | Scan history absent despite database tables; `GET /scans` 404s for initially final scans |
| F22 | Migration and deployment path incomplete (Alembic offline mode, env loading, no migrate/seed in Compose) |
| F23 | Configuration is descriptive, not executable; README and config claims stale |
| F24 | Health and deployment do not establish usable scanning; most containers run as root |
| F25 | Browser and client integration unbuilt (no dashboard, CLI, hook, extension, CORS) |
| F26 | Reproducibility and evaluation gaps (loose dependency pins, no CI, latency tooling issues) |

---

## 14. Checkpoint 1: results and status

Branch `codex/checkpoint-1-contracts`. No trained model, XGBoost or SHAP was built, by design. All eight suites were run to completion with fakeredis and Semgrep installed: **401 tests pass** (Trust Engine 191, CipherGuard 16, License 33, Prompt Injection 41, Code Security 27, Docker 38, Secret Detection 29, Workflow 26). Real bundled Semgrep rules executed; registry and LLM correctness tests used controlled responses. "Fixed" means a local regression passes, not a verified deployment.

| ID | Status after Checkpoint 1 | Remaining |
|---|---|---|
| F01, F02, F03 | Fixed | Deployment verification; independent live calibration for F03 |
| F04 | Fixed | Container and CVE-image verification blocked or unrun |
| F05 | Fixed | Running-stack schema audit blocked |
| F06 | Fixed | Policy sign-off may refine rules |
| F07, F08 | Fixed | Go, GitLab, pyproject/Pipfile intentionally partial |
| F09, F10 | Fixed | Broader corpus calibration (F10) |
| F11, F12 | Fixed | Build verification absent; external-registry verification explicitly unverified |
| F13 | Fixed | Live model quality; durable delivery |
| F14 | Not fixed | Deadlines, bounded workers; cold Semgrep exceeded 8 s |
| F15 | Partial | Redis URL consistency, memory TTL/size limits |
| F16, F17, F18, F19 | Fixed | See notes in the status file |
| F20, F21, F22 | Not fixed | Checkpoint 2 |
| F23 | Not fixed | Make configs executable; reconcile claims |
| F24 | Partial | Other services' readiness, non-root, scoped secrets, resource limits |
| F25 | Not fixed | Dashboard, CLI, hook, CORS, multi-file API |
| F26 | Partial | Pins, CI, percentile and time-to-final fixes |

Promised features still **not built**: PostgreSQL scan history, dashboard, CLI and pre-commit hook, public multi-file API, XGBoost model, SHAP explanations, Docker build verification, a ten-second end-to-end guarantee. **Not confirmed:** a full Compose end-to-end scan, because Docker socket access was denied.

Other notes: the original TestClient hangs did not reproduce (cause unconfirmed); the verification venv inherits system packages, so it is not a clean-environment run; host Hadolint 2.15.1 and Trivy 0.74.0 smoke scans completed.

---

## 15. What is left

### 15.1 Checkpoint 2 (agent work, in order)
1. **Latency and readiness** (F14, F15, F24): warm up Semgrep and report degraded readiness until a real scan succeeds; end-to-end deadline budgets under 10 s; bounded global workers; one Redis URL convention; cache TTLs and size limits; no cached failures; honest readiness for every service; non-root containers; scoped secrets; resource limits.
2. **Persistence and lifecycle** (F21, F22): PostgreSQL writes for scans, agent results, findings, routing and score; fix Alembic and the Integer score precision; migrate and seed agents in Compose with healthcheck-based `depends_on`; `GET /scans/{id}` for every scan; paginated history.
3. **Async reliability** (F20): durable Prompt Injection callback retry, overdue scans finalized as timeout/error (never Accept), atomic callback updates.
4. **Interfaces** (F25): public multi-file API with per-file outcomes and bounds; CLI with exit codes and threshold; pre-commit hook; same-origin proxy or scoped CORS; minimal dashboard with PDF export.
5. **Evaluation tooling** (F26): pinned dependencies; CI for all eight suites and the contract drift check; percentile fix; async time-to-final; evaluation-claim cleanup; `scripts/run_labeled_corpus.py`.
6. **Docs** (F23): configs executable or claims deleted; README and config match the code; state that no trained model or SHAP exists yet.

Scope guard: the agent must not modify `scorers.py`, the `fuse()` seam, or the feature-log schema (except for reported bug fixes), so the ML teammate's parallel work stays conflict-free.

### 15.2 ML work (teammate)
Build the labeled artifact corpus; run it through the stack to produce features; train a monotonic XGBoost (or logistic regression) `Scorer`; compare against the weighted baseline; add SHAP only for the trained model; keep the overrides authoritative.

### 15.3 Evaluation and research
- Synthetic end-to-end dataset with labeled severity and clean controls.
- Per-agent and end-to-end latency (p50/p95, cold and warm), including time-to-final.
- Calibration plus an ablation (drop each agent, show the effect), a strong viva exhibit.
- Held-out attacks not written by the rule author; pinned versions and provenance so results can be regenerated.

### 15.4 Documents and paper
- Reconcile the paper with the real build (section 16), fill the Results tables, port the ten-paper literature review into the empty paper section, and fill the Prompt Injection and Trust Engine descriptions.
- Submission documents: SRS, SDD (with router and `agent_ran` decisions), Gantt chart, test plan and cases, user manual, final report, deck, demo video, plagiarism report.

### 15.5 Priority if time is short
Protect, in order: end-to-end and failure tests, latency numbers, CLI plus demo video, paper reconciliation, persistence and dashboard. Cut or shrink the VS Code extension first.

### 15.6 Re-verification loop
After the teammate pushes, pull and ask the agent to re-verify against the new push using `docs/STATUS.md` as the baseline, then complete whatever remains.

---

## 16. Documents vs build: inconsistencies to fix

| Topic | What documents say | What is true | Fix |
|---|---|---|---|
| CipherGuard ML | Paper, Final Documentation, Synopsis: scikit-learn classifier, "ML-based hallucination prediction" | Fully deterministic; ML rejected with benchmark evidence | Rewrite as the deterministic 4-stage pipeline and keep the rejection rationale |
| Similarity library | RapidFuzz / python-Levenshtein | `jellyfish` with normalized distance | Update tech-stack tables |
| Registries | PyPI, npm, crates.io; OSV.dev | PyPI and npm only; OSV and crates.io not implemented | State scope honestly; move crates.io to future work |
| Benchmark comparators | dep-hallucinator, slop-scan, slopcheck, Aikido SafeChain | Actually run: slopcheck, dep-hallucinator, matt-slopcheck, slopguard | Update paper tables |
| Agent count | Synopsis: 8 agents including a Hallucination Detection agent | 7 detectors plus the Trust Engine; hallucination detection is CipherGuard | Align wording |
| Trust Engine ML | Synopsis: "custom ML models", predicts hallucination risk | Deterministic scorer; model is the planned teammate piece | Word as baseline plus planned extension |
| Explanation layer | Final Documentation: LLM; paper: SHAP | Undecided | Choose one |
| Secret Detection | Gitleaks/TruffleHog wrapper | Native vendor, structural and entropy detectors | Describe what exists |
| Code Security | Python, JS, Go; Bandit, Tree-sitter | Python, JS/TS, PHP, Java rules; no Go, Bandit or Tree-sitter | Describe what exists |
| Prompt Injection | Regex plus Llama 3 | Heuristics, embeddings, LLM judge, callbacks | Update description and latency discussion |
| Literature review | Paper section II empty | Ten-paper table exists in the Final Documentation | Port it |
| Config claims | Configs describe SHAP, weights, thresholds, OSV | Several are not loaded by runtime code (F23) | Make executable or delete |

---

## 17. Viva preparation

| Likely challenge | Prepared answer (backed by data) |
|---|---|
| Why no ML in CipherGuard? | The benchmark showed zero misses from naming-plausibility tricks; the real failures were collision blindness and fail-open errors, both fixed deterministically, with explainability preserved |
| Your recall is below target | Deliberate tradeoff: lowering FPR to 8.28% dropped blind-spot catches from 105/222 to 5/222; the shipped rule keeps 57/222 where baselines catch 0 |
| Why microservices for a student project? | Three parallel developers, no merge conflicts, independent dependencies; network overhead is about 10-50 ms |
| What is actually novel? | Pre-acceptance interception and the fusion/explainability layer; individual detectors wrap mature tools and we say so |
| Is the Trust Score really predictive? | Calibrated deterministic fusion today; a trained model is a constrained extension compared against the baseline; do not oversell |
| Is 3 seconds real? | Scoped claim: six synchronous agents, Prompt Injection async; show measured p50/p95 including misses |
| A detector is down; what happens? | Status `error`, `agent_ran` true, score floored at Review: fail closed |
| Why can CipherGuard heuristics never hard-block? | Maximum heuristic score is 74, below the 90 threshold, so a new legitimate package is never auto-rejected without human review |
| How do you know the system works end to end? | Say what is verified (401 local tests, real Semgrep, host Hadolint/Trivy) and what is not (full Compose stack until Docker access is fixed) |
| What did your audit find? | 26 findings; fixed the contract, routing and fail-open issues first; show the status table |

---

## 18. Submission checklist

| Document | Status |
|---|---|
| Project Synopsis | Exists; update wording per section 16 |
| SRS | To do |
| System Design Document (diagrams, DFD, ER, sequence) | To do; include router and `agent_ran` decisions |
| Gantt chart | To do |
| Literature survey | Content exists in the Final Documentation; port into the paper |
| Test plan and test cases | To do; include the CipherGuard benchmark comparison |
| User manual | After CLI, extension and dashboard |
| Source repository and README | Per-service READMEs and the main README must match the code |
| Final project report | Draft exists; Results pending |
| Presentation deck (10-15 slides) | To do |
| Demo video (3-5 min) | To do; live intercept, route, analyze, score |
| Plagiarism / originality report | To do |
| Research paper (fusion methodology) | First draft exists; Literature, Results, reconciliation pending |

---

## 19. Open decisions

| Decision | Current default |
|---|---|
| License conflict: Reject or Review? | Review; only an explicit denylist rejects *(assistant-proposed, confirm)* |
| Add Go rules to Code Security? | No; Go stays partial coverage *(assistant-proposed, confirm)* |
| Explanation layer: SHAP, direct contributions, or LLM narration? | Direct contributions; SHAP only with a trained model; LLM may narrate verified results only |
| Does Prompt Injection extend beyond code? | Code and Markdown today; widen only if Dev B confirms the extractor |
| Does Docker accept Compose files? | Yes, as built |
| Where do the Accept/Review/Reject thresholds live for the CI gate? | Configurable constants (80 / 50 as built) |
| Include the VS Code extension? | Last priority; first to cut |

---

## 20. Glossary

| Term | Meaning |
|---|---|
| Slopsquatting | Registering a package name that AI models hallucinate, so an install fetches attacker code |
| Typosquat / combosquat | A package name close to a popular one, or a popular name plus extra words |
| Fail closed | On error or uncertainty, treat the result as risky or needs-review, never clean |
| Hard override | A rule that forces Reject regardless of the weighted score |
| Coverage (full, partial, none) | How much of the intended analysis actually ran on an artifact |
| `agent_ran` | Set by the orchestrator: the call was attempted (even if it errored or is pending) |
| Provisional score | A score issued while Prompt Injection's async judgment is pending |
| Scorer seam | The `Scorer` interface in `scorers.py` where a trained model can plug in below the overrides |
| Feature log | Append-only JSONL of per-request detector observations for ML training |
| Monotonic constraint | A model constraint so that more risk can never raise the score |
| Capability matrix | The single table that drives routing, API validation, detector guards, docs and tests |
| SBOM | Software bill of materials |
| SPDX | Standard license identifier and expression format |