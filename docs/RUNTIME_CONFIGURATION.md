# Current executable runtime configuration

See FINAL_PROJECT_DOCUMENTATION.md and USER_MANUAL.md for deployment and evidence. Only License and Prompt services consume YAML config; the other former placeholder YAML files were removed.

| Setting | Effect |
|---|---|
| TRUST_SCORER | weighted (default) or ml synthetic-pilot candidate; policy gates remain external |
| TRUST_MODEL_PATH | Native model JSON with adjacent metadata/checksum; bundled service/models/guardian.json by default |
| FEATURE_LOG_PATH | Privacy-safe JSONL observation version 2.0, including fixed numeric category groups; empty disables |
| DATABASE_URL | SQLite standalone, explicitly migrated PostgreSQL in Compose; no outage fallback |
| REDIS_URL | Bounded detector caches; cache failure does not certify a clean result |
| CALLBACK_TOKEN | Required authenticated callback secret; native launcher generates/scopes one without printing |
| CALLBACK_OUTBOX_PATH | Private bounded durable prompt job/result journal |
| PENDING_TIMEOUT_SECONDS | Default 180; late clean callbacks cannot replace timeout uncertainty |
| SCAN_WORKERS / GLOBAL_AGENT_WORKERS | Default 4 local scanner workers / 12 outgoing calls per process |
| SCAN_DEADLINE_SECONDS | Dispatch including queue, maximum 9; POST absolute work budget 9.8 seconds |
| MAX_BODY_BYTES | Default 2 MiB streaming cap, alongside smaller typed file/batch work limits |
| SEMGREP_TIMEOUT_SECONDS | Native request subprocess cap 7.5 seconds; CLI fallback remains bounded; cold warm-up separate 90-second budget |
| EMBEDDING_MODEL_PATH / EMBEDDING_MODEL_REVISION | Project-local MiniLM snapshot, otherwise pinned hub revision; readiness reports missing model |
| LLM_PROVIDER / OLLAMA_HOST / OLLAMA_MODEL / OPENAI_API_KEY / OPENAI_MODEL | Prompt judge only; provider output must satisfy typed verdict. Native launcher uses bounded guardian-judge alias |
| PROMPT_JUDGE_WORKERS | Default 1, hard maximum 2. Ollama JSON generation/context and threads are explicitly bounded |
| ENV_FILE | Explicit optional migration dotenv path; process settings take precedence |

Public response scoring metadata is persisted independently of detector evidence. Exact TreeSHAP explains the raw numerical model score before clamping/policy gates. Old feature-version-1 logs must not be silently mixed with version-2 model inputs. Model loading/inference error exposes weighted fallback; health reports failed model readiness in ml mode.

Native local setup has a captured Python 3.12/Linux resolved lock in evaluation/trust_model/runtime-python312-linux.lock.txt. CPU Torch comes from its official wheel index; direct container requirements remain separate. This is a platform dependency snapshot, not a hashed cross-platform universal lock. Data/model quality, tool availability, correct startup and measured latency are separate evidence.

The local/team app has no public multi-tenant authentication, TLS or automatic retention. Protect .data, SQL/journal volumes and backups; snapshots retain submitted content. Return redaction is credential-shaped output hygiene, not proof that every secret format is detected. Browser/editor and Docker checks remain separately reported.
