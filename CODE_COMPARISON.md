> Historical comparison snapshot; it predates Checkpoints 1–2. Current implementation and claims are documented in README.md, docs/STATUS.md and evaluation/README.md. External tool versions/quotes were not re-verified during Checkpoint 2.

# Code-Level Architecture Comparison — All Tools + CipherGuard

## 1. Summary Comparison Table

| Tool | Language & Runtime | Core LOC | Core Dependencies | Concurrency Model | Existence Check | Typosquat / Similarity Logic | Metadata Signals Used | ML / LLM Usage | Output Format & Schema | Caching Backend & TTL |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **slopcheck** | Python $\ge 3.9$ | ~1,760 LOC | `requests` | `ThreadPoolExecutor` (sync worker pool) | 2 calls/pkg (`pypi.org`, `pypistats.org` / `registry.npmjs.org`, `api.npmjs.org`) | Pure-Python raw Levenshtein vs ~37 PyPI / ~32 npm popular packages | `created` (oldest upload), `downloads` (last_month), `version`, `repo_url` | None | 3-tier verdict (`SLOP`, `SUS`, `OK`, `ERROR`), `package`, `flags` | None (no caching) |
| **dep-hallucinator** | Python $\ge 3.8$ | ~12,581 LOC | `httpx[http2]`, `click`, `structlog`, `toml`, `rich` | Asyncio (`httpx.AsyncClient`, `asyncio.Semaphore`) | 1 call/pkg (`pypi.org/json`, `registry.npmjs.org`) | Raw Levenshtein vs curated package list | `created`, `author`, `maintainers`, `downloads`, `license`, `repo_url` | None (Has `ml_engine.py` 1,407 LOC, but uses stdlib `re`/`math`, no ML/AI models) | 4-tier verdict (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `package`, `confidence`, `reasons` | Memory dict + disk file cache (`lz4` compression, default TTL 3600s) |
| **matt-slopcheck** | TypeScript, Node.js $\ge 20$ | ~916 LOC | stdlib `fetch` (Zero external deps) | Async batch loop (`Promise.all`, default 10 conc) | 1 HTTP `HEAD` call/pkg (`registry.npmjs.org`), +1 download call on 404 | None (No typosquatting/similarity checks) | HTTP status (200, 404, 451), `downloads > 0` on 404 | None | Binary / Flagged invalid packages (`name`, `exists`, `httpStatus`, `isUnpublished`, `isSecurityHold`) | None (no caching) |
| **slopguard** | Node.js ES Modules (`.mjs`), Node $\ge 18$ | ~913 LOC | stdlib `fetch` (Zero external deps) | Async parallel (`Promise.all` up to 12 pkgs max) | 1 HTTP GET call/pkg (`registry.npmjs.org`, `pypi.org/json`) | None (No typosquatting/similarity checks) | `created` / upload time to compute `ageDays` | None | Claude Code CLI hook decisions (`allow()`, `decide('deny')` 404, `decide('ask')` <120d) | None (no caching) |
| **CipherGuard** | Python $\ge 3.11$ (Docker `python:3.11-slim`) | ~674 LOC | `fastapi`, `httpx`, `jellyfish`, `pydantic`, `redis`, `python-dateutil` | Asyncio continuous stream (`asyncio.gather`, `httpx.Limits`, `Semaphore(80)`) | 1 HTTP GET call/pkg (`pypi.org/json`, `registry.npmjs.org`) | Normalized Levenshtein ($\text{norm\_dist} = \frac{\text{dist}}{\max(\text{len1}, \text{len2})}$, `jellyfish` + LRU cache) vs top 10,000 pkgs/eco | `age_days`, `maintainer_count` (unique emails/array), `downloads_last_month` | None | Continuous 0-100 score + 4-tier status (`pass`, `warn`, `fail`, `error`), `AgentResult` schema | Async Redis (`redis://`) with automatic in-memory fallback (TTL 86,400s / 24h) |

---

## 2. Implementation Details by Tool

### 1. slopcheck (`0xToxSec/slopcheck`)
slopcheck is a synchronous, multi-threaded CLI tool written in Python. It executes 2 HTTP requests per candidate package: one to the core registry API and a secondary request to download statistics endpoints (`pypistats.org` for PyPI and `api.npmjs.org` for npm).

**Typosquatting Corpus Code Quotation (`slopcheck/detect.py` lines 64–103):**
```python
POPULAR_PACKAGES = {
    "pypi": [
        "requests", "flask", "django", "fastapi", "numpy", "pandas",
        "scipy", "matplotlib", "sqlalchemy", "celery", "redis", "boto3",
        "pillow", "beautifulsoup4", "scrapy", "pytest", "black", "httpx",
        "pydantic", "uvicorn", "gunicorn", "click", "typer", "openai",
        "langchain", "transformers", "torch", "tensorflow", "scikit-learn",
        "streamlit", "gradio", "anthropic", "cryptography", "paramiko",
        "fabric", "jinja2", "aiohttp",
    ], ...
}
```
**Impact on False Positive Rate:**
Because slopcheck compares package names against a hardcoded list of **only 37 PyPI packages**, any legitimate package with raw edit distance 1 or 2 to one of these 37 names (e.g. `motor` vs `boto3`, `flair` vs `flask`, `spacy` vs `scipy`) triggers a `TYPOSQUAT_RISK` false positive. This directly accounts for slopcheck's **22.50% FPR** measured in benchmarks. In contrast, CipherGuard evaluates against the **top 10,000 PyPI packages**, where `motor`, `flair`, and `spacy` are recognised as top packages (`dist = 0`), eliminating coincidental typosquat false alarms.

### 2. dep-hallucinator (`serhanwbahar/dep-hallucinator`)
dep-hallucinator is a feature-rich, 12,581-LOC Python security scanner using `httpx[http2]` and `asyncio`. Inspection of its source code reveals that while it includes a prominent `ml_engine.py` file (1,407 lines) and lists `scikit-learn` in optional dependencies, **`ml_engine.py` contains zero machine learning or AI model code**. It consists entirely of standard library regex (`re`), string parsing, and mathematical heuristic rules wrapped in a class named `MLPatternEngine`. It includes an advanced caching manager (`cache_manager.py`) with memory and disk persistence supporting `lz4` compression.

### 3. matt-slopcheck (`mattschaller/slopcheck`)
matt-slopcheck is a lightweight TypeScript scanner built for Node.js $\ge 20$. It has zero runtime dependencies, relying exclusively on Node's native `fetch` API. It performs HTTP `HEAD` requests to the npm registry in batch loops of 10 (`Promise.all`). Crucially, **it performs zero typosquatting or edit distance checks**; it functions strictly as a fast manifest existence validator and checks npm download endpoints on 404s to detect unpublished packages.

### 4. slopguard (`singhlabs/slopguard`)
slopguard is an interactive security plugin built for the Claude Code CLI environment, written in native Node.js ES modules (`.mjs`). It hooks into pre-execution bash commands (`guard-bash.mjs`) to intercept `npm install` and `pip install` commands. Like `matt-slopcheck`, **slopguard contains zero typosquatting or string similarity logic**. It performs a single HTTP GET per package to fetch creation timestamps, blocking nonexistent packages (`deny`) and prompting developers (`ask`) if a package was created under 120 days ago.

### 5. CipherGuard (`services/cipherguard`)
CipherGuard is a production microservice (~674 LOC) running Python 3.11 in Docker. Unlike baseline tools that use small static lists, CipherGuard evaluates normalized Levenshtein distance ($\text{norm\_dist} = \frac{\text{dist}}{\max(\text{len1}, \text{len2})}$) against a complete snapshot of the top 10,000 packages per ecosystem (`top_pypi_packages.json`, `top_npm_packages.json`) using C-compiled `jellyfish` distance with `@functools.lru_cache` and mathematical lower-bound short-circuiting. Its execution engine streams continuous `asyncio.gather(*tasks)` calls bounded by `httpx.Limits` and `asyncio.Semaphore(80)`, backed by an async Redis cache with automatic in-memory fallback.
