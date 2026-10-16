"""
Provider-agnostic LLM interface — prompt_injection's own copy.

This service is one of only two in the system that genuinely needs an
LLM call for detection itself (not just for generating a fix), so it
gets its own small `call_llm` rather than importing a shared package
across service boundaries (trust_engine has an identical copy — some
duplication between services is intentional here, see repo root
README).

Provider selection
-------------------
Defaults to a **local Ollama model** — free, fast enough for day-to-day
development, and avoids burning API credits on every test run. OpenAI
remains available as an explicit opt-in (e.g. for a demo where response
quality matters more than cost), controlled by the LLM_PROVIDER env var:

    LLM_PROVIDER=ollama   (default — no env var needed)
    LLM_PROVIDER=openai   (requires OPENAI_API_KEY)
    LLM_PROVIDER=grok     (requires XAI_API_KEY and XAI_MODEL)
    LLM_PROVIDER=groq     (requires GROQ_API_KEY and GROQ_MODEL)

Ollama-over-WSL note
----------------------
When this service runs inside WSL2 but Ollama runs on Windows (common
dev setup), `localhost` does NOT reach it — WSL2's `localhost` forwarding
only works Windows→WSL, not the other way around. `_resolve_ollama_host()`
below handles this automatically:
  1. If OLLAMA_HOST is set explicitly, always use that (highest priority).
  2. Else try localhost first (works if Ollama runs inside WSL/Linux directly,
     or in a native Linux/Docker deployment).
  3. Else fall back to the WSL2 default-gateway IP (resolved live via
     `ip route`, NOT hardcoded — that IP can change between reboots).

On Windows, Ollama must be started with OLLAMA_HOST=0.0.0.0 (not the
default 127.0.0.1-only bind) and a firewall rule opened for port 11434,
or WSL won't be able to reach it. See README "Running Stage 3 locally
with Ollama" for the one-time setup steps.
"""

import os
import re
from functools import lru_cache

_OLLAMA_PORT = 11434


@lru_cache(maxsize=1)
def _resolve_ollama_host() -> str:
    """
    Figure out which host to use for Ollama's API, cached for the life
    of the process (resolved once, not on every call).
    """
    explicit = os.getenv("OLLAMA_HOST")
    if explicit:
        # Allow either "host" or "host:port" or a full URL.
        if explicit.startswith("http"):
            return explicit
        return f"http://{explicit}:{_OLLAMA_PORT}"

    # Try localhost first — correct when this service and Ollama run in
    # the same OS/container (native Linux, Docker, or Ollama-inside-WSL).
    import socket

    try:
        socket.create_connection(("127.0.0.1", _OLLAMA_PORT), timeout=0.3).close()
        return f"http://127.0.0.1:{_OLLAMA_PORT}"
    except OSError:
        pass

    # Fall back to the WSL2 default-gateway IP — this is how a WSL2
    # process reaches services running on the Windows host. Resolved
    # live via `ip route` rather than hardcoded, since this IP can
    # change across reboots/network changes. (Note: /etc/resolv.conf's
    # nameserver entry is NOT reliably the same as this gateway IP on
    # every WSL2 setup — some environments differ — so we ask the
    # routing table directly instead of assuming they match.)
    try:
        import subprocess

        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        match = re.search(r"default via ([\d.]+)", result.stdout)
        if match:
            return f"http://{match.group(1)}:{_OLLAMA_PORT}"
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    # Last resort — plain localhost; will fail loudly with a clear
    # connection error rather than silently guessing further.
    return f"http://127.0.0.1:{_OLLAMA_PORT}"


async def call_llm(prompt: str, system: str = "") -> str:
    """
    Send a prompt to the configured LLM provider and return its text
    response. Provider is selected via the LLM_PROVIDER env var,
    defaulting to "ollama".
    """
    provider = os.getenv("LLM_PROVIDER", "ollama")

    if provider == "groq":
        return await _call_openai(prompt, system, groq=True)
    if provider == "grok":
        return await _call_openai(prompt, system, grok=True)
    if provider == "openai":
        return await _call_openai(prompt, system)
    elif provider == "ollama":
        return await _call_ollama(prompt, system)
    elif provider == 'local':
        from app.local_judge import generate
        from app.runtime import bounded_work
        return await bounded_work(generate,prompt,system)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider}")


async def _call_openai(prompt: str, system: str, grok: bool=False, groq: bool=False) -> str:
    from openai import AsyncOpenAI

    key=os.getenv("GROQ_API_KEY" if groq else "XAI_API_KEY" if grok else "OPENAI_API_KEY", "")
    model=os.getenv("GROQ_MODEL", "") if groq else os.getenv("XAI_MODEL", "") if grok else os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    if not key or not model:raise ValueError("Judge API key and model must be configured")
    settings={"api_key":key,"timeout":60.0,"max_retries":0}
    if grok:settings["base_url"]="https://api.x.ai/v1"
    if groq:settings["base_url"]="https://api.groq.com/openai/v1"
    client = AsyncOpenAI(**settings)

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    extra={}
    if groq:
        extra={'temperature':0,'response_format':{'type':'json_object'},'extra_body':{'reasoning_format':'hidden'}}
        if model.startswith('openai/gpt-oss'):extra['reasoning_effort']='low'
    async with client:
        response = await client.chat.completions.create(
            model=model,
            messages=messages,
            max_completion_tokens=1024 if groq else 256,
            **extra,
        )
    return response.choices[0].message.content or ""



async def _call_ollama(prompt: str, system: str) -> str:
    import httpx

    host = _resolve_ollama_host()
    model = os.getenv("OLLAMA_MODEL", "phi3:mini")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{host}/api/chat",
            json={"model": model, "messages": messages, "stream": False,"format":"json",
                "options":{"temperature":0,"num_predict":192,"num_ctx":2048,"num_thread":4}},
        )
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "")
