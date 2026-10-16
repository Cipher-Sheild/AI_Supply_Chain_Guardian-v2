"""
Provider-agnostic LLM interface — trust_engine's own copy.

Used later to narrate the SHAP explanation of the Trust Score in plain
English — never to compute the score itself, which is deterministic
(weighted-sum now, XGBoost later). `prompt_injection` has an identical
copy of this file; some duplication between services is intentional
here, see repo root README.
"""

import os


async def call_llm(prompt: str, system: str = "") -> str:
    """
    Send a prompt to the configured LLM provider and return its text
    response. Provider is selected via the LLM_PROVIDER env var.
    """
    provider = os.getenv("LLM_PROVIDER", "openai")

    if provider == "openai":
        return await _call_openai(prompt, system)
    elif provider == "ollama":
        return await _call_ollama(prompt, system)
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider}")


async def _call_openai(prompt: str, system: str) -> str:
    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    response = await client.chat.completions.create(
        model="gpt-4o-mini",  # TODO: confirm final model choice with the team
        messages=messages,
    )
    return response.choices[0].message.content or ""


async def _call_ollama(prompt: str, system: str) -> str:
    # Ollama support planned — see config.
    raise NotImplementedError("Ollama support planned")
