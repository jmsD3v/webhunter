from __future__ import annotations

import asyncio
import os

# Priority order — must stay identical across every tool in the portfolio
# (webhunter, reconai, phishsim, ...): first API key found wins.
_PROVIDER_ENV_VARS: tuple[tuple[str, str], ...] = (
    ("ANTHROPIC_API_KEY", "anthropic"),
    ("GEMINI_API_KEY", "gemini"),
    ("OPENAI_API_KEY", "openai"),
)


class NoAIProviderError(RuntimeError):
    pass


def detect_provider() -> tuple[str, str]:
    for env_var, provider in _PROVIDER_ENV_VARS:
        api_key = os.getenv(env_var, "").strip()
        if api_key:
            return provider, api_key

    raise NoAIProviderError(
        "No AI provider API key set. Set one of: "
        "ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY."
    )


async def get_completion(prompt: str) -> str:
    provider, api_key = detect_provider()

    if provider == "anthropic":
        return await _complete_anthropic(prompt, api_key)
    if provider == "gemini":
        return await _complete_gemini(prompt, api_key)
    if provider == "openai":
        return await _complete_openai(prompt, api_key)

    raise NoAIProviderError(f"Unsupported provider: {provider}")


async def _complete_anthropic(prompt: str, api_key: str) -> str:
    import anthropic  # type: ignore[import]

    client = anthropic.Anthropic(api_key=api_key)
    response = await asyncio.to_thread(
        client.messages.create,
        model="claude-3-5-haiku-latest",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if hasattr(block, "text"))


async def _complete_gemini(prompt: str, api_key: str) -> str:
    import google.generativeai as genai  # type: ignore[import]

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = await asyncio.to_thread(model.generate_content, prompt)
    return response.text


async def _complete_openai(prompt: str, api_key: str) -> str:
    from openai import OpenAI  # type: ignore[import]

    client = OpenAI(api_key=api_key)
    response = await asyncio.to_thread(
        client.chat.completions.create,
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content or ""
