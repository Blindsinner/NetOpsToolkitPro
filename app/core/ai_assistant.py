# -*- coding: utf-8 -*-
import asyncio
import json
import httpx
from openai import AsyncOpenAI
import google.generativeai as genai
import ollama
from typing import AsyncGenerator

class AIAssistant:
    """Handles communication with multiple, configurable LLM APIs."""

    def __init__(self, settings: dict):
        self.provider = settings.get("provider")
        self.api_key = settings.get("api_key")
        self.base_url = settings.get("base_url")
        self.client = None

        if self.provider == "OpenAI":
            if self.api_key and self.base_url:
                self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)
        elif self.provider == "Google Gemini":
            if self.api_key:
                genai.configure(api_key=self.api_key)
        elif self.provider == "Ollama":
            self.client = ollama.AsyncClient(host=self.base_url)

    async def get_analysis_stream(self, settings: dict, prompt: str, context: str) -> AsyncGenerator[str, None]:
        """Async generator that streams responses from the selected AI provider."""
        system_prompt = settings.get("system_prompt", "You are a helpful assistant.")
        model = settings.get("model")
        temp = float(settings.get("temperature", 0.7))
        max_tokens = int(settings.get("max_tokens", 2048))
        
        if not model:
            if self.provider == "Google Gemini": model = "gemini-1.5-flash"
            elif self.provider == "OpenAI": model = "gpt-4o"
            elif self.provider == "Ollama": model = "llama3"
            else: model = "default-model"

        try:
            if self.provider == "OpenAI":
                # FIX: Use 'yield' to send error message, then 'return' to exit.
                if not self.client:
                    yield "ERROR: OpenAI client not initialized. Check API Key and Base URL."
                    return
                full_prompt = f"User Request: {prompt}\n\nContext Data:\n---\n{context}\n---"
                stream = await self.client.chat.completions.create(
                    model=model, temperature=temp, max_tokens=max_tokens,
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": full_prompt}],
                    stream=True
                )
                async for chunk in stream:
                    yield chunk.choices[0].delta.content or ""

            elif self.provider == "Google Gemini":
                # FIX: Use 'yield' to send error message, then 'return' to exit.
                if not self.api_key:
                    yield "ERROR: Google Gemini API key not configured."
                    return
                full_prompt = f"{system_prompt}\n\nUser Request: {prompt}\n\nContext Data:\n---\n{context}\n---"
                gemini_model = genai.GenerativeModel(model)
                generation_config = genai.types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=temp
                )
                
                async for chunk in await gemini_model.generate_content_async(
                    full_prompt,
                    stream=True,
                    generation_config=generation_config
                ):
                    yield chunk.text

            elif self.provider == "Ollama":
                # FIX: Use 'yield' to send error message, then 'return' to exit.
                if not self.client:
                    yield "ERROR: Ollama client not initialized. Check Host URL."
                    return
                full_prompt = f"User Request: {prompt}\n\nContext Data:\n---\n{context}\n---"
                stream = await self.client.chat(
                    model=model,
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": full_prompt}],
                    stream=True
                )
                async for chunk in stream:
                    yield chunk['message']['content']
            
            elif self.provider == "Custom":
                yield await self._handle_custom_api(settings, prompt, context)

        except Exception as e:
            yield f"\n\nERROR: API call failed. Details: {e}"

    async def _handle_custom_api(self, settings, prompt, context) -> str:
        url = settings.get("base_url")
        headers_str = settings.get("custom_headers", "")
        body_template = settings.get("custom_body", "")
        api_key = settings.get("api_key", "")

        try:
            headers = json.loads(headers_str.replace("<KEY>", api_key)) if api_key else json.loads(headers_str)
            body_str = body_template.replace("{prompt}", json.dumps(prompt)).replace("{context}", json.dumps(context))
            body = json.loads(body_str)
        except json.JSONDecodeError as e:
            return f"ERROR: Invalid JSON in headers or body template: {e}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=body, headers=headers, timeout=60)
                response.raise_for_status()
                return f"SUCCESS:\n{json.dumps(response.json(), indent=2)}"
        except httpx.RequestError as e:
            return f"ERROR: Custom API request failed: {e}"