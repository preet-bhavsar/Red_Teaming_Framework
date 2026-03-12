import os
from typing import Optional, Dict, Any

import requests


class OllamaClient:
    """
    Thin wrapper around the local Ollama HTTP API.

    By default this targets the standard Ollama endpoint at http://localhost:11434
    and uses the `llama3` model, but you can override both via environment variables:

    - OLLAMA_HOST (default: http://localhost:11434)
    - OLLAMA_MODEL (default: llama3)
    """

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None, timeout: int = 120) -> None:
        self.base_url = base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        # Basic normalize – allow either host or full root URL
        if self.base_url.endswith("/"):
            self.base_url = self.base_url[:-1]
        self.model = model or os.environ.get("OLLAMA_MODEL", "llama3")
        self.timeout = timeout

    def generate(self, prompt: str, system_prompt: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> str:
        """
        Call Ollama's /api/generate endpoint and return the full response text.
        """
        url = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if options:
            payload["options"] = options

        resp = requests.post(url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        # Ollama returns a `response` field for non-streaming calls
        return data.get("response", "")


def get_default_client() -> OllamaClient:
    return OllamaClient()


