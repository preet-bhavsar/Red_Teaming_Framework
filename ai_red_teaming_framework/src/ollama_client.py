import os
from typing import Optional, Dict, Any, List, Tuple

import requests


class OllamaClient:
    """
    Thin wrapper around the local Ollama HTTP API.

    By default this targets the standard Ollama endpoint at:
        http://localhost:11434

    The model can be explicitly supplied by RedLens. If no model is
    supplied, OLLAMA_MODEL is used, followed by the default llama3.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:

        self.base_url = base_url or os.environ.get(
            "OLLAMA_HOST",
            "http://localhost:11434",
        )

        if self.base_url.endswith("/"):
            self.base_url = self.base_url[:-1]

        # IMPORTANT:
        # Explicit model selection has priority over the environment
        # variable. This allows the Dashboard-selected model to control
        # the actual Ollama request.
        self.model = (
            model
            or os.environ.get("OLLAMA_MODEL")
            or "llama3"
        )

        # Generation timeout (seconds). Configurable via OLLAMA_TIMEOUT
        # because CPU-only inference of larger models can legitimately
        # take well over the old hardcoded 120s, especially on the
        # first request after the model has to be loaded into memory.
        # A too-short timeout here doesn't fail fast, it fails *slow*:
        # every one of hundreds/thousands of prompts hits the full
        # timeout before erroring out.
        self.timeout = (
            timeout
            if timeout is not None
            else int(os.environ.get("OLLAMA_TIMEOUT", "300"))
        )

    def check_connection(
        self,
        timeout: float = 5.0,
    ) -> Tuple[bool, str, List[str]]:
        """
        Quick, cheap reachability check against /api/tags (metadata
        only — does not load or run a model, so it stays fast even
        while a generate() call is in flight on a busy server).

        Returns (ok, message, available_model_names).
        """

        url = f"{self.base_url}/api/tags"

        try:
            resp = requests.get(url, timeout=timeout)
        except requests.exceptions.ConnectionError:
            return (
                False,
                f"Cannot reach Ollama at {self.base_url}. "
                "Is 'ollama serve' running?",
                [],
            )
        except requests.exceptions.Timeout:
            return (
                False,
                f"Ollama at {self.base_url} did not respond within "
                f"{timeout:.0f}s (server may be overloaded).",
                [],
            )
        except Exception as exc:
            return False, f"Ollama connectivity check failed: {exc}", []

        if resp.status_code != 200:
            return False, f"Ollama returned HTTP {resp.status_code}", []

        try:
            data = resp.json()
            models = [
                m.get("name", "")
                for m in data.get("models", [])
                if m.get("name")
            ]
        except Exception:
            models = []

        return True, "Connected", models

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Call Ollama's /api/generate endpoint and return the response text.
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

        resp = requests.post(
            url,
            json=payload,
            timeout=self.timeout,
        )

        resp.raise_for_status()

        data = resp.json()

        return data.get("response", "")


def get_default_client(
    model: Optional[str] = None,
) -> OllamaClient:
    """
    Create an Ollama client.

    If model is supplied, that exact model is used.

    This is important for RedLens because the Dashboard passes
    the selected model here.
    """

    return OllamaClient(model=model)