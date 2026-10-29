"""Unprotected baseline terminal client for a local Ollama language model."""

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests

import config


class OllamaError(Exception):
    """Base exception for Ollama API failures."""


class OllamaConnectionError(OllamaError):
    """Raised when Ollama cannot be reached."""


class OllamaTimeoutError(OllamaError):
    """Raised when an Ollama request times out."""


def build_chat_payload(prompt: str) -> dict[str, Any]:
    """Build the non-streaming Ollama chat API request payload."""
    return {
        "model": config.MODEL_NAME,
        "messages": [
            {"role": "system", "content": config.SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
    }


def generate_response(
    prompt: str,
    session: Optional[requests.Session] = None,
    timeout: Optional[float] = None,
) -> tuple[str, int, float]:
    """Send one prompt to Ollama and return response text, status, and latency."""
    http = session or requests
    request_timeout = config.REQUEST_TIMEOUT_SECONDS if timeout is None else timeout
    started_at = time.perf_counter()

    try:
        response = http.post(
            config.OLLAMA_CHAT_URL,
            json=build_chat_payload(prompt),
            timeout=request_timeout,
        )
    except requests.exceptions.Timeout as exc:
        raise OllamaTimeoutError("The Ollama request timed out.") from exc
    except requests.exceptions.ConnectionError as exc:
        raise OllamaConnectionError(
            "Could not connect to Ollama at http://127.0.0.1:11434. "
            "Start Ollama and try again."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise OllamaError(f"Ollama request failed: {exc}") from exc

    latency = time.perf_counter() - started_at
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise OllamaError(f"Ollama returned HTTP {response.status_code}: {exc}") from exc

    try:
        data = response.json()
        message = data["message"]["content"]
    except (requests.exceptions.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise OllamaError("Ollama returned an invalid chat response.") from exc

    if not isinstance(message, str):
        raise OllamaError("Ollama returned a non-text model response.")
    return message, response.status_code, latency


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_interaction(
    prompt: str,
    response: Optional[str],
    latency_seconds: float,
    http_status: Optional[int],
    success: bool,
    log_path: Optional[Path] = None,
) -> None:
    """Append one interaction record to the JSON Lines log."""
    target = log_path or (
        Path(__file__).resolve().parent / config.LOG_DIRECTORY / config.BASELINE_LOG_FILE
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "interaction_id": str(uuid.uuid4()),
        "timestamp_utc": utc_timestamp(),
        "model": config.MODEL_NAME,
        "user_prompt": prompt,
        "model_response": response,
        "response_latency_seconds": round(latency_seconds, 6),
        "http_status": http_status,
        "success": success,
    }
    with target.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_cli() -> None:
    print("SentinelLLM baseline assistant")
    print("Each prompt is an independent interaction.")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        try:
            prompt = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return

        if prompt.lower() in {"exit", "quit"}:
            print("Goodbye.")
            return
        if not prompt:
            continue

        started_at = time.perf_counter()
        try:
            response, status, api_latency = generate_response(prompt)
            latency = api_latency
            print(f"Assistant: {response}\n")
            log_interaction(prompt, response, latency, status, True)
        except OllamaTimeoutError as exc:
            latency = time.perf_counter() - started_at
            print(f"Error: {exc}\n", file=sys.stderr)
            log_interaction(prompt, None, latency, None, False)
        except OllamaConnectionError as exc:
            latency = time.perf_counter() - started_at
            print(f"Error: {exc}\n", file=sys.stderr)
            log_interaction(prompt, None, latency, None, False)
        except OllamaError as exc:
            latency = time.perf_counter() - started_at
            print(f"Error: {exc}\n", file=sys.stderr)
            log_interaction(prompt, None, latency, None, False)


if __name__ == "__main__":
    run_cli()
