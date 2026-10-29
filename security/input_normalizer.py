"""Safe, non-destructive normalization for prompt analysis."""

import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedInput:
    original: str
    normalized: str


def normalize_input(prompt: str) -> NormalizedInput:
    """Normalize a copy for detection without changing the prompt sent to Ollama."""
    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string")

    compatible = unicodedata.normalize("NFKC", prompt)
    without_controls = "".join(
        character for character in compatible
        if unicodedata.category(character)[0] != "C" or character in "\t\n\r"
    )
    normalized = re.sub(r"\s+", " ", without_controls).strip()
    normalized = normalized.replace("_", " ")
    return NormalizedInput(original=prompt, normalized=normalized)
