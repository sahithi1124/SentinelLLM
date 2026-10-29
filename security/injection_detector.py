"""Explainable, bounded rule-based prompt-injection detection."""

import base64
import binascii
import re
from dataclasses import dataclass, field


CATEGORY_WEIGHTS = {
    "instruction_override": 25,
    "role_spoofing": 25,
    "system_prompt_extraction": 30,
    "jailbreak_indicator": 25,
    "encoded_payload": 20,
    "context_manipulation": 15,
}

EDUCATIONAL_PATTERNS = (
    r"what is prompt injection",
    r"explain\s+.*(prompt injection|jailbreak|jailbreaking)",
    r"why is\s+(revealing|extracting|printing).*(system prompt|internal instructions).*dangerous",
    r"examples? of prompt injection",
    r"how (do|does).*prompt injection.*work",
    r"base64 encoding work",
)

RULES = {
    "instruction_override": (
        r"ignore\s+(all\s+)?(previous|prior) instructions",
        r"disregard\s+(your\s+)?(system prompt|instructions)",
        r"forget\s+(all\s+)?(your\s+)?(safety|security|previous) rules",
        r"bypass\s+(your\s+)?(safety|rules|restrictions)",
    ),
    "role_spoofing": (
        r"you are now\s+(?:the|a)\s+",
        r"\[\s*system\s*\].*(override|ignore)",
        r"developer message.*(disable|remove|bypass).*restrictions",
        r"act as (?:an? )?(unrestricted|administrator)",
    ),
    "system_prompt_extraction": (
        r"(?:reveal|show|print|display|output).*(hidden|system|internal|initial).*(prompt|instructions)",
        r"what are your (hidden|system|internal) instructions",
        r"copy\s+(your\s+)?(system prompt|initial instructions)",
    ),
    "jailbreak_indicator": (
        r"enable unrestricted mode",
        r"(pretend|act like)\s+(you\s+)?(have\s+)?no\s+(safety|restrictions)",
        r"\bdan\s+(mode|activated|enabled)",
        r"jailbreak mode",
        r"without (safety|ethical) restrictions",
    ),
    "context_manipulation": (
        r"everything above is irrelevant",
        r"previous instructions.*(only|were).*test",
        r"treat this message as (higher|top) priority",
        r"new instructions take precedence",
    ),
}

DANGEROUS_DECODE_TERMS = (
    "ignore", "disregard", "forget", "reveal", "system prompt", "developer message",
    "unrestricted", "bypass", "dan mode", "new instructions", "jailbreak",
)


@dataclass(frozen=True)
class DetectionResult:
    categories: tuple[str, ...]
    matched_indicators: tuple[str, ...]
    benign_context: bool = False


def _is_benign_educational(text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in EDUCATIONAL_PATTERNS)


def _encoded_indicators(text: str) -> list[str]:
    matches: list[str] = []

    for escaped in re.findall(r"(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){2,}", text, re.IGNORECASE):
        matches.append(f"unicode escape sequence: {escaped[:32]}")

    compact = text.replace(" ", "")
    for candidate in re.findall(r"(?<![0-9a-zA-Z])[0-9A-Za-z+/]{20,}={0,2}(?![0-9a-zA-Z])", text):
        padded = candidate + "=" * ((-len(candidate)) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        decoded = decoded.lower()
        if any(term in decoded for term in DANGEROUS_DECODE_TERMS):
            matches.append(f"base64 payload decodes to instruction-like text: {candidate[:24]}")

    candidates = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{12,}(?![0-9a-fA-F])", compact)
    candidates += re.findall(r"(?:[0-9a-fA-F]{2}[\s:-]){5,}[0-9a-fA-F]{2}", text)
    for candidate in candidates:
        raw_hex = re.sub(r"[^0-9a-fA-F]", "", candidate)
        try:
            decoded = bytes.fromhex(raw_hex).decode("utf-8", errors="strict").lower()
        except (ValueError, UnicodeDecodeError):
            continue
        if any(term in decoded for term in DANGEROUS_DECODE_TERMS):
            matches.append(f"hex payload decodes to instruction-like text: {raw_hex[:24]}")

    if len(compact) >= 24 and len(set(compact.lower())) <= 8 and not compact.isalpha():
        matches.append("excessive obfuscation: repeated character alphabet")
    return matches[:8]


def detect_injection(text: str) -> DetectionResult:
    normalized = text.strip()
    casefolded = normalized.casefold()
    if _is_benign_educational(casefolded):
        return DetectionResult(tuple(), tuple(), True)

    categories: list[str] = []
    indicators: list[str] = []

    for category, patterns in RULES.items():
        for pattern in patterns:
            match = re.search(pattern, normalized, re.IGNORECASE)
            if match:
                if category not in categories:
                    categories.append(category)
                indicators.append(f"{category}: {match.group(0)}")
                break

    encoded = _encoded_indicators(normalized)
    if encoded:
        categories.append("encoded_payload")
        indicators.extend(encoded)

    benign_context = _is_benign_educational(normalized)
    if benign_context and not any(categories):
        return DetectionResult(tuple(), tuple(), True)
    return DetectionResult(tuple(categories), tuple(indicators[:12]), benign_context)
