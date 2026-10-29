"""Maps risk levels to Phase 2 security decisions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityDecision:
    decision: str
    explanation: str


def make_decision(risk_level: str, moderate_threshold: int = 25, high_threshold: int = 50) -> SecurityDecision:
    level = risk_level.upper()
    if level == "LOW":
        return SecurityDecision("ALLOW", "Risk is low and no blocking threshold was reached.")
    if level == "MODERATE":
        return SecurityDecision("FLAG", "Risk is moderate; the prompt is suspicious but is forwarded under the Phase 2 FLAG policy.")
    if level in {"HIGH", "CRITICAL"}:
        return SecurityDecision("BLOCK", "Risk is high or critical; Ollama invocation is blocked for this prompt.")
    raise ValueError(f"Unknown risk level: {risk_level}")
