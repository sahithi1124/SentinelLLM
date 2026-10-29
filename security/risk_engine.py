"""Configurable weighted risk scoring for detected injection indicators."""

from dataclasses import dataclass

from .injection_detector import CATEGORY_WEIGHTS, DetectionResult


@dataclass(frozen=True)
class RiskResult:
    score: int
    level: str
    categories: tuple[str, ...]
    matched_indicators: tuple[str, ...]
    explanation: str


def risk_level(score: int) -> str:
    if score <= 24:
        return "LOW"
    if score <= 49:
        return "MODERATE"
    if score <= 74:
        return "HIGH"
    return "CRITICAL"


def calculate_risk(
    detection: DetectionResult,
    weights: dict[str, int] | None = None,
    educational_reduction: int = 0,
) -> RiskResult:
    active_weights = weights or CATEGORY_WEIGHTS
    score = sum(int(active_weights.get(category, 0)) for category in detection.categories)
    if detection.benign_context:
        score = max(0, score - educational_reduction)
    score = max(0, min(100, score))
    level = risk_level(score)

    if detection.categories:
        names = ", ".join(detection.categories)
        explanation = f"Detected threat category/categories: {names}. {len(detection.matched_indicators)} explainable indicator(s) matched."
    elif detection.benign_context:
        explanation = "The prompt appears to discuss prompt-security concepts; no suspicious indicators matched."
    else:
        explanation = "No configured prompt-injection indicators matched."
    return RiskResult(score, level, detection.categories, detection.matched_indicators, explanation)
