"""Protected Phase 2 terminal client for SentinelLLM."""

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import config
from baseline import generate_response
from security.decision_engine import make_decision
from security.injection_detector import detect_injection
from security.input_normalizer import normalize_input
from security.risk_engine import calculate_risk

SECURITY_MESSAGE = "Blocked by SentinelLLM Phase 2 security policy: the prompt exceeded the configured risk threshold."


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_security_event(
    original_prompt: str,
    normalized_prompt: str,
    risk_result,
    decision: str,
    explanation: str,
    ollama_invoked: bool,
    latency: float,
    log_path: Optional[Path] = None,
) -> None:
    target = log_path or Path(__file__).resolve().parent / config.LOG_DIRECTORY / "security_events.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp_utc": utc_timestamp(),
        "original_prompt": original_prompt,
        "normalized_prompt": normalized_prompt,
        "detected_threat_categories": list(risk_result.categories),
        "risk_score": risk_result.score,
        "risk_level": risk_result.level,
        "security_decision": decision,
        "explanation": explanation,
        "ollama_invoked": ollama_invoked,
        "response_latency_seconds": round(latency, 6),
    }
    with target.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")


def process_prompt(prompt: str, model_call: Callable = generate_response):
    normalized = normalize_input(prompt)
    detected = detect_injection(normalized.normalized)
    risk = calculate_risk(detected)
    security_decision = make_decision(risk.level)

    ollama_invoked = False
    latency = 0.0
    response = None
    error = None
    if security_decision.decision == "BLOCK":
        response = SECURITY_MESSAGE
    else:
        ollama_invoked = True
        started_at = time.perf_counter()
        try:
            response_text, _, _ = model_call(normalized.original)
            response = response_text
        except Exception as exc:
            error = str(exc)
            response = f"LLM request failed: {exc}"
        latency = time.perf_counter() - started_at

    explanation = "; ".join(filter(None, [risk.explanation, security_decision.explanation]))
    log_security_event(
        normalized.original,
        normalized.normalized,
        risk,
        security_decision.decision,
        explanation,
        ollama_invoked,
        latency,
    )
    return {
        "risk": risk,
        "decision": security_decision.decision,
        "explanation": explanation,
        "response": response,
        "ollama_invoked": ollama_invoked,
        "latency": latency,
        "error": error,
    }


def run_cli() -> None:
    print("SentinelLLM — Protected Mode")
    print("Rule-based prompt-injection detection is active.\n")

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

        result = process_prompt(prompt)
        risk = result["risk"]
        categories = ", ".join(risk.categories) if risk.categories else "None"
        print("\nSecurity Analysis")
        print("------------------------------")
        print(f"Risk Score: {risk.score}")
        print(f"Risk Level: {risk.level}")
        print(f"Threat Categories: {categories}")
        print(f"Decision: {result['decision']}")
        print(f"Explanation: {result['explanation']}")
        print("\nLLM Response:")
        print(result["response"] + "\n")


if __name__ == "__main__":
    run_cli()
