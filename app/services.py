import time
from pathlib import Path

import requests

import config
from baseline import generate_response
from protected_llm import log_security_event
from security.decision_engine import make_decision
from security.injection_detector import detect_injection
from security.input_normalizer import normalize_input
from security.risk_engine import calculate_risk

MAX_EVENTS = 100
SECURITY_MESSAGE = "Blocked by SentinelLLM Phase 2 policy: this prompt exceeded the risk threshold and Ollama was not invoked."


def analyze_prompt(prompt: str):
    started = time.perf_counter()
    normalized = normalize_input(prompt)
    detection = detect_injection(normalized.normalized)
    risk = calculate_risk(detection)
    security_decision = make_decision(risk.level)
    latency = time.perf_counter() - started
    explanation = "; ".join(filter(None, [risk.explanation, security_decision.explanation]))
    return normalized, risk, security_decision, explanation, latency


def run_chat(prompt: str, mode: str) -> dict:
    total_started = time.perf_counter()
    security_latency = 0.0

    if mode == "protected":
        normalized, risk, decision, explanation, security_latency = analyze_prompt(prompt)
        if decision.decision == "BLOCK":
            model_latency = 0.0
            ollama_invoked = False
            response = SECURITY_MESSAGE
        else:
            model_started = time.perf_counter()
            try:
                response, _, _ = generate_response(normalized.original)
            except Exception as exc:
                raise RuntimeError("The local model request failed") from exc
            model_latency = time.perf_counter() - model_started
            ollama_invoked = True

        log_security_event(
            normalized.original, normalized.normalized, risk, decision.decision,
            explanation, ollama_invoked, model_latency,
        )
        return {
            "model_response": response,
            "security_decision": decision.decision,
            "risk_score": risk.score,
            "risk_level": risk.level,
            "threat_categories": list(risk.categories),
            "explanation": explanation,
            "ollama_invoked": ollama_invoked,
            "model_latency_seconds": model_latency,
            "security_latency_seconds": security_latency,
            "total_latency_seconds": time.perf_counter() - total_started,
        }

    model_started = time.perf_counter()
    try:
        response, _, measured_latency = generate_response(prompt)
    except Exception as exc:
        raise RuntimeError("The local model request failed") from exc
    model_latency = measured_latency if measured_latency >= 0 else time.perf_counter() - model_started
    return {
        "model_response": response,
        "security_decision": "BASELINE",
        "risk_score": 0,
        "risk_level": "LOW",
        "threat_categories": [],
        "explanation": "Baseline mode intentionally applies no prompt-injection analysis.",
        "ollama_invoked": True,
        "model_latency_seconds": model_latency,
        "security_latency_seconds": security_latency,
        "total_latency_seconds": time.perf_counter() - total_started,
    }


def health_status() -> dict:
    ollama_connectivity = False
    model_available = False
    try:
        response = requests.get("http://127.0.0.1:11434/api/tags", timeout=3)
        response.raise_for_status()
        ollama_connectivity = True
        models = response.json().get("models", [])
        model_available = any(str(item.get("name", "")).split(":")[0] == config.MODEL_NAME.split(":")[0]
                             for item in models)
    except requests.RequestException:
        pass
    return {
        "status": "operational" if ollama_connectivity else "degraded",
        "ollama_connectivity": ollama_connectivity,
        "model_available": model_available,
        "model": config.MODEL_NAME,
    }


def recent_security_events(limit: int = 20) -> list[dict]:
    limit = max(1, min(limit, MAX_EVENTS))
    path = Path(__file__).resolve().parent.parent / config.LOG_DIRECTORY / config.SECURITY_LOG_FILE
    if not path.exists():
        return []
    records = []
    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            try:
                record = __import__("json").loads(line)
            except ValueError:
                continue
            records.append({
                "event_id": record.get("event_id", "unknown"),
                "timestamp_utc": record.get("timestamp_utc", ""),
                "risk_score": record.get("risk_score"),
                "risk_level": record.get("risk_level"),
                "security_decision": record.get("security_decision"),
                "threat_categories": record.get("detected_threat_categories", []),
            })
    return records[-limit:][::-1]
