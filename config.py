"""Central configuration for the SentinelLLM baseline application."""

MODEL_NAME = "qwen2.5:3b"
OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"
REQUEST_TIMEOUT_SECONDS = 120

LOG_DIRECTORY = "logs"
BASELINE_LOG_FILE = "baseline.jsonl"
SECURITY_LOG_FILE = "security_events.jsonl"

MODERATE_RISK_THRESHOLD = 25
HIGH_RISK_THRESHOLD = 50
CRITICAL_RISK_THRESHOLD = 75

SYSTEM_PROMPT = (
    "You are a helpful educational assistant. Provide clear, accurate, and "
    "concise explanations to support cybersecurity learning."
)
