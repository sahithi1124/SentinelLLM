from typing import Literal, Optional

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
    mode: Literal["baseline", "protected"] = "protected"


class ChatResponse(BaseModel):
    model_response: str
    security_decision: Literal["ALLOW", "FLAG", "BLOCK", "BASELINE"]
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    threat_categories: list[str]
    explanation: str
    ollama_invoked: bool
    model_latency_seconds: float = Field(ge=0)
    security_latency_seconds: float = Field(ge=0)
    total_latency_seconds: float = Field(ge=0)


class HealthResponse(BaseModel):
    status: str
    ollama_connectivity: bool
    model_available: bool
    model: str


class SecurityEvent(BaseModel):
    event_id: str
    timestamp_utc: str
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    security_decision: Optional[str] = None
    threat_categories: list[str] = []


class ConfigResponse(BaseModel):
    application_mode: str
    model: str
    ollama_host_local: bool
    max_prompt_length: int
