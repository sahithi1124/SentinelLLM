from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import config
from app.schemas import ChatRequest, ChatResponse, ConfigResponse, HealthResponse, SecurityEvent
from app.services import health_status, recent_security_events, run_chat

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
MAX_PROMPT_LENGTH = 4000

app = FastAPI(title="SentinelLLM Web Dashboard", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    index = FRONTEND / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="Dashboard frontend not found")
    return FileResponse(index)


@app.post("/api/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    if len(request.prompt.strip()) == 0:
        raise HTTPException(status_code=400, detail="Prompt must contain non-whitespace text")
    if len(request.prompt) > MAX_PROMPT_LENGTH:
        raise HTTPException(status_code=400, detail=f"Prompt exceeds {MAX_PROMPT_LENGTH} characters")
    try:
        return run_chat(request.prompt, request.mode)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/health", response_model=HealthResponse)
def health():
    return health_status()


@app.get("/api/security/events", response_model=list[SecurityEvent])
def security_events(limit: int = Query(default=20, ge=1, le=100)):
    return recent_security_events(limit)


@app.get("/api/config", response_model=ConfigResponse)
def public_config():
    return ConfigResponse(
        application_mode="local",
        model=config.MODEL_NAME,
        ollama_host_local=True,
        max_prompt_length=MAX_PROMPT_LENGTH,
    )
