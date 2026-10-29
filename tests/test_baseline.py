import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

import baseline
import config


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=None):
        self.status_code = status_code
        self._payload = payload
        self._json_error = json_error

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError("HTTP error")

    def json(self):
        if self._json_error:
            raise self._json_error
        return self._payload


def test_build_chat_payload():
    payload = baseline.build_chat_payload("Explain cyber risk")

    assert payload["model"] == config.MODEL_NAME
    assert payload["stream"] is False
    assert payload["messages"] == [
        {"role": "system", "content": config.SYSTEM_PROMPT},
        {"role": "user", "content": "Explain cyber risk"},
    ]


def test_successful_response_parsing():
    session = Mock()
    session.post.return_value = FakeResponse(
        payload={"message": {"role": "assistant", "content": "A useful answer"}}
    )

    answer, status, latency = baseline.generate_response("Hello", session=session)

    assert answer == "A useful answer"
    assert status == 200
    assert latency >= 0
    session.post.assert_called_once()
    call = session.post.call_args
    assert call.args[0] == config.OLLAMA_CHAT_URL
    assert call.kwargs["timeout"] == config.REQUEST_TIMEOUT_SECONDS
    assert call.kwargs["json"]["messages"][1]["content"] == "Hello"


def test_connection_error_handling():
    session = Mock()
    session.post.side_effect = requests.exceptions.ConnectionError("offline")

    with pytest.raises(baseline.OllamaConnectionError):
        baseline.generate_response("Hello", session=session)


def test_timeout_handling():
    session = Mock()
    session.post.side_effect = requests.exceptions.Timeout("slow")

    with pytest.raises(baseline.OllamaTimeoutError):
        baseline.generate_response("Hello", session=session)


def test_jsonl_logging(tmp_path: Path):
    log_file = tmp_path / "baseline.jsonl"

    baseline.log_interaction("Question", "Answer", 0.123456, 200, True, log_file)
    baseline.log_interaction("Failure", None, 0.5, None, False, log_file)

    lines = log_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["user_prompt"] == "Question"
    assert first["model_response"] == "Answer"
    assert first["http_status"] == 200
    assert first["success"] is True
    assert first["interaction_id"]
    assert first["timestamp_utc"]
    assert first["model"] == config.MODEL_NAME
    assert second["success"] is False
