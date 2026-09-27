"""Drives the real Anthropic SDK against a local stub to verify the wire request and parsing."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from neurawall.core.errors import RecoverableError
from neurawall.modules.llm_advisor import schemas
from neurawall.modules.llm_advisor.backend import ClaudeBackend

DRAFT = {
    "threat_assessment": "C2 beaconing",
    "name": "Block C2",
    "rationale": "Periodic callbacks.",
    "action": "drop",
    "priority": 150,
    "match": {
        "src_cidrs": [],
        "dst_cidrs": ["203.0.113.9/32"],
        "dst_ports": [],
        "protocols": [],
        "sni_suffixes": [],
        "dns_suffixes": [],
        "http_path_prefixes": [],
        "ja3": [],
        "labels": [],
        "min_label_confidence": 0.0,
        "min_anomaly_score": None,
    },
    "confidence": 0.9,
}


class Stub(BaseHTTPRequestHandler):
    captured: list[dict] = []
    stop_reason = "end_turn"

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        Stub.captured.append({"path": self.path, "headers": dict(self.headers), "body": body})
        msg = {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "content": [{"type": "text", "text": json.dumps(DRAFT)}],
            "stop_reason": Stub.stop_reason,
            "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
        data = json.dumps(msg).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


@pytest.fixture
def stub(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("ANTHROPIC_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    Stub.captured, Stub.stop_reason = [], "end_turn"
    yield Stub
    server.shutdown()


def backend(fallbacks=True):
    return ClaudeBackend(
        api_key="sk-ant-test",
        model="claude-opus-5",
        max_tokens=16000,
        effort="high",
        timeout_seconds=10,
        server_side_fallbacks=fallbacks,
    )


def test_request_shape_and_structured_parse(stub):
    out = backend().generate(
        "Draft a rule.", "<untrusted_flow_data>{}</untrusted_flow_data>", schemas.LlmRuleDraft
    )
    assert isinstance(out, schemas.LlmRuleDraft) and out.match.dst_cidrs == ["203.0.113.9/32"]
    req = stub.captured[0]
    body, headers = req["body"], {k.lower(): v for k, v in req["headers"].items()}
    assert req["path"].startswith("/v1/messages")
    assert body["model"] == "claude-opus-5" and body["max_tokens"] == 16000
    assert body["thinking"] == {"type": "adaptive"}
    assert body["output_config"]["effort"] == "high"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in headers["anthropic-beta"]
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["messages"][0]["content"].endswith("Task: Draft a rule.")


def test_fallbacks_can_be_disabled(stub):
    backend(fallbacks=False).generate("t", "c", schemas.LlmRuleDraft)
    body = stub.captured[0]["body"]
    assert "fallbacks" not in body


def test_refusal_is_recoverable(stub):
    stub.stop_reason = "refusal"
    with pytest.raises(RecoverableError, match="declined"):
        backend().generate("t", "c", schemas.LlmRuleDraft)
