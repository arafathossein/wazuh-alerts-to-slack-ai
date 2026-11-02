import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wazuh_ai_triage import api
from wazuh_ai_triage.service import TriageService

from .conftest import ALERTS, ROOT, alert

SCRIPT = ROOT / "integration" / "custom-ai-triage.py"


@pytest.fixture
def client(settings, console, monkeypatch):
    monkeypatch.setattr(api, "_service", TriageService(settings, notifier=console))
    monkeypatch.delenv("SERVICE_API_KEY", raising=False)
    return TestClient(api.app)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_alert_endpoint(client, console):
    r = client.post("/wazuh/alert", json=alert("01_ssh_bruteforce.json"))
    assert r.status_code == 200 and r.json()["decision"] == "notify"
    assert len(console.sent) == 1


def test_rejects_non_alerts(client):
    assert client.post("/wazuh/alert", json={"hello": "world"}).status_code == 422


def test_api_key(client, monkeypatch):
    monkeypatch.setenv("SERVICE_API_KEY", "k3y")
    assert client.post("/wazuh/alert", json=alert("01_ssh_bruteforce.json")).status_code == 401
    ok = client.post("/wazuh/alert", json=alert("01_ssh_bruteforce.json"), headers={"X-API-Key": "k3y"})
    assert ok.status_code == 200


class _Recorder(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Recorder.received.append((self.headers.get("X-API-Key"), json.loads(body)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


def test_integration_script_forwards_alert_like_wazuh_does(tmp_path: Path):
    """Run the script exactly as Wazuh's integrator would: <alert_file> <api_key> <hook_url>."""
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/wazuh/alert"
        alert_file = tmp_path / "alert.json"
        alert_file.write_text((ALERTS / "03_web_sqli.json").read_text())
        _Recorder.received.clear()
        proc = subprocess.run([sys.executable, str(SCRIPT), str(alert_file), "secret-key", url], timeout=30)
        assert proc.returncode == 0
        key, body = _Recorder.received[0]
        assert key == "secret-key" and body["rule"]["id"] == "31103"
    finally:
        server.shutdown()


def test_integration_script_reports_unreachable_service(tmp_path: Path):
    alert_file = tmp_path / "alert.json"
    alert_file.write_text("{}")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(alert_file), "", "http://127.0.0.1:9/nowhere"], timeout=30, capture_output=True
    )
    assert proc.returncode == 1
