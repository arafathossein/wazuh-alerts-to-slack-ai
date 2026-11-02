"""HTTP endpoint the Wazuh integration script posts alerts to.

POST /wazuh/alert   body: raw Wazuh alert JSON   header: X-API-Key (if configured)
GET  /health
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from .models import Triage
from .service import TriageService

app = FastAPI(title="Wazuh AI triage", version="0.1.0")
_service: TriageService | None = None


def get_service() -> TriageService:
    global _service
    if _service is None:
        _service = TriageService()
    return _service


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = os.getenv("SERVICE_API_KEY")
    if expected and not (x_api_key and hmac.compare_digest(x_api_key, expected)):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


@app.get("/health")
def health() -> dict:
    s = get_service()
    return {
        "status": "ok",
        "summarizer": s.summarizer.name,
        "notifier": type(s.notifier).__name__,
        "min_level": s.settings.min_level,
    }


@app.post("/wazuh/alert", response_model=Triage, dependencies=[Depends(require_key)])
async def receive_alert(request: Request) -> Triage:
    try:
        raw = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Body must be a Wazuh alert in JSON") from exc
    if not isinstance(raw, dict) or "rule" not in raw:
        raise HTTPException(status_code=422, detail="Not a Wazuh alert: missing 'rule'")
    return get_service().handle(raw)
