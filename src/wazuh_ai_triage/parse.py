"""Turn a raw Wazuh alert (JSON) into an ``Alert``, redacting as we go."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .models import Alert
from .redact import Redactor


def _get(d: dict, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)  # type: ignore[assignment]
    return d


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    # Wazuh writes e.g. 2026-10-30T08:14:02.123+0000
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def parse_alert(raw: dict, redactor: Redactor | None = None) -> tuple[Alert, int]:
    """Return the normalised alert and how many values were redacted."""
    redactor = redactor or Redactor()
    rule = raw.get("rule") or {}
    data = raw.get("data") or {}
    agent = raw.get("agent") or {}
    syscheck = raw.get("syscheck") or {}
    mitre = rule.get("mitre") or {}

    full_log, n = redactor.text(raw.get("full_log"))

    alert = Alert(
        id=str(raw.get("id") or raw.get("_id") or ""),
        timestamp=_ts(raw.get("timestamp")),
        rule_id=str(rule.get("id", "")),
        rule_level=int(rule.get("level", 0)),
        rule_description=str(rule.get("description", "")),
        groups=list(rule.get("groups") or []),
        mitre_ids=list(mitre.get("id") or []),
        mitre_tactics=list(mitre.get("tactic") or []),
        agent_id=agent.get("id"),
        agent_name=agent.get("name"),
        agent_ip=redactor.ip(agent.get("ip")),
        src_ip=redactor.ip(data.get("srcip") or _get(data, "src_ip")),
        src_user=data.get("srcuser"),
        dst_user=data.get("dstuser"),
        file_path=syscheck.get("path"),
        full_log=full_log,
        location=raw.get("location"),
        firedtimes=rule.get("firedtimes"),
    )
    return alert, n
