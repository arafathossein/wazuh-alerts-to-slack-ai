"""Summaries from an OpenAI-compatible model, with the playbook as fallback."""

from __future__ import annotations

import json
import logging
import re
from typing import Protocol

import httpx

from .models import Alert, Summary
from .playbooks import playbook_summary

log = logging.getLogger("wazuh_ai_triage")


class Summarizer(Protocol):
    name: str

    def summarize(self, alert: Alert) -> Summary: ...


class PlaybookSummarizer:
    name = "playbook"

    def summarize(self, alert: Alert) -> Summary:
        return playbook_summary(alert)


_SYSTEM = """You are a security analyst writing a short Slack summary of one Wazuh alert for an on-call engineer.
Reply with JSON only:
{"headline": str (max 90 chars), "what_happened": str (1-2 sentences),
 "why_it_matters": str (1 sentence), "actions": [str, ...] (2-4 concrete checks),
 "false_positive_hints": [str, ...] (0-2)}
Rules:
- Use only facts present in the alert. Do not invent IPs, users, files or counts.
- Recommend checks and containment for a human to perform. Never claim anything was already done.
- Plain, specific language. No markdown."""


class LLMSummarizer:
    name = "llm"

    def __init__(self, base_url: str, api_key: str, model: str, client: httpx.Client | None = None, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.client = client or httpx.Client(timeout=timeout)

    def summarize(self, alert: Alert) -> Summary:
        payload = alert.model_dump(mode="json", exclude_none=True)
        resp = self.client.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            json={
                "model": self.model,
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": json.dumps(payload)[:12000]},
                ],
            },
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content)
        summary = Summary.model_validate(json.loads(content))
        if not summary.actions:
            raise ValueError("model returned no actions")
        summary.actions = summary.actions[:4]
        summary.headline = summary.headline[:120]
        return summary


class FallbackSummarizer:
    """Try the model; on any failure use the playbook and say so."""

    def __init__(self, primary: Summarizer):
        self.primary = primary
        self.fallback = PlaybookSummarizer()
        self.name = primary.name

    def summarize_with_source(self, alert: Alert) -> tuple[Summary, str]:
        try:
            return self.primary.summarize(alert), self.primary.name
        except Exception as exc:  # network, quota, invalid JSON, schema mismatch
            log.warning("summarizer %s failed (%s); using playbook", self.primary.name, exc)
            return self.fallback.summarize(alert), "playbook (llm failed)"
