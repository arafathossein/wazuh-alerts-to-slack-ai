"""The triage pipeline: raw Wazuh alert → decision → (maybe) a message."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .models import Triage
from .notify import ConsoleNotifier, Notifier, SlackNotifier
from .parse import parse_alert
from .redact import Redactor
from .summarize import FallbackSummarizer, LLMSummarizer, PlaybookSummarizer, Summarizer
from .throttle import Throttle


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _bool(name: str) -> bool:
    return _env(name).lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    min_level: int = field(default_factory=lambda: int(_env("MIN_LEVEL", "7")))
    window_seconds: int = field(default_factory=lambda: int(_env("THROTTLE_WINDOW_SECONDS", "600")))
    escalate_every: int = field(default_factory=lambda: int(_env("ESCALATE_EVERY", "50")))
    mask_private_ips: bool = field(default_factory=lambda: _bool("MASK_PRIVATE_IPS"))
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "data")))
    slack_webhook_url: str | None = field(default_factory=lambda: _env("SLACK_WEBHOOK_URL") or None)
    dashboard_url: str | None = field(default_factory=lambda: _env("WAZUH_DASHBOARD_URL") or None)
    llm_base_url: str | None = field(default_factory=lambda: _env("LLM_BASE_URL") or None)
    llm_api_key: str = field(default_factory=lambda: _env("LLM_API_KEY"))
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL", "gpt-4o-mini"))


class TriageService:
    def __init__(
        self,
        settings: Settings | None = None,
        summarizer: Summarizer | None = None,
        notifier: Notifier | None = None,
    ):
        self.settings = s = settings or Settings()
        self.redactor = Redactor(mask_private_ips=s.mask_private_ips)
        self.throttle = Throttle(s.data_dir / "throttle.sqlite3", s.window_seconds, s.escalate_every)
        if summarizer is None:
            summarizer = (
                LLMSummarizer(s.llm_base_url, s.llm_api_key, s.llm_model) if s.llm_base_url else PlaybookSummarizer()
            )
        self.summarizer = FallbackSummarizer(summarizer)
        self.notifier: Notifier = notifier or (
            SlackNotifier(s.slack_webhook_url, s.dashboard_url) if s.slack_webhook_url else ConsoleNotifier()
        )
        self._audit_lock = threading.Lock()
        self.audit_path = s.data_dir / "audit.jsonl"

    def handle(self, raw: dict, *, now: float | None = None, send: bool = True) -> Triage:
        alert, redactions = parse_alert(raw, self.redactor)

        if alert.rule_level < self.settings.min_level:
            summary = PlaybookSummarizer().summarize(alert)
            result = Triage(
                alert=alert,
                severity=alert.severity,
                summary=summary,
                summarizer="playbook",
                decision="below_threshold",
                redactions=redactions,
            )
            self._audit(result)
            return result

        should_send, held = self.throttle.check(alert, now=now)
        if not should_send:
            result = Triage(
                alert=alert,
                severity=alert.severity,
                summary=PlaybookSummarizer().summarize(alert),  # cheap; the model is not called for repeats
                summarizer="playbook",
                suppressed_since_last=held,
                decision="suppress",
                redactions=redactions,
            )
            self._audit(result)
            return result

        summary, source = self.summarizer.summarize_with_source(alert)
        result = Triage(
            alert=alert,
            severity=alert.severity,
            summary=summary,
            summarizer=source,
            suppressed_since_last=held,
            decision="notify",
            redactions=redactions,
        )
        if send:
            self.notifier.send(result)
        self._audit(result)
        return result

    def _audit(self, result: Triage) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_lock, self.audit_path.open("a", encoding="utf-8") as f:
            f.write(result.model_dump_json() + "\n")
