"""Delivery: Slack incoming webhook (Block Kit) or console."""

from __future__ import annotations

from typing import Protocol

import httpx

from .models import Severity, Triage

_ICON = {Severity.LOW: "🔵", Severity.MEDIUM: "🟡", Severity.HIGH: "🟠", Severity.CRITICAL: "🔴"}


class Notifier(Protocol):
    def send(self, triage: Triage) -> None: ...


def render_text(t: Triage) -> str:
    """Plain-text version, used for the console and as Slack's notification fallback."""
    a, s = t.alert, t.summary
    lines = [
        f"{_ICON[t.severity]} [{t.severity.value.upper()}] {s.headline}",
        f"Rule {a.rule_id} · level {a.rule_level} · agent {a.agent_name or '-'}"
        + (f" · source {a.src_ip}" if a.src_ip else ""),
        "",
        s.what_happened,
        f"Why it matters: {s.why_it_matters}",
        "Suggested checks:",
        *[f"  • {x}" for x in s.actions],
    ]
    if s.false_positive_hints:
        lines.append(f"Possible false positive: {s.false_positive_hints[0]}")
    if t.suppressed_since_last:
        lines.append(f"{t.suppressed_since_last} similar alert(s) were held back since the last message.")
    lines.append(f"Summary by {t.summarizer}. Verify before acting.")
    return "\n".join(lines)


def slack_payload(t: Triage, dashboard_url: str | None = None) -> dict:
    a, s = t.alert, t.summary
    fields = [
        f"*Severity*\n{_ICON[t.severity]} {t.severity.value.capitalize()} (level {a.rule_level})",
        f"*Rule*\n{a.rule_id}: {a.rule_description[:120]}",
        f"*Agent*\n{a.agent_name or '-'}" + (f" ({a.agent_ip})" if a.agent_ip else ""),
    ]
    if a.src_ip:
        fields.append(f"*Source*\n{a.src_ip}")
    if a.file_path:
        fields.append(f"*File*\n`{a.file_path}`")
    if a.mitre_ids:
        tactic = f" — {', '.join(a.mitre_tactics)}" if a.mitre_tactics else ""
        fields.append(f"*MITRE ATT&CK*\n{', '.join(a.mitre_ids)}{tactic}")

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{_ICON[t.severity]} {s.headline}"[:150]}},
        {"type": "section", "fields": [{"type": "mrkdwn", "text": f} for f in fields[:10]]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*What happened*\n{s.what_happened}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Why it matters*\n{s.why_it_matters}"}},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Suggested checks*\n" + "\n".join(f"• {x}" for x in s.actions)},
        },
    ]
    context = [f"Summary by {t.summarizer}. Verify before acting."]
    if t.suppressed_since_last:
        context.insert(0, f"{t.suppressed_since_last} similar alert(s) held back since the last message.")
    if s.false_positive_hints:
        context.append(f"Possible false positive: {s.false_positive_hints[0]}")
    if a.id:
        context.append(f"Alert {a.id}")
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": c} for c in context]})
    if dashboard_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in Wazuh"},
                        "url": dashboard_url,
                    }
                ],
            }
        )
    return {"text": render_text(t).split("\n", 1)[0], "blocks": blocks}


class SlackNotifier:
    def __init__(self, webhook_url: str, dashboard_url: str | None = None, client: httpx.Client | None = None):
        self.webhook_url = webhook_url
        self.dashboard_url = dashboard_url
        self.client = client or httpx.Client(timeout=10)

    def send(self, triage: Triage) -> None:
        resp = self.client.post(self.webhook_url, json=slack_payload(triage, self.dashboard_url))
        resp.raise_for_status()


class ConsoleNotifier:
    def __init__(self) -> None:
        self.sent: list[Triage] = []

    def send(self, triage: Triage) -> None:
        self.sent.append(triage)
        print(render_text(triage), end="\n\n", flush=True)
