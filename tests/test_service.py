import json

import httpx

from wazuh_ai_triage.notify import SlackNotifier, slack_payload
from wazuh_ai_triage.service import TriageService
from wazuh_ai_triage.summarize import LLMSummarizer

from .conftest import alert


def test_below_threshold_is_not_sent(service, console):
    t = service.handle(alert("04_sudo_low.json"))
    assert t.decision == "below_threshold" and console.sent == []


def test_repeats_are_suppressed_then_reported(service, console):
    raw = alert("01_ssh_bruteforce.json")
    assert service.handle(raw, now=1000).decision == "notify"
    for i in range(4):
        assert service.handle(raw, now=1001 + i).decision == "suppress"
    later = service.handle(raw, now=1000 + 601)  # window over
    assert later.decision == "notify" and later.suppressed_since_last == 4
    assert len(console.sent) == 2


def test_long_running_attack_escalates(settings, console):
    settings.escalate_every = 5
    svc = TriageService(settings, notifier=console)
    raw = alert("01_ssh_bruteforce.json")
    decisions = [svc.handle(raw, now=2000 + i).decision for i in range(7)]
    assert decisions == ["notify", "suppress", "suppress", "suppress", "suppress", "notify", "suppress"]


def test_different_sources_are_not_merged(service):
    a = alert("01_ssh_bruteforce.json")
    b = alert("01_ssh_bruteforce.json")
    b["data"]["srcip"] = "203.0.113.99"
    assert service.handle(a, now=1).decision == "notify"
    assert service.handle(b, now=2).decision == "notify"


def test_every_alert_is_audited(service, settings):
    for name in ["01_ssh_bruteforce.json", "04_sudo_low.json"]:
        service.handle(alert(name))
    lines = (settings.data_dir / "audit.jsonl").read_text().splitlines()
    assert [json.loads(x)["decision"] for x in lines] == ["notify", "below_threshold"]


def _llm(content: str) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert "Summer2026!" not in sent["messages"][1]["content"]  # redacted before leaving
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_llm_summary_used_when_valid(settings, console):
    content = json.dumps(
        {
            "headline": "VPN login for j.doe after 9 failures",
            "what_happened": "Login succeeded after repeated failures.",
            "why_it_matters": "Possible password guessing.",
            "actions": ["Confirm with the user", "Reset credentials if unconfirmed"],
        }
    )
    llm = LLMSummarizer("http://llm.test/v1", "k", "m", client=_llm(content))
    t = TriageService(settings, summarizer=llm, notifier=console).handle(alert("05_secret_in_log.json"))
    assert t.summarizer == "llm" and t.summary.headline.startswith("VPN login")


def test_invalid_llm_output_falls_back_to_playbook(settings, console):
    llm = LLMSummarizer("http://llm.test/v1", "k", "m", client=_llm("not json at all"))
    t = TriageService(settings, summarizer=llm, notifier=console).handle(alert("05_secret_in_log.json"))
    assert t.summarizer == "playbook (llm failed)"
    assert t.summary.headline.startswith("Possible account takeover")


def test_slack_payload_shape(service):
    t = service.handle(alert("02_fim_etc_passwd.json"), send=False)
    p = slack_payload(t, "https://wazuh.example/app")
    types = [b["type"] for b in p["blocks"]]
    assert types[0] == "header" and "actions" in types and types.count("context") == 1
    assert len(p["blocks"][0]["text"]["text"]) <= 150
    assert "/etc/passwd" in json.dumps(p)


def test_slack_notifier_posts_payload(service):
    t = service.handle(alert("03_web_sqli.json"), send=False)
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, text="ok")

    SlackNotifier("https://hooks.slack.test/x", client=httpx.Client(transport=httpx.MockTransport(handler))).send(t)
    assert seen["body"]["blocks"][0]["type"] == "header"
