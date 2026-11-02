import pytest

from wazuh_ai_triage.parse import parse_alert
from wazuh_ai_triage.playbooks import playbook_summary

from .conftest import alert


@pytest.mark.parametrize(
    ("name", "expected_headline_start"),
    [
        ("01_ssh_bruteforce.json", "Repeated failed logins"),
        ("02_fim_etc_passwd.json", "Monitored file changed"),
        ("03_web_sqli.json", "Web attack pattern"),
        ("04_sudo_low.json", "deploy gained root"),
        ("05_secret_in_log.json", "Possible account takeover"),
    ],
)
def test_each_sample_gets_the_right_playbook(name, expected_headline_start):
    a, _ = parse_alert(alert(name))
    s = playbook_summary(a)
    assert s.headline.startswith(expected_headline_start)
    assert 2 <= len(s.actions) <= 4


def test_unknown_alert_gets_generic_summary():
    a, _ = parse_alert({"rule": {"id": "99999", "level": 9, "description": "Something odd", "groups": ["custom"]}, "agent": {"name": "h1"}})
    s = playbook_summary(a)
    assert s.headline == "Something odd on h1"


def test_playbooks_never_claim_action_was_taken():
    for name in ["01_ssh_bruteforce.json", "02_fim_etc_passwd.json", "03_web_sqli.json", "05_secret_in_log.json"]:
        s = playbook_summary(parse_alert(alert(name))[0])
        text = " ".join([s.what_happened, *s.actions]).lower()
        assert "was blocked" not in text and "has been blocked" not in text and "we blocked" not in text
