import pytest

from wazuh_ai_triage.models import Severity
from wazuh_ai_triage.parse import parse_alert
from wazuh_ai_triage.redact import Redactor

from .conftest import alert


def test_parse_fields():
    a, _ = parse_alert(alert("01_ssh_bruteforce.json"))
    assert (a.rule_id, a.rule_level, a.agent_name, a.src_ip, a.dst_user) == ("5763", 10, "web-prod-01", "203.0.113.45", "admin")
    assert a.mitre_ids == ["T1110"] and "authentication_failures" in a.groups
    assert a.timestamp is not None and a.timestamp.year == 2026


def test_fim_path_parsed():
    a, _ = parse_alert(alert("02_fim_etc_passwd.json"))
    assert a.file_path == "/etc/passwd"


def test_secrets_and_emails_are_redacted():
    a, n = parse_alert(alert("05_secret_in_log.json"))
    assert n == 3
    assert "Summer2026!" not in a.full_log and "eyJhbGci" not in a.full_log and "@example.com" not in a.full_log


@pytest.mark.parametrize(
    "text",
    [
        "AKIAABCDEFGHIJKLMNOP leaked",
        "Authorization: Bearer abcdefghijklmnop1234",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
        "pwd: hunter2",
    ],
)
def test_redaction_patterns(text):
    out, n = Redactor().text(text)
    assert n >= 1 and "REDACTED" in out


def test_private_ip_masking_is_optional():
    raw = alert("01_ssh_bruteforce.json")
    plain, _ = parse_alert(raw)
    masked, _ = parse_alert(raw, Redactor(mask_private_ips=True))
    assert plain.agent_ip == "10.20.4.11"
    assert masked.agent_ip == "[internal-ip]"
    assert masked.src_ip == "203.0.113.45"  # public addresses are kept: they are what you block


@pytest.mark.parametrize(
    ("level", "sev"),
    [(3, Severity.LOW), (6, Severity.LOW), (7, Severity.MEDIUM), (11, Severity.MEDIUM), (12, Severity.HIGH), (15, Severity.CRITICAL)],
)
def test_severity_bands(level, sev):
    assert Severity.from_level(level) is sev
