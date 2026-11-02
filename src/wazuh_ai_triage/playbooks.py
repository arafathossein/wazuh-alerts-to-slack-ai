"""Deterministic summaries for common alert families.

Used when no language model is configured, when the model call fails, and
as the baseline the model's output is compared against in tests. Each
playbook suggests checks a person should make; none of them acts.
"""

from __future__ import annotations

from collections.abc import Callable

from .models import Alert, Summary

_WHY = {
    "low": "Low severity on its own. Worth a look if it repeats or appears with other alerts.",
    "medium": "Medium severity: an attempt or change that should be confirmed as expected.",
    "high": "High severity: likely malicious or a significant control failure. Investigate promptly.",
    "critical": "Critical severity: treat as an active incident until shown otherwise.",
}


def _where(a: Alert) -> str:
    return a.agent_name or a.agent_ip or "an agent"


def _has(a: Alert, *groups: str) -> bool:
    return any(g in a.groups for g in groups)


def _bruteforce(a: Alert) -> Summary:
    src = a.src_ip or "an unknown source"
    return Summary(
        headline=f"Repeated failed logins on {_where(a)} from {src}",
        what_happened=(
            f"Wazuh rule {a.rule_id} ({a.rule_description}) fired"
            + (f" {a.firedtimes} times" if a.firedtimes else "")
            + f" for logins to {_where(a)} from {src}"
            + (f", targeting user '{a.dst_user or a.src_user}'." if (a.dst_user or a.src_user) else ".")
        ),
        why_it_matters="A password-guessing attempt. It matters most if any login from the same source later succeeded.",
        actions=[
            f"Search for a successful login from {src} after this alert (e.g. rule 5715 for SSH).",
            f"Block {src} at the firewall, or enable Wazuh active response for this rule if not already on.",
            "Confirm password authentication is disabled for SSH and key-based login is enforced.",
            "Check whether the targeted usernames exist; unexpected valid usernames suggest prior reconnaissance.",
        ],
        false_positive_hints=["A user or script with a stale password can trigger this from an internal address."],
    )


def _compromised_login(a: Alert) -> Summary:
    who = a.src_user or a.dst_user or "an account"
    src = a.src_ip or "an unknown source"
    return Summary(
        headline=f"Possible account takeover: {who} logged in to {_where(a)} after repeated failures",
        what_happened=(
            f"Rule {a.rule_id}: {a.rule_description} The successful login for {who} came from {src}."
        ),
        why_it_matters="A success after a run of failures often means a password was guessed. Treat it as a compromised account until confirmed otherwise.",
        actions=[
            f"Contact {who} through a separate channel to confirm whether this login was theirs.",
            "If not confirmed, disable or lock the account, revoke its sessions and reset its credentials.",
            f"Review what {who} did after logging in and block {src} if it is not a known location.",
            "Check whether multi-factor authentication is enforced for this service.",
        ],
        false_positive_hints=["A user who mistyped their password several times will produce the same pattern."],
    )


def _fim(a: Alert) -> Summary:
    path = a.file_path or "a monitored file"
    return Summary(
        headline=f"Monitored file changed on {_where(a)}: {path}",
        what_happened=f"File integrity monitoring reported: {a.rule_description} Path: {path}.",
        why_it_matters=(
            "Unexpected changes to system or configuration files are a common sign of persistence or tampering."
            if path.startswith(("/etc", "/bin", "/sbin", "/usr/bin", "C:\\Windows"))
            else "A monitored file changed. Confirm it matches planned work."
        ),
        actions=[
            "Check the change against your change log or deployment history for this host.",
            "Review the diff and, if whodata is enabled, which user and process made the change.",
            "If the change is unexplained, preserve the file and isolate the host before investigating further.",
        ],
        false_positive_hints=["Package updates and configuration management runs change monitored files routinely."],
    )


def _web(a: Alert) -> Summary:
    src = a.src_ip or "an unknown source"
    return Summary(
        headline=f"Web attack pattern against {_where(a)} from {src}",
        what_happened=f"Rule {a.rule_id} matched a request in the web server log: {a.rule_description}",
        why_it_matters="Most scans fail, but a success response means the application may be vulnerable.",
        actions=[
            "Check the HTTP status code in the log line; 200 responses deserve a closer look than 4xx.",
            "Review application logs around the same time for errors or unusual queries.",
            f"Consider blocking {src} at the WAF or reverse proxy if it keeps scanning.",
            "Confirm the application is patched and uses parameterised queries.",
        ],
        false_positive_hints=["Authorised vulnerability scanners produce the same patterns."],
    )


def _malware(a: Alert) -> Summary:
    return Summary(
        headline=f"Possible malware or rootkit indicator on {_where(a)}",
        what_happened=f"Rule {a.rule_id}: {a.rule_description}"
        + (f" Path: {a.file_path}." if a.file_path else ""),
        why_it_matters="Indicators of compromise on a host should be treated as an incident until disproved.",
        actions=[
            "Isolate the host from the network if it holds sensitive data or credentials.",
            "Collect the flagged file's hash and check it against threat intelligence.",
            "Review recent logins and processes on the host.",
            "Escalate to your incident response process.",
        ],
        false_positive_hints=["Some admin and security tools are flagged by generic signatures."],
    )


def _sudo(a: Alert) -> Summary:
    who = a.src_user or "a user"
    return Summary(
        headline=f"{who} gained root via sudo on {_where(a)}",
        what_happened=f"Rule {a.rule_id}: {a.rule_description}",
        why_it_matters="Privilege use is normal for admins; it matters when the user or timing is unexpected.",
        actions=[
            f"Confirm {who} is expected to administer {_where(a)} at this time.",
            "Review the command that was run (full log) for anything outside normal duties.",
        ],
        false_positive_hints=["Scheduled maintenance and automation accounts use sudo routinely."],
    )


def _vuln(a: Alert) -> Summary:
    return Summary(
        headline=f"Vulnerable package detected on {_where(a)}",
        what_happened=f"Vulnerability detection: {a.rule_description}",
        why_it_matters="Known vulnerabilities are a common entry point, especially on internet-facing hosts.",
        actions=[
            "Check whether a fixed package version is available and schedule the update.",
            "Prioritise if the host is internet-facing or the CVE is known to be exploited.",
        ],
    )


def _generic(a: Alert) -> Summary:
    return Summary(
        headline=f"{a.rule_description} on {_where(a)}",
        what_happened=f"Wazuh rule {a.rule_id} (level {a.rule_level}) fired on {_where(a)}"
        + (f" involving {a.src_ip}." if a.src_ip else "."),
        why_it_matters=_WHY[a.severity.value],
        actions=[
            "Open the alert in the Wazuh dashboard and review the full log.",
            "Check for related alerts on the same host or source in the last hour.",
        ],
    )


_RULES: list[tuple[Callable[[Alert], bool], Callable[[Alert], Summary]]] = [
    (lambda a: _has(a, "rootcheck", "malware", "virustotal", "yara"), _malware),
    # success after failures outranks plain brute force
    (lambda a: _has(a, "authentication_success") and (_has(a, "attack", "authentication_failures") or a.rule_id == "40112"), _compromised_login),
    (lambda a: _has(a, "authentication_failures", "brute_force") or a.rule_id in {"5712", "5720", "5763"}, _bruteforce),
    (lambda a: _has(a, "syscheck", "syscheck_entry_modified", "syscheck_file"), _fim),
    (lambda a: _has(a, "web", "accesslog", "sql_injection", "web_scan"), _web),
    (lambda a: _has(a, "sudo"), _sudo),
    (lambda a: _has(a, "vulnerability-detector"), _vuln),
]


def playbook_summary(alert: Alert) -> Summary:
    for match, build in _RULES:
        if match(alert):
            return build(alert)
    return _generic(alert)
