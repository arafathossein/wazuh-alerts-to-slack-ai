"""Remove secrets and personal data from log text before it leaves the server.

Alert logs regularly contain things that must never reach a chat channel or
a third-party model: passwords in failed commands, bearer tokens in web
logs, cloud keys, email addresses.
"""

from __future__ import annotations

import ipaddress
import re

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("password", re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    ("bearer", re.compile(r"(?i)\b(bearer|token|api[_-]?key|apikey)\s*[=: ]\s*[A-Za-z0-9._\-~+/]{8,}=*"), r"\1 [REDACTED]"),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_KEY]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[email]"),
]

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Internal ranges only. ipaddress.is_private also covers documentation and
# other reserved ranges, which would hide the very addresses you need to block.
_INTERNAL = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10")
]


def is_internal(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == 4 and any(ip in net for net in _INTERNAL)


class Redactor:
    def __init__(self, mask_private_ips: bool = False):
        self.mask_private_ips = mask_private_ips

    def text(self, value: str | None) -> tuple[str | None, int]:
        if not value:
            return value, 0
        count = 0
        for _name, pattern, repl in _PATTERNS:
            value, n = pattern.subn(repl, value)
            count += n
        if self.mask_private_ips:
            masked = 0

            def mask(m: re.Match[str]) -> str:
                nonlocal masked
                if is_internal(m.group(0)):
                    masked += 1
                    return "[internal-ip]"
                return m.group(0)

            value = _IPV4.sub(mask, value)
            count += masked
        return value, count

    def ip(self, value: str | None) -> str | None:
        """Mask a single private IP field when masking is on."""
        if not value or not self.mask_private_ips:
            return value
        return "[internal-ip]" if is_internal(value) else value
