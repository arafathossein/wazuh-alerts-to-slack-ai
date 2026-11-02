#!/var/ossec/framework/python/bin/python3
"""Wazuh integration: forward an alert to the AI triage service.

Install on the Wazuh manager:
    cp custom-ai-triage.py /var/ossec/integrations/
    chmod 750 /var/ossec/integrations/custom-ai-triage.py
    chown root:wazuh /var/ossec/integrations/custom-ai-triage.py

Wazuh's integrator calls it as:
    custom-ai-triage.py <alert_file> <api_key> <hook_url> [debug]

Deliberately standard-library only, so nothing extra is installed on the
manager, and it never blocks Wazuh for long: one short HTTP POST, then exit.
"""

import json
import sys
import time
import urllib.error
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"
TIMEOUT_SECONDS = 10
RETRIES = 2


def log(message, debug_enabled):
    if not debug_enabled:
        return
    line = f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-ai-triage: {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


def post(hook_url, api_key, alert):
    body = json.dumps(alert).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "wazuh-custom-ai-triage/0.1"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(hook_url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return resp.status


def main(argv):
    if len(argv) < 4:
        sys.stderr.write("usage: custom-ai-triage.py <alert_file> <api_key> <hook_url> [debug]\n")
        return 2
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    debug_enabled = len(argv) > 4 and argv[4] == "debug"

    try:
        with open(alert_file, encoding="utf-8") as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        log(f"cannot read alert file {alert_file}: {exc}", True)
        return 1

    for attempt in range(RETRIES + 1):
        try:
            status = post(hook_url, api_key, alert)
            log(f"alert {alert.get('id')} rule {alert.get('rule', {}).get('id')} -> HTTP {status}", debug_enabled)
            return 0
        except urllib.error.HTTPError as exc:
            log(f"HTTP {exc.code} from triage service", True)
            if exc.code < 500:
                return 1  # client error: retrying won't help
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log(f"attempt {attempt + 1} failed: {exc}", True)
        time.sleep(1 + attempt)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
