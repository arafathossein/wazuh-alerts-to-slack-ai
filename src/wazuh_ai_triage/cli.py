"""Command line.

    wazuh-ai-triage triage samples/alerts/*.json      # print what would be sent
    wazuh-ai-triage slack-json samples/alerts/01_ssh_bruteforce.json
    wazuh-ai-triage serve --port 8080
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .notify import ConsoleNotifier, slack_payload
from .service import Settings, TriageService


def _load(paths: list[str]) -> list[tuple[str, dict]]:
    out = []
    for p in paths:
        text = Path(p).read_text(encoding="utf-8").strip()
        # a single (possibly pretty-printed) alert, or Wazuh's alerts.json with one alert per line
        try:
            docs = [json.loads(text)]
        except json.JSONDecodeError:
            docs = [json.loads(x) for x in text.splitlines() if x.strip()]
        out += [(Path(p).name, d) for d in docs]
    return out


def _triage(args: argparse.Namespace) -> int:
    settings = Settings(data_dir=Path(tempfile.mkdtemp())) if args.fresh else Settings()
    service = TriageService(settings, notifier=ConsoleNotifier())
    print(f"summarizer: {service.summarizer.name} | min level: {settings.min_level}\n", file=sys.stderr)
    for name, raw in _load(args.files):
        t = service.handle(raw)
        if t.decision != "notify":
            print(f"[{t.decision}] {name}: rule {t.alert.rule_id} level {t.alert.rule_level}\n")
    return 0


def _slack_json(args: argparse.Namespace) -> int:
    service = TriageService(Settings(data_dir=Path(tempfile.mkdtemp())), notifier=ConsoleNotifier())
    for _, raw in _load(args.files):
        t = service.handle(raw, send=False)
        print(json.dumps(slack_payload(t, service.settings.dashboard_url), indent=2, ensure_ascii=False))
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("wazuh_ai_triage.api:app", host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wazuh-ai-triage")
    sub = parser.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("triage", help="Triage alert JSON files and print the messages")
    t.add_argument("files", nargs="+")
    t.add_argument("--fresh", action="store_true", help="Use an empty throttle state")
    t.set_defaults(func=_triage)

    j = sub.add_parser("slack-json", help="Print the Slack Block Kit payload for alert files")
    j.add_argument("files", nargs="+")
    j.set_defaults(func=_slack_json)

    s = sub.add_parser("serve", help="Run the HTTP endpoint")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
