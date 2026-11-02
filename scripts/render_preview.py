"""Render docs/preview.html from the real Block Kit payload of a sample alert.

    python scripts/render_preview.py samples/alerts/05_secret_in_log.json > docs/preview.html
The HTML is a neutral approximation of how a chat client lays out the blocks.
"""

import html
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wazuh_ai_triage.notify import ConsoleNotifier, slack_payload  # noqa: E402
from wazuh_ai_triage.service import Settings, TriageService  # noqa: E402


def md(text: str) -> str:
    t = html.escape(text)
    t = re.sub(r"\*(.+?)\*", r"<b>\1</b>", t)
    t = re.sub(r"`(.+?)`", r"<code>\1</code>", t)
    return t.replace("\n", "<br>")


def render(payload: dict) -> str:
    parts = []
    for b in payload["blocks"]:
        if b["type"] == "header":
            parts.append(f'<div class="h">{html.escape(b["text"]["text"])}</div>')
        elif b["type"] == "section" and "fields" in b:
            parts.append('<div class="f">' + "".join(f"<div>{md(f['text'])}</div>" for f in b["fields"]) + "</div>")
        elif b["type"] == "section":
            parts.append(f'<div class="s">{md(b["text"]["text"])}</div>')
        elif b["type"] == "context":
            parts.append('<div class="c">' + " &nbsp;·&nbsp; ".join(md(e["text"]) for e in b["elements"]) + "</div>")
        elif b["type"] == "actions":
            parts.append('<div class="a">' + "".join(f'<span>{html.escape(e["text"]["text"])}</span>' for e in b["elements"]) + "</div>")
    return f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;padding:28px;background:#f4f4f6;font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1d1c1d}}
.m{{max-width:720px;background:#fff;border:1px solid #e2e2e6;border-radius:10px;padding:18px 20px;border-left:4px solid #e8912d}}
.who{{font-weight:700;margin-bottom:8px}}.who small{{font-weight:400;color:#616061;margin-left:6px}}
.h{{font-size:18px;font-weight:700;margin:4px 0 12px}}
.f{{display:grid;grid-template-columns:1fr 1fr;gap:10px 24px;margin-bottom:12px}}
.s{{margin:10px 0}}.c{{color:#616061;font-size:12.5px;margin-top:12px}}
.a span{{display:inline-block;margin-top:12px;border:1px solid #c9c9cd;border-radius:6px;padding:4px 12px;font-weight:600;font-size:13.5px}}
code{{background:#f2f2f4;border-radius:3px;padding:0 4px;font-size:13px}}</style>
<div class="m"><div class="who">wazuh-ai-triage <small>APP · 06:12</small></div>{''.join(parts)}</div>"""


if __name__ == "__main__":
    raw = json.loads(Path(sys.argv[1]).read_text())
    svc = TriageService(Settings(data_dir=Path(tempfile.mkdtemp()), slack_webhook_url=None, llm_base_url=None), notifier=ConsoleNotifier())
    t = svc.handle(raw, send=False)
    print(render(slack_payload(t, "https://wazuh.example.internal/app/threat-hunting")))
