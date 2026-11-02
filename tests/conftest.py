import json
from pathlib import Path

import pytest

from wazuh_ai_triage.notify import ConsoleNotifier
from wazuh_ai_triage.service import Settings, TriageService

ROOT = Path(__file__).resolve().parents[1]
ALERTS = ROOT / "samples" / "alerts"


def alert(name: str) -> dict:
    return json.loads((ALERTS / name).read_text())


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path, slack_webhook_url=None, llm_base_url=None, min_level=7)


@pytest.fixture
def console() -> ConsoleNotifier:
    return ConsoleNotifier()


@pytest.fixture
def service(settings: Settings, console: ConsoleNotifier) -> TriageService:
    return TriageService(settings, notifier=console)
