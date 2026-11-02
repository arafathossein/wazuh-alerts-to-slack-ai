"""Alert-fatigue control: one message per (rule, agent, source) per window.

The first alert in a window is sent. Repeats inside the window are counted,
not sent; the next message that does go out reports how many were held back.
Every ``escalate_every`` repeats, an update is sent anyway so a long-running
attack is never silent.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from .models import Alert


class Throttle:
    def __init__(self, path: Path, window_seconds: int = 600, escalate_every: int = 50):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.window = window_seconds
        self.escalate_every = escalate_every
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, last_sent REAL, suppressed INTEGER)"
        )
        self._db.commit()

    @staticmethod
    def key(alert: Alert) -> str:
        return "|".join([alert.rule_id, alert.agent_id or alert.agent_name or "-", alert.src_ip or alert.file_path or "-"])

    def check(self, alert: Alert, now: float | None = None) -> tuple[bool, int]:
        """Return (send?, number of repeats suppressed since the last message)."""
        now = time.time() if now is None else now
        k = self.key(alert)
        with self._lock:
            row = self._db.execute("SELECT last_sent, suppressed FROM seen WHERE key = ?", (k,)).fetchone()
            if row is None or now - row[0] >= self.window:
                held = row[1] if row else 0
                self._db.execute("REPLACE INTO seen VALUES (?, ?, 0)", (k, now))
                self._db.commit()
                return True, held
            suppressed = row[1] + 1
            if suppressed >= self.escalate_every:
                self._db.execute("UPDATE seen SET last_sent = ?, suppressed = 0 WHERE key = ?", (now, k))
                self._db.commit()
                return True, suppressed
            self._db.execute("UPDATE seen SET suppressed = ? WHERE key = ?", (suppressed, k))
            self._db.commit()
            return False, suppressed
