"""Append-only JSONL audit log — the ISE Live Logs equivalent."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from agenttrustsec.models import Decision


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, decision: Decision) -> None:
        line = json.dumps(decision.to_audit_record(), sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]
