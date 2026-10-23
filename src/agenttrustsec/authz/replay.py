"""Used-token store (item B): single use must survive a gateway restart.

TrustSec analogy: ISE's session table. Kept only in RAM, a reboot forgets which approvals were
spent, and a used change approval (15 min ttl) could be replayed against a restarted gateway
that shares the broker key. `SqliteJtiStore` keeps the spent token ids on disk.

`claim(jti, exp)` is the only operation: True the first time, False for a replay. The SQLite
primary key makes the claim atomic, also across processes sharing the file. Rows are purged
once their token has expired — the broker refuses an expired token before it asks the store.
Any storage error raises `ReplayStoreError` (fail closed: the gate records approval ERROR = BLOCK).
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Protocol

DEFAULT_DB = Path.home() / ".agenttrustsec" / "state" / "jti.sqlite3"


class ReplayStoreError(RuntimeError):
    """The store cannot answer -> the token is not accepted."""


class JtiStore(Protocol):
    def claim(self, jti: str, exp: int) -> bool: ...


class MemoryJtiStore:
    """Process memory only (unit tests, the offline demo). Forgets on restart."""

    def __init__(self) -> None:
        self._used: dict[str, int] = {}
        self._lock = threading.Lock()

    def claim(self, jti: str, exp: int) -> bool:
        now = int(time.time())
        with self._lock:
            self._used = {j: e for j, e in self._used.items() if e > now}
            if jti in self._used:
                return False
            self._used[jti] = int(exp)
            return True


class SqliteJtiStore:
    def __init__(self, path: str | Path = DEFAULT_DB, timeout_s: float = 5.0):
        self.path = Path(path)
        self._timeout = timeout_s
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            db = self._connect()
            try:
                with db:
                    db.execute("CREATE TABLE IF NOT EXISTS used_jti (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL)")
            finally:
                db.close()
        except (sqlite3.Error, OSError) as e:
            raise ReplayStoreError(f"used-token store unavailable: {e}") from None

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=self._timeout, isolation_level="IMMEDIATE")

    def claim(self, jti: str, exp: int) -> bool:
        try:
            db = self._connect()
            try:
                with db:                                    # one transaction: purge + insert
                    db.execute("DELETE FROM used_jti WHERE exp <= ?", (int(time.time()),))
                    db.execute("INSERT INTO used_jti (jti, exp) VALUES (?, ?)", (jti, int(exp)))
                return True
            except sqlite3.IntegrityError:
                return False                                # already claimed: replay
            finally:
                db.close()
        except (sqlite3.Error, OSError) as e:
            raise ReplayStoreError(f"used-token store unavailable: {e}") from None
