"""Item B: spent token ids survive a restart (SQLite store), claims are atomic across threads
and processes, and a broken store is a BLOCK. Never loosen."""
import multiprocessing
import secrets
import sqlite3
import threading
import time

import pytest

from agenttrustsec.authz.broker import TokenBroker, TokenError, lines_digest
from agenttrustsec.authz.gate import Gate
from agenttrustsec.authz.intent import BaselineIntentChecker
from agenttrustsec.authz.replay import MemoryJtiStore, ReplayStoreError, SqliteJtiStore
from agenttrustsec.models import Intent, Session, Status, ToolCall, Verdict

LINES = ["no permit ip any any"]
PUSH = {"device": "edge-fw-01", "lines": LINES}
CHANGE = Session("Remove the permit ip any any rule from the ACL on edge-fw-01", Intent.CHANGE)
LATER = int(time.time()) + 900


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return MemoryJtiStore() if request.param == "memory" else SqliteJtiStore(tmp_path / "jti.sqlite3")


def test_second_claim_is_a_replay(store):
    assert store.claim("a", LATER) is True
    assert store.claim("a", LATER) is False
    assert store.claim("b", LATER) is True


def test_sqlite_claims_survive_a_restart(tmp_path):
    db = tmp_path / "jti.sqlite3"
    assert SqliteJtiStore(db).claim("a", LATER)
    assert SqliteJtiStore(db).claim("a", LATER) is False               # new instance = restarted gateway


def test_default_store_creates_its_directory(tmp_path):
    db = tmp_path / "state" / "deeper" / "jti.sqlite3"
    assert SqliteJtiStore(db).claim("a", LATER) and db.exists()


def test_expired_ids_are_purged(tmp_path, store):
    store.claim("old", int(time.time()) - 1)
    store.claim("new", LATER)                                          # purges on every claim
    if isinstance(store, SqliteJtiStore):
        with sqlite3.connect(store.path) as db:
            assert [r[0] for r in db.execute("SELECT jti FROM used_jti")] == ["new"]
    else:
        assert set(store._used) == {"new"}


def test_concurrent_threads_exactly_one_wins(store):
    results, barrier = [], threading.Barrier(8)

    def claim():
        barrier.wait()
        results.append(store.claim("same", LATER))
    threads = [threading.Thread(target=claim) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == [False] * 7 + [True]


def _claim_in_process(path, start, out):
    start.wait()
    out.put(SqliteJtiStore(path).claim("same", LATER))


def test_concurrent_processes_exactly_one_wins(tmp_path):
    db = tmp_path / "jti.sqlite3"
    SqliteJtiStore(db)
    ctx = multiprocessing.get_context("spawn")
    start, out = ctx.Event(), ctx.Queue()
    procs = [ctx.Process(target=_claim_in_process, args=(db, start, out)) for _ in range(2)]
    [p.start() for p in procs]
    start.set()
    got = sorted(out.get(timeout=60) for _ in procs)
    [p.join(30) for p in procs]
    assert got == [False, True]


def test_unopenable_store_refuses(tmp_path):
    (tmp_path / "dir.sqlite3").mkdir()                                 # a directory, not a db file
    with pytest.raises(ReplayStoreError):
        SqliteJtiStore(tmp_path / "dir.sqlite3")


def test_corrupt_store_raises_not_allows(tmp_path):
    db = tmp_path / "jti.sqlite3"
    store = SqliteJtiStore(db)
    db.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(ReplayStoreError):
        store.claim("a", LATER)


# --- broker + gate ---------------------------------------------------------------------------

def test_broker_replay_across_restart_with_the_same_key(tmp_path):
    key, db = secrets.token_bytes(32), tmp_path / "jti.sqlite3"
    tok = TokenBroker(key, jti_store=SqliteJtiStore(db)).mint_approval(
        "CR-1", "edge-fw-01", LINES, CHANGE.session_id, ["reviewer-01"])
    TokenBroker(key, jti_store=SqliteJtiStore(db)).redeem_approval(tok, "edge-fw-01", LINES, CHANGE.session_id)
    with pytest.raises(TokenError, match="already used"):
        TokenBroker(key, jti_store=SqliteJtiStore(db)).redeem_approval(tok, "edge-fw-01", LINES, CHANGE.session_id)


def test_access_tokens_use_the_store_too(tmp_path):
    key, db = secrets.token_bytes(32), tmp_path / "jti.sqlite3"
    tok = TokenBroker(key).mint("reader-01", "lookup_threat_intel", "s1", "threat-intel")
    TokenBroker(key, jti_store=SqliteJtiStore(db)).redeem(tok, "threat-intel", "lookup_threat_intel")
    with pytest.raises(TokenError, match="already used"):
        TokenBroker(key, jti_store=SqliteJtiStore(db)).redeem(tok, "threat-intel", "lookup_threat_intel")


def test_token_without_jti_is_refused():
    b = TokenBroker(secrets.token_bytes(32))
    now = int(time.time())
    tok = b._sign({"iss": b.issuer, "typ": "approval", "iat": now, "exp": now + 60, "change_id": "C",
                   "device": "edge-fw-01", "lines": lines_digest(LINES), "sid": CHANGE.session_id,
                   "approvers": ["r"]})
    with pytest.raises(TokenError, match="no jti"):
        b.redeem_approval(tok, "edge-fw-01", LINES, CHANGE.session_id)


class BrokenStore:
    def claim(self, jti, exp):
        raise ReplayStoreError("used-token store unavailable: disk I/O error")


def test_broken_store_blocks_the_push_with_approval_error(verifier, policy, audit):
    b = TokenBroker(secrets.token_bytes(32), jti_store=BrokenStore())
    gate = Gate(verifier, policy, BaselineIntentChecker(), audit, approvals=b)
    tok = b.mint_approval("CR-1", "edge-fw-01", LINES, CHANGE.session_id, ["reviewer-01"])
    d = gate.authorize(ToolCall("executor-01", verifier.issue("executor-01", "executor"),
                                "push_config", CHANGE, PUSH, approval=tok))
    assert d.verdict is Verdict.BLOCK and d.blocked_by == "approval"
    assert d.checks[-1].status is Status.ERROR and "store unavailable" in d.checks[-1].reason
