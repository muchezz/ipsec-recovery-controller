"""Persistent admission control. No retries after admission, including uncertain failures."""
from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from ipsec_recovery_controller.config import RecoveryPolicy

log = logging.getLogger(__name__)


def audit(connection: str, decision: str, event: str) -> None:
    log.info("audit_event %s", json.dumps({"event": "recovery", "connection": connection,
                                         "decision": decision, "event_id": event}, sort_keys=True))


class RecoveryGate:
    def __init__(self, policy: RecoveryPolicy):
        self.policy = policy

    def run(self, connection: str, event: str, operation) -> str:
        decision = "recovery_failed"
        try:
            decision = self._run(connection, event, operation)
        except Exception:
            # State store, lock, transport and verification failures all close admission.
            log.exception("recovery failed closed for %s", connection)
        audit(connection, decision, event)
        return decision

    def _run(self, connection: str, event: str, operation) -> str:
        directory = Path(self.policy.state_directory)
        # Provisioned by deployment, never silently replace missing persistent storage.
        uri = (directory / "recovery.sqlite3").absolute().as_uri() + "?mode=rw"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            if (db.execute("PRAGMA user_version").fetchone() != (1,)
                    or db.execute("PRAGMA quick_check").fetchall() != [("ok",)]):
                raise ValueError("persistent recovery state is invalid or uninitialized")
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            db.execute("DELETE FROM arrivals WHERE at < ?", (now - self.policy.storm_window_seconds,))
            db.execute("INSERT INTO arrivals VALUES (?)", (now,))
            count = db.execute("SELECT count(*) FROM arrivals").fetchone()[0]
            if count > self.policy.storm_threshold:
                db.execute("INSERT OR REPLACE INTO breaker VALUES (1, ?)",
                           (now + self.policy.breaker_seconds,))
            blocked = db.execute("SELECT until FROM breaker WHERE id=1").fetchone()
            db.commit()
            if blocked and now < blocked[0]:
                return "circuit_open"
            # Kernel locks survive neither crashes nor reboots; admission records do.
            with open(directory / "global.lock", "a") as global_lock:
                try:
                    fcntl.flock(global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return "recovery_busy"
                key = hashlib.sha256(connection.encode()).hexdigest()
                with open(directory / (key + ".lock"), "a") as connection_lock:
                    fcntl.flock(connection_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    db.execute("BEGIN IMMEDIATE")
                    # Storm arrivals can open the breaker while waiting for locks.
                    blocked = db.execute("SELECT until FROM breaker WHERE id=1").fetchone()
                    if blocked and time.time() < blocked[0]:
                        db.rollback()
                        return "circuit_open"
                    if db.execute("SELECT 1 FROM seen WHERE event=?", (event,)).fetchone():
                        db.rollback()
                        return "duplicate_alert"
                    inflight = db.execute("SELECT until FROM inflight WHERE id=1").fetchone()
                    if inflight and now < inflight[0]:
                        db.rollback()
                        return "recovery_busy"
                    previous = db.execute("SELECT at FROM attempts WHERE connection=?", (connection,)).fetchone()
                    if previous and now - previous[0] < self.policy.cooldown_seconds:
                        db.rollback()
                        return "cooldown"
                    db.execute("INSERT INTO seen VALUES (?)", (event,))
                    db.execute("INSERT OR REPLACE INTO attempts VALUES (?, ?)", (connection, now))
                    # Exceeds the 60s request admission deadline plus bounded helper work.
                    db.execute("INSERT OR REPLACE INTO inflight VALUES (1, ?)", (now + 180,))
                    db.commit()  # Consume before side effects; crashes cannot trigger a retry.
                    audit(connection, "recovery_admitted", event)
                    result = operation()
                    if result == "recovered":
                        db.execute("DELETE FROM inflight WHERE id=1")
                        db.commit()
                    return result


def mapping_hash(connection) -> str:
    return hashlib.sha256(json.dumps({key: getattr(connection, key) for key in (
        "ike_connection", "child_connection", "local_selector", "remote_selector"
    )}, sort_keys=True).encode()).hexdigest()


def recover_alert(config, identifier, alert, remote=None):
    from datetime import datetime, timezone

    from ipsec_recovery_controller.gateway.https_agent import HTTPSAgentTransport

    expected = config.connections[identifier]
    if not expected.recovery_enabled:
        return "recovery_disabled"
    if alert.labels.get("alertname") != "PakakobeIPsecTunnelMissing":
        return "recovery_alert_not_allowed"
    try:
        started = datetime.fromisoformat((alert.startsAt or "").replace("Z", "+00:00"))
        if started.tzinfo is None:
            return "recovery_alert_invalid"
        started = started.astimezone(timezone.utc)
        age = (datetime.now(timezone.utc) - started).total_seconds()
        if not 1800 <= age <= 86400 or not alert.fingerprint:
            return "recovery_alert_invalid"
    except (ValueError, TypeError, OverflowError):
        return "recovery_alert_invalid"
    gateway = config.gateways[expected.gateway]
    if gateway.transport != "agent":
        return "recovery_transport_not_allowed"
    # Do not trust fingerprint uniqueness: key by configured target + incident start.
    event = hashlib.sha256((identifier + "|" + started.isoformat()).encode()).hexdigest()
    remote = remote or HTTPSAgentTransport()
    return RecoveryGate(config.recovery).run(identifier, event, lambda: remote.initiate(
        gateway, identifier, expected, event))
