"""Authenticated, atomic JSON checkpoints for the Part 2 ticket service.

This is a classroom demonstration, not a production-grade distributed database.
"""
import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path

import config

MAX_CHECKPOINT_BYTES = 1024 * 1024


class CheckpointError(Exception):
    """Checkpoint cannot be trusted or read."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def save_checkpoint(tickets):
    """Save session tickets before acknowledging a successful LOGIN.

    Atomic replace prevents partially written files; the HMAC detects tampering.
    """
    if not isinstance(tickets, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in tickets.items()):
        raise CheckpointError("invalid ticket state")
    state = {"version": 1, "saved_at": time.time(), "tickets": dict(tickets)}
    signature = hmac.new(config.CHECKPOINT_SECRET, _canonical(state), hashlib.sha256).hexdigest()
    raw = _canonical({"state": state, "hmac": signature})
    if len(raw) > MAX_CHECKPOINT_BYTES:
        raise CheckpointError("checkpoint too large")
    target = Path(config.CHECKPOINT_FILE).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent, prefix=target.name + ".", suffix=".tmp", delete=False) as tmp:
            temp_name = tmp.name
            tmp.write(raw)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(temp_name, target)
    except OSError as exc:
        raise CheckpointError(f"could not save checkpoint: {exc}") from exc
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    print(f"[CHECKPOINT] saved {len(tickets)} tickets to {target.name}", flush=True)


def load_checkpoint():
    """Return (tickets, status). On missing/corrupt file, return empty state.

    Missing checkpoint can happen on a new install. Tampered/corrupt checkpoints
    always fail closed: no tickets are restored from untrusted state.
    """
    path = Path(config.CHECKPOINT_FILE)
    if not path.exists():
        return {}, "MISSING (starting with no tickets)"
    try:
        if path.stat().st_size > MAX_CHECKPOINT_BYTES:
            raise CheckpointError("file too large")
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or set(doc) != {"state", "hmac"}:
            raise CheckpointError("invalid checkpoint envelope")
        state, signature = doc["state"], doc["hmac"]
        if not isinstance(state, dict) or not isinstance(signature, str):
            raise CheckpointError("invalid checkpoint types")
        expected = hmac.new(config.CHECKPOINT_SECRET, _canonical(state), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise CheckpointError("HMAC mismatch (tampering detected)")
        if state.get("version") != 1 or not isinstance(state.get("tickets"), dict):
            raise CheckpointError("unsupported checkpoint schema")
        tickets = state["tickets"]
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in tickets.items()):
            raise CheckpointError("invalid ticket entries")
        return dict(tickets), f"OK ({len(tickets)} tickets restored)"
    except (OSError, UnicodeError, ValueError, TypeError, CheckpointError) as exc:
        return {}, f"REJECTED ({exc}; starting with no tickets)"
