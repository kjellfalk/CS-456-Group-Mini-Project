"""Heartbeat wire format, shared by the service (sender) and monitor (receiver).

Two modes:

  Plain (baseline, intentionally vulnerable):
      HEARTBEAT

  Secure (--secure):
      HEARTBEAT|<node_id>|<boot_id>|<seq>|<timestamp>|<hmac>

      node_id   - name of the sending node, e.g. "primary"
      boot_id   - random value chosen each time the process starts, so a
                  restarted service can begin its sequence numbers at 0 again
      seq       - counter that increases by 1 with every beat
      timestamp - sender's wall-clock time (seconds since epoch)
      hmac      - HMAC-SHA256 over everything before it, keyed with
                  config.SHARED_SECRET

The HMAC defeats spoofing (an attacker without the key cannot forge a beat).
The sequence number and timestamp defeat replay (the monitor rejects any
beat it has already seen, or one that is too old).
"""
import hashlib
import hmac
import time
from dataclasses import dataclass

import config

PLAIN_BEAT = b"HEARTBEAT"


@dataclass
class Beat:
    node_id: str
    boot_id: str
    seq: int
    timestamp: float


def _sign(body: str) -> str:
    return hmac.new(config.SHARED_SECRET, body.encode(), hashlib.sha256).hexdigest()


def build_heartbeat(node_id: str, boot_id: str, seq: int, secure: bool) -> bytes:
    """Return the bytes the service should send for one heartbeat."""
    if not secure:
        return PLAIN_BEAT
    body = f"HEARTBEAT|{node_id}|{boot_id}|{seq}|{time.time():.3f}"
    return f"{body}|{_sign(body)}".encode()


def parse_heartbeat(data: bytes, secure: bool) -> Beat:
    """Decode and verify one heartbeat. Raises ValueError with a reason if invalid.

    This checks the format, the HMAC, and timestamp freshness. Sequence-number
    replay checks need memory of past beats, so the monitor does those.
    """
    if not secure:
        if data.strip() != PLAIN_BEAT:
            raise ValueError("not a heartbeat")
        return Beat(node_id="unknown", boot_id="-", seq=0, timestamp=time.time())

    try:
        text = data.decode()
    except UnicodeDecodeError:
        raise ValueError("non-text payload")

    parts = text.split("|")
    if len(parts) != 6 or parts[0] != "HEARTBEAT":
        raise ValueError("malformed heartbeat")
    _, node_id, boot_id, seq_s, ts_s, mac = parts

    body = "|".join(parts[:5])
    if not hmac.compare_digest(mac, _sign(body)):
        raise ValueError("bad HMAC (spoofed or tampered)")

    try:
        seq = int(seq_s)
        ts = float(ts_s)
    except ValueError:
        raise ValueError("bad seq/timestamp field")

    age = time.time() - ts
    if abs(age) > config.MAX_CLOCK_SKEW_S:
        raise ValueError(f"stale timestamp ({age:+.1f}s old)")

    return Beat(node_id=node_id, boot_id=boot_id, seq=seq, timestamp=ts)