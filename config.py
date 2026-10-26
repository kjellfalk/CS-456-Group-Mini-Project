"""Shared settings for the service, monitor, client, and attacker.

Every process imports this file so ports and timing stay in sync.
"""
import os

HOST = "127.0.0.1"

# Auth service listens here for client requests (TCP).
SERVICE_PORT = 5000

# Monitor listens here for heartbeats (UDP).
MONITOR_PORT = 5001

# Heartbeat interval T, in milliseconds. Must match HEARTBEAT_INTERVAL in service.py.
HEARTBEAT_INTERVAL_MS = 2000

# Missed-beat threshold N. Timeout window W = N * T (6 s by default).
MISSED_BEAT_THRESHOLD = 3

# Secure mode only: reject beats whose timestamp is further than this from
# the monitor's clock. Limits how long a captured beat stays replayable.
MAX_CLOCK_SKEW_S = 2.0

# Secure mode only: HMAC key shared by the service and monitor.
# Override with the HB_SECRET environment variable; never commit a real key.
SHARED_SECRET = os.environ.get("HB_SECRET", "cs456-demo-secret-key").encode()

# Monitor appends every state change and alert here.
INCIDENT_LOG = "incidents.log"
