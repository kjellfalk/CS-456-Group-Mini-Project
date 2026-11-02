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

# Part 2: script the monitor launches when the primary is declared DOWN.
# It must sit in this folder, accept --secure, load the checkpoint, take over
# SERVICE_PORT, and send heartbeats. If SERVICE_PORT is still taken (the
# primary is alive after a false failover), it should exit instead of serving.
STANDBY_SCRIPT = "secondary.py"

# The standby's own output goes here, so it doesn't mix with the monitor's.
STANDBY_LOG = "standby.log"

# Part 2: the primary writes its tickets here after every LOGIN; the standby
# loads them on start-up.
CHECKPOINT_FILE = "checkpoint.json"

# HMAC key for the checkpoint. Separate from the heartbeat key, so leaking one
# doesn't expose the other. Override with the CKPT_SECRET environment variable.
CHECKPOINT_SECRET = os.environ.get("CKPT_SECRET", "cs456-checkpoint-secret-key").encode()
