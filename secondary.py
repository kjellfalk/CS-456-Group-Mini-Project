"""Passive redundancy: monitor launches this process after detecting a failure.

The secondary loads the most recent authenticated checkpoint, then attempts
exclusive ownership of the TCP service port. If primary is still alive, this
process refuses to become a conflicting primary (split-brain prevention).
"""
import sys
from auth_service import run_server


if __name__ == "__main__":
    print("[STANDBY] Promotion requested by heartbeat monitor", flush=True)
    sys.exit(run_server(secure="--secure" in sys.argv, restore=True,
                        crash_probability=0.0, node_id="secondary"))
