
import hashlib
import hmac
import json
import os
import tempfile

from pathlib import Path

import config


class CheckpointError(Exception):
    """Raised when a checkpoint cannot be trusted or restored."""


def serialize_state(active_tickets):
    """Convert ticket state into a consistent JSON string."""
    return json.dumps(
        active_tickets,
        sort_keys=True,
        separators=(",", ":")
    )


def generate_hmac(data):
    """Generate an HMAC for the serialized checkpoint data."""
    return hmac.new(
        config.CHECKPOINT_SECRET,
        data.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def save_checkpoint(active_tickets):
    """Save authenticated ticket state using atomic file replacement."""

    if not isinstance(active_tickets, dict):
        raise CheckpointError("Ticket state must be a dictionary.")

    if not all(
        isinstance(ticket, str) and isinstance(username, str)
        for ticket, username in active_tickets.items()
    ):
        raise CheckpointError("Ticket state contains invalid entries.")

    payload = {
        "version": 1,
        "active_tickets": active_tickets
    }

    serialized = serialize_state(payload)
    signature = generate_hmac(serialized)

    checkpoint = {
        "payload": payload,
        "hmac": signature
    }

    checkpoint_path = Path(config.CHECKPOINT_FILE)
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=checkpoint_path.parent,
            delete=False
        ) as file:

            temp_path = Path(file.name)

            json.dump(checkpoint, file, indent=4)

            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, checkpoint_path)

    except OSError as error:
        raise CheckpointError(
            f"Could not save checkpoint: {error}"
        ) from error

    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def load_checkpoint():
    """Load and verify the saved ticket state."""

    checkpoint_path = Path(config.CHECKPOINT_FILE)

    try:
        with checkpoint_path.open("r", encoding="utf-8") as file:
            checkpoint = json.load(file)

    except FileNotFoundError as error:
        raise CheckpointError("Checkpoint file does not exist.") from error

    except (OSError, json.JSONDecodeError) as error:
        raise CheckpointError(
            f"Could not read checkpoint: {error}"
        ) from error

    if not isinstance(checkpoint, dict):
        raise CheckpointError("Checkpoint must contain a JSON object.")

    payload = checkpoint.get("payload")
    signature = checkpoint.get("hmac")

    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise CheckpointError("Checkpoint structure is invalid.")

    if payload.get("version") != 1:
        raise CheckpointError("Unsupported checkpoint version.")

    active_tickets = payload.get("active_tickets")

    if not isinstance(active_tickets, dict):
        raise CheckpointError("Invalid ticket state.")

    if not all(
        isinstance(ticket, str) and isinstance(username, str)
        for ticket, username in active_tickets.items()
    ):
        raise CheckpointError("Ticket state contains invalid entries.")

    serialized = serialize_state(payload)
    expected_signature = generate_hmac(serialized)

    if not hmac.compare_digest(signature, expected_signature):
        raise CheckpointError("Checkpoint integrity verification failed.")

    return active_tickets
