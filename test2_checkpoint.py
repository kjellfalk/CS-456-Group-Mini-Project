from checkpoint import load_checkpoint, CheckpointError

try:
    tickets = load_checkpoint()
    print("Checkpoint accepted:", tickets)

except CheckpointError as error:
    print("Checkpoint rejected:", error)