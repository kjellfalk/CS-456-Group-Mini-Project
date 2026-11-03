from checkpoint import save_checkpoint, load_checkpoint


original_tickets = {
    "ticket_abc123": "student",
    "ticket_def456": "student",
    "ticket_ghi789": "student"
}

# Save the dictionary.
save_checkpoint(original_tickets)

print("Checkpoint saved.")

# Load the dictionary.
restored_tickets = load_checkpoint()

print("Checkpoint loaded.")
print(restored_tickets)

# Compare the original and restored dictionaries.
assert original_tickets == restored_tickets

print("SUCCESS: Original and restored states match.")