# Role Distribution:

### Jason Arthur:

#### Part 1:
* config.py
* heartbeat_monitor.py
* protocol.py

#### Part 2:
* updated heartbeat_monitor.py for automated failover (launches the standby on crash, logs crash detected → failover triggered → service restored)
* updated config.py with standby and checkpoint settings
* .gitignore
* tested failover, checkpoint tampering, and false failover (split-brain)

### Kjell Falk:

* auth_service.py
* created GitHub repo

### Myla Vencill:

#### Part 1:
* client.py
* Wrote some of the report document

#### Part 2:
* Updated client.py with fault-tolerant logic to automatically loop and reconnect to the standby node after a primary server crash.
* Implemented persistent ticket validation tests to demonstrate pre-crash state preservation.
* Improved network read reliability by converting socket reception to file-like stream reading (readline()) and added JSONDecodeError handling for interrupted transmissions.
* Started report document

### Soumyabrata Ghosh:
- Developed `audit_script.py`, an independent adversarial testing script for heartbeat spoofing and replay attacks.
- Implemented configurable heartbeat spoofing to test whether forged messages could conceal an authentication server crash.
- Demonstrated that the baseline monitor incorrectly accepted fake heartbeats and failed to detect a real server outage while the attack was active.
- Tested the secure monitor against forged plaintext heartbeats. The monitor rejected the messages and detected the real server failure after 6.28 seconds.
- Implemented a replay test that captures genuine signed heartbeats, forwards them to the monitor, and resends identical copies.
- Verified that the secure monitor rejected previously accepted heartbeats using sequence-number replay detection.
- Conducted the experiments, collected terminal evidence, and submitted the audit script through Pull Request #5.
