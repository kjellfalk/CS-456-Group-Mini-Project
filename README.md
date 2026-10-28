
# CS 456 — Resilient Security Systems
## Mini Group Project 1: Failure Detection

**Course:** CS 456 — Modern Cybersecurity  
**Colorado State University**  
**Instructor:** Viktoria Koscinski

### Team Members
- Jason Arthur
- Kjell Falk
- Myla Vencill
- Soumyabrata Ghosh

---

## 1. Project Overview

How can we tell whether a security service is actually running? And what happens if someone deliberately tries to convince our monitoring system that a crashed service is still alive?

These were the main questions we explored in this project.

Our team built a lightweight **TCP authentication and ticket service** along with an independent **heartbeat monitoring system**. The authentication server handles client login and ticket validation requests, while the monitor checks whether the server is still running.

We also introduced simulated server crashes and developed an adversarial audit script to test whether an attacker could manipulate the heartbeat messages.

The project compares two monitoring approaches:

1. **Baseline monitoring:** Accepts plaintext heartbeat messages without authenticating the sender.
2. **Secure monitoring:** Uses HMAC-SHA256 authentication, timestamps, and sequence numbers to validate heartbeats and reject repeated messages.

We tested both approaches against heartbeat spoofing and replay attacks.

### Project Objectives

- Build a working authentication and ticket service.
- Simulate unexpected server failures.
- Detect service failures using an independent heartbeat monitor.
- Compare baseline and secure heartbeat communication.
- Demonstrate heartbeat spoofing and replay attacks.
- Evaluate whether the monitor can correctly distinguish genuine messages from attacker-generated messages.

---

## 2. Project Files

| File | Description |
|------|-------------|
| `auth_service.py` | TCP authentication server that handles login and ticket validation requests and simulates random crashes. |
| `client.py` | Test client that sends authentication and ticket validation requests. |
| `heartbeat_monitor.py` | Independent UDP heartbeat monitor that detects service outages. |
| `protocol.py` | Defines the baseline and secure heartbeat message formats and validation logic. |
| `config.py` | Shared settings for network addresses, ports, heartbeat intervals, and security parameters. |
| `audit_script.py` | Adversarial testing script for heartbeat spoofing and replay attacks. |
| `CONTRIBUTIONS.md` | Documents each team member's contribution. |
| `README.md` | Project description, setup instructions, and experimental findings. |

---

## 3. How the System Works

The system has three main components: the authentication service, the heartbeat monitor, and the client.

### Authentication Service

The authentication server listens for TCP connections on port `5000`.

The client sends a username and password to log in. When the credentials are valid, the server generates a session ticket.

The client can then use this ticket for subsequent validation requests.

To simulate unexpected failures, each incoming client request has a **15% probability of triggering a complete server crash**.

The crash is implemented using `os._exit(1)`, which immediately terminates the process without normal cleanup.

### Heartbeat Monitor

The monitor runs independently of the authentication server.

The server periodically sends UDP heartbeat messages to the monitor. As long as valid messages continue arriving, the monitor considers the service to be running.

If the monitor does not receive a valid heartbeat within the configured timeout window, it reports:

`ALERT SERVICE DOWN`

Because the monitor runs as a separate process, it can continue detecting failures even when the authentication service crashes.

### Client

The client connects to the authentication service, logs in, receives a ticket, and sends ticket validation requests.

These requests also provide a way to trigger the simulated random crash.

---

## 4. Heartbeat Configuration

Our system uses the following parameters:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Heartbeat interval (T) | 2 seconds | Time between heartbeat messages |
| Missed-beat threshold (N) | 3 | Number of missed heartbeat intervals tolerated |
| Timeout window (W) | 6 seconds | Maximum time without a valid heartbeat before reporting an outage |
| Authentication service port | TCP 5000 | Client-server communication |
| Heartbeat monitor port | UDP 5001 | Normal heartbeat communication |
| Replay test monitor port | UDP 5002 | Separate monitoring port used during replay testing |
| Maximum clock skew | 2 seconds | Freshness tolerance for secure heartbeat timestamps |

The timeout window is calculated as:

**W = T × N = 2 × 3 = 6 seconds**

We chose this configuration to balance detection speed and false alarms.

A shorter timeout would detect failures faster, but it could also incorrectly classify a temporary communication delay as a server crash.

A longer timeout would tolerate more delays but would leave actual failures undetected for longer.

For our project, six seconds provided a reasonable balance between responsiveness and tolerance for occasional missed messages.

---

## 5. Heartbeat Communication

### Baseline Mode

In baseline mode, the authentication service sends a simple plaintext message:

`HEARTBEAT`

The monitor accepts messages matching this value.

However, it does not verify whether the message actually came from the authentication server.

This creates a security weakness: another process can send the same message and make the monitor believe the server is still running.

### Secure Mode

In secure mode, the heartbeat follows this format:

`HEARTBEAT|node_id|boot_id|seq|timestamp|hmac`

Each field serves a purpose:

- **node_id:** Identifies the sending service.
- **boot_id:** Identifies a particular instance of the service after startup.
- **seq:** A sequence number that increases with each heartbeat.
- **timestamp:** Records when the heartbeat was generated.
- **hmac:** An HMAC-SHA256 signature used to authenticate the message and protect its contents against modification.

The monitor checks the message format, HMAC signature, timestamp, and sequence number before accepting a heartbeat.

If the message fails any of these checks, it is rejected.

The default demonstration secret is configured in `config.py`. It can also be provided using the `HB_SECRET` environment variable. The service and monitor must use the same secret.

---

## 6. Requirements and Installation

### Requirements

- Python 3
- Git
- Windows, Linux, or macOS
- A terminal or an IDE such as Visual Studio Code

The project uses Python's standard library for its authentication, networking, heartbeat, and audit functionality.

No separate compilation step is required.

### Clone the Repository

```bash
git clone https://github.com/kjellfalk/CS-456-Group-Mini-Project.git
cd CS-456-Group-Mini-Project
```

Repository access is required if the GitHub repository is private.

### Python Commands

For our Windows PowerShell experiments, we used:

`python`

Some Linux and macOS installations use:

`python3`

The commands below use `python`, but either can be used depending on the operating system.

**Important:** Run each component in a separate terminal from the project root directory.

Before switching experiments, stop the previous service, monitor, and attack processes to avoid port conflicts.

---

## 7. Running the Baseline System

### Step 1 — Start the Heartbeat Monitor

Open Terminal 1:

```powershell
python .\heartbeat_monitor.py
```

The monitor starts listening for UDP heartbeats on port `5001`.

Initially, its status is `WAITING`.

### Step 2 — Start the Authentication Server

Open Terminal 2:

```powershell
python .\auth_service.py
```

The server begins listening for TCP connections and sending periodic heartbeat messages.

The monitor changes its status to `UP` after receiving the first valid heartbeat.

### Step 3 — Run the Client

Open Terminal 3:

```powershell
python .\client.py
```

The client attempts to log in and validates the resulting ticket.

Each incoming request has a 15% chance of triggering the server's simulated crash.

When the server crashes, the client loses its connection.

If no further valid heartbeat arrives, the monitor reports the outage after approximately six seconds.

---

## 8. Adversarial Audit: Heartbeat Spoofing

### What Is Heartbeat Spoofing?

Heartbeat spoofing happens when an attacker sends fake heartbeat messages to make a monitoring system believe that a service is still functioning.

Our baseline monitor only checks whether it receives the expected plaintext heartbeat.

It does not authenticate the sender.

We wanted to test whether this weakness could be used to conceal an actual server failure.

### Running the Spoofing Attack

Start the baseline monitor:

```powershell
python .\heartbeat_monitor.py
```

Start the authentication server in another terminal:

```powershell
python .\auth_service.py
```

Start the adversarial audit script in a third terminal:

```powershell
python .\audit_script.py --mode spoof --duration 300 --interval 1
```

The arguments mean:

- `--mode spoof`: Run the heartbeat spoofing attack.
- `--duration 300`: Continue sending messages for 300 seconds.
- `--interval 1`: Send a fake heartbeat every second.

Next, run the client in another terminal:

```powershell
python .\client.py
```

The client sends requests until the server encounters its simulated random crash.

### What We Observed

The baseline monitor continued accepting the fake heartbeats even after the authentication server had crashed.

As long as the attacker continued sending messages, the monitor remained in the `UP` state.

After the attack stopped, the monitor finally detected that no valid heartbeat messages were arriving.

In one experiment, the monitor reported the outage **6.09 seconds after the last accepted fake heartbeat**.

We also repeated the experiment by manually terminating the authentication service. The monitor continued accepting the attacker's messages and reported the failure only after the fake messages stopped.

### Finding

The baseline monitor could not distinguish a genuine heartbeat from an attacker-generated heartbeat.

An attacker could therefore conceal an actual service failure simply by continuing to send the expected plaintext message.

---

## 9. Testing Spoofing Against Secure Monitoring

We repeated the same attack using authenticated heartbeat messages.

### Step 1 — Start the Secure Monitor

```powershell
python .\heartbeat_monitor.py --secure
```

### Step 2 — Start the Secure Authentication Server

```powershell
python .\auth_service.py --secure
```

### Step 3 — Run the Spoofing Attack

```powershell
python .\audit_script.py --mode spoof --duration 600 --interval 1
```

### Step 4 — Trigger the Simulated Crash

```powershell
python .\client.py
```

### What We Observed

The secure monitor accepted genuine signed heartbeats from the authentication server.

However, the fake plaintext heartbeats sent by our audit script were rejected as malformed messages.

When the authentication server crashed, the monitor detected the outage even though the attacker was still sending fake messages.

In our experiment, the secure monitor reported:

`SERVICE DOWN: no valid heartbeat for 6.28s`

The attacker continued sending messages after this alert, and the monitor continued rejecting them.

### Finding

Unlike the baseline monitor, the secure monitor did not treat the attacker-generated plaintext heartbeats as valid evidence that the service was running.

The attack failed to conceal the server crash.

---

## 10. Adversarial Audit: Replay Attack

### What Is a Replay Attack?

A replay attack involves capturing a legitimate message and sending it again.

Unlike basic spoofing, the attacker does not necessarily need to create a new message or forge a signature.

Instead, the attacker attempts to reuse a message that was already valid.

For our experiment, we wanted to see whether the monitor would accept the same signed heartbeat more than once.

### How We Tested It

Our audit script temporarily acts as an intermediary between the authentication service and the heartbeat monitor.

The authentication service sends its secure heartbeats to UDP port `5001`.

Our audit script listens on this port, captures the original message, and forwards it unchanged to the secure monitor on port `5002`.

The script then sends an identical copy of that same heartbeat.

### Step 1 — Start the Secure Monitor on Port 5002

```powershell
python .\heartbeat_monitor.py --secure --port 5002
```

### Step 2 — Start the Replay Audit Script

```powershell
python .\audit_script.py --mode replay --duration 120 --monitor-port 5002
```

### Step 3 — Start the Secure Authentication Server

```powershell
python .\auth_service.py --secure
```

**Note:** Start the replay script before starting the authentication server. The script needs to listen on port `5001` to capture the genuine heartbeats.

### What We Observed

The secure monitor accepted each original signed heartbeat.

However, when the audit script immediately sent an identical copy, the monitor rejected it.

For example, the monitor accepted a heartbeat with sequence number `35`.

When the same signed message was sent again, the monitor reported:

`REJECTED: replayed/out-of-order seq=35 (last=35)`

This happened consistently during our experiment.

### Finding

A valid signature alone does not mean a heartbeat is new.

The monitor's sequence-number checks prevented the repeated messages from being accepted as fresh heartbeats.

The timestamp validation also provides an additional check against stale messages.

---

## 11. Experimental Results

We conducted multiple experiments to compare the baseline and secure monitoring systems.

| Experiment | Observation | Result |
|------------|-------------|--------|
| Normal heartbeat monitoring | The monitor accepted genuine heartbeats and reported the service as running. | Successful |
| Simulated server crash | The monitor detected the absence of valid heartbeats after approximately six seconds. | Successful |
| Baseline heartbeat spoofing | Fake heartbeats concealed the real server failure while the attack continued. | Attack successful |
| Secure heartbeat spoofing | The monitor rejected unsigned fake heartbeats and reported the real outage after 6.28 seconds. | Attack rejected |
| Secure heartbeat replay | Original signed heartbeats were accepted, but identical repeated messages were rejected. | Replay rejected |

### Main Takeaway

The most important finding from this project was that receiving regular heartbeat messages does not necessarily prove that a service is still alive.

In our baseline implementation, the heartbeat monitor trusted messages without checking their origin. This allowed our attack script to conceal an actual server failure.

The secure implementation performed better because it validated message authenticity and rejected repeated sequence numbers.

However, these results apply to the specific spoofing and replay attacks we tested. They do not establish that the system is secure against every possible attack.

---

## 12. Limitations

Our project is a demonstration of failure detection and heartbeat security rather than a production-ready authentication system.

Some important limitations are:

- The system is configured for local testing using `127.0.0.1`.
- The authentication service uses demonstration credentials.
- The default shared secret is intended for testing, not production deployment.
- The heartbeat monitor detects failures but does not automatically restart the service.
- A six-second timeout is suitable for our demonstration but may need adjustment under different network conditions.
- The security audit focuses on plaintext heartbeat spoofing and duplicate-message replay rather than every possible attack on the system.

A possible next step would be to extend the monitor with automated recovery, such as starting a standby authentication service after detecting a failure.

---

## 13. Troubleshooting

### Python Is Not Found

On Windows, use:

```powershell
python .\heartbeat_monitor.py
```

If `python3` is not recognized, use `python` instead.

### Port Already in Use

Make sure another copy of the monitor or audit script is not already running.

The normal monitor uses UDP port `5001`. During replay testing, the audit script uses port `5001`, so the secure monitor must run on port `5002`.

### Server Fails During Startup or Requests

Check that `auth_service.py` imports all modules it uses, including `random` and `os`.

Also confirm that another application is not already using TCP port `5000`.

### Secure Heartbeats Are Rejected

Make sure both the authentication server and monitor were started with `--secure`.

Both processes must also use the same shared secret. If `HB_SECRET` is configured, its value must match.

### Monitor Does Not Detect a Failure

Check whether the attacker is still sending heartbeat messages.

In baseline mode, fake heartbeats can continue resetting the monitor's failure detection timer even after the real authentication service has stopped.

---

## 14. Team Contributions

### Jason Arthur

- Developed `config.py`.
- Implemented `heartbeat_monitor.py`.
- Developed the heartbeat protocol in `protocol.py`, including secure message validation and replay protection.

### Kjell Falk

- Developed `auth_service.py`.
- Implemented the authentication service and simulated server failure functionality.
- Created the team's GitHub repository.

### Myla Vencill

- Developed `client.py`.
- Helped prepare the project report and document the team's implementation.

### Soumyabrata Ghosh

- Developed `audit_script.py`.
- Implemented configurable heartbeat spoofing and replay attack tests.
- Demonstrated the baseline monitor's vulnerability to false heartbeat messages.
- Tested the secure monitor against spoofed plaintext heartbeats.
- Captured and replayed genuine signed heartbeat messages.
- Verified sequence-number-based replay rejection.
- Conducted experiments, collected terminal evidence, and documented the adversarial audit findings.
- Submitted the audit implementation through Pull Request #5.

For a more detailed breakdown, see [CONTRIBUTIONS.md](CONTRIBUTIONS.md).

---

## 15. Conclusion

This project started with a straightforward goal: detect when an authentication service stops running.

However, our adversarial testing showed that detecting a heartbeat and verifying the actual state of a service are not always the same thing.

The baseline monitor worked under normal conditions, but it could be fooled by an attacker sending fake heartbeat messages. Even when the authentication server had crashed, the monitor continued reporting that the service was available.

By adding authenticated heartbeat messages and replay protection, the secure monitor was able to reject the attacks we tested and detect actual server failures.

The project helped us understand why failure detection systems need to consider not only whether messages are arriving, but also whether those messages can be trusted.

---

**CS 456 — Modern Cybersecurity**  
**Colorado State University — Fall 2026**
