# OpenClaw-SPIRE-NHP

A prototype SPIFFE/SPIRE daemon that provisions **Non-Human Persona (NHP)** identities for OpenClaw agents in enterprise environments.

Traditional IAM treats machine identities as static service accounts with long-lived secrets. NHP identities are different: they are short-lived, hardware-bound, cryptographically verifiable, and scoped to a specific mission. This daemon implements the identity infrastructure layer that makes that possible.

## How It Works

The daemon runs a single-server SPIRE deployment on a Linux host. It manages a Root CA, issues short-lived X.509-SVIDs (SPIFFE Verifiable Identity Documents), and exposes a Unix Domain Socket for workload attestation.

1. The **SPIRE Server** initializes a Root CA and creates a Trust Bundle containing the root certificate and active signing keys.
2. **Registration entries** define which workloads are authorized, identified by Unix selectors (UID, binary SHA-256 hash).
3. The **SPIRE Agent** listens on a Unix Domain Socket. When an OpenClaw process connects, the agent uses `SO_PEERCRED` to read the caller's PID, UID, and GID from the kernel, then hashes the binary at `/proc/<pid>/exe`.
4. If the attested selectors match a registration entry, the agent mints a short-lived X.509-SVID and delivers it in-memory. No secrets are written to disk.
5. Workloads use the Trust Bundle to verify peer certificates via mutual TLS. Certificates signed by an unknown CA are rejected.

## Architecture

```
OpenClaw Process
    |
    | (Unix Domain Socket)
    v
SPIRE Agent
    |  - SO_PEERCRED attestation (PID, UID, binary hash)
    |  - Delivers SVID + Trust Bundle in-memory
    v
SPIRE Server
    |  - Root CA (self-signed, RSA 2048)
    |  - Registration Store (SQLite)
    |  - SVID minting with configurable TTL
    |  - Emergency revocation
    v
SQLite Logger
    - All events logged to SQLite (no text log files)
    - Structured fields: component, level, SPIFFE ID, event type, JSON metadata
```

## Project Structure

```
nhp_daemon/
  __init__.py          Package marker
  __main__.py          python -m nhp_daemon entry point
  config.py            Trust domain, socket path, TTL defaults
  ca.py                Root CA and X.509-SVID signing
  tpm_simulator.py     Software TPM (key generation, PCR measurement, quotes)
  trust_bundle.py      Trust Bundle creation, serialization, SVID verification
  registration.py      SQLite-backed registration entry CRUD and selector matching
  attestation.py       SO_PEERCRED workload attestation
  spire_server.py      SPIRE Server (CA + registration + minting + revocation)
  spire_agent.py       SPIRE Agent (UDS listener, attestation, SVID delivery)
  workload_api.py      Client library for OpenClaw workloads
  sqlite_logger.py     Structured SQLite logger
  main.py              Daemon startup and demo flow

tests/
  conftest.py          Shared pytest fixtures
  test_ca.py           CA and SVID signing tests
  test_tpm_simulator.py TPM simulator tests
  test_trust_bundle.py Trust Bundle tests
  test_registration.py Registration store tests
  test_attestation.py  Attestation helper tests
  test_spire_server.py Server-level tests
  test_sqlite_logger.py Logger tests
  test_integration.py  Full Agent + Workload API flow over UDS
```

## Requirements

- Python 3.12+
- Linux (SO_PEERCRED requires a Linux kernel)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the Daemon

```bash
python -m nhp_daemon
```

This starts the SPIRE Server and Agent, registers two demo NHP personas (`finance-auditor` and `research-agent`), then runs a demo flow that:

1. Fetches the Trust Bundle from the Agent over the Unix socket
2. Requests an X.509-SVID for the `finance-auditor` persona
3. Validates the SVID certificate against the Trust Bundle

Output looks like:

```
[NHP] Trust Domain : enterprise.com
[NHP] SPIFFE ID    : spiffe://enterprise.com/nhp/openclaw/finance-auditor
[NHP] SVID TTL     : 300s
[NHP] SVID Valid   : True
[NHP] Log database : /tmp/spire-nhp/spire_nhp_log.db
[NHP] Daemon running. Press Ctrl+C to stop.
```

Press `Ctrl+C` to shut down.

## Running Tests

### Automated Test Suite

Run all 49 tests:

```bash
python -m pytest tests/ -v
```

The test suite covers every module. Key test files and what they verify:

| Test file | What it covers |
| :--- | :--- |
| `test_integration.py` | Full end-to-end flow: Agent over a real Unix socket, SVID fetch, validation, foreign cert rejection |
| `test_spire_server.py` | Registration, minting, revocation, multi-entry selector matching |
| `test_ca.py` | Root CA generation, SVID signing, TTL enforcement, foreign-CA rejection |
| `test_trust_bundle.py` | Bundle creation, serialization roundtrip, SVID verification |
| `test_registration.py` | CRUD, exact/superset/partial selector matching |
| `test_tpm_simulator.py` | Endorsement key uniqueness, PCR measurement, TPM quotes |
| `test_attestation.py` | Selector building from peer credentials, binary hashing |
| `test_sqlite_logger.py` | Log levels, metadata JSON, SPIFFE ID filtering, time-range queries |

Run a single test file:

```bash
python -m pytest tests/test_integration.py -v
```

### Manual Testing Against a Live Daemon

Start the daemon in one terminal:

```bash
python -m nhp_daemon
```

In a second terminal, simulate an OpenClaw workload requesting an identity:

```python
from nhp_daemon.workload_api import WorkloadAPIClient

c = WorkloadAPIClient("/tmp/spire-nhp/workload.sock")
print(c.fetch_bundle()["trust_domain"])
svid = c.fetch_svid("spiffe://enterprise.com/nhp/openclaw/finance-auditor")
print(svid["spiffe_id"], "expires:", svid["expires_at"])
print("valid:", c.validate_peer_certificate(svid["certificate_pem"]))
```

Inspect the registration store:

```bash
sqlite3 /tmp/spire-nhp/spire_nhp.db \
  "SELECT spiffe_id, selectors, ttl FROM registration_entries"
```

Watch events in real time:

```bash
watch -n 2 "sqlite3 /tmp/spire-nhp/spire_nhp_log.db \
  \"SELECT datetime(timestamp,'unixepoch'), event_type, component, message \
    FROM logs ORDER BY timestamp DESC LIMIT 15\""
```

Check all minted SVIDs:

```bash
sqlite3 /tmp/spire-nhp/spire_nhp_log.db \
  "SELECT datetime(timestamp,'unixepoch'), spiffe_id, metadata FROM logs WHERE event_type='svid_minted'"
```

## Docker

### Build and Run

```bash
docker compose up --build
```

This builds the image from the included `Dockerfile` (Python 3.14-slim) and starts the daemon. SQLite databases are persisted in a named volume (`spire-data`).

### Run Tests in Docker

```bash
docker compose run --rm test
```

The `test` service is under a profile and only runs when explicitly invoked.

### Inspect Logs in a Running Container

```bash
docker compose exec nhp-daemon \
  sqlite3 /var/run/spire-nhp/spire_nhp_log.db \
  "SELECT datetime(timestamp,'unixepoch'), event_type, message FROM logs ORDER BY timestamp DESC LIMIT 10"
```

### Stop and Clean Up

```bash
docker compose down
```

To also remove the persisted volume:

```bash
docker compose down -v
```

## Configuration

All settings can be overridden via environment variables:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SPIRE_NHP_SOCKET` | `/tmp/spire-nhp/workload.sock` | Agent Unix Domain Socket path |
| `SPIRE_NHP_DB` | `/tmp/spire-nhp/spire_nhp.db` | Registration entry database |
| `SPIRE_NHP_LOG_DB` | `/tmp/spire-nhp/spire_nhp_log.db` | Structured log database |

SVID TTL defaults to 300 seconds (5 minutes). The maximum is 900 seconds (15 minutes).

## Key Design Decisions

- **Identity as State, not Secret.** Workloads are attested by kernel-verified process attributes (UID, binary hash), not passwords or API keys.
- **No secrets on disk.** SVIDs and the Trust Bundle are delivered in-memory over the Unix socket.
- **All logging to SQLite.** Every event (SVID minted, attestation failed, entry revoked) is stored as a structured row with component, level, SPIFFE ID, event type, and JSON metadata. No text log files exist.
- **Selector-based matching.** A registration entry's selectors must be a subset of the workload's attested attributes. Presenting extra attributes is fine; missing a required one causes rejection.
- **Emergency revocation.** Deleting a registration entry immediately invalidates the cached SVID. The workload loses network access at the next rotation check.
- **Simulated TPM.** The TPM module uses software-generated keys and SHA-256 hashing to stand in for hardware TPM operations. Replace with real TPM bindings for production use.

## Querying Logs

Since all logs are in SQLite, you can query them directly:

```bash
sqlite3 /tmp/spire-nhp/spire_nhp_log.db \
  "SELECT datetime(timestamp, 'unixepoch'), level, component, message FROM logs ORDER BY timestamp DESC LIMIT 20"
```

Or filter by event type:

```bash
sqlite3 /tmp/spire-nhp/spire_nhp_log.db \
  "SELECT datetime(timestamp, 'unixepoch'), message, metadata FROM logs WHERE event_type = 'svid_minted'"
```

## License

This is a research prototype. See the repository for license details.
