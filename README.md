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
    |  - Root CA (P-256 ECDSA via TROPIC01 hardware, or RSA-2048 in software)
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
  config.py            Trust domain, socket path, TROPIC01 settings, TTL defaults
  ca.py                Root CA and X.509-SVID signing (RSA or P-256 ECDSA via hardware)
  tropic01_hw.py       ctypes wrapper for the TROPIC01 bridge library (TRNG, ECC, sign)
  tpm_simulator.py     Tropic01Attestor: key generation, PCR measurement, quotes
  trust_bundle.py      Trust Bundle creation, serialization, SVID verification
  registration.py      SQLite-backed registration entry CRUD and selector matching
  attestation.py       SO_PEERCRED workload attestation
  spire_server.py      SPIRE Server (CA + registration + minting + revocation)
  spire_agent.py       SPIRE Agent (UDS listener, attestation, SVID delivery)
  workload_api.py      Client library for OpenClaw workloads
  sqlite_logger.py     Structured SQLite logger
  main.py              Daemon startup and demo flow

tropic01-req/
  libtropic/           TropicSquare libtropic C library (git submodule)
  libtropic_bridge/    C bridge shared library (tropic01_bridge.so)
    tropic01_bridge.h  Public API: init, random, keygen, read, sign, erase
    tropic01_bridge.c  Implementation (singleton + pthread mutex)
    CMakeLists.txt     Builds libtropic01_bridge.so

tests/
  conftest.py          Shared pytest fixtures
  test_ca.py           CA, SVID signing, and Tropic01ECPrivateKey proxy tests
  test_tpm_simulator.py Tropic01Attestor tests (ECC key pairs, PCR, quotes)
  test_trust_bundle.py  Trust Bundle tests (RSA and ECDSA verification)
  test_registration.py  Registration store CRUD and selector matching
  test_attestation.py   Attestation helper tests
  test_spire_server.py  Server-level tests
  test_sqlite_logger.py Logger tests
  test_integration.py   Full Agent + Workload API flow over UDS
```

## Requirements

- Python 3.12+
- Linux (SO_PEERCRED requires a Linux kernel)
- For hardware mode only: TROPIC01 USB engineering sample, `cmake`, `build-essential`

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the Daemon

### Software mode (no hardware required)

```bash
python -m nhp_daemon
```

Output:

```
[NHP] Software mode: RSA-2048 / software RNG
[NHP] Trust Domain : enterprise.com
[NHP] SPIFFE ID    : spiffe://enterprise.com/nhp/openclaw/finance-auditor
[NHP] SVID TTL     : 300s
[NHP] SVID Valid   : True
[NHP] Log database : /tmp/spire-nhp/spire_nhp_log.db
[NHP] Daemon running. Press Ctrl+C to stop.
```

Press `Ctrl+C` to stop.

### Hardware mode (TROPIC01 USB devkit)

Install the udev rule so the device is accessible without `sudo`:

```bash
sudo tee /etc/udev/rules.d/99-tropic01.rules <<'EOF'
SUBSYSTEM=="tty", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", ATTRS{manufacturer}=="TropicSquare", MODE="0666"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Build the C bridge library (one-time, requires `cmake` and `build-essential`):

```bash
cmake -S tropic01-req/libtropic_bridge \
      -B tropic01-req/libtropic_bridge/build \
      -DCMAKE_BUILD_TYPE=Release
cmake --build tropic01-req/libtropic_bridge/build --parallel
```

Run with hardware offload enabled:

```bash
USE_TROPIC01_HW=true python -m nhp_daemon
```

Output:

```
[NHP] Hardware mode: TROPIC01 ECDSA P-256
[NHP] Trust Domain : enterprise.com
[NHP] SPIFFE ID    : spiffe://enterprise.com/nhp/openclaw/finance-auditor
...
```

If the device is absent the daemon logs the error and **automatically falls back to software mode** — it does not crash.

Environment variables for hardware mode:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `USE_TROPIC01_HW` | `false` | Set `true` to enable TROPIC01 hardware |
| `TROPIC01_DEVICE` | `/dev/serial/by-id/usb-TropicSquare_SPI_interface_4986323F384B-if00` | Device path |
| `TROPIC01_PAIRING_KEYS` | `eng_sample` | Key set: `eng_sample` or `prod0` |
| `TROPIC01_BRIDGE_SO` | `tropic01-req/libtropic_bridge/build/libtropic01_bridge.so` | Path to built .so |

## Running Tests

### Automated Test Suite

Run all 55 tests:

```bash
python -m pytest tests/ -v
```

The test suite covers every module. Key test files and what they verify:

| Test file | What it covers |
| :--- | :--- |
| `test_integration.py` | Full end-to-end: Agent over a real Unix socket, SVID fetch, validation, foreign cert rejection |
| `test_spire_server.py` | Registration, minting, revocation, multi-entry selector matching |
| `test_ca.py` | Root CA generation, SVID signing, TTL enforcement, `Tropic01ECPrivateKey` proxy |
| `test_trust_bundle.py` | Bundle creation, serialization roundtrip, ECDSA and RSA SVID verification |
| `test_registration.py` | CRUD, exact/superset/partial selector matching |
| `test_tpm_simulator.py` | EK uniqueness, PCR measurement, TPM quotes, P-256 key pair type |
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

### Build and Run (software mode)

```bash
docker compose up --build
```

### Build and Run (hardware mode)

Plug in the TROPIC01 USB devkit, then:

```bash
USE_TROPIC01_HW=true docker compose up --build
```

The `docker-compose.yml` passes `/dev/ttyACM0` into the container automatically.

### Run Tests in Docker

```bash
docker compose run --rm test
```

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
| `USE_TROPIC01_HW` | `false` | Enable TROPIC01 hardware offload |
| `TROPIC01_DEVICE` | (by-id symlink) | TROPIC01 device path |
| `TROPIC01_PAIRING_KEYS` | `eng_sample` | Key set for pairing |
| `TROPIC01_BRIDGE_SO` | (auto) | Path to `libtropic01_bridge.so` |

SVID TTL defaults to 300 seconds (5 minutes). The maximum is 900 seconds (15 minutes).

## Key Design Decisions

- **Identity as State, not Secret.** Workloads are attested by kernel-verified process attributes (UID, binary hash), not passwords or API keys.
- **No secrets on disk.** SVIDs and the Trust Bundle are delivered in-memory over the Unix socket.
- **Hardware-backed Root CA.** When `USE_TROPIC01_HW=true`, the Root CA P-256 private key is generated on-chip and never exported. All signing goes through the TROPIC01 USB engineering sample via a ctypes bridge.
- **Graceful hardware fallback.** If the TROPIC01 device is unavailable, the daemon falls back to RSA-2048 / software RNG without crashing.
- **All logging to SQLite.** Every event (SVID minted, attestation failed, entry revoked) is stored as a structured row with component, level, SPIFFE ID, event type, and JSON metadata. No text log files exist.
- **Selector-based matching.** A registration entry's selectors must be a subset of the workload's attested attributes. Presenting extra attributes is fine; missing a required one causes rejection.
- **Emergency revocation.** Deleting a registration entry immediately invalidates the cached SVID.

## Querying Logs

```bash
sqlite3 /tmp/spire-nhp/spire_nhp_log.db \
  "SELECT datetime(timestamp, 'unixepoch'), level, component, message FROM logs ORDER BY timestamp DESC LIMIT 20"
```

Filter by event type:

```bash
sqlite3 /tmp/spire-nhp/spire_nhp_log.db \
  "SELECT datetime(timestamp, 'unixepoch'), message, metadata FROM logs WHERE event_type = 'svid_minted'"
```

## FAQ

**Q: Can TROPIC01's 32 ECC slots be used to cycle through keys in a LIFO pattern, deleting the oldest key to make space for new ones?**

The hardware supports it mechanically: `generate_ecc_key`, `read_ecc_pubkey`, and `erase_ecc_key` all accept a slot index in the range 0-31, so iterating over them is straightforward. It is not conducive to this SPIRE design for three reasons:

- The Root CA key in slot 0 is the trust anchor for the entire Trust Bundle. Cycling it invalidates every issued SVID and requires re-distributing the bundle to all workloads. Root CA rotation is a deliberate, scheduled security event, not an operational pattern.
- SVID private keys cannot use hardware slots at all. TROPIC01 never exports private key material, but workloads must receive their SVID private key in-memory to perform mTLS handshakes themselves. Using hardware slots for SVIDs would require a signing-proxy endpoint that the daemon does not have.
- LIFO would erase the most recently generated key, which is likely the one currently in active use. FIFO (oldest out first) is the correct eviction order once a key's signed certificates have expired.

The appropriate use of slots 1-31 is a FIFO-based intermediate CA key pool: the Root CA signs intermediate certificates, intermediates sign SVIDs, and the oldest intermediate slot is erased only after all SVIDs it signed have passed their TTL. This is a meaningful future addition but requires an intermediate CA layer not currently present.

---

**Q: Would it be better to erase and regenerate the Root CA key in slot 0 on every daemon restart?**

No. The three main objections are:

- **Flash wear.** TROPIC01 NVM has a finite erase/write cycle count. Erasing on every `kill`/restart prematurely damages the chip.
- **Every crash becomes a full trust reset.** Erasing slot 0 invalidates every active SVID held by every running workload. With a 300-second TTL, workloads recover at the next rotation, but the disruption is caused by an operational event (restart) rather than a security event, which is unnecessary.
- **It nullifies the benefit of hardware key storage.** The reason to use TROPIC01 for the Root CA is that the key persists, cannot be exported, and cannot be cloned. Erasing it on restart turns a hardware-protected long-lived anchor into a functional equivalent of an ephemeral software key.

Root CA rotation should be triggered by a rotation policy, a suspected compromise, or an explicit operator command. The correct behavior on restart is to reuse the existing key if the slot is occupied and generate only when the slot is empty. For development and testing scenarios where a fresh key on each run is desirable, an opt-in flag is the right mechanism:

```bash
TROPIC01_FORCE_REGEN=true python -m nhp_daemon   # dev/test only
```

---

## Changelog

### 2026-04-06

**Fix: TROPIC01 hardware mode fails on daemon restart (`Tropic01NotAvailable: tropic_bridge_ecc_key_generate failed (slot=0)`)**

- **Root cause.** The daemon unconditionally called `generate_ecc_key(slot=0)` at startup. The TROPIC01 firmware rejects key generation into an already-occupied slot, and ECC keys persist in flash across reboots and power cycles. The first run succeeded; every subsequent run failed.
- **Fix.** `CertificateAuthority.__init__` now attempts `read_ecc_pubkey(slot=0)` first. If the read succeeds the existing on-chip key is reused. `generate_ecc_key` is only called when the read raises `Tropic01NotAvailable`, indicating an empty slot.
- **Files changed.** `nhp_daemon/ca.py`

---

## License

This is a research prototype. See the repository for license details.

