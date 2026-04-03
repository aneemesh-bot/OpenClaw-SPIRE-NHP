"""Main entry point for the SPIRE NHP daemon prototype.

Starts the SPIRE Server, registers NHP personas, launches the Agent,
and runs a demo flow (bootstrap → SVID fetch → validation).
"""

import os
import signal
import sys
import time

from .config import DB_PATH, DEFAULT_SVID_TTL, LOG_DB_PATH, SOCKET_PATH, TRUST_DOMAIN
from .spire_agent import SPIREAgent
from .spire_server import SPIREServer
from .sqlite_logger import SQLiteLogger
from .tpm_simulator import TPMSimulator
from .workload_api import WorkloadAPIClient


def main():
    logger = SQLiteLogger(LOG_DB_PATH)
    logger.info("main", "=== SPIRE NHP Daemon Starting ===", event_type="startup")

    # Simulated TPM
    tpm = TPMSimulator()
    logger.info(
        "main",
        f"TPM simulator ready (EK: {tpm.endorsement_key_hash[:16]}...)",
        event_type="tpm_init",
    )

    # SPIRE Server
    server = SPIREServer(TRUST_DOMAIN, DB_PATH, logger)

    # Register NHP personas
    uid = os.getuid()
    server.create_registration_entry(
        spiffe_id=f"spiffe://{TRUST_DOMAIN}/nhp/openclaw/finance-auditor",
        parent_id=f"spiffe://{TRUST_DOMAIN}/spire/agent/linux-node-01",
        selectors=[("unix", f"uid:{uid}")],
        ttl=DEFAULT_SVID_TTL,
    )
    server.create_registration_entry(
        spiffe_id=f"spiffe://{TRUST_DOMAIN}/nhp/openclaw/research-agent",
        parent_id=f"spiffe://{TRUST_DOMAIN}/spire/agent/linux-node-01",
        selectors=[("unix", f"uid:{uid}")],
        ttl=DEFAULT_SVID_TTL,
    )

    # SPIRE Agent
    agent = SPIREAgent(SOCKET_PATH, server, logger, tpm)
    agent.start()
    logger.info("main", "=== SPIRE NHP Daemon Ready ===", event_type="ready")

    time.sleep(0.5)

    # Demo: simulate an OpenClaw workload obtaining its NHP identity
    try:
        client = WorkloadAPIClient(SOCKET_PATH)

        bundle = client.fetch_bundle()
        logger.info(
            "main",
            f"Bundle fetched (domain: {bundle['trust_domain']})",
            event_type="demo_bundle",
        )

        svid = client.fetch_svid(
            f"spiffe://{TRUST_DOMAIN}/nhp/openclaw/finance-auditor"
        )
        logger.info(
            "main",
            f"SVID received (expires: {svid['expires_at']:.0f})",
            spiffe_id=svid["spiffe_id"],
            event_type="demo_svid",
        )

        valid = client.validate_peer_certificate(svid["certificate_pem"])
        logger.info(
            "main",
            f"SVID validation: {'PASSED' if valid else 'FAILED'}",
            event_type="demo_validation",
        )

        print(f"[NHP] Trust Domain : {bundle['trust_domain']}")
        print(f"[NHP] SPIFFE ID    : {svid['spiffe_id']}")
        print(f"[NHP] SVID TTL     : {svid['ttl']}s")
        print(f"[NHP] SVID Valid   : {valid}")
        print(f"[NHP] Log database : {LOG_DB_PATH}")
    except Exception as exc:
        logger.error("main", f"Demo failed: {exc}", event_type="demo_error")
        print(f"Error: {exc}", file=sys.stderr)

    # Keep running until interrupted
    def _shutdown(sig, frame):
        print("\n[NHP] Shutting down...")
        agent.stop()
        logger.info(
            "main", "=== SPIRE NHP Daemon Stopped ===", event_type="shutdown"
        )
        logger.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("[NHP] Daemon running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
