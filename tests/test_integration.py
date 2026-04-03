"""Integration tests — full Agent + Workload API flow over Unix Domain Socket."""

import os
import time

import pytest

from cryptography.hazmat.primitives import serialization

from nhp_daemon.ca import CertificateAuthority
from nhp_daemon.spire_agent import SPIREAgent
from nhp_daemon.spire_server import SPIREServer
from nhp_daemon.sqlite_logger import SQLiteLogger
from nhp_daemon.tpm_simulator import TPMSimulator
from nhp_daemon.workload_api import WorkloadAPIClient

DOMAIN = "test.example.com"


@pytest.fixture
def full_stack(tmp_path):
    """Spin up server + agent and yield a WorkloadAPIClient."""
    logger = SQLiteLogger(str(tmp_path / "log.db"))
    server = SPIREServer(DOMAIN, str(tmp_path / "reg.db"), logger)

    uid = os.getuid()
    server.create_registration_entry(
        spiffe_id=f"spiffe://{DOMAIN}/nhp/openclaw/test-agent",
        parent_id=f"spiffe://{DOMAIN}/spire/agent/node",
        selectors=[("unix", f"uid:{uid}")],
        ttl=300,
    )

    sock_path = str(tmp_path / "workload.sock")
    tpm = TPMSimulator()
    agent = SPIREAgent(sock_path, server, logger, tpm)
    agent.start()
    time.sleep(0.3)

    client = WorkloadAPIClient(sock_path)
    yield client, server, logger

    agent.stop()
    logger.close()


class TestIntegration:
    def test_fetch_bundle(self, full_stack):
        client, _, _ = full_stack
        bundle = client.fetch_bundle()
        assert bundle["trust_domain"] == DOMAIN

    def test_fetch_svid(self, full_stack):
        client, _, _ = full_stack
        svid = client.fetch_svid(f"spiffe://{DOMAIN}/nhp/openclaw/test-agent")
        assert svid["spiffe_id"] == f"spiffe://{DOMAIN}/nhp/openclaw/test-agent"
        assert "certificate_pem" in svid
        assert "private_key_pem" in svid

    def test_validate_svid(self, full_stack):
        client, _, _ = full_stack
        svid = client.fetch_svid(f"spiffe://{DOMAIN}/nhp/openclaw/test-agent")
        assert client.validate_peer_certificate(svid["certificate_pem"]) is True

    def test_reject_unknown_spiffe_id(self, full_stack):
        client, _, _ = full_stack
        with pytest.raises(RuntimeError, match="attestation_failed"):
            client.fetch_svid(f"spiffe://{DOMAIN}/nhp/unknown")

    def test_reject_foreign_cert(self, full_stack):
        client, _, _ = full_stack
        foreign_ca = CertificateAuthority("evil.com")
        cert, _ = foreign_ca.sign_svid("spiffe://evil.com/w", 60)
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        assert client.validate_peer_certificate(pem) is False

    def test_logs_in_sqlite(self, full_stack):
        client, _, logger = full_stack
        client.fetch_bundle()
        rows = logger.query(component="spire-agent")
        assert len(rows) > 0

    def test_svid_stored_in_client(self, full_stack):
        client, _, _ = full_stack
        assert client.current_svid is None
        client.fetch_svid(f"spiffe://{DOMAIN}/nhp/openclaw/test-agent")
        assert client.current_svid is not None
        assert client.current_svid["spiffe_id"].endswith("test-agent")

    def test_bundle_stored_in_client(self, full_stack):
        client, _, _ = full_stack
        assert client.current_bundle is None
        client.fetch_bundle()
        assert client.current_bundle is not None
