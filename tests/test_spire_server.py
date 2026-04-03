"""Tests for the SPIRE Server."""

import os

from cryptography import x509

from nhp_daemon.spire_server import SPIREServer

DOMAIN = "test.example.com"


class TestSPIREServer:
    def test_trust_bundle(self, server):
        bundle = server.get_trust_bundle()
        assert bundle["trust_domain"] == DOMAIN
        assert "root_certificate_pem" in bundle

    def test_registration_and_mint(self, server):
        uid = os.getuid()
        server.create_registration_entry(
            spiffe_id=f"spiffe://{DOMAIN}/nhp/agent1",
            parent_id=f"spiffe://{DOMAIN}/node",
            selectors=[("unix", f"uid:{uid}")],
            ttl=120,
        )
        svid = server.mint_svid(
            f"spiffe://{DOMAIN}/nhp/agent1",
            [("unix", f"uid:{uid}")],
        )
        assert svid is not None
        assert svid["spiffe_id"] == f"spiffe://{DOMAIN}/nhp/agent1"
        assert svid["ttl"] == 120
        assert "certificate_pem" in svid
        assert "private_key_pem" in svid

    def test_mint_denied_no_entry(self, server):
        svid = server.mint_svid("spiffe://test/unknown", [("unix", "uid:0")])
        assert svid is None

    def test_revoke(self, server):
        uid = os.getuid()
        eid = server.create_registration_entry(
            spiffe_id=f"spiffe://{DOMAIN}/nhp/revokable",
            parent_id=f"spiffe://{DOMAIN}/node",
            selectors=[("unix", f"uid:{uid}")],
        )
        server.mint_svid(
            f"spiffe://{DOMAIN}/nhp/revokable",
            [("unix", f"uid:{uid}")],
        )
        assert server.is_svid_valid(f"spiffe://{DOMAIN}/nhp/revokable")

        assert server.revoke_entry(eid) is True
        assert not server.is_svid_valid(f"spiffe://{DOMAIN}/nhp/revokable")

    def test_revoke_nonexistent(self, server):
        assert server.revoke_entry("no-such-id") is False

    def test_svid_verification_via_bundle(self, server):
        uid = os.getuid()
        server.create_registration_entry(
            spiffe_id=f"spiffe://{DOMAIN}/nhp/verify",
            parent_id=f"spiffe://{DOMAIN}/node",
            selectors=[("unix", f"uid:{uid}")],
        )
        svid = server.mint_svid(
            f"spiffe://{DOMAIN}/nhp/verify",
            [("unix", f"uid:{uid}")],
        )
        cert = x509.load_pem_x509_certificate(svid["certificate_pem"].encode())
        assert server.trust_bundle.verify_svid(cert) is True

    def test_multiple_entries_correct_match(self, server):
        uid = os.getuid()
        server.create_registration_entry(
            spiffe_id=f"spiffe://{DOMAIN}/nhp/a",
            parent_id=f"spiffe://{DOMAIN}/node",
            selectors=[("unix", f"uid:{uid}")],
            ttl=60,
        )
        server.create_registration_entry(
            spiffe_id=f"spiffe://{DOMAIN}/nhp/b",
            parent_id=f"spiffe://{DOMAIN}/node",
            selectors=[("unix", f"uid:{uid}")],
            ttl=180,
        )
        svid_a = server.mint_svid(
            f"spiffe://{DOMAIN}/nhp/a", [("unix", f"uid:{uid}")]
        )
        svid_b = server.mint_svid(
            f"spiffe://{DOMAIN}/nhp/b", [("unix", f"uid:{uid}")]
        )
        assert svid_a["ttl"] == 60
        assert svid_b["ttl"] == 180
