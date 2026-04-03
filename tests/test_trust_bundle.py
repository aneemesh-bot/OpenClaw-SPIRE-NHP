"""Tests for the Trust Bundle."""

from nhp_daemon.ca import CertificateAuthority
from nhp_daemon.trust_bundle import TrustBundle

DOMAIN = "test.example.com"


class TestTrustBundle:
    def test_create(self, trust_bundle):
        assert trust_bundle.trust_domain == DOMAIN
        assert len(trust_bundle.active_signing_keys) == 1
        assert trust_bundle.sequence_number == 1

    def test_verify_valid_svid(self, ca, trust_bundle):
        cert, _ = ca.sign_svid(f"spiffe://{DOMAIN}/w", ttl_seconds=60)
        assert trust_bundle.verify_svid(cert) is True

    def test_reject_invalid_svid(self, trust_bundle):
        foreign = CertificateAuthority("evil.com")
        cert, _ = foreign.sign_svid("spiffe://evil.com/w", ttl_seconds=60)
        assert trust_bundle.verify_svid(cert) is False

    def test_serialize_roundtrip(self, trust_bundle):
        data = trust_bundle.to_dict()
        restored = TrustBundle.from_dict(data)
        assert restored.trust_domain == trust_bundle.trust_domain
        assert restored.sequence_number == trust_bundle.sequence_number

    def test_roundtrip_verification(self, ca, trust_bundle):
        """Bundle survives serialisation and still verifies SVIDs."""
        cert, _ = ca.sign_svid(f"spiffe://{DOMAIN}/w", 60)
        data = trust_bundle.to_dict()
        restored = TrustBundle.from_dict(data)
        assert restored.verify_svid(cert) is True
