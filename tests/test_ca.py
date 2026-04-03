"""Tests for the Certificate Authority."""

from cryptography import x509

from nhp_daemon.ca import CertificateAuthority

DOMAIN = "test.example.com"


class TestCertificateAuthority:
    def test_root_cert_is_ca(self, ca):
        bc = ca.root_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        )
        assert bc.value.ca is True

    def test_root_cert_has_spiffe_san(self, ca):
        san = ca.root_certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert f"spiffe://{DOMAIN}" in uris

    def test_sign_svid(self, ca):
        spiffe_id = f"spiffe://{DOMAIN}/agent/test"
        cert, key = ca.sign_svid(spiffe_id, ttl_seconds=60)
        assert cert is not None
        assert key is not None

        # SVID must not be a CA
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

        # SVID SAN must contain the SPIFFE ID
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert spiffe_id in uris

    def test_verify_own_svid(self, ca):
        cert, _ = ca.sign_svid(f"spiffe://{DOMAIN}/w", ttl_seconds=60)
        assert ca.verify_certificate(cert) is True

    def test_reject_foreign_cert(self, ca):
        other_ca = CertificateAuthority("other.com")
        cert, _ = other_ca.sign_svid("spiffe://other.com/w", ttl_seconds=60)
        assert ca.verify_certificate(cert) is False

    def test_svid_ttl(self, ca):
        cert, _ = ca.sign_svid(f"spiffe://{DOMAIN}/w", ttl_seconds=120)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert abs(delta.total_seconds() - 120) < 2
