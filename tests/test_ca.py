"""Tests for the Certificate Authority."""

from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicNumbers,
)

from nhp_daemon.ca import CertificateAuthority, Tropic01ECPrivateKey

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

        # SVID key must now be ECC P-256
        assert isinstance(key, EllipticCurvePrivateKey)
        assert isinstance(key.curve, SECP256R1)

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


class TestTropic01ECPrivateKey:
    """Unit tests for the hardware proxy key using a mock Tropic01HW."""

    def _make_proxy(self):
        hw = MagicMock()
        # hw.ecdsa_sign returns a DER-encoded signature
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        r = int.from_bytes(b"\x01" * 32, "big")
        s = int.from_bytes(b"\x02" * 32, "big")
        hw.ecdsa_sign.return_value = encode_dss_signature(r, s)

        # Derive a real P-256 public key from a throwaway private key
        from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key
        pub = generate_private_key(SECP256R1()).public_key()

        return Tropic01ECPrivateKey(hw, slot=0, pub_key=pub), hw

    def test_curve_and_key_size(self):
        proxy, _ = self._make_proxy()
        assert isinstance(proxy.curve, SECP256R1)
        assert proxy.key_size == 256

    def test_sign_delegates_to_hw(self):
        proxy, hw = self._make_proxy()
        sig = proxy.sign(b"hello", ECDSA(None))
        hw.ecdsa_sign.assert_called_once_with(0, b"hello")
        assert sig  # non-empty DER bytes

    def test_private_numbers_raises(self):
        proxy, _ = self._make_proxy()
        with pytest.raises(NotImplementedError):
            proxy.private_numbers()

    def test_private_bytes_raises(self):
        proxy, _ = self._make_proxy()
        with pytest.raises(NotImplementedError):
            proxy.private_bytes(None, None, None)

