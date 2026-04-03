"""Certificate Authority for the SPIRE NHP daemon.

Generates a self-signed Root CA and signs short-lived X.509-SVIDs for
workloads.  The Root CA certificate is the anchor of the Trust Bundle.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CertificateAuthority:
    """Root CA for the single-server SPIRE deployment."""

    def __init__(self, trust_domain: str, key_size: int = 2048):
        self.trust_domain = trust_domain
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        self._certificate = self._generate_root_cert()

    # ── Root CA generation ──

    def _generate_root_cert(self) -> x509.Certificate:
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPIRE NHP"),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                f"SPIRE Root CA - {self.trust_domain}",
            ),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    UniformResourceIdentifier(f"spiffe://{self.trust_domain}"),
                ]),
                critical=False,
            )
        )
        return builder.sign(self._private_key, hashes.SHA256())

    # ── Properties ──

    @property
    def root_certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def root_certificate_pem(self) -> bytes:
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def public_key(self):
        return self._private_key.public_key()

    @property
    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # ── SVID signing ──

    def sign_svid(self, spiffe_id: str, ttl_seconds: int = 300) -> tuple:
        """Sign an X.509-SVID for a workload.

        Returns ``(certificate, private_key)`` where the private key belongs
        to the SVID (not to the CA).
        """
        svid_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPIRE NHP Workload"),
            x509.NameAttribute(NameOID.COMMON_NAME, spiffe_id),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(svid_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(seconds=ttl_seconds))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    UniformResourceIdentifier(spiffe_id),
                ]),
                critical=True,
            )
        )
        certificate = builder.sign(self._private_key, hashes.SHA256())
        return certificate, svid_key

    # ── Verification ──

    def verify_certificate(self, cert: x509.Certificate) -> bool:
        """Verify that *cert* was signed by this CA's root key."""
        try:
            pub = self.public_key
            algo = cert.signature_hash_algorithm
            if not isinstance(pub, RSAPublicKey) or algo is None:
                return False
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                algo,
            )
            return True
        except Exception:
            return False
