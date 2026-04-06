"""Certificate Authority for the SPIRE NHP daemon.

Generates a self-signed Root CA and signs short-lived X.509-SVIDs for
workloads.  The Root CA certificate is the anchor of the Trust Bundle.

When TROPIC01 hardware is available (``config.TROPIC01_ENABLED`` and a live
``Tropic01HW`` instance is injected) the Root CA key is generated and stored
on-chip in P-256 ECC slot 0.  Signing is always delegated back to the chip.

When running in software-only mode the behaviour falls back to RSA-2048 so
that the daemon can be tested without physical hardware.
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import config


# ──────────────────────────────────────────────────────────────────────────
# Hardware proxy key
# ──────────────────────────────────────────────────────────────────────────

class Tropic01ECPrivateKey(EllipticCurvePrivateKey):
    """EllipticCurvePrivateKey proxy whose private bytes never leave the chip.

    ``sign()`` forwards the TBS bytes to the TROPIC01 hardware, which
    SHA-256-hashes them internally then returns a 64-byte raw P-256
    signature (R‖S).  We convert that to DER before returning so that
    ``CertificateBuilder.sign()`` receives the format it expects.
    """

    def __init__(self, hw, slot: int, pub_key: EllipticCurvePublicKey):
        self._hw   = hw
        self._slot = slot
        self._pub  = pub_key

    # ── EllipticCurvePrivateKey abstract interface ──

    @property
    def curve(self):
        return SECP256R1()

    @property
    def key_size(self) -> int:
        return 256

    def public_key(self) -> EllipticCurvePublicKey:
        return self._pub

    def sign(self, data: bytes, signature_algorithm) -> bytes:
        """Delegate signing to the hardware chip; return DER-encoded signature."""
        return self._hw.ecdsa_sign(self._slot, data)

    def exchange(self, algorithm, public_key):
        raise NotImplementedError("ECDH exchange is not supported by TROPIC01 proxy key")

    def private_numbers(self):
        raise NotImplementedError("Private key never leaves the TROPIC01 chip")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise NotImplementedError("Private key never leaves the TROPIC01 chip")

    def __copy__(self):
        return self


# ──────────────────────────────────────────────────────────────────────────
# Helper: hardware-RNG serial number (fits in 20 bytes per RFC 5280)
# ──────────────────────────────────────────────────────────────────────────

def _serial_number(hw=None) -> int:
    """Return a positive X.509 serial number from hardware TRNG or system RNG."""
    if hw is not None:
        raw = hw.get_random(20)
        # Ensure the top bit is clear (positive integer, max 160-bit)
        value = int.from_bytes(raw, "big") & ((1 << 159) - 1)
        return value if value > 0 else 1
    return x509.random_serial_number()


class CertificateAuthority:
    """Root CA for the single-server SPIRE deployment."""

    def __init__(self, trust_domain: str, hw=None):
        """Create the CA.

        Args:
            trust_domain: SPIFFE trust domain string (e.g. "example.org").
            hw: Optional ``Tropic01HW`` instance.  When provided the Root CA
                key is placed in ECC slot ``config.TROPIC01_ROOT_CA_SLOT`` and
                all signing is delegated to the hardware.
        """
        self.trust_domain = trust_domain
        self._hw          = hw

        if hw is not None:
            # Generate on-chip P-256 key and wrap it in a proxy
            slot = config.TROPIC01_ROOT_CA_SLOT
            hw.generate_ecc_key(slot)
            pub = hw.read_ecc_pubkey(slot)
            self._private_key = Tropic01ECPrivateKey(hw, slot, pub)
        else:
            # Software fallback: RSA-2048
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
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
            .serial_number(_serial_number(self._hw))
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

        The SVID key is always a software-ephemeral P-256 key so that the
        caller can serialise ``private_key_pem`` for workload delivery.
        The CA certificate is signed by the Root CA key (hardware proxy or
        software RSA depending on initialisation).

        Returns ``(certificate, private_key)`` where *private_key* belongs
        to the SVID (not to the CA).
        """
        svid_key = ec.generate_private_key(SECP256R1())
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
            .serial_number(_serial_number(self._hw))
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
            pub  = self.public_key
            algo = cert.signature_hash_algorithm
            if algo is None:
                return False
            if isinstance(pub, RSAPublicKey):
                pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    algo,
                )
            elif isinstance(pub, EllipticCurvePublicKey):
                pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ECDSA(algo),
                )
            else:
                return False
            return True
        except Exception:
            return False
