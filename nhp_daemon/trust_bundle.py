"""Trust Bundle management for the SPIRE NHP daemon.

The Trust Bundle is the *Source of Truth* — the collection of Root CA
certificates and active signing keys that all agents and tools use to
recognise each other.

Verify(SVID_peer, B) ⟹ ∃ K_pub ∈ B such that Verify(σ, K_pub) = True
"""

import time
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


@dataclass
class TrustBundle:
    trust_domain: str
    root_certificate: x509.Certificate
    active_signing_keys: list = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    refresh_interval: int = 60
    sequence_number: int = 0

    @property
    def root_certificate_pem(self) -> bytes:
        return self.root_certificate.public_bytes(serialization.Encoding.PEM)

    def add_signing_key(self, public_key_pem: bytes):
        self.active_signing_keys.append(public_key_pem)
        self.sequence_number += 1

    # ── Verification ──

    def verify_svid(self, svid_cert: x509.Certificate) -> bool:
        """Check that *svid_cert* was signed by the Root CA in this bundle."""
        try:
            pub = self.root_certificate.public_key()
            algo = svid_cert.signature_hash_algorithm
            if not isinstance(pub, RSAPublicKey) or algo is None:
                return False
            pub.verify(
                svid_cert.signature,
                svid_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                algo,
            )
            return True
        except Exception:
            return False

    # ── Serialisation ──

    def to_dict(self) -> dict:
        return {
            "trust_domain": self.trust_domain,
            "root_certificate_pem": self.root_certificate_pem.decode(),
            "active_signing_keys": [
                k.decode() if isinstance(k, bytes) else k
                for k in self.active_signing_keys
            ],
            "created_at": self.created_at,
            "refresh_interval": self.refresh_interval,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TrustBundle":
        root_cert = x509.load_pem_x509_certificate(
            data["root_certificate_pem"].encode()
        )
        bundle = cls(
            trust_domain=data["trust_domain"],
            root_certificate=root_cert,
            refresh_interval=data.get("refresh_interval", 60),
            sequence_number=data.get("sequence_number", 0),
        )
        bundle.created_at = data.get("created_at", time.time())
        for k in data.get("active_signing_keys", []):
            bundle.active_signing_keys.append(
                k.encode() if isinstance(k, str) else k
            )
        return bundle
