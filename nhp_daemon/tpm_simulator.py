"""Simulated TPM for software-based key generation and attestation.

In production the private key would never leave the TPM boundary; here
we use ``secrets`` / ``hashlib`` to emulate the relevant operations so
the prototype can run on any Linux host without real TPM hardware.
"""

import hashlib
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class TPMSimulator:
    """Software stand-in for a Trusted Platform Module."""

    def __init__(self):
        self._pcrs: dict[int, str] = {}
        self._endorsement_key = self._generate_ek()

    @staticmethod
    def _generate_ek() -> bytes:
        """Simulated Endorsement Key (EK) via software RNG."""
        return secrets.token_bytes(32)

    @property
    def endorsement_key_hash(self) -> str:
        return hashlib.sha256(self._endorsement_key).hexdigest()

    # ── PCR operations ──

    def measure_binary(self, binary_path: str) -> str:
        """Hash a binary and store the measurement in the next PCR slot."""
        try:
            h = hashlib.sha256()
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            measurement = h.hexdigest()
        except FileNotFoundError:
            measurement = hashlib.sha256(binary_path.encode()).hexdigest()

        pcr_index = len(self._pcrs)
        self._pcrs[pcr_index] = measurement
        return measurement

    def get_pcr(self, index: int) -> str | None:
        return self._pcrs.get(index)

    # ── Key generation ──

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Return ``(private_pem, public_pem)`` using software RNG."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_bytes, public_bytes

    # ── Quote ──

    def quote(self, pcr_indices: list[int], nonce: bytes) -> dict:
        """Simulate a TPM Quote — a signed attestation of PCR values."""
        pcr_values = {i: self._pcrs.get(i) for i in pcr_indices}
        digest = hashlib.sha256(
            str(pcr_values).encode() + nonce
        ).hexdigest()
        return {
            "pcr_values": pcr_values,
            "nonce": nonce.hex(),
            "digest": digest,
            "simulated": True,
        }
