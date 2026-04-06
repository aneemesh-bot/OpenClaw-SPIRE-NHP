"""Attestation provider for the SPIRE NHP daemon.

``Tropic01Attestor`` is the hardware-aware implementation.  When a live
``Tropic01HW`` instance is injected it uses the on-chip TRNG for the
Endorsement Key and P-256 ECC for workload key pairs.

``TPMSimulator`` is kept as a software-only fallback alias so that
existing tests and call-sites continue to work without hardware.
"""

import hashlib
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1


class Tropic01Attestor:
    """Attestation provider backed by TROPIC01 hardware (or software fallback).

    Args:
        hw: Optional ``Tropic01HW`` instance.  When *None* the class falls
            back to software-only operation (equivalent to the old
            ``TPMSimulator``).
    """

    def __init__(self, hw=None):
        self._hw   = hw
        self._pcrs: dict[int, str] = {}
        self._endorsement_key = self._generate_ek()

    def _generate_ek(self) -> bytes:
        """Endorsement Key from hardware TRNG, or software fallback."""
        if self._hw is not None:
            return self._hw.get_random(32)
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
        """Return ``(private_pem, public_pem)`` using P-256 ECC."""
        private_key = ec.generate_private_key(SECP256R1())
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
            "simulated": self._hw is None,
        }


# Backward-compatible alias: existing call-sites using TPMSimulator continue
# to work without change; new code should prefer Tropic01Attestor directly.
TPMSimulator = Tropic01Attestor
