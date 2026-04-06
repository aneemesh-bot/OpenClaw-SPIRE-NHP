"""Python ctypes wrapper around the tropic01_bridge shared library.

This module exposes a single ``Tropic01HW`` class that owns the hardware
connection lifecycle and provides:

* ``get_random(n)``           – hardware TRNG bytes (max 255 per call)
* ``generate_ecc_key(slot)``  – on-chip P-256 key generation
* ``read_ecc_pubkey(slot)``   – export P-256 public key (never the private key)
* ``ecdsa_sign(slot, data)``  – hardware ECDSA P-256 signature
* ``erase_ecc_key(slot)``     – delete an ECC slot

A global singleton ``_hw`` is managed by ``get_hw()``; call ``init_hw()``
once at daemon startup and ``deinit_hw()`` at shutdown.  If the bridge .so
cannot be loaded (device absent, USE_TROPIC01_HW=false) every operation
raises ``Tropic01NotAvailable`` at call time so the software fallback path
in the caller can take over gracefully.
"""

import ctypes
import os
import threading
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import config


class Tropic01NotAvailable(RuntimeError):
    """Raised when the TROPIC01 hardware is not reachable or not enabled."""


# ──────────────────────────────────────────────────────────────────────────
# ctypes bridge loader
# ──────────────────────────────────────────────────────────────────────────

def _load_bridge(so_path: str) -> ctypes.CDLL:
    """Load the shared library and assign all argtypes / restypes."""
    lib = ctypes.CDLL(so_path)

    lib.tropic_bridge_init.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.tropic_bridge_init.restype  = ctypes.c_int

    lib.tropic_bridge_deinit.argtypes = []
    lib.tropic_bridge_deinit.restype  = None

    lib.tropic_bridge_get_random.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint8
    ]
    lib.tropic_bridge_get_random.restype = ctypes.c_int

    lib.tropic_bridge_ecc_key_generate.argtypes = [ctypes.c_uint8]
    lib.tropic_bridge_ecc_key_generate.restype  = ctypes.c_int

    lib.tropic_bridge_ecc_key_read.argtypes = [
        ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint8)
    ]
    lib.tropic_bridge_ecc_key_read.restype = ctypes.c_int

    lib.tropic_bridge_ecdsa_sign.argtypes = [
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.tropic_bridge_ecdsa_sign.restype = ctypes.c_int

    lib.tropic_bridge_ecc_key_erase.argtypes = [ctypes.c_uint8]
    lib.tropic_bridge_ecc_key_erase.restype  = ctypes.c_int

    return lib


# ──────────────────────────────────────────────────────────────────────────
# Public class
# ──────────────────────────────────────────────────────────────────────────

class Tropic01HW:
    """Live connection to the TROPIC01 USB engineering sample.

    Not intended to be instantiated directly; use the module-level
    ``init_hw()`` / ``get_hw()`` helpers.
    """

    def __init__(self, so_path: str, device: str, pairing_keys: str):
        self._lib = _load_bridge(so_path)
        use_eng = 1 if pairing_keys == "eng_sample" else 0
        rc = self._lib.tropic_bridge_init(device.encode(), use_eng)
        if rc != 0:
            raise Tropic01NotAvailable(
                f"tropic_bridge_init failed (rc={rc}). "
                f"Device: {device}, keys: {pairing_keys}"
            )

    def deinit(self) -> None:
        self._lib.tropic_bridge_deinit()

    # ── RNG ──────────────────────────────────────────────────────────────

    def get_random(self, n: int) -> bytes:
        """Return *n* hardware-random bytes.  *n* must be in 1..255."""
        if not 1 <= n <= 255:
            raise ValueError(f"TROPIC01 TRNG supports 1-255 bytes, got {n}")
        buf = (ctypes.c_uint8 * n)()
        rc = self._lib.tropic_bridge_get_random(buf, ctypes.c_uint8(n))
        if rc != 0:
            raise Tropic01NotAvailable("tropic_bridge_get_random failed")
        return bytes(buf)

    def get_random_int(self, n_bytes: int) -> int:
        """Return a non-negative integer from *n_bytes* hardware-random bytes."""
        return int.from_bytes(self.get_random(n_bytes), "big")

    # ── ECC key management ────────────────────────────────────────────────

    def generate_ecc_key(self, slot: int) -> None:
        """Generate a P-256 key pair in *slot* (0-31).  Private key stays on chip."""
        rc = self._lib.tropic_bridge_ecc_key_generate(ctypes.c_uint8(slot))
        if rc != 0:
            raise Tropic01NotAvailable(
                f"tropic_bridge_ecc_key_generate failed (slot={slot})"
            )

    def read_ecc_pubkey(self, slot: int) -> EllipticCurvePublicKey:
        """Return the P-256 public key stored in *slot* as a Python EC key object."""
        buf = (ctypes.c_uint8 * 64)()
        rc = self._lib.tropic_bridge_ecc_key_read(
            ctypes.c_uint8(slot),
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8)),
        )
        if rc != 0:
            raise Tropic01NotAvailable(
                f"tropic_bridge_ecc_key_read failed (slot={slot})"
            )
        raw = bytes(buf)  # 64 bytes: first 32 = X, next 32 = Y
        x = int.from_bytes(raw[:32], "big")
        y = int.from_bytes(raw[32:], "big")
        return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()

    def erase_ecc_key(self, slot: int) -> None:
        """Erase the ECC key in *slot*."""
        rc = self._lib.tropic_bridge_ecc_key_erase(ctypes.c_uint8(slot))
        if rc != 0:
            raise Tropic01NotAvailable(
                f"tropic_bridge_ecc_key_erase failed (slot={slot})"
            )

    # ── Signing ───────────────────────────────────────────────────────────

    def ecdsa_sign(self, slot: int, data: bytes) -> bytes:
        """ECDSA P-256 sign *data* with the key in *slot*.

        TROPIC01 SHA-256-hashes *data* internally.

        Returns a **DER-encoded** ECDSA signature compatible with the
        ``cryptography`` library's X.509 builder.
        """
        msg_buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        rs_buf  = (ctypes.c_uint8 * 64)()
        rc = self._lib.tropic_bridge_ecdsa_sign(
            ctypes.c_uint8(slot),
            ctypes.cast(msg_buf, ctypes.POINTER(ctypes.c_uint8)),
            ctypes.c_uint32(len(data)),
            ctypes.cast(rs_buf, ctypes.POINTER(ctypes.c_uint8)),
        )
        if rc != 0:
            raise Tropic01NotAvailable(
                f"tropic_bridge_ecdsa_sign failed (slot={slot})"
            )
        raw = bytes(rs_buf)
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        return encode_dss_signature(r, s)  # DER-encoded SEQUENCE { INTEGER r, INTEGER s }


# ──────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ──────────────────────────────────────────────────────────────────────────

_hw: Optional[Tropic01HW] = None
_hw_lock = threading.Lock()


def init_hw() -> Optional[Tropic01HW]:
    """Initialise the hardware singleton.

    No-ops and returns ``None`` when ``config.TROPIC01_ENABLED`` is false.
    Raises ``Tropic01NotAvailable`` on hardware failure.
    """
    global _hw
    if not config.TROPIC01_ENABLED:
        return None
    with _hw_lock:
        if _hw is None:
            if not os.path.exists(config.TROPIC01_BRIDGE_SO):
                raise Tropic01NotAvailable(
                    f"Bridge .so not found: {config.TROPIC01_BRIDGE_SO}\n"
                    "Build it with: cd tropic01-req/libtropic_bridge && "
                    "mkdir build && cd build && cmake .. && make"
                )
            _hw = Tropic01HW(
                so_path=config.TROPIC01_BRIDGE_SO,
                device=config.TROPIC01_DEVICE,
                pairing_keys=config.TROPIC01_PAIRING_KEYS,
            )
    return _hw


def get_hw() -> Optional[Tropic01HW]:
    """Return the hardware singleton, or ``None`` if not enabled/initialised."""
    return _hw


def deinit_hw() -> None:
    """Deinitialise the hardware singleton if active."""
    global _hw
    with _hw_lock:
        if _hw is not None:
            _hw.deinit()
            _hw = None
