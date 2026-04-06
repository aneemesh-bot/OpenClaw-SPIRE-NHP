"""Configuration for the SPIRE NHP prototype."""

import os

TRUST_DOMAIN = "enterprise.com"
SOCKET_PATH = os.environ.get("SPIRE_NHP_SOCKET", "/tmp/spire-nhp/workload.sock")
DB_PATH = os.environ.get("SPIRE_NHP_DB", "/tmp/spire-nhp/spire_nhp.db")
LOG_DB_PATH = os.environ.get("SPIRE_NHP_LOG_DB", "/tmp/spire-nhp/spire_nhp_log.db")

DEFAULT_SVID_TTL = 300  # 5 minutes
MAX_SVID_TTL = 900  # 15 minutes
BUNDLE_REFRESH_INTERVAL = 60  # seconds

CA_KEY_SIZE = 2048
SVID_KEY_SIZE = 2048

# ── TROPIC01 hardware offload ──────────────────────────────────────────────
# Set USE_TROPIC01_HW=true to enable hardware-backed RNG, CA key generation,
# and certificate signing via the TROPIC01 USB engineering sample.
# When false (default) the daemon runs entirely in software.
TROPIC01_ENABLED: bool = os.environ.get("USE_TROPIC01_HW", "false").lower() == "true"

# Stable by-ID symlink for the TropicSquare USB devkit (falls back to ACM0).
TROPIC01_DEVICE: str = os.environ.get(
    "TROPIC01_DEVICE",
    "/dev/serial/by-id/usb-TropicSquare_SPI_interface_4986323F384B-if00",
)

# "eng_sample" for TROPIC01-ES engineering samples, "prod0" for production.
TROPIC01_PAIRING_KEYS: str = os.environ.get("TROPIC01_PAIRING_KEYS", "eng_sample")

# ECC slot reserved for the Root CA private key (never erased at runtime).
TROPIC01_ROOT_CA_SLOT: int = 0

# ECC slots used for rotating SVID keys (currently unused – SVIDs use
# ephemeral software ECDSA keys so the private key can be delivered to
# workloads without a signing-proxy endpoint).
TROPIC01_SVID_SLOT_RANGE: tuple[int, int] = (1, 31)

# Path to the compiled bridge shared library.
_BRIDGE_DEFAULT = os.path.join(
    os.path.dirname(__file__),
    "..", "tropic01-req", "libtropic_bridge", "build", "libtropic01_bridge.so",
)
TROPIC01_BRIDGE_SO: str = os.environ.get(
    "TROPIC01_BRIDGE_SO",
    os.path.normpath(_BRIDGE_DEFAULT),
)
