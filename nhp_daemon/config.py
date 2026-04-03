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
