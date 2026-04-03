"""Workload attestation via Unix Domain Socket peer credentials.

The SPIRE Agent uses SO_PEERCRED (Linux) to identify the connecting
process's PID, UID, and GID, then resolves the binary path from
``/proc/<pid>/exe`` and computes its SHA-256 hash.
"""

import hashlib
import os
import socket
import struct
from dataclasses import dataclass


@dataclass
class PeerInfo:
    """Kernel-verified information about a connected peer process."""
    pid: int
    uid: int
    gid: int
    binary_path: str = ""
    binary_hash: str = ""


class WorkloadAttestor:
    """Attests workloads using SO_PEERCRED on a Unix Domain Socket."""

    def __init__(self, tpm_simulator=None, logger=None):
        self.tpm = tpm_simulator
        self.logger = logger

    def get_peer_credentials(self, client_socket: socket.socket) -> PeerInfo:
        """Extract peer credentials via SO_PEERCRED (Linux only)."""
        creds = client_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, gid = struct.unpack("3i", creds)

        binary_path = ""
        binary_hash = ""
        try:
            binary_path = os.readlink(f"/proc/{pid}/exe")
            binary_hash = self._hash_binary(binary_path)
        except (OSError, FileNotFoundError):
            pass

        return PeerInfo(
            pid=pid, uid=uid, gid=gid,
            binary_path=binary_path, binary_hash=binary_hash,
        )

    # ── helpers ──

    @staticmethod
    def _hash_binary(path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return ""

    @staticmethod
    def build_selectors_from_peer(peer: PeerInfo) -> list[tuple[str, str]]:
        """Derive selector tuples from kernel-attested peer info."""
        selectors = [("unix", f"uid:{peer.uid}")]
        if peer.binary_hash:
            selectors.append(("unix", f"sha256:{peer.binary_hash}"))
        return selectors
