"""Workload API client — used by OpenClaw processes to obtain NHP identities.

The client connects to the SPIRE Agent's Unix Domain Socket, which
authenticates the caller via SO_PEERCRED (no passwords involved).
"""

import json
import socket
import struct


class WorkloadAPIClient:
    """Client for the SPIRE Agent Workload API (UDS)."""

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self._svid: dict | None = None
        self._bundle: dict | None = None

    def _send_request(self, request: dict) -> dict:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.socket_path)
            data = json.dumps(request).encode()
            sock.sendall(struct.pack("!I", len(data)) + data)

            # read response
            header = b""
            while len(header) < 4:
                chunk = sock.recv(4 - len(header))
                if not chunk:
                    raise ConnectionError("Connection closed by agent")
                header += chunk
            length = struct.unpack("!I", header)[0]

            response_data = b""
            while len(response_data) < length:
                chunk = sock.recv(min(4096, length - len(response_data)))
                if not chunk:
                    raise ConnectionError("Connection closed by agent")
                response_data += chunk

            return json.loads(response_data)
        finally:
            sock.close()

    # ── Public API ──

    def fetch_svid(self, spiffe_id: str) -> dict:
        """Request an X.509-SVID for *spiffe_id*."""
        resp = self._send_request({"type": "fetch_svid", "spiffe_id": spiffe_id})
        if "error" in resp:
            raise RuntimeError(
                f"SVID fetch failed: {resp['error']} — {resp.get('message', '')}"
            )
        svid: dict = resp["svid"]
        self._svid = svid
        return svid

    def fetch_bundle(self) -> dict:
        """Retrieve the Trust Bundle from the SPIRE Agent."""
        resp = self._send_request({"type": "fetch_bundle"})
        if "error" in resp:
            raise RuntimeError(f"Bundle fetch failed: {resp['error']}")
        bundle: dict = resp["bundle"]
        self._bundle = bundle
        return bundle

    def validate_peer_certificate(self, cert_pem: str) -> bool:
        """Validate a peer's certificate against the Trust Bundle."""
        resp = self._send_request(
            {"type": "validate_peer", "certificate_pem": cert_pem}
        )
        return resp.get("valid", False)

    @property
    def current_svid(self):
        return self._svid

    @property
    def current_bundle(self):
        return self._bundle
