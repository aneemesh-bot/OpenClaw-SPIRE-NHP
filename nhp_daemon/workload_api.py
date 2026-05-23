"""Workload API client — used by OpenClaw processes to obtain NHP identities.

The client connects to the SPIRE Agent's Unix Domain Socket, which
authenticates the caller via SO_PEERCRED (no passwords involved).
"""

import hashlib
import json
import socket
import struct
import urllib.error as _urllib_err
import urllib.request as _urllib_req


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

    # ── Intent signing ──

    def sign_agent_intent(self, chain_of_thought_block: str) -> str:
        """Hash and hardware-sign an agent CoT reasoning trace.

        Computes SHA-256 of the sanitized *chain_of_thought_block*, then
        requests an ECDSA P-256 signature from TROPIC01 slot 1 (never
        slot 0 which is reserved for the Root CA key).  Falls back to
        returning the bare hex digest when hardware is unavailable.

        Returns a hex-encoded signature string suitable for the
        ``X-Agent-Intent-Hash`` header.
        """
        sanitized = chain_of_thought_block.strip().encode("utf-8", errors="replace")
        digest = hashlib.sha256(sanitized).digest()

        try:
            from .tropic01_hw import get_hw
            hw = get_hw()
            if hw is not None:
                sig_der = hw.ecdsa_sign(slot=1, data=digest)
                return sig_der.hex()
        except Exception:
            pass

        # Software fallback: return the raw SHA-256 hex digest
        return digest.hex()

    def make_resource_request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        jwt_token: str = "",
        chain_of_thought: str = "",
    ) -> dict:
        """Make an outbound HTTP request with NHP identity headers attached.

        Injects:
          Authorization       – Bearer <jwt_token>
          X-Agent-Intent-Hash – TROPIC01-signed SHA-256 of *chain_of_thought*
          X-Agent-SVID-Serial – serial number of the current in-memory SVID

        Returns a dict with ``status``, ``headers``, and ``body`` keys.
        """
        intent_hash = self.sign_agent_intent(chain_of_thought) if chain_of_thought else ""
        svid_serial = ""
        if self._svid:
            svid_serial = str(self._svid.get("serial_number", ""))

        headers: dict[str, str] = {
            "Authorization": f"Bearer {jwt_token}",
            "X-Agent-Intent-Hash": intent_hash,
            "X-Agent-SVID-Serial": svid_serial,
        }
        if body is not None:
            headers["Content-Length"] = str(len(body))

        req = _urllib_req.Request(url, data=body, method=method.upper(), headers=headers)
        try:
            with _urllib_req.urlopen(req, timeout=10) as resp:
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read(),
                }
        except _urllib_err.HTTPError as exc:
            return {"status": exc.code, "headers": {}, "body": exc.read()}
        except _urllib_err.URLError as exc:
            return {"status": 0, "headers": {}, "body": str(exc.reason).encode()}

    @property
    def current_svid(self):
        return self._svid

    @property
    def current_bundle(self):
        return self._bundle
