"""SPIRE Agent — Unix Domain Socket server for workload attestation.

Listens on a UDS, attests connecting workloads via SO_PEERCRED, and
delivers X.509-SVIDs and the Trust Bundle in-memory (no secrets on disk).
"""

import json
import os
import socket
import struct
import threading

from .attestation import WorkloadAttestor
from .sqlite_logger import SQLiteLogger
from .trust_bundle import TrustBundle


class SPIREAgent:
    """Agent process co-located with workloads on a Linux host."""

    def __init__(
        self,
        socket_path: str,
        server,
        logger: SQLiteLogger,
        tpm_simulator=None,
    ):
        self.socket_path = socket_path
        self.server = server
        self.logger = logger
        self.tpm = tpm_simulator
        self.attestor = WorkloadAttestor(tpm_simulator, logger)
        self._running = False
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._trust_bundle: dict | None = None

        self._refresh_bundle()

    # ── Bundle management ──

    def _refresh_bundle(self):
        self._trust_bundle = self.server.get_trust_bundle()
        seq = self._trust_bundle.get("sequence_number", 0) if self._trust_bundle else 0
        self.logger.info(
            "spire-agent",
            "Trust bundle refreshed",
            event_type="bundle_refresh",
            metadata={"sequence": seq},
        )

    # ── Socket lifecycle ──

    def start(self):
        """Bind and listen on the workload UDS."""
        os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)
        os.chmod(self.socket_path, 0o660)
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

        self.logger.info(
            "spire-agent",
            f"Agent listening on {self.socket_path}",
            event_type="agent_started",
        )

    def stop(self):
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        if self._thread:
            self._thread.join(timeout=5)
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        self.logger.info("spire-agent", "Agent stopped", event_type="agent_stopped")

    # ── Accept loop ──

    def _accept_loop(self):
        while self._running:
            try:
                assert self._server_socket is not None
                client, _ = self._server_socket.accept()
                threading.Thread(
                    target=self._handle_client, args=(client,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client_socket: socket.socket):
        try:
            peer = self.attestor.get_peer_credentials(client_socket)
            self.logger.info(
                "spire-agent",
                f"Workload connected: pid={peer.pid} uid={peer.uid}",
                event_type="workload_connect",
                metadata={
                    "pid": peer.pid,
                    "uid": peer.uid,
                    "binary": peer.binary_path,
                },
            )

            data = _recv_message(client_socket)
            if not data:
                return

            request = json.loads(data)
            response = self._process_request(request, peer)
            _send_message(client_socket, json.dumps(response).encode())
        except Exception as exc:
            self.logger.error(
                "spire-agent",
                f"Client error: {exc}",
                event_type="client_error",
            )
        finally:
            client_socket.close()

    # ── Request dispatch ──

    def _process_request(self, request: dict, peer) -> dict:
        req_type = request.get("type")
        if req_type == "fetch_svid":
            return self._handle_fetch_svid(request, peer)
        if req_type == "fetch_bundle":
            return self._handle_fetch_bundle()
        if req_type == "validate_peer":
            return self._handle_validate_peer(request)
        return {"error": "unknown_request_type", "message": f"Unknown: {req_type}"}

    def _handle_fetch_svid(self, request: dict, peer) -> dict:
        spiffe_id = request.get("spiffe_id")
        if not spiffe_id:
            return {"error": "missing_spiffe_id"}

        selectors = WorkloadAttestor.build_selectors_from_peer(peer)
        svid_data = self.server.mint_svid(spiffe_id, selectors)

        if not svid_data:
            self.logger.warning(
                "spire-agent",
                f"Attestation failed for pid={peer.pid}",
                spiffe_id=spiffe_id,
                event_type="attestation_failed",
            )
            return {
                "error": "attestation_failed",
                "message": "No matching registration entry",
            }

        self.logger.info(
            "spire-agent",
            f"SVID delivered to pid={peer.pid}",
            spiffe_id=spiffe_id,
            event_type="svid_delivered",
        )
        return {"type": "svid_response", "svid": svid_data}

    def _handle_fetch_bundle(self) -> dict:
        return {"type": "bundle_response", "bundle": self._trust_bundle}

    def _handle_validate_peer(self, request: dict) -> dict:
        cert_pem = request.get("certificate_pem")
        if not cert_pem:
            return {"error": "missing_certificate"}

        from cryptography import x509 as x509_mod

        cert = x509_mod.load_pem_x509_certificate(cert_pem.encode())
        if self._trust_bundle is None:
            return {"error": "no_trust_bundle"}
        bundle = TrustBundle.from_dict(self._trust_bundle)
        valid = bundle.verify_svid(cert)
        return {"type": "validation_response", "valid": valid}


# ── Wire helpers (length-prefixed JSON) ──


def _recv_message(
    sock: socket.socket, max_size: int = 1_000_000
) -> bytes | None:
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    length = struct.unpack("!I", header)[0]
    if length > max_size:
        return None
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            return None
        data += chunk
    return data


def _send_message(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)
