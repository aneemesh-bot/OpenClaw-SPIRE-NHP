"""Gateway telemetry — Envoy/API gateway simulator with OTel accounting.

Simulates the ingress mTLS gateway layer that sits between workload clients
and backend resource APIs.  Every intercepted request is:

  1. Authenticated  – SPIFFE URI SAN extracted from the client X.509 cert.
  2. Authorized     – Bearer JWT decoded; ``sub`` claim isolated.
  3. Accounted      – W3C trace ID assigned or propagated; structured JSON
                      record emitted to ``telemetry_queue``.

``telemetry_queue`` is the in-process OTel/SIEM sink.  ``web_ui.py``
subscribes to it and broadcasts records to connected WebSocket clients.
"""

import base64
import json
import queue
import secrets
import time
from typing import Optional


# ── Module-level SIEM / OTel sink ────────────────────────────────────────────
# Bounded queue; producer (GatewayTelemetry) drops on Full, never blocks.
telemetry_queue: queue.Queue = queue.Queue(maxsize=1000)


class GatewayTelemetry:
    """Envoy/API gateway simulator for NHP AAA telemetry.

    Usage::

        gw = GatewayTelemetry(trust_domain="enterprise.com",
                              tropic01_serial="A8F9B2C4D6E8")
        record = gw.handle_request(
            client_cert_pem=cert_pem,
            authorization_header="Bearer <jwt>",
            traceparent_header="",
            intent_hash_header="<hex>",
            method="GET",
            resource="/api/v1/data",
            status=200,
        )
    """

    def __init__(self, trust_domain: str, tropic01_serial: str = "SIMULATED"):
        self.trust_domain = trust_domain
        self.tropic01_serial = tropic01_serial

    def handle_request(
        self,
        *,
        client_cert_pem: Optional[str] = None,
        authorization_header: str = "",
        traceparent_header: str = "",
        intent_hash_header: str = "",
        method: str = "GET",
        resource: str = "/",
        status: int = 200,
    ) -> dict:
        """Process an intercepted gateway request and emit a telemetry record.

        Returns the compiled record dict.  The record is also placed on
        ``telemetry_queue`` for asynchronous consumption by web_ui.py.
        """
        agent_spiffe_id = self._extract_spiffe_id(client_cert_pem)
        delegated_human_sub = self._extract_jwt_sub(authorization_header)
        trace_id = self._extract_or_generate_trace_id(traceparent_header)

        record = {
            "timestamp": str(int(time.time())),
            "trace_id": trace_id,
            "agent_spiffe_id": agent_spiffe_id,
            "tropic01_serial": self.tropic01_serial,
            "delegated_human_sub": delegated_human_sub,
            "intent_hash": intent_hash_header or "",
            "resource": resource,
            "action": method.upper(),
            "status": status,
        }

        try:
            telemetry_queue.put_nowait(record)
        except queue.Full:
            pass  # drop rather than block the request path

        return record

    # ── Private helpers ───────────────────────────────────────────────────

    def _extract_spiffe_id(self, cert_pem: Optional[str]) -> str:
        """Extract the SPIFFE URI SAN from a PEM-encoded X.509 certificate."""
        if not cert_pem:
            return f"spiffe://{self.trust_domain}/unknown"
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for uri in san_ext.value.get_values_for_type(
                x509.UniformResourceIdentifier
            ):
                if uri.startswith("spiffe://"):
                    return uri
        except Exception:
            pass
        return f"spiffe://{self.trust_domain}/unknown"

    def _extract_jwt_sub(self, authorization_header: str) -> str:
        """Decode a Bearer JWT (no signature verification) and return ``sub``."""
        if not authorization_header:
            return "anonymous"
        parts = authorization_header.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return "anonymous"
        try:
            payload_b64 = parts[1].split(".")[1]
            # Restore base64url padding
            padding = (4 - len(payload_b64) % 4) % 4
            payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return str(payload.get("sub", "anonymous"))
        except Exception:
            return "anonymous"

    def _extract_or_generate_trace_id(self, traceparent: str) -> str:
        """Return the W3C trace-id from a traceparent header, or generate one."""
        if traceparent:
            parts = traceparent.strip().split("-")
            if len(parts) >= 2 and len(parts[1]) == 32:
                return parts[1]
        return secrets.token_hex(16)
