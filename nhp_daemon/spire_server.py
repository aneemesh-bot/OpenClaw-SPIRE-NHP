"""SPIRE Server — the single Root of Trust for all NHP identities.

Manages the Root CA, Trust Bundle, Registration Entries, and SVID
minting / revocation.  All state changes are logged to SQLite.
"""

import concurrent.futures
import json as _json
import threading
import time
import urllib.error as _urllib_err
import urllib.request as _urllib_req

from cryptography.hazmat.primitives import serialization

from . import config
from .ca import CertificateAuthority
from .registration import RegistrationEntry, RegistrationStore, Selector
from .sqlite_logger import SQLiteLogger
from .tropic01_hw import get_tropic01_serial
from .trust_bundle import TrustBundle


class SPIREServer:
    """Single-server SPIRE deployment for NHP identity provisioning."""

    def __init__(self, trust_domain: str, db_path: str, logger: SQLiteLogger, hw=None):
        self.trust_domain = trust_domain
        self.logger = logger
        self._hw = hw
        self.ca = CertificateAuthority(trust_domain, hw=hw)
        self.registration_store = RegistrationStore(db_path)
        self.trust_bundle = self._create_trust_bundle()
        self._issued_svids: dict[str, tuple] = {}  # spiffe_id → (cert, expiry)
        self._lock = threading.Lock()
        self._ledger_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="nhp-ledger"
        )

        mode = "hardware (TROPIC01)" if hw is not None else "software"
        logger.info(
            "spire-server",
            f"Server initialised for domain: {trust_domain} [{mode}]",
            event_type="server_init",
        )

    def _create_trust_bundle(self) -> TrustBundle:
        bundle = TrustBundle(
            trust_domain=self.trust_domain,
            root_certificate=self.ca.root_certificate,
        )
        bundle.add_signing_key(self.ca.public_key_pem)
        return bundle

    # ── Registration ──

    def create_registration_entry(
        self,
        spiffe_id: str,
        parent_id: str,
        selectors: list[tuple[str, str]],
        ttl: int = 300,
        admin: bool = False,
    ) -> str:
        """Register an NHP workload identity.

        *selectors* is a list of ``(type, value)`` tuples,
        e.g. ``[("unix", "uid:1001")]``.
        """
        entry = RegistrationEntry(
            spiffe_id=spiffe_id,
            parent_id=parent_id,
            selectors=[Selector(type=t, value=v) for t, v in selectors],
            ttl=ttl,
            admin=admin,
        )
        entry_id = self.registration_store.create_entry(entry)
        self.logger.info(
            "spire-server",
            f"Registration entry created: {spiffe_id}",
            spiffe_id=spiffe_id,
            event_type="entry_created",
            metadata={"entry_id": entry_id, "ttl": ttl},
        )
        return entry_id

    # ── SVID lifecycle ──

    def mint_svid(self, spiffe_id: str, workload_selectors: list[tuple[str, str]]):
        """Issue an X.509-SVID for a verified workload.

        Returns a dict with PEM-encoded certificate, private key, bundle,
        and expiry — or ``None`` if no matching registration entry exists.
        """
        sel_objs = [Selector(type=t, value=v) for t, v in workload_selectors]
        entries = self.registration_store.find_by_selectors(sel_objs)
        matching = [e for e in entries if e.spiffe_id == spiffe_id]

        if not matching:
            self.logger.warning(
                "spire-server",
                f"No matching entry for {spiffe_id}",
                spiffe_id=spiffe_id,
                event_type="svid_denied",
                metadata={"workload_selectors": workload_selectors},
            )
            return None

        entry = matching[0]
        cert, key = self.ca.sign_svid(spiffe_id, ttl_seconds=entry.ttl)
        expiry = time.time() + entry.ttl

        with self._lock:
            self._issued_svids[spiffe_id] = (cert, expiry)

        self.logger.info(
            "spire-server",
            f"SVID minted for {spiffe_id}",
            spiffe_id=spiffe_id,
            event_type="svid_minted",
            metadata={"ttl": entry.ttl, "serial": str(cert.serial_number)},
        )

        notarization_entry = {
            "timestamp": int(time.time()),
            "svid_serial": str(cert.serial_number),
            "spiffe_id": spiffe_id,
            "hardware_identity_binding": get_tropic01_serial(self._hw),
        }
        self._ledger_pool.submit(self._post_to_ledger, notarization_entry)

        return {
            "spiffe_id": spiffe_id,
            "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "private_key_pem": key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            "bundle_pem": self.trust_bundle.root_certificate_pem.decode(),
            "expires_at": expiry,
            "ttl": entry.ttl,
        }

    def _post_to_ledger(self, entry: dict) -> None:
        """Background worker: POST notarization entry to the immutable ledger.

        Failures are silently swallowed — ledger latency must never stall SVID
        delivery to the calling workload.
        """
        payload = _json.dumps(entry).encode()
        req = _urllib_req.Request(
            config.LEDGER_ENDPOINT,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with _urllib_req.urlopen(req, timeout=3):
                pass
        except Exception:
            pass

    def revoke_entry(self, entry_id: str) -> bool:
        """Emergency revocation — delete registration and cached SVID."""
        entry = self.registration_store.get_entry(entry_id)
        if not entry:
            return False
        self.registration_store.delete_entry(entry_id)
        with self._lock:
            self._issued_svids.pop(entry.spiffe_id, None)
        self.logger.critical(
            "spire-server",
            f"Entry revoked: {entry.spiffe_id}",
            spiffe_id=entry.spiffe_id,
            event_type="entry_revoked",
            metadata={"entry_id": entry_id},
        )
        return True

    def list_svids(self) -> list[dict]:
        """Return a snapshot of all tracked SVIDs with expiry metadata."""
        now = time.time()
        with self._lock:
            snapshot = {sid: expiry for sid, (_, expiry) in self._issued_svids.items()}
        ttl_map = {e.spiffe_id: e.ttl for e in self.registration_store.list_entries()}
        return [
            {
                "spiffe_id": sid,
                "expires_at": expiry,
                "remaining_s": max(0.0, round(expiry - now, 1)),
                "ttl": ttl_map.get(sid, 300),
                "expired": expiry < now,
            }
            for sid, expiry in snapshot.items()
        ]

    def revoke_svid(self, spiffe_id: str) -> bool:
        """Drop a cached SVID without deleting its registration entry.

        The workload will receive a fresh SVID on the next attestation cycle.
        """
        with self._lock:
            if spiffe_id not in self._issued_svids:
                return False
            del self._issued_svids[spiffe_id]
        self.logger.warning(
            "spire-server",
            f"SVID manually revoked by admin: {spiffe_id}",
            spiffe_id=spiffe_id,
            event_type="svid_revoked",
        )
        return True

    def is_svid_valid(self, spiffe_id: str) -> bool:
        """Check whether a previously issued SVID is still within TTL."""
        with self._lock:
            if spiffe_id not in self._issued_svids:
                return False
            _, expiry = self._issued_svids[spiffe_id]
            return time.time() < expiry

    # ── Bundle access ──

    def get_trust_bundle(self) -> dict:
        return self.trust_bundle.to_dict()
