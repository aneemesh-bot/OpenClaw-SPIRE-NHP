"""Admin web interface for the SPIRE NHP daemon.

Serves a single-page admin UI on http://127.0.0.1:8080 (default) using only
Python stdlib — http.server, json, urllib.parse.  Zero external packages.

Architecture
────────────
  AdminWebUI          – public API: start() / stop()
  _make_handler(ui)   – factory returning a BaseHTTPRequestHandler subclass
                        closed over the AdminWebUI instance
  GET  /              – serves nhp_daemon/static/index.html
  GET  /api/status    – daemon health snapshot
  GET  /api/svids     – active SVID list
  DELETE /api/svids   – {spiffe_id} → manual SVID revocation
  GET  /api/entries   – registration entry list
  POST /api/entries   – {spiffe_id, parent_id, selectors, ttl, admin} → create
  DELETE /api/entries – {entry_id} → revoke entry (also drops SVID)
  GET  /api/logs      – filtered log query (?level= &component= &event_type=
                        &spiffe_id= &since= &limit= &offset=)
  GET  /api/bundle    – trust bundle / root CA info
  GET  /api/attestor  – endorsement key hash + PCR measurements
  WS   /ws/logs       – WebSocket stream; pushes new log rows as JSON every 500 ms
"""

import base64
import hashlib
import json
import os
import struct
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import config
from .sqlite_logger import LogLevel

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_MAX_BODY = 65_536  # bytes; reject oversized POST/DELETE bodies
_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ── WebSocket helpers ─────────────────────────────────────────────────────

def _ws_accept_key(client_key: str) -> str:
    combined = (client_key.strip() + _WS_MAGIC).encode()
    return base64.b64encode(hashlib.sha1(combined).digest()).decode()


def _ws_send_text(sock, text: str) -> bool:
    """Encode *text* as a WebSocket text frame and write it to *sock*.
    Returns False if the send fails (dead connection)."""
    payload = text.encode("utf-8")
    n = len(payload)
    if n < 126:
        header = bytes([0x81, n])
    elif n < 65536:
        header = struct.pack("!BBH", 0x81, 126, n)
    else:
        header = struct.pack("!BBQ", 0x81, 127, n)
    try:
        sock.sendall(header + payload)
        return True
    except OSError:
        return False


def _ws_recv_frame_opcode(rfile) -> int | None:
    """Read one WebSocket frame, drain its payload, and return the opcode.
    Returns None on EOF or any I/O error (connection closed)."""
    try:
        header = rfile.read(2)
        if len(header) < 2:
            return None
        opcode = header[0] & 0x0F
        masked_len_byte = header[1]
        masked = bool(masked_len_byte & 0x80)
        payload_len = masked_len_byte & 0x7F
        if payload_len == 126:
            ext = rfile.read(2)
            if len(ext) < 2:
                return None
            payload_len = struct.unpack("!H", ext)[0]
        elif payload_len == 127:
            ext = rfile.read(8)
            if len(ext) < 8:
                return None
            payload_len = struct.unpack("!Q", ext)[0]
        to_drain = (4 if masked else 0) + payload_len
        if to_drain:
            rfile.read(to_drain)
        return opcode
    except OSError:
        return None


# ── Helper ────────────────────────────────────────────────────────────────

def _entry_to_dict(e) -> dict:
    return {
        "entry_id": e.entry_id,
        "spiffe_id": e.spiffe_id,
        "parent_id": e.parent_id,
        "selectors": [{"type": s.type, "value": s.value} for s in e.selectors],
        "ttl": e.ttl,
        "admin": e.admin,
        "created_at": e.created_at,
    }


# ── Request handler factory ───────────────────────────────────────────────

def _make_handler(ui: "AdminWebUI"):
    """Return a handler class that carries a reference to *ui*."""

    class _Handler(BaseHTTPRequestHandler):

        def log_message(self, fmt, *args):
            pass  # suppress default stderr access log

        def do_GET(self):
            self._dispatch()

        def do_POST(self):
            self._dispatch()

        def do_DELETE(self):
            self._dispatch()

        # ── routing ──

        def _dispatch(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            qs = parse_qs(parsed.query, keep_blank_values=False)
            try:
                if path == "/" and self.command == "GET":
                    self._serve_file("index.html", "text/html; charset=utf-8")
                elif path == "/style.css" and self.command == "GET":
                    self._serve_file("style.css", "text/css; charset=utf-8")
                elif self.command == "GET" and path.startswith("/api/"):
                    self._handle_get(path[5:], qs)
                elif self.command == "POST" and path.startswith("/api/"):
                    self._handle_post(path[5:])
                elif self.command == "DELETE" and path.startswith("/api/"):
                    self._handle_delete(path[5:])
                elif (path == "/ws/logs" and self.command == "GET"
                      and self.headers.get("Upgrade", "").lower() == "websocket"):
                    self._handle_ws_upgrade()
                else:
                    self._err(404, "not found")
            except Exception as exc:
                self._err(500, str(exc))

        def _handle_get(self, resource: str, qs: dict):
            if resource == "status":
                self._json(ui._api_status())
            elif resource == "svids":
                self._json({"svids": ui._spire_server.list_svids()})
            elif resource == "entries":
                entries = ui._spire_server.registration_store.list_entries()
                self._json({"entries": [_entry_to_dict(e) for e in entries]})
            elif resource == "logs":
                self._json(ui._api_logs(qs))
            elif resource == "bundle":
                self._json(ui._api_bundle())
            elif resource == "attestor":
                self._json(ui._api_attestor())
            else:
                self._err(404, "not found")

        def _handle_post(self, resource: str):
            body = self._read_json_body()
            if resource == "entries":
                self._json(ui._api_create_entry(body))
            else:
                self._err(404, "not found")

        def _handle_delete(self, resource: str):
            body = self._read_json_body()
            if resource == "svids":
                spiffe_id = body.get("spiffe_id", "").strip()
                if not spiffe_id:
                    self._json({"ok": False, "error": "spiffe_id required"})
                    return
                ok = ui._spire_server.revoke_svid(spiffe_id)
                self._json({"ok": ok})
            elif resource == "entries":
                entry_id = body.get("entry_id", "").strip()
                if not entry_id:
                    self._json({"ok": False, "error": "entry_id required"})
                    return
                ok = ui._spire_server.revoke_entry(entry_id)
                self._json({"ok": ok})
            else:
                self._err(404, "not found")

        def _handle_ws_upgrade(self):
            ws_key = self.headers.get("Sec-WebSocket-Key", "").strip()
            if not ws_key:
                self._err(400, "missing Sec-WebSocket-Key")
                return
            accept = _ws_accept_key(ws_key)
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            sock = self.connection
            with ui._ws_lock:
                ui._ws_clients.append(sock)
            try:
                while True:
                    opcode = _ws_recv_frame_opcode(self.rfile)
                    if opcode is None or opcode == 8:  # 8 = connection close
                        break
            except Exception:
                pass
            finally:
                with ui._ws_lock:
                    try:
                        ui._ws_clients.remove(sock)
                    except ValueError:
                        pass

        # ── response helpers ──

        def _serve_file(self, filename: str, content_type: str):
            filepath = os.path.join(_STATIC_DIR, filename)
            try:
                with open(filepath, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                self._err(404, "not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: dict):
            body = json.dumps(data, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _err(self, code: int, msg: str):
            body = json.dumps({"error": msg}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            if length > _MAX_BODY:
                raise ValueError("Request body too large")
            raw = self.rfile.read(length)
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}

    return _Handler


# ── Public API ────────────────────────────────────────────────────────────

class AdminWebUI:
    """Lightweight HTTP admin server for the SPIRE NHP daemon.

    Usage::

        ui = AdminWebUI(spire_server, logger, tpm)
        url = ui.start()          # returns "http://127.0.0.1:8080/"
        ...
        ui.stop()
    """

    def __init__(self, spire_server, logger, tpm):
        self._spire_server = spire_server
        self._logger = logger
        self._tpm = tpm
        self._start_time = time.time()
        self._http_server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        # WebSocket log-stream state
        self._ws_clients: list = []
        self._ws_lock = threading.Lock()
        self._ws_last_ts: float = time.time()

    def start(self, host: str | None = None, port: int | None = None) -> str:
        host = host or config.WEB_UI_HOST
        port = port or config.WEB_UI_PORT
        self._http_server = ThreadingHTTPServer((host, port), _make_handler(self))
        self._thread = threading.Thread(
            target=self._http_server.serve_forever,
            daemon=True,
            name="nhp-admin-web",
        )
        self._thread.start()
        threading.Thread(
            target=self._ws_broadcaster_loop,
            daemon=True,
            name="nhp-ws-broadcast",
        ).start()
        return f"http://{host}:{port}/"

    def stop(self):
        if self._http_server:
            self._http_server.shutdown()
    def _ws_broadcaster_loop(self):
        """Poll the logger every 500 ms and push new rows to all WebSocket clients."""
        while True:
            time.sleep(0.5)
            try:
                rows = self._logger.query_logs(since=self._ws_last_ts, limit=50)
            except Exception:
                continue
            if not rows:
                continue
            self._ws_last_ts = max(r["timestamp"] for r in rows) + 0.001
            payload = json.dumps({"logs": rows}, default=str)
            with self._ws_lock:
                if not self._ws_clients:
                    continue
                dead = []
                for sock in list(self._ws_clients):
                    if not _ws_send_text(sock, payload):
                        dead.append(sock)
                for s in dead:
                    try:
                        self._ws_clients.remove(s)
                    except ValueError:
                        pass
    # ── API data providers ────────────────────────────────────────────────

    def _api_status(self) -> dict:
        ca = self._spire_server.ca
        now = time.time()
        ca_expires_at = ca.root_certificate.not_valid_after_utc.timestamp()
        svids = self._spire_server.list_svids()
        entries = self._spire_server.registration_store.list_entries()
        recent = self._logger.query_logs(since=now - 3600, limit=500)
        warning_plus = sum(
            1 for r in recent if r["level"] in ("WARNING", "ERROR", "CRITICAL")
        )
        return {
            "trust_domain": self._spire_server.trust_domain,
            "hw_mode": "TROPIC01 P-256" if ca._hw is not None else "Software RSA-2048",
            "hw_enabled": ca._hw is not None,
            "uptime_s": int(now - self._start_time),
            "ca_serial": str(ca.root_certificate.serial_number),
            "ca_not_before": ca.root_certificate.not_valid_before_utc.timestamp(),
            "ca_expires_at": ca_expires_at,
            "ca_expires_in_s": int(ca_expires_at - now),
            "svid_count": len(svids),
            "active_svid_count": sum(1 for s in svids if not s["expired"]),
            "entry_count": len(entries),
            "recent_warning_count": warning_plus,
        }

    def _api_logs(self, qs: dict) -> dict:
        def _first(key, default=""):
            vals = qs.get(key)
            return vals[0] if vals else default

        level_str = _first("level")
        component = _first("component") or None
        event_type = _first("event_type") or None
        spiffe_id = _first("spiffe_id") or None
        limit = min(int(_first("limit", "200")), 500)
        offset = int(_first("offset", "0"))
        since_str = _first("since", "0")
        since = float(since_str) if since_str and since_str != "0" else None
        lv = LogLevel(level_str) if level_str else None

        rows = self._logger.query_logs(
            level=lv,
            component=component,
            event_type=event_type,
            spiffe_id=spiffe_id,
            since=since,
            limit=limit,
            offset=offset,
        )
        return {"logs": rows, "count": len(rows)}

    def _api_bundle(self) -> dict:
        b = self._spire_server.trust_bundle
        keys = [k.decode() if isinstance(k, bytes) else k for k in b.active_signing_keys]
        return {
            "trust_domain": b.trust_domain,
            "root_certificate_pem": b.root_certificate_pem.decode(),
            "signing_keys": keys,
            "sequence_number": b.sequence_number,
            "created_at": b.created_at,
            "refresh_interval": b.refresh_interval,
        }

    def _api_attestor(self) -> dict:
        return {
            "endorsement_key_hash": self._tpm.endorsement_key_hash,
            "hw_backed": self._tpm._hw is not None,
            "pcrs": self._tpm._pcrs,
        }

    def _api_create_entry(self, body: dict) -> dict:
        spiffe_id = body.get("spiffe_id", "").strip()
        parent_id = body.get("parent_id", "").strip()
        selectors_raw = body.get("selectors", [])
        ttl = max(1, min(int(body.get("ttl", 300)), config.MAX_SVID_TTL))
        admin = bool(body.get("admin", False))

        if not spiffe_id or not parent_id:
            return {"ok": False, "error": "spiffe_id and parent_id are required"}
        if not spiffe_id.startswith("spiffe://"):
            return {"ok": False, "error": "spiffe_id must start with spiffe://"}
        if not selectors_raw:
            return {"ok": False, "error": "at least one selector is required"}
        try:
            selectors = [(str(s["type"]), str(s["value"])) for s in selectors_raw]
        except (KeyError, TypeError):
            return {"ok": False, "error": "selectors must be a list of {type, value} objects"}

        entry_id = self._spire_server.create_registration_entry(
            spiffe_id=spiffe_id,
            parent_id=parent_id,
            selectors=selectors,
            ttl=ttl,
            admin=admin,
        )
        return {"ok": True, "entry_id": entry_id}
