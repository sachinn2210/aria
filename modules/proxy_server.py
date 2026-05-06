"""
ARIA – Reverse Proxy Server
Forwards HTTP requests to a target URL and writes Apache Combined Log Format
entries to a log file that ARIA's LogWatcher picks up automatically.

Usage:
    Start via the ARIA dashboard "Live Proxy" panel, or directly:
        python -m modules.proxy_server --target https://example.com --port 8888
"""

import os
import re
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_PROXY_PORT = int(os.getenv("ARIA_PROXY_PORT", "8888"))
DEFAULT_LOG_FILE   = os.getenv("ARIA_PROXY_LOG", "logs/proxy_access.log")

os.makedirs("logs", exist_ok=True)

# Shared state
_proxy_state = {
    "running":    False,
    "target":     "",
    "port":       DEFAULT_PROXY_PORT,
    "log_file":   DEFAULT_LOG_FILE,
    "requests":   0,
    "errors":     0,
    "server":     None,
    "thread":     None,
    "started_at": None,
}
_state_lock = threading.Lock()


# ── Log writer ─────────────────────────────────────────────────────────────────

def _write_log(client_ip: str, method: str, path: str,
               status: int, size: int, referer: str = "-",
               user_agent: str = "-"):
    """Write one Apache Combined Log Format line."""
    now = datetime.now(timezone.utc)
    ts  = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = (
        f'{client_ip} - - [{ts}] '
        f'"{method} {path} HTTP/1.1" '
        f'{status} {size} '
        f'"{referer}" "{user_agent}"'
    )
    log_path = _proxy_state["log_file"]
    try:
        with open(log_path, "a") as f:
            f.write(line + "\n")
            f.flush()
    except Exception as e:
        print(f"[ARIA/Proxy] Log write failed: {e}")
    return line


# ── Request handler ────────────────────────────────────────────────────────────

class ProxyHandler(BaseHTTPRequestHandler):
    """Transparent HTTP reverse proxy that logs every transaction."""

    def log_message(self, format, *args):
        pass  # suppress default stderr output

    def _forward(self, body: Optional[bytes] = None):
        target  = _proxy_state["target"].rstrip("/")
        path    = self.path
        url     = target + path

        client_ip  = self.client_address[0]
        method     = self.command
        referer    = self.headers.get("Referer", "-")
        user_agent = self.headers.get("User-Agent", "-")

        # Build forwarding headers (strip hop-by-hop)
        forward_headers = {}
        hop_by_hop = {
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers",
            "transfer-encoding", "upgrade", "host",
        }
        for k, v in self.headers.items():
            if k.lower() not in hop_by_hop:
                forward_headers[k] = v

        # Try to parse target host for Host header
        try:
            parsed = urllib.parse.urlparse(target)
            forward_headers["Host"] = parsed.netloc
        except Exception:
            pass

        status, size = 502, 0
        try:
            req = urllib.request.Request(
                url, data=body, headers=forward_headers, method=method
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                status      = resp.status
                resp_body   = resp.read()
                size        = len(resp_body)
                resp_headers = dict(resp.headers)

                self.send_response(status)
                skip = {
                    "transfer-encoding", "connection",
                    "keep-alive", "content-encoding",
                }
                for k, v in resp_headers.items():
                    if k.lower() not in skip:
                        try:
                            self.send_header(k, v)
                        except Exception:
                            pass
                self.send_header("Content-Length", str(size))
                self.end_headers()
                self.wfile.write(resp_body)

        except urllib.error.HTTPError as e:
            status    = e.code
            err_body  = e.read()
            size      = len(err_body)
            self.send_response(status)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            self.wfile.write(err_body)

        except Exception as e:
            status = 502
            msg    = f"ARIA Proxy Error: {e}".encode()
            size   = len(msg)
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            self.wfile.write(msg)
            with _state_lock:
                _proxy_state["errors"] += 1

        _write_log(client_ip, method, path, status, size, referer, user_agent)
        with _state_lock:
            _proxy_state["requests"] += 1

        print(f"[ARIA/Proxy] {method} {path} → {status} ({size}B) [{client_ip}]")

    def do_GET(self):    self._forward()
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self._forward(self.rfile.read(length) if length else None)
    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0))
        self._forward(self.rfile.read(length) if length else None)
    def do_DELETE(self): self._forward()
    def do_HEAD(self):   self._forward()
    def do_OPTIONS(self): self._forward()
    def do_PATCH(self):
        length = int(self.headers.get("Content-Length", 0))
        self._forward(self.rfile.read(length) if length else None)


# ── Public API ─────────────────────────────────────────────────────────────────

def start_proxy(target_url: str, port: int = DEFAULT_PROXY_PORT,
                log_file: str = DEFAULT_LOG_FILE) -> dict:
    """Start the proxy server. Returns state dict."""
    with _state_lock:
        if _proxy_state["running"]:
            return {"ok": False, "error": "Proxy already running"}

        # Normalise target
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        _proxy_state.update({
            "target":     target_url,
            "port":       port,
            "log_file":   log_file,
            "requests":   0,
            "errors":     0,
            "started_at": datetime.utcnow().isoformat(),
        })

    try:
        server = HTTPServer(("0.0.0.0", port), ProxyHandler)
        server.timeout = 1.0

        def _serve():
            with _state_lock:
                _proxy_state["running"] = True
                _proxy_state["server"]  = server
            print(f"[ARIA/Proxy] Started → proxying {target_url} on :{port}")
            try:
                server.serve_forever()
            finally:
                with _state_lock:
                    _proxy_state["running"] = False
                    _proxy_state["server"]  = None
                print("[ARIA/Proxy] Server stopped.")

        t = threading.Thread(target=_serve, daemon=True, name="aria-proxy")
        t.start()
        with _state_lock:
            _proxy_state["thread"] = t

        time.sleep(0.3)  # let server bind
        return {"ok": True, "port": port, "target": target_url}

    except Exception as e:
        with _state_lock:
            _proxy_state["running"] = False
        return {"ok": False, "error": str(e)}


def stop_proxy() -> dict:
    """Stop the running proxy server."""
    with _state_lock:
        server = _proxy_state.get("server")
        if not server:
            return {"ok": False, "error": "No proxy running"}

    threading.Thread(target=server.shutdown, daemon=True).start()
    return {"ok": True}


def proxy_status() -> dict:
    with _state_lock:
        return {
            "running":    _proxy_state["running"],
            "target":     _proxy_state["target"],
            "port":       _proxy_state["port"],
            "log_file":   _proxy_state["log_file"],
            "requests":   _proxy_state["requests"],
            "errors":     _proxy_state["errors"],
            "started_at": _proxy_state["started_at"],
        }


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ARIA Reverse Proxy")
    ap.add_argument("--target", required=True, help="Target URL (e.g. https://example.com)")
    ap.add_argument("--port",   type=int, default=DEFAULT_PROXY_PORT)
    ap.add_argument("--log",    default=DEFAULT_LOG_FILE)
    args = ap.parse_args()

    result = start_proxy(args.target, args.port, args.log)
    if not result["ok"]:
        print(f"[ARIA/Proxy] Failed to start: {result['error']}")
    else:
        print(f"[ARIA/Proxy] Listening on http://localhost:{args.port}")
        print(f"[ARIA/Proxy] Forwarding to  {args.target}")
        print(f"[ARIA/Proxy] Logging to      {args.log}")
        print("[ARIA/Proxy] Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_proxy()
            print("\n[ARIA/Proxy] Stopped.")