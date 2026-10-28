import re
import socket
import struct
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from scanner import (
    CHAIN_CLEANUP_TOKEN,
    CHAIN_SHELL_NAME_RE,
    CHAIN_UPLOAD_MARKER,
    CHAIN_UPLOAD_TOKEN,
    NODEJS_BROTLI_CONTROL_PAYLOAD,
)


@dataclass
class Scenario:
    php: Optional[str] = None
    react: Optional[str] = None
    react_router: Optional[str] = None
    node_passive: bool = False
    node_poc: Optional[str] = None
    nginx: Optional[str] = None


class TargetState:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.requests: List[dict] = []
        self.shells: List[str] = []
        self.lock = threading.Lock()

    def add_shell(self, name: str) -> None:
        with self.lock:
            if name not in self.shells:
                self.shells.append(name)

    def remove_shell(self, name: str) -> None:
        with self.lock:
            if name in self.shells:
                self.shells.remove(name)

    def clear_shells(self) -> None:
        with self.lock:
            self.shells.clear()

    def has_shell(self, name: str) -> bool:
        with self.lock:
            return name in self.shells

    def record(self, method: str, path: str, headers: Dict[str, str], body: bytes) -> None:
        with self.lock:
            self.requests.append(
                {
                    "method": method,
                    "path": path,
                    "headers": dict(headers),
                    "body": body,
                }
            )

    def count(self, method: str, predicate=None) -> int:
        with self.lock:
            matches = [
                item
                for item in self.requests
                if item["method"] == method
                and (predicate is None or predicate(item))
            ]
        return len(matches)

    def matching(self, method: str, predicate=None) -> List[dict]:
        with self.lock:
            return [
                dict(item)
                for item in self.requests
                if item["method"] == method
                and (predicate is None or predicate(item))
            ]


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: TargetState

    def log_message(self, format, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (ConnectionError, OSError):
            pass

    def do_HEAD(self):
        self.state.record("HEAD", self.path, dict(self.headers), b"")
        self._send(200, b"")

    def do_GET(self):
        self.state.record("GET", self.path, dict(self.headers), b"")
        if self._handle_shell_request(b""):
            return
        if self._handle_nginx_probe():
            return

        path = urlsplit(self.path).path
        if path == "/__manifest" and self.state.scenario.react_router:
            self._send(200, self._react_router_manifest())
            return
        self._send(200, self._baseline_body(), self._baseline_headers())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        self.state.record("POST", self.path, dict(self.headers), body)

        if self._handle_shell_request(body):
            return
        if self.state.scenario.php and self._is_php_request():
            self._php_response(body)
            return
        if self.state.scenario.react and self._is_react_payload(body):
            self._react_response(body)
            return
        if self.state.scenario.node_poc and self._is_node_payload():
            self._node_response(body)
            return
        self._send(404, b"not found")

    def _is_php_request(self) -> bool:
        content_type = self.headers.get("Content-Type", "").lower()
        if "multipart/form-data" not in content_type:
            return False
        return (
            content_type.endswith("boundary=x")
            or content_type.endswith("boundary=")
        )

    def _is_react_payload(self, body: bytes) -> bool:
        content_type = self.headers.get("Content-Type", "").lower()
        return "multipart/form-data" in content_type and (
            b"$1:aa:aa" in body
            or b"NEXT_REDIRECT" in body
            or b"41*271" in body
        )

    def _is_node_payload(self) -> bool:
        return (
            self.headers.get("Content-Encoding", "").lower() == "br"
            and "application/json" in self.headers.get("Content-Type", "").lower()
        )

    # --- Rantai webshell (react = rce-upload / rce-fixed) -------------------

    def _handle_shell_request(self, body: bytes) -> bool:
        """Sajikan /poc_shell_<hex8>.php: GET/POST c= dan ?cleanup=."""
        scenario = self.state.scenario.react
        if scenario not in ("rce-upload", "rce-fixed"):
            return False
        parsed = urlsplit(self.path)
        shell_name = parsed.path.rsplit("/", 1)[-1]
        if not CHAIN_SHELL_NAME_RE.fullmatch(shell_name):
            return False
        fields = parse_qs(parsed.query)
        if not fields and body:
            try:
                fields = parse_qs(body.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                fields = {}
        if fields.get("cleanup") == [CHAIN_CLEANUP_TOKEN]:
            self.state.clear_shells()
            self._send(200, b"cleanup ok")
            return True
        if not self.state.has_shell(shell_name):
            self._send(404, b"webshell tidak ada")
            return True
        c_values = fields.get("c")
        if c_values:
            self._send(
                200,
                f"<POC_OUT>{c_values[0]}</POC_OUT>".encode("utf-8"),
            )
            return True
        self._send(200, b"<!-- webshell tersaji -->")
        return True

    def _react_chain_shell_names(self, body: bytes) -> List[str]:
        text = body.decode("utf-8", "replace")
        return [match.group(0) for match in CHAIN_SHELL_NAME_RE.finditer(text)]

    def _react_chain_upload_response(self, body: bytes) -> None:
        scenario = self.state.scenario.react
        names = self._react_chain_shell_names(body)
        if scenario != "rce-upload" or not names:
            self._send(200, b"ok")
            return
        for name in names:
            self.state.add_shell(name)
        self._send(
            200,
            b"ok",
            {
                "X-Action-Redirect":
                f"/login?a={CHAIN_UPLOAD_MARKER}{names[0]};307;"
            },
        )

    def _react_chain_cleanup_response(self, body: bytes) -> None:
        scenario = self.state.scenario.react
        names = self._react_chain_shell_names(body)
        if scenario != "rce-upload":
            self._send(200, b"ok")
            return
        for name in names:
            self.state.remove_shell(name)
        self._send(
            200,
            b"ok",
            {"X-Action-Redirect": f"/login?a={CHAIN_CLEANUP_TOKEN};307;"},
        )

    def _php_response(self, body: bytes) -> None:
        headers = self._php_powered_by()
        if b'Content-Disposition: form-data; name="file"' in body:
            self._send(200, b"valid multipart", headers)
            return
        if b"Content-Disposition:name=a;filename=" in body:
            self._send(200, b"ok", headers)
            return
        if self.state.scenario.php in ("crash", "version"):
            self._send(500, b"", headers)
            return
        self._send(200, b"ok", headers)

    def _php_powered_by(self) -> Dict[str, str]:
        if self.state.scenario.php == "fixed":
            return {"X-Powered-By": "PHP/8.3.36"}
        if self.state.scenario.php == "version":
            return {"X-Powered-By": "PHP/8.3.35"}
        return {}

    def _react_response(self, body: bytes) -> None:
        scenario = self.state.scenario.react
        if CHAIN_UPLOAD_TOKEN.encode() in body:
            self._react_chain_upload_response(body)
            return
        if CHAIN_CLEANUP_TOKEN.encode() in body:
            self._react_chain_cleanup_response(body)
            return
        if b"$1:aa:aa" in body:
            if scenario == "safe-vulnerable":
                self._send(500, b'E{"digest":"NEXT_REDIRECT"}')
            else:
                self._send(400, b"invalid action")
            return
        if b"NEXT_REDIRECT" in body or b"41*271" in body:
            if scenario == "rce-vulnerable":
                self._send(
                    200,
                    b"ok",
                    {"X-Action-Redirect": "/login?a=11111;307;"},
                )
            else:
                self._send(200, b"ok")
            return
        self._send(400, b"invalid action")

    def _node_response(self, body: bytes) -> None:
        if body == NODEJS_BROTLI_CONTROL_PAYLOAD:
            self._send(200, b"ok")
            return
        if self.state.scenario.node_poc == "vulnerable":
            self._send(500, b"ERROR_FORMAT_BLOCK_LENGTH_1")
            return
        self._send(500, b"ERROR_FORMAT_BLOCK_SWITCH")

    def _handle_nginx_probe(self) -> bool:
        scenario = self.state.scenario.nginx
        if scenario not in (
            "poc-vulnerable",
            "poc-patched",
            "poc-blocked",
        ):
            return False

        path = urlsplit(self.path).path
        if not path.startswith("/api/"):
            return False

        if "+" in path:
            if scenario == "poc-vulnerable":
                self._abort_connection()
            else:
                self._send(200, b"probe accepted")
            return True

        if scenario == "poc-blocked":
            self._send(403, b"blocked")
        else:
            self._send(200, b"control accepted")
        return True

    def _baseline_headers(self) -> Dict[str, str]:
        headers = {}
        scenario = self.state.scenario
        if scenario.php:
            headers["Set-Cookie"] = "PHPSESSID=e2e"
            headers.update(self._php_powered_by())
        if scenario.node_passive and "X-Powered-By" not in headers:
            headers["X-Powered-By"] = "Express"
        if scenario.react_router:
            headers["X-React-Router-Version"] = self._react_router_version()
        if scenario.nginx:
            if scenario.nginx == "fixed":
                headers["Server"] = "nginx/1.30.1"
            else:
                headers["Server"] = "nginx/1.30.0"
        return headers

    def _baseline_body(self) -> bytes:
        parts = [b"<html><body>e2e fixture</body></html>"]
        scenario = self.state.scenario
        if scenario.react_router:
            version = self._react_router_version()
            parts.append(
                (
                    f'<script>window.__reactRouterVersion="{version}";'
                    "</script><div id=\"__reactRouterContext\"></div>"
                ).encode("ascii")
            )
        if scenario.node_passive:
            parts.append(b"<footer>Express</footer>")
        return b"".join(parts)

    def _react_router_version(self) -> str:
        return "7.14.2" if self.state.scenario.react_router == "fixed" else "7.14.1"

    def _react_router_manifest(self) -> bytes:
        version = self._react_router_version()
        return (
            f'{{"react-router":"{version}","__reactRouterManifest":true}}'
        ).encode("ascii")

    def _send(self, status: int, body: bytes, headers: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _abort_connection(self) -> None:
        try:
            self.connection.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
            self.connection.close()
        except OSError:
            pass
        self.close_connection = True


def make_handler(state: TargetState):
    class Handler(FixtureHandler):
        pass

    Handler.state = state
    return Handler


class FixtureTarget:
    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.state = TargetState(scenario)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.state)
        )
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
