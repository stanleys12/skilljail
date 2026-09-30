"""Egress proxy: the only network path out of a jail.

The sandbox profile permits exactly one outbound destination — ``127.0.0.1:<port>`` —
where this proxy listens. The proxy enforces the manifest's ``net.allow`` rules by
*destination*, so we never need to see inside TLS.

Supported: absolute-URI HTTP (``GET http://host/…``) and ``CONNECT host:port``.
Denied requests get ``403`` + ``X-SkillJail-Blocked: <reason>`` and an audit line.

Modes:
  enforce — allowed hosts are dialed; everything else is 403.
  sink    — nothing is dialed. Every request is recorded and answered 200 (plain HTTP)
            or the CONNECT is acknowledged and the client's first bytes are captured
            then the socket closed. Used by the evaluation harness so malware can be
            *observed* attempting exfiltration without ever reaching the internet.

SSRF guard: resolved addresses in loopback / link-local / RFC1918 / CGNAT / metadata /
ULA ranges are denied unless ``allow_private`` is set.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .manifest import validate_net_rule

DEFAULT_PORTS = (80, 443)
_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10", "::ffff:0:0/96",
    )
]


@dataclass(frozen=True)
class NetRule:
    host: str  # "*", "example.com", "*.example.com", ip literal
    port: int | None  # None → default ports, -1 → any

    @classmethod
    def parse(cls, rule: str) -> "NetRule":
        host, port = validate_net_rule(rule)
        return cls(host=host, port=port)

    def matches(self, host: str, port: int) -> bool:
        host = host.lower().rstrip(".")
        if self.host == "*":
            host_ok = True
        elif self.host.startswith("*."):
            suffix = self.host[1:]  # ".example.com"
            host_ok = host.endswith(suffix) and host != suffix[1:]
        else:
            host_ok = host == self.host
        if not host_ok:
            return False
        if self.port is None:
            return port in DEFAULT_PORTS
        if self.port == -1:
            return True
        return port == self.port

    def __str__(self) -> str:
        if self.port is None:
            return self.host
        return f"{self.host}:{'*' if self.port == -1 else self.port}"


@dataclass
class NetPolicy:
    rules: list[NetRule] = field(default_factory=list)
    allow_private: bool = False

    @classmethod
    def from_rules(cls, rules: list[str], allow_private: bool = False) -> "NetPolicy":
        return cls(rules=[NetRule.parse(r) for r in rules], allow_private=allow_private)

    def match(self, host: str, port: int) -> NetRule | None:
        for r in self.rules:
            if r.matches(host, port):
                return r
        return None


def is_private_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in n for n in _PRIVATE_NETS)


@dataclass
class ProxyEvent:
    ts: float
    method: str  # "CONNECT" | "GET" | ...
    host: str
    port: int
    decision: str  # "allow" | "deny" | "sink"
    reason: str
    bytes_up: int = 0
    bytes_down: int = 0
    url: str | None = None
    resolved: list[str] = field(default_factory=list)
    preview: str | None = None  # first bytes of a sunk request (redacted length-limited)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False)


class EgressProxy:
    """Runs an asyncio proxy in a background thread; ``start()`` returns the bound port."""

    def __init__(
        self,
        policy: NetPolicy,
        on_event: Callable[[ProxyEvent], None] | None = None,
        mode: str = "enforce",
        host: str = "127.0.0.1",
        port: int = 0,
        connect_timeout: float = 10.0,
        idle_timeout: float = 120.0,
        dial: bool = True,
    ):
        if mode not in ("enforce", "sink"):
            raise ValueError("mode must be 'enforce' or 'sink'")
        self.policy = policy
        self.mode = mode
        # dial=False (eval only): evaluate allow/deny exactly like enforce, but SINK 'allow'
        # decisions instead of dialing upstream — so the harness never touches the real network.
        self.dial = dial
        self.on_event = on_event or (lambda e: None)
        self.bind_host = host
        self.bind_port = port
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.events: list[ProxyEvent] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self.port: int = 0

    # ------------------------------------------------------------- lifecycle
    def start(self) -> int:
        self._thread = threading.Thread(target=self._run, name="skilljail-proxy", daemon=True)
        self._thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("proxy failed to start")
        return self.port

    def stop(self) -> None:
        if self._loop and self._server:
            loop = self._loop

            async def _shutdown():
                self._server.close()
                await self._server.wait_closed()

            fut = asyncio.run_coroutine_threadsafe(_shutdown(), loop)
            try:
                fut.result(5)
            except Exception:
                pass
            loop.call_soon_threadsafe(loop.stop)
        if self._thread:
            self._thread.join(5)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        server = loop.run_until_complete(
            asyncio.start_server(self._handle, self.bind_host, self.bind_port, reuse_address=True)
        )
        self._server = server
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    # -------------------------------------------------------------- helpers
    def _emit(self, ev: ProxyEvent) -> None:
        self.events.append(ev)
        try:
            self.on_event(ev)
        except Exception:
            pass

    async def _resolve(self, host: str) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), self.connect_timeout)
        except Exception:
            return []
        return sorted({i[4][0] for i in infos})

    async def _decide(self, method: str, host: str, port: int) -> tuple[str, str, list[str]]:
        """Return (decision, reason, resolved)."""
        rule = self.policy.match(host, port)
        if self.mode == "sink":
            return "sink", f"sink-mode ({'would allow: ' + str(rule) if rule else 'would deny: no rule'})", []
        if rule is None:
            return "deny", f"no net.allow rule matches {host}:{port}", []
        if not self.dial:
            return "sink", f"allowed by rule {rule} (sunk: eval no-dial)", []
        resolved = await self._resolve(host)
        if not resolved:
            return "deny", f"could not resolve {host}", []
        if not self.policy.allow_private:
            priv = [a for a in resolved if is_private_address(a)]
            if priv:
                return "deny", f"{host} resolves to private/link-local/metadata address {priv[0]}", resolved
        return "allow", f"matched rule {rule}", resolved

    @staticmethod
    def _http_response(code: int, reason: str, headers: dict[str, str] | None = None, body: bytes = b"") -> bytes:
        h = {"Content-Length": str(len(body)), "Connection": "close", "Proxy-Agent": "skilljail"}
        if headers:
            h.update(headers)
        head = f"HTTP/1.1 {code} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
        return head.encode() + body

    async def _pipe(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> int:
        n = 0
        try:
            while True:
                data = await asyncio.wait_for(r.read(65536), self.idle_timeout)
                if not data:
                    break
                n += len(data)
                w.write(data)
                await w.drain()
        except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass
        return n

    # --------------------------------------------------------------- handler
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                writer.close()
                return
            lines = head.decode("latin-1").split("\r\n")
            request_line = lines[0]
            parts = request_line.split(" ")
            if len(parts) < 2:
                writer.write(self._http_response(400, "Bad Request"))
                await writer.drain()
                writer.close()
                return
            method, target = parts[0].upper(), parts[1]
            headers: dict[str, str] = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if method == "CONNECT":
                host, _, port_s = target.rpartition(":")
                host = host.strip("[]")
                port = int(port_s) if port_s.isdigit() else 443
                url = None
            else:
                # absolute-URI proxying: METHOD http://host[:port]/path
                if "://" in target:
                    scheme, rest = target.split("://", 1)
                    hostport, _, path = rest.partition("/")
                    path = "/" + path
                else:
                    hostport = headers.get("host", "")
                    path = target
                    scheme = "http"
                if hostport.startswith("["):
                    host, _, port_s = hostport[1:].partition("]:")
                else:
                    host, _, port_s = hostport.partition(":")
                port = int(port_s) if port_s.isdigit() else (443 if scheme == "https" else 80)
                url = f"{scheme}://{hostport}{path}"

            ev = ProxyEvent(ts=time.time(), method=method, host=host, port=port, decision="", reason="", url=url)
            decision, reason, resolved = await self._decide(method, host, port)
            ev.decision, ev.reason, ev.resolved = decision, reason, resolved

            if decision == "deny":
                writer.write(self._http_response(403, "Forbidden", {"X-SkillJail-Blocked": reason}, b"blocked by skilljail\n"))
                await writer.drain()
                writer.close()
                self._emit(ev)
                return

            if decision == "sink":
                await self._sink(method, headers, reader, writer, ev)
                self._emit(ev)
                return

            # allow → dial upstream
            try:
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(resolved[0], port), self.connect_timeout)
            except Exception as e:
                ev.reason += f"; upstream connect failed: {e.__class__.__name__}"
                writer.write(self._http_response(502, "Bad Gateway", {"X-SkillJail-Upstream": "connect-failed"}))
                await writer.drain()
                writer.close()
                self._emit(ev)
                return

            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: skilljail\r\n\r\n")
                await writer.drain()
            else:
                # forward the request with a relative path and hop-by-hop headers stripped
                req_lines = [f"{method} {path} HTTP/1.1"]
                for ln in lines[1:]:
                    if ln.lower().startswith(("proxy-connection:", "proxy-authorization:")):
                        continue
                    req_lines.append(ln)
                up_w.write(("\r\n".join(req_lines) + "\r\n\r\n").encode("latin-1"))
                await up_w.drain()

            up_task = asyncio.create_task(self._pipe(reader, up_w))
            down_task = asyncio.create_task(self._pipe(up_r, writer))
            ev.bytes_up, ev.bytes_down = await asyncio.gather(up_task, down_task)
            self._emit(ev)
        except Exception as e:  # never let a handler crash the server
            try:
                writer.write(self._http_response(500, "Proxy Error", body=str(e).encode()))
                await writer.drain()
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

    async def _sink(self, method, headers, reader, writer, ev: ProxyEvent) -> None:
        """Record the attempt, never dial out."""
        if method == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: skilljail-sink\r\n\r\n")
            await writer.drain()
            try:
                first = await asyncio.wait_for(reader.read(4096), 3)
            except (asyncio.TimeoutError, ConnectionError):
                first = b""
            ev.bytes_up = len(first)
            ev.preview = _preview(first)
            writer.close()
            return
        body = b""
        n = int(headers.get("content-length", "0") or 0)
        if n > 0:
            try:
                body = await asyncio.wait_for(reader.readexactly(min(n, 1_000_000)), 10)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                body = b""
        ev.bytes_up = len(body)
        ev.preview = _preview(body)
        writer.write(self._http_response(200, "OK", {"Content-Type": "application/json", "X-SkillJail-Sink": "1"}, b'{"ok":true}'))
        await writer.drain()
        writer.close()


def _preview(data: bytes, limit: int = 240) -> str | None:
    if not data:
        return None
    if data[:1] == b"\x16":  # TLS record — don't pretend it is text
        return f"<tls-client-hello {len(data)}B>"
    txt = data[:limit].decode("utf-8", errors="replace")
    return txt + ("…" if len(data) > limit else "")


def proxy_env(port: int, host: str = "127.0.0.1") -> dict[str, str]:
    """Environment variables that point well-behaved tools at the proxy."""
    url = f"http://{host}:{port}"
    return {
        "HTTP_PROXY": url, "HTTPS_PROXY": url, "ALL_PROXY": url,
        "http_proxy": url, "https_proxy": url, "all_proxy": url,
        "NO_PROXY": "", "no_proxy": "",
        # tools that need an explicit proxy variable
        "GIT_HTTP_PROXY": url, "npm_config_proxy": url, "npm_config_https_proxy": url,
        "PIP_PROXY": url, "GLOBAL_AGENT_HTTP_PROXY": url,
    }


if __name__ == "__main__":  # manual smoke test: python -m skilljail.proxy example.com
    import sys

    rules = sys.argv[1:] or ["example.com"]
    p = EgressProxy(NetPolicy.from_rules(rules), on_event=lambda e: print(e.to_json()))
    port = p.start()
    print(f"listening on 127.0.0.1:{port}  rules={rules}", file=sys.stderr)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        p.stop()
