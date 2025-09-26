import json
import socket
import threading
import time
from http.client import HTTPConnection

import server as srv


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    addr, port = s.getsockname()
    s.close()
    return port


def test_now_payload_fields():
    p = srv.now_payload()
    assert "iso8601" in p and p["timezone"] == "UTC"
    assert isinstance(p["epoch_millis"], int)


def test_parse_tracking_sample():
    sample = """
Reference ID    : 47505300 (GPS)
Stratum         : 1
Ref time (UTC)  : Mon Sep 09 10:10:10 2024
System time     : 0.000000001 seconds fast of NTP time
Root delay      : 0.000000001 seconds
Last offset     : -0.025 seconds
RMS offset      : 0.030 seconds
""".strip()
    d = srv.parse_tracking(sample)
    assert d.get("Stratum") == "1"
    assert "Last offset" in d


def test_session_cookie_roundtrip():
    cookie = srv.make_session_cookie("tester", ttl_seconds=5)
    user = srv.parse_session_cookie(cookie)
    assert user == "tester"


def test_http_time_endpoint():
    # start server on a free port
    port = _free_port()
    httpd = srv.HTTPServer(("127.0.0.1", port), srv.TimeHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        time.sleep(0.1)
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", "/time")
        resp = conn.getresponse()
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["timezone"] == "UTC"
    finally:
        httpd.shutdown()
        httpd.server_close()

