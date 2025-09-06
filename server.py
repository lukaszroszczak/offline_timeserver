#!/usr/bin/env python3
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone


def now_payload():
    now = datetime.now(timezone.utc)
    iso = now.isoformat().replace("+00:00", "Z")
    epoch_seconds = now.timestamp()
    epoch_millis = int(epoch_seconds * 1000)
    return {
        "iso8601": iso,
        "epoch_seconds": epoch_seconds,
        "epoch_millis": epoch_millis,
        "timezone": "UTC",
    }


class TimeHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 (keep stdlib name)
        if self.path == "/" or self.path.startswith("/index"):
            self._set_headers(200, "text/html; charset=utf-8")
            body = (
                "<html><head><title>timeserver</title></head>"
                "<body>"
                "<h1>timeserver</h1>"
                "<p>Użyj endpointu <a href=\"/time\">/time</a> dla JSON.</p>"
                "</body></html>"
            )
            self.wfile.write(body.encode("utf-8"))
            return

        if self.path.startswith("/time"):
            self._set_headers(200)
            payload = now_payload()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Not Found"}).encode("utf-8"))

    def log_message(self, fmt, *args):  # reduce noise
        sys.stderr.write("%s - - [%s] " % (self.address_string(), self.log_date_time_string()))
        sys.stderr.write((fmt % args) + "\n")


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError:
        port = 8000

    # Allow --host and --port CLI args to override env
    args = sys.argv[1:]
    if "--host" in args:
        try:
            host = args[args.index("--host") + 1]
        except Exception:
            pass
    if "--port" in args:
        try:
            port = int(args[args.index("--port") + 1])
        except Exception:
            pass

    httpd = HTTPServer((host, port), TimeHandler)
    print(f"timeserver listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

