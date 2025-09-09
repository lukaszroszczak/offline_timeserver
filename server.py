#!/usr/bin/env python3
import json
import logging
import logging.handlers
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone


def setup_logging():
    """Configure application logging.

    Uses environment variables:
    - LOG_LEVEL: DEBUG/INFO/WARNING/ERROR (default: INFO)
    - LOG_FILE: absolute or relative path to a log file (optional)
    - LOG_DIR: directory for log file (if LOG_FILE not provided). File will be LOG_DIR/timeserver.log
    - LOG_MAX_BYTES: rotate size in bytes (default: 1048576)
    - LOG_BACKUP_COUNT: rotated files to keep (default: 5)
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    if root.handlers:
        # Already configured
        root.setLevel(level)
        return

    root.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    root.addHandler(stream)

    log_file = os.environ.get("LOG_FILE")
    if not log_file:
        log_dir = os.environ.get("LOG_DIR")
        if log_dir:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                # Fallback to current directory if mkdir fails
                log_dir = "."
            log_file = os.path.join(log_dir, "timeserver.log")

    if log_file:
        try:
            max_bytes = int(os.environ.get("LOG_MAX_BYTES", "1048576"))
        except ValueError:
            max_bytes = 1048576
        try:
            backup_count = int(os.environ.get("LOG_BACKUP_COUNT", "5"))
        except ValueError:
            backup_count = 5
        rotate = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        rotate.setFormatter(fmt)
        root.addHandler(rotate)


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
    server_version = "offline_timeserver/1.0"

    @property
    def logger(self):
        return logging.getLogger("timeserver.http")

    def log_message(self, fmt, *args):  # reduce noise, route to logging
        try:
            msg = (fmt % args)
        except Exception:
            msg = fmt
        logging.getLogger("timeserver.http").info(
            "%s - %s", self.address_string(), msg
        )

    def log_access(self, status: int, length: int):
        self.logger.info(
            "%s \"%s %s\" %d %d",
            self.client_address[0],
            self.command,
            self.path,
            status,
            length,
        )
    def _set_headers(self, status=200, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 (keep stdlib name)
        try:
            if self.path == "/" or self.path.startswith("/index"):
                self._set_headers(200, "text/html; charset=utf-8")
                body = (
                    "<html><head><title>timeserver</title></head>"
                    "<body>"
                    "<h1>timeserver</h1>"
                    "<p>Użyj endpointu <a href=\"/time\">/time</a> dla JSON.</p>"
                    "</body></html>"
                )
                data = body.encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/time"):
                self._set_headers(200)
                payload = now_payload()
                data = json.dumps(payload).encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            self._set_headers(404)
            data = json.dumps({"error": "Not Found"}).encode("utf-8")
            self.wfile.write(data)
            self.log_access(404, len(data))
        except Exception:
            logging.getLogger("timeserver").exception("Unhandled error servicing request")
            try:
                self._set_headers(500)
                data = json.dumps({"error": "Internal Server Error"}).encode("utf-8")
                self.wfile.write(data)
                self.log_access(500, len(data))
            except Exception:
                pass

    def log_message(self, fmt, *args):  # reduce noise
        sys.stderr.write("%s - - [%s] " % (self.address_string(), self.log_date_time_string()))
        sys.stderr.write((fmt % args) + "\n")


def main():
    setup_logging()
    log = logging.getLogger("timeserver")
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
    log.info("listening on http://%s:%s", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down (KeyboardInterrupt)")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
