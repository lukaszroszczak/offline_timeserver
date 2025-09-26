#!/usr/bin/env python3
import base64
import hmac
import hashlib
import json
import logging
import logging.handlers
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone
from datetime import timedelta
from urllib.parse import parse_qs
import subprocess
import shlex
from typing import Dict, Any, Optional, Tuple, List
import ipaddress


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


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _run(cmd: str, timeout: int = 2) -> Tuple[int, str, str]:
    """Run a shell command safely (no shell=True), return (code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return 127, "", str(e)


_CACHED_SECRET = None

def cookie_secret() -> bytes:
    """Return the secret key used to sign cookies.

    Uses SECRET_KEY env var or generates a process-local random key.
    """
    global _CACHED_SECRET
    if _CACHED_SECRET is not None:
        return _CACHED_SECRET
    
    secret = os.environ.get("SECRET_KEY")
    if secret:
        _CACHED_SECRET = _b(secret)
    else:
        # ephemeral secret each run (dev fallback)
        _CACHED_SECRET = os.urandom(32)
    return _CACHED_SECRET


def sign_value(value: str, secret: Optional[bytes] = None) -> str:
    key = secret or cookie_secret()
    mac = hmac.new(key, _b(value), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")


def make_session_cookie(username: str, ttl_seconds: int = 3600) -> str:
    """Create a signed session value: base64(username)|expiry|sig"""
    exp = int((datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).timestamp())
    u = base64.urlsafe_b64encode(_b(username)).decode("ascii").rstrip("=")
    payload = f"{u}|{exp}"
    sig = sign_value(payload)
    return f"{payload}|{sig}"


def parse_session_cookie(cookie: str) -> Optional[str]:
    try:
        parts = cookie.split("|")
        if len(parts) != 3:
            return None
        u_b64, exp_s, sig = parts
        payload = f"{u_b64}|{exp_s}"
        if not hmac.compare_digest(sign_value(payload), sig):
            return None
        exp = int(exp_s)
        if exp < int(datetime.now(timezone.utc).timestamp()):
            return None
        # decode username
        pad = '=' * (-len(u_b64) % 4)
        username = base64.urlsafe_b64decode(u_b64 + pad).decode("utf-8")
        return username
    except Exception:
        return None


def read_body(handler: "TimeHandler") -> bytes:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0
    if length <= 0:
        return b""
    return handler.rfile.read(length)


def parse_form_urlencoded(body: bytes) -> Dict[str, str]:
    try:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except Exception:
        return {}
    return {k: v[0] for k, v in parsed.items()}


def get_gps_status() -> Dict[str, Any]:
    """Return GPS status via gpspipe if available.

    Attempts JSON output (-w). Falls back to raw NMEA presence check.
    """
    status: Dict[str, Any] = {"available": False, "fix": None, "sats": None, "mode": None, "lat": None, "lon": None}
    code, out, _ = _run("gpspipe -w -n 10", timeout=3)
    if code == 0 and out:
        tpv = None
        sky = None
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            cls = obj.get("class")
            if cls == "TPV":
                tpv = obj
            elif cls == "SKY":
                sky = obj
        if tpv:
            status["available"] = True
            status["mode"] = tpv.get("mode")  # 2 or 3 when fix
            status["fix"] = tpv.get("time")
            status["lat"] = tpv.get("lat")
            status["lon"] = tpv.get("lon")
        if sky:
            status["sats"] = len(sky.get("satellites", []))
        return status

    # Fallback to raw NMEA
    code, out, _ = _run("gpspipe -r -n 5", timeout=3)
    if code == 0 and out and any(l.startswith("$GP") or l.startswith("$GN") for l in out.splitlines()):
        status["available"] = True
    return status


def parse_tracking(text: str) -> Dict[str, Any]:
    """Parse chronyc tracking output into a dictionary."""
    data: Dict[str, Any] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def get_ntp_status() -> Dict[str, Any]:
    code, out, err = _run("chronyc tracking", timeout=2)
    status: Dict[str, Any] = {"available": code == 0}
    if code == 0:
        status.update(parse_tracking(out))
    else:
        status["error"] = err
    code2, out2, _ = _run("chronyc sources -v", timeout=2)
    if code2 == 0:
        status["sources"] = out2
    return status


def nmcli_available() -> bool:
    return _run("nmcli -t -f GENERAL.STATE nm", timeout=2)[0] == 0


def _guess_iface_type(name: str) -> str:
    """Best-effort guess of interface type from its name.

    Returns one of: 'wifi', 'ethernet', 'loopback', or 'other'.
    """
    n = name.lower()
    if n in ("lo", "loopback"):
        return "loopback"
    if n.startswith("wl") or "wlan" in n:
        return "wifi"
    if n.startswith("en") or n.startswith("eth") or n.startswith("end"):
        return "ethernet"
    return "other"


def _parse_ip_brief(text: str) -> list[Dict[str, Any]]:
    """Parse output of `ip -brief addr` into interface summaries compatible with UI.

    Produces entries with keys: ifname, type, state, connection (IP if known).
    """
    interfaces: list[Dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ifname = parts[0]
        state = parts[1]
        remainder = " ".join(parts[2:]) if len(parts) > 2 else ""

        # Extract first IPv4 address if present
        ip4 = None
        for token in remainder.replace("\t", " ").split():
            if token.count(".") == 3 and "/" in token:
                # very rough IPv4/len match
                ip4 = token
                break

        iface_type = _guess_iface_type(ifname)
        # Consider connected if interface is up and has an IPv4 assigned
        connected = (state.upper() in ("UP", "UNKNOWN") and ip4 is not None and iface_type != "loopback")

        interfaces.append({
            "ifname": ifname,
            "type": iface_type,
            "state": "connected" if connected else ("disconnected" if state.upper() == "DOWN" else state.lower()),
            "connection": ip4 or "--",
        })
    return interfaces


def get_network_status() -> Dict[str, Any]:
    """Collect network status for the admin panel.

    Uses NetworkManager (`nmcli`) when available. Falls back to `ip -brief addr`
    parsing on systems without NM, so the dashboard can still indicate Ethernet
    connectivity.
    """
    status: Dict[str, Any] = {"nmcli": nmcli_available(), "interfaces": []}
    if status["nmcli"]:
        code, out, _ = _run("nmcli -t device status", timeout=2)
        if code == 0:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 4:
                    status["interfaces"].append({
                        "ifname": parts[0],
                        "type": parts[1],
                        "state": parts[2],
                        "connection": parts[3],
                    })
        code, out, _ = _run("nmcli -t -f IP4.ADDRESS,GENERAL.CONNECTION device show", timeout=2)
        status["ip_info_raw"] = out if code == 0 else None
    else:
        code, out, _ = _run("ip -brief addr", timeout=2)
        if code == 0 and out:
            status["interfaces"] = _parse_ip_brief(out)
        status["ip_brief"] = out if code == 0 else None
    return status


def apply_wifi_settings(ssid: str, psk: str) -> Tuple[bool, str]:
    """Connect or update Wi-Fi using nmcli. Returns (ok, msg)."""
    if not nmcli_available():
        return False, "nmcli not available"
    if not ssid:
        return False, "SSID required"
    # Do not log PSK
    code, out, err = _run(f"nmcli dev wifi connect {shlex.quote(ssid)} password {shlex.quote(psk)}", timeout=10)
    if code == 0:
        return True, out or "connected"
    return False, err or out or "failed"


def get_ssh_status() -> Dict[str, Any]:
    """Get SSH service status."""
    code, out, _ = _run("systemctl is-active ssh", timeout=2)
    active = code == 0 and out.strip() == "active"
    code2, out2, _ = _run("systemctl is-enabled ssh", timeout=2)
    enabled = code2 == 0 and out2.strip() == "enabled"
    return {"active": active, "enabled": enabled}


def control_ssh_service(action: str) -> Tuple[bool, str]:
    """Control SSH service. Actions: start, stop, enable, disable."""
    if action not in ["start", "stop", "enable", "disable"]:
        return False, "Invalid action"
    code, out, err = _run(f"systemctl {action} ssh", timeout=5)
    if code == 0:
        return True, f"SSH {action} successful"
    return False, err or out or f"Failed to {action} SSH"


def change_admin_password(new_password: str) -> Tuple[bool, str]:
    """Change admin password by updating environment file."""
    env_file = "/etc/default/offline_timeserver"
    if not new_password or len(new_password) < 4:
        return False, "Password must be at least 4 characters"
    
    try:
        # Read existing config
        config_lines = []
        admin_user = _env_str("ADMIN_USER", "admin")
        secret_key = _env_str("SECRET_KEY", "")
        
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                config_lines = f.readlines()
        
        # Update or add password line
        updated = False
        for i, line in enumerate(config_lines):
            if line.strip().startswith('ADMIN_PASS='):
                config_lines[i] = f'ADMIN_PASS={new_password}\n'
                updated = True
                break
        
        if not updated:
            config_lines.append(f'ADMIN_PASS={new_password}\n')
        
        # Ensure other required vars exist
        has_user = any(line.strip().startswith('ADMIN_USER=') for line in config_lines)
        has_secret = any(line.strip().startswith('SECRET_KEY=') for line in config_lines)
        
        if not has_user:
            config_lines.append(f'ADMIN_USER={admin_user}\n')
        if not has_secret and secret_key:
            config_lines.append(f'SECRET_KEY={secret_key}\n')
        
        # Write config file
        with open(env_file, 'w') as f:
            f.writelines(config_lines)
        
        return True, "Password updated (restart required)"
    except Exception as e:
        return False, f"Failed to update password: {str(e)}"


def get_system_info() -> Dict[str, Any]:
    """Get system information."""
    info = {}
    
    # Hostname
    code, out, _ = _run("hostname", timeout=2)
    info["hostname"] = out if code == 0 else "unknown"
    
    # Uptime
    code, out, _ = _run("uptime -p", timeout=2)
    info["uptime"] = out if code == 0 else "unknown"
    
    # Load average
    code, out, _ = _run("uptime", timeout=2)
    if code == 0 and "load average:" in out:
        load_part = out.split("load average:")[1].strip()
        info["load"] = load_part
    else:
        info["load"] = "unknown"
    
    # Memory info
    code, out, _ = _run("free -h", timeout=2)
    info["memory"] = out if code == 0 else "unknown"
    
    # Disk usage
    code, out, _ = _run("df -h /", timeout=2)
    info["disk"] = out if code == 0 else "unknown"
    
    return info


def scan_wifi_networks() -> List[Dict[str, Any]]:
    """Scan for available Wi-Fi networks."""
    networks = []
    if not nmcli_available():
        return networks
    
    code, out, _ = _run("nmcli -t -f SSID,SIGNAL,SECURITY device wifi list", timeout=10)
    if code == 0:
        for line in out.splitlines():
            parts = line.split(':')
            if len(parts) >= 3:
                ssid = parts[0]
                if ssid and ssid != "--":
                    networks.append({
                        "ssid": ssid,
                        "signal": parts[1],
                        "security": parts[2] if parts[2] else "Open"
                    })
    
    return networks[:20]  # Limit to 20 networks


def get_ethernet_config() -> Dict[str, Any]:
    """Get current ethernet configuration."""
    config = {"available": False, "interface": None, "method": "unknown", "ip": None, "gateway": None, "dns": []}
    
    if not nmcli_available():
        return config
    
    # Find ethernet interface
    code, out, _ = _run("nmcli -t -f DEVICE,TYPE,STATE connection show --active", timeout=3)
    if code == 0:
        for line in out.splitlines():
            parts = line.split(':')
            if len(parts) >= 3 and parts[1] == "ethernet" and parts[2] == "activated":
                config["interface"] = parts[0]
                config["available"] = True
                break
    
    if not config["interface"]:
        # Try to find any ethernet device
        code, out, _ = _run("nmcli -t -f DEVICE,TYPE device status", timeout=3)
        if code == 0:
            for line in out.splitlines():
                parts = line.split(':')
                if len(parts) >= 2 and parts[1] == "ethernet":
                    config["interface"] = parts[0]
                    config["available"] = True
                    break
    
    if config["interface"]:
        # Get detailed configuration
        code, out, _ = _run(f"nmcli -t -f ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns connection show {config['interface']}", timeout=3)
        if code == 0:
            for line in out.splitlines():
                if line.startswith('ipv4.method:'):
                    config["method"] = line.split(':', 1)[1]
                elif line.startswith('ipv4.addresses:'):
                    addr = line.split(':', 1)[1]
                    if addr and addr != '--':
                        config["ip"] = addr
                elif line.startswith('ipv4.gateway:'):
                    gw = line.split(':', 1)[1]
                    if gw and gw != '--':
                        config["gateway"] = gw
                elif line.startswith('ipv4.dns:'):
                    dns = line.split(':', 1)[1]
                    if dns and dns != '--':
                        config["dns"] = dns.split(',')
    
    return config


def configure_ethernet(method: str, ip: str = "", mask: str = "", gateway: str = "", dns: str = "") -> Tuple[bool, str]:
    """Configure ethernet interface. Method: 'auto' (DHCP) or 'manual' (static)."""
    if not nmcli_available():
        return False, "NetworkManager not available"
    
    # Find ethernet interface
    eth_config = get_ethernet_config()
    if not eth_config["available"] or not eth_config["interface"]:
        return False, "No ethernet interface found"
    
    interface = eth_config["interface"]
    
    if method == "auto":
        # Configure DHCP
        code, out, err = _run(f"nmcli connection modify {shlex.quote(interface)} ipv4.method auto", timeout=10)
        if code != 0:
            return False, f"Failed to set DHCP: {err}"
        
        # Clear any static settings
        _run(f"nmcli connection modify {shlex.quote(interface)} ipv4.addresses '' ipv4.gateway '' ipv4.dns ''", timeout=5)
        
    elif method == "manual":
        if not ip or not mask:
            return False, "IP address and mask required for manual configuration"
        
        # Validate IP format (basic check)
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            if gateway:
                ipaddress.ip_address(gateway)
        except ValueError:
            return False, "Invalid IP address format"
        
        # Configure static IP
        ip_with_mask = f"{ip}/{mask}"
        code, out, err = _run(f"nmcli connection modify {shlex.quote(interface)} ipv4.method manual ipv4.addresses {shlex.quote(ip_with_mask)}", timeout=10)
        if code != 0:
            return False, f"Failed to set static IP: {err}"
        
        # Set gateway if provided
        if gateway:
            code, out, err = _run(f"nmcli connection modify {shlex.quote(interface)} ipv4.gateway {shlex.quote(gateway)}", timeout=5)
            if code != 0:
                return False, f"Failed to set gateway: {err}"
        
        # Set DNS if provided
        if dns:
            dns_servers = dns.replace(' ', ',')  # Convert space-separated to comma-separated
            code, out, err = _run(f"nmcli connection modify {shlex.quote(interface)} ipv4.dns {shlex.quote(dns_servers)}", timeout=5)
            if code != 0:
                return False, f"Failed to set DNS: {err}"
        
    else:
        return False, "Invalid method. Use 'auto' or 'manual'"
    
    # Restart the connection
    code, out, err = _run(f"nmcli connection down {shlex.quote(interface)} && nmcli connection up {shlex.quote(interface)}", timeout=15)
    if code != 0:
        return False, f"Failed to restart connection: {err}"
    
    return True, f"Ethernet configured successfully ({method})"


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
    def _set_headers(self, status=200, content_type="application/json; charset=utf-8", extra_headers: Optional[Dict[str, str]] = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    # --- auth helpers ---
    def _auth_creds(self) -> Tuple[str, str]:
        user = _env_str("ADMIN_USER", "admin")
        pw = _env_str("ADMIN_PASS", "admin")
        return user, pw

    def _session_user(self) -> Optional[str]:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                value = part.split("=", 1)[1].strip()
                return parse_session_cookie(value)
        return None

    def _require_auth(self) -> Optional[str]:
        user = self._session_user()
        if user:
            return user
        # redirect to login
        self._set_headers(302, "text/plain", {"Location": "/login"})
        data = b"redirecting to /login\n"
        self.wfile.write(data)
        self.log_access(302, len(data))
        return None

    def do_GET(self):  # noqa: N802 (keep stdlib name)
        try:
            if self.path == "/" or self.path.startswith("/index"):
                # Check if user is already logged in
                user = self._session_user()
                if user:
                    # User is logged in, redirect to admin panel
                    self._set_headers(302, "text/plain", {"Location": "/admin"})
                    data = b"redirecting to admin panel\n"
                    self.wfile.write(data)
                    self.log_access(302, len(data))
                    return
                else:
                    # User not logged in, redirect to login
                    self._set_headers(302, "text/plain", {"Location": "/login"})
                    data = b"redirecting to login\n"
                    self.wfile.write(data)
                    self.log_access(302, len(data))
                    return

            if self.path.startswith("/time"):
                self._set_headers(200)
                payload = now_payload()
                data = json.dumps(payload).encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/login"):
                self._set_headers(200, "text/html; charset=utf-8")
                default_user, _ = self._auth_creds()
                body = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>Panel Logowania</title>
                    <style>
                        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                               background: #f5f5f5; color: #333; line-height: 1.6; 
                               display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
                        .login-container {{ background: white; border-radius: 8px; padding: 2rem; 
                                           box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }}
                        .header {{ text-align: center; margin-bottom: 2rem; }}
                        .header h1 {{ color: #2c3e50; margin-bottom: 0.5rem; }}
                        .header p {{ color: #7f8c8d; font-size: 14px; }}
                        .form-group {{ margin-bottom: 1.5rem; }}
                        label {{ display: block; margin-bottom: 0.5rem; font-weight: 500; color: #2c3e50; }}
                        input {{ padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; 
                                font-size: 14px; width: 100%; transition: border-color 0.3s; }}
                        input:focus {{ outline: none; border-color: #3498db; box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2); }}
                        button {{ background: #3498db; color: white; border: none; cursor: pointer; 
                                 padding: 0.75rem; border-radius: 4px; font-size: 14px; width: 100%;
                                 transition: background 0.3s; font-weight: 500; }}
                        button:hover {{ background: #2980b9; }}
                        .device-info {{ background: #ecf0f1; padding: 1rem; border-radius: 4px; 
                                       margin-top: 1.5rem; font-size: 12px; color: #7f8c8d; text-align: center; }}
                        @media (max-width: 768px) {{
                            .login-container {{ margin: 1rem; padding: 1.5rem; }}
                        }}
                    </style>
                </head>
                <body>
                    <div class="login-container">
                        <div class="header">
                            <h1>🔒 Panel Administracyjny</h1>
                            <p>Zaloguj się aby uzyskać dostęp do konfiguracji</p>
                        </div>
                        <form method="post" action="/login">
                            <div class="form-group">
                                <label for="username">👤 Nazwa użytkownika</label>
                                <input type="text" id="username" name="username" value="{default_user}" required>
                            </div>
                            <div class="form-group">
                                <label for="password">🔑 Hasło</label>
                                <input type="password" id="password" name="password" required>
                            </div>
                            <button type="submit">🚀 Zaloguj się</button>
                        </form>
                        <div class="device-info">
                            📡 Offline Time Server - Secure Access Portal
                        </div>
                    </div>
                </body>
                </html>
                """
                data = body.encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/logout"):
                headers = {"Set-Cookie": "session=deleted; HttpOnly; Max-Age=0; Path=/"}
                self._set_headers(302, "text/plain", {**headers, "Location": "/"})
                data = b"Wylogowano\n"
                self.wfile.write(data)
                self.log_access(302, len(data))
                return

            if self.path.startswith("/admin"):
                user = self._require_auth()
                if not user:
                    return
                self._set_headers(200, "text/html; charset=utf-8")
                body = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <title>Panel Administracyjny</title>
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                               background: #f5f5f5; color: #333; line-height: 1.6; }
                        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
                        .header { background: #2c3e50; color: white; padding: 1rem; border-radius: 8px; margin-bottom: 2rem; 
                                  display: flex; justify-content: space-between; align-items: center; }
                        .card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; 
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
                        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; }
                        .status-item { background: #ecf0f1; padding: 1rem; border-radius: 4px; border-left: 4px solid #3498db; }
                        .status-good { border-left-color: #27ae60; }
                        .status-warning { border-left-color: #f39c12; }
                        .status-error { border-left-color: #e74c3c; }
                        .form-group { margin-bottom: 1rem; }
                        label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
                        input, select, button { padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; 
                                               font-size: 14px; width: 100%; }
                        button { background: #3498db; color: white; border: none; cursor: pointer; 
                                transition: background 0.3s; }
                        button:hover { background: #2980b9; }
                        .btn-danger { background: #e74c3c; }
                        .btn-danger:hover { background: #c0392b; }
                        .btn-success { background: #27ae60; }
                        .btn-success:hover { background: #229954; }
                        .gps-signal { height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; }
                        .gps-signal-fill { height: 100%; transition: width 0.3s, background-color 0.3s; }
                        .signal-0 { width: 0%; background: #e74c3c; }
                        .signal-1 { width: 25%; background: #e67e22; }
                        .signal-2 { width: 50%; background: #f39c12; }
                        .signal-3 { width: 75%; background: #f1c40f; }
                        .signal-4 { width: 100%; background: #27ae60; }
                        .tabs { display: flex; border-bottom: 1px solid #ddd; margin-bottom: 1rem; }
                        .tab { padding: 1rem 1.5rem; cursor: pointer; border-bottom: 2px solid transparent; }
                        .tab.active { border-bottom-color: #3498db; background: #f8f9fa; }
                        .tab-content { display: none; }
                        .tab-content.active { display: block; }
                        pre { background: #f8f9fa; padding: 1rem; border-radius: 4px; overflow-x: auto; 
                              font-size: 12px; white-space: pre-wrap; }
                        .wifi-list { max-height: 300px; overflow-y: auto; }
                        .wifi-item { display: flex; justify-content: space-between; align-items: center; 
                                    padding: 0.5rem; border-bottom: 1px solid #eee; cursor: pointer; }
                        .wifi-item:hover { background: #f8f9fa; }
                        .signal-bars { display: flex; gap: 2px; }
                        .signal-bar { width: 4px; height: 16px; background: #ddd; border-radius: 1px; }
                        .signal-bar.active { background: #27ae60; }
                        @media (max-width: 768px) {
                            .container { padding: 10px; }
                            .grid { grid-template-columns: 1fr; }
                            .header { flex-direction: column; gap: 1rem; text-align: center; }
                            .tabs { flex-wrap: wrap; }
                            .tab { flex: 1; min-width: 120px; text-align: center; }
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Panel Administracyjny</h1>
                            <div>
                                <span id="current-time"></span>
                                <a href="/logout" style="color: white; margin-left: 20px; text-decoration: none;">🚪 Wyloguj</a>
                            </div>
                        </div>

                        <div class="card">
                            <div class="tabs">
                                <div class="tab active" onclick="showTab('overview')">🏠 Przegląd</div>
                                <div class="tab" onclick="showTab('network')">📡 Wi-Fi</div>
                                <div class="tab" onclick="showTab('ethernet')">🔌 Ethernet</div>
                                <div class="tab" onclick="showTab('gps')">🛰️ GPS</div>
                                <div class="tab" onclick="showTab('system')">⚙️ System</div>
                                <div class="tab" onclick="showTab('security')">🔒 Bezpieczeństwo</div>
                            </div>

                            <div id="overview" class="tab-content active">
                                <h2>Status Systemu</h2>
                                <div id="system-status" class="status-grid">
                                    <div class="status-item">Ładowanie...</div>
                                </div>
                            </div>

                            <div id="network" class="tab-content">
                                <h2>Konfiguracja Wi-Fi</h2>
                                <div class="grid">
                                    <div>
                                        <h3>Aktualne Połączenia</h3>
                                        <div id="network-status">Ładowanie...</div>
                                    </div>
                                    <div>
                                        <h3>Dostępne Sieci Wi-Fi</h3>
                                        <button onclick="scanWifi()">🔍 Skanuj Sieci</button>
                                        <div id="wifi-list" class="wifi-list"></div>
                                    </div>
                                </div>
                                <div>
                                    <h3>Połącz z Siecią Wi-Fi</h3>
                                    <form onsubmit="connectWifi(event)">
                                        <div class="form-group">
                                            <label for="ssid">SSID:</label>
                                            <input type="text" id="ssid" name="ssid" required>
                                        </div>
                                        <div class="form-group">
                                            <label for="psk">Hasło:</label>
                                            <input type="password" id="psk" name="psk">
                                        </div>
                                        <button type="submit">📡 Połącz</button>
                                    </form>
                                </div>
                            </div>

                            <div id="ethernet" class="tab-content">
                                <h2>Konfiguracja Ethernet</h2>
                                <div class="grid">
                                    <div>
                                        <h3>Status Interfejsu</h3>
                                        <div id="ethernet-status">Ładowanie...</div>
                                    </div>
                                    <div>
                                        <h3>Konfiguracja IP</h3>
                                        <form onsubmit="configureEthernet(event)">
                                            <div class="form-group">
                                                <label for="eth-method">Metoda konfiguracji:</label>
                                                <select id="eth-method" name="method" onchange="toggleEthernetFields()">
                                                    <option value="auto">DHCP (Automatyczna)</option>
                                                    <option value="manual">Manualna (Statyczny IP)</option>
                                                </select>
                                            </div>
                                            <div id="manual-fields" style="display: none;">
                                                <div class="form-group">
                                                    <label for="eth-ip">Adres IP:</label>
                                                    <input type="text" id="eth-ip" name="ip" placeholder="192.168.1.100">
                                                </div>
                                                <div class="form-group">
                                                    <label for="eth-mask">Maska (CIDR):</label>
                                                    <input type="number" id="eth-mask" name="mask" min="1" max="30" value="24" placeholder="24">
                                                </div>
                                                <div class="form-group">
                                                    <label for="eth-gateway">Brama (opcjonalnie):</label>
                                                    <input type="text" id="eth-gateway" name="gateway" placeholder="192.168.1.1">
                                                </div>
                                                <div class="form-group">
                                                    <label for="eth-dns">Serwery DNS (opcjonalnie):</label>
                                                    <input type="text" id="eth-dns" name="dns" placeholder="8.8.8.8 8.8.4.4">
                                                    <small>Oddziel spacjami lub przecinkami</small>
                                                </div>
                                            </div>
                                            <button type="submit">🔌 Zastosuj Konfiguracje</button>
                                        </form>
                                    </div>
                                </div>
                            </div>

                            <div id="gps" class="tab-content">
                                <h2>Status GPS</h2>
                                <div class="grid">
                                    <div>
                                        <h3>Siła Sygnału</h3>
                                        <div class="gps-signal">
                                            <div id="gps-signal-fill" class="gps-signal-fill signal-0"></div>
                                        </div>
                                        <p id="gps-signal-text">Brak sygnału</p>
                                    </div>
                                    <div id="gps-details">
                                        <h3>Szczegóły GPS</h3>
                                        <div id="gps-info">Ładowanie...</div>
                                    </div>
                                </div>
                            </div>

                            <div id="system" class="tab-content">
                                <h2>Informacje Systemowe</h2>
                                <div id="system-info">Ładowanie...</div>
                            </div>

                            <div id="security" class="tab-content">
                                <h2>Bezpieczeństwo</h2>
                                <div class="grid">
                                    <div>
                                        <h3>Zmiana Hasła</h3>
                                        <form onsubmit="changePassword(event)">
                                            <div class="form-group">
                                                <label for="new-password">Nowe Hasło:</label>
                                                <input type="password" id="new-password" minlength="4" required>
                                            </div>
                                            <div class="form-group">
                                                <label for="confirm-password">Potwierdź Hasło:</label>
                                                <input type="password" id="confirm-password" minlength="4" required>
                                            </div>
                                            <button type="submit">🔐 Zmień Hasło</button>
                                        </form>
                                    </div>
                                    <div>
                                        <h3>Dostęp SSH</h3>
                                        <div id="ssh-status">Ładowanie...</div>
                                        <div style="margin-top: 1rem;">
                                            <button id="ssh-toggle" onclick="toggleSSH()" class="btn-danger">⏹️ Zatrzymaj SSH</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <script>
                        let currentData = {};
                        
                        function showTab(tabName) {
                            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                            event.target.classList.add('active');
                            document.getElementById(tabName).classList.add('active');
                        }
                        
                        function updateTime() {
                            const now = new Date();
                            document.getElementById('current-time').textContent = 
                                now.toLocaleString('pl-PL', {timeZone: 'Europe/Warsaw'});
                        }
                        
                        function signalBars(strength) {
                            const bars = Math.ceil((parseInt(strength) || 0) / 25);
                            let html = '<div class="signal-bars">';
                            for (let i = 0; i < 4; i++) {
                                html += `<div class="signal-bar ${i < bars ? 'active' : ''}"></div>`;
                            }
                            html += '</div>';
                            return html;
                        }
                        
                        async function loadStatus() {
                            try {
                                const response = await fetch('/api/status');
                                currentData = await response.json();
                                updateOverview();
                                updateGPS();
                                updateNetwork();
                                updateEthernet();
                                updateSystemInfo();
                                updateSSHStatus();
                            } catch (error) {
                                console.error('Error loading status:', error);
                            }
                        }
                        
                        function updateOverview() {
                            const container = document.getElementById('system-status');
                            let html = '';
                            
                            // Time status
                            html += `<div class="status-item status-good">
                                <strong>🕒 Czas Systemu</strong><br>
                                ${currentData.time?.iso8601 || 'N/A'}
                            </div>`;
                            
                            // GPS status
                            const gps = currentData.gps;
                            const gpsClass = gps?.available && gps?.mode >= 2 ? 'status-good' : 
                                           gps?.available ? 'status-warning' : 'status-error';
                            html += `<div class="status-item ${gpsClass}">
                                <strong>🛰️ GPS</strong><br>
                                ${gps?.available ? (gps.mode >= 2 ? 'Aktywny' : 'Szuka sygnału') : 'Niedostępny'}
                            </div>`;
                            
                            // NTP status
                            const ntp = currentData.ntp;
                            const ntpClass = ntp?.available ? 'status-good' : 'status-error';
                            html += `<div class="status-item ${ntpClass}">
                                <strong>⏰ NTP</strong><br>
                                ${ntp?.available ? 'Aktywny' : 'Niedostępny'}
                            </div>`;
                            
                            // Network status - prioritize Ethernet connection
                            const network = currentData.network;
                            const ethernetConnected = network?.interfaces?.some(i => i.type === 'ethernet' && i.state === 'connected');
                            const anyConnected = network?.interfaces?.some(i => i.state === 'connected');
                            const netClass = ethernetConnected ? 'status-good' : (anyConnected ? 'status-warning' : 'status-error');
                            const statusText = ethernetConnected ? 'Ethernet połączony' : (anyConnected ? 'Tylko WiFi/inne' : 'Brak połączenia');
                            html += `<div class="status-item ${netClass}">
                                <strong>🔌 Sieć Ethernet</strong><br>
                                ${statusText}
                            </div>`;
                            
                            container.innerHTML = html;
                        }
                        
                        function updateGPS() {
                            const gps = currentData.gps;
                            const signalFill = document.getElementById('gps-signal-fill');
                            const signalText = document.getElementById('gps-signal-text');
                            const gpsInfo = document.getElementById('gps-info');
                            
                            if (gps?.available) {
                                let signalClass = 'signal-0';
                                let signalDesc = 'Brak sygnału';
                                
                                if (gps.mode >= 3) {
                                    signalClass = 'signal-4';
                                    signalDesc = 'Excellent (3D Fix)';
                                } else if (gps.mode >= 2) {
                                    signalClass = 'signal-3';
                                    signalDesc = 'Good (2D Fix)';
                                } else if (gps.sats > 0) {
                                    signalClass = 'signal-2';
                                    signalDesc = 'Szuka sygnału';
                                } else {
                                    signalClass = 'signal-1';
                                    signalDesc = 'Weak';
                                }
                                
                                signalFill.className = `gps-signal-fill ${signalClass}`;
                                signalText.textContent = signalDesc;
                                
                                gpsInfo.innerHTML = `
                                    <p><strong>Satelity:</strong> ${gps.sats || 'N/A'}</p>
                                    <p><strong>Tryb:</strong> ${gps.mode || 'N/A'}</p>
                                    <p><strong>Szerokość:</strong> ${gps.lat || 'N/A'}</p>
                                    <p><strong>Długość:</strong> ${gps.lon || 'N/A'}</p>
                                    <p><strong>Ostatni Fix:</strong> ${gps.fix || 'N/A'}</p>
                                `;
                            } else {
                                signalFill.className = 'gps-signal-fill signal-0';
                                signalText.textContent = 'GPS niedostępny';
                                gpsInfo.innerHTML = '<p>GPS nie jest dostępny lub wyłączony</p>';
                            }
                        }
                        
                        function updateNetwork() {
                            const network = currentData.network;
                            const container = document.getElementById('network-status');
                            
                            if (network?.interfaces) {
                                let html = '<div class="status-grid">';
                                // Show only WiFi interfaces in WiFi tab
                                const wifiInterfaces = network.interfaces.filter(i => i.type === 'wifi');
                                if (wifiInterfaces.length === 0) {
                                    html += '<div class="status-item status-warning">Brak interfejsów Wi-Fi</div>';
                                } else {
                                    wifiInterfaces.forEach(iface => {
                                        const statusClass = iface.state === 'connected' ? 'status-good' : 
                                                          iface.state === 'connecting' ? 'status-warning' : 'status-error';
                                        html += `<div class="status-item ${statusClass}">
                                            <strong>${iface.ifname}</strong> (${iface.type})<br>
                                            ${iface.state} - ${iface.connection || 'N/A'}
                                        </div>`;
                                    });
                                }
                                html += '</div>';
                                container.innerHTML = html;
                            } else {
                                container.innerHTML = '<p>Brak informacji o sieci Wi-Fi</p>';
                            }
                        }
                        
                        async function updateEthernet() {
                            try {
                                const response = await fetch('/api/ethernet/status');
                                const data = await response.json();
                                const container = document.getElementById('ethernet-status');
                                
                                if (data.available) {
                                    const statusClass = data.method === 'auto' ? 'status-good' : 'status-warning';
                                    let html = `<div class="status-grid">`;
                                    html += `<div class="status-item ${statusClass}">
                                        <strong>Interfejs:</strong> ${data.interface}<br>
                                        <strong>Metoda:</strong> ${data.method === 'auto' ? 'DHCP' : 'Statyczny IP'}
                                    </div>`;
                                    
                                    if (data.ip) {
                                        html += `<div class="status-item status-good">
                                            <strong>IP:</strong> ${data.ip}<br>
                                            <strong>Brama:</strong> ${data.gateway || 'N/A'}
                                        </div>`;
                                    }
                                    
                                    if (data.dns && data.dns.length > 0) {
                                        html += `<div class="status-item status-good">
                                            <strong>DNS:</strong><br>${data.dns.join(', ')}
                                        </div>`;
                                    }
                                    
                                    html += '</div>';
                                    container.innerHTML = html;
                                    
                                    // Update form fields
                                    document.getElementById('eth-method').value = data.method;
                                    toggleEthernetFields();
                                    
                                    if (data.method === 'manual') {
                                        const ipParts = (data.ip || '').split('/');
                                        if (ipParts.length === 2) {
                                            document.getElementById('eth-ip').value = ipParts[0];
                                            document.getElementById('eth-mask').value = ipParts[1];
                                        }
                                        document.getElementById('eth-gateway').value = data.gateway || '';
                                        document.getElementById('eth-dns').value = (data.dns || []).join(' ');
                                    }
                                } else {
                                    container.innerHTML = '<div class="status-item status-error">Ethernet niedostępny</div>';
                                }
                            } catch (error) {
                                console.error('Error loading ethernet status:', error);
                            }
                        }
                        
                        function toggleEthernetFields() {
                            const method = document.getElementById('eth-method').value;
                            const manualFields = document.getElementById('manual-fields');
                            manualFields.style.display = method === 'manual' ? 'block' : 'none';
                        }
                        
                        async function configureEthernet(event) {
                            event.preventDefault();
                            const formData = new FormData(event.target);
                            
                            try {
                                const response = await fetch('/api/ethernet/config', {
                                    method: 'POST',
                                    body: new URLSearchParams({
                                        method: formData.get('method'),
                                        ip: formData.get('ip') || '',
                                        mask: formData.get('mask') || '',
                                        gateway: formData.get('gateway') || '',
                                        dns: formData.get('dns') || ''
                                    })
                                });
                                
                                const result = await response.json();
                                alert(result.message);
                                if (result.ok) {
                                    loadStatus();
                                    updateEthernet();
                                }
                            } catch (error) {
                                alert('Błąd konfiguracji Ethernet: ' + error.message);
                            }
                        }
                        
                        async function updateSystemInfo() {
                            try {
                                const response = await fetch('/api/system');
                                const data = await response.json();
                                const container = document.getElementById('system-info');
                                
                                container.innerHTML = `
                                    <div class="status-grid">
                                        <div class="status-item">
                                            <strong>🖥️ Hostname</strong><br>${data.hostname || 'N/A'}
                                        </div>
                                        <div class="status-item">
                                            <strong>⏱️ Uptime</strong><br>${data.uptime || 'N/A'}
                                        </div>
                                        <div class="status-item">
                                            <strong>📊 Load Average</strong><br>${data.load || 'N/A'}
                                        </div>
                                    </div>
                                    <h3>Pamięć</h3>
                                    <pre>${data.memory || 'N/A'}</pre>
                                    <h3>Dysk</h3>
                                    <pre>${data.disk || 'N/A'}</pre>
                                `;
                            } catch (error) {
                                console.error('Error loading system info:', error);
                            }
                        }
                        
                        async function updateSSHStatus() {
                            try {
                                const response = await fetch('/api/ssh/status');
                                const data = await response.json();
                                const container = document.getElementById('ssh-status');
                                const button = document.getElementById('ssh-toggle');
                                
                                const statusClass = data.active ? 'status-good' : 'status-error';
                                container.innerHTML = `<div class="status-item ${statusClass}">
                                    <strong>Status:</strong> ${data.active ? 'Aktywny' : 'Nieaktywny'}<br>
                                    <strong>Autostart:</strong> ${data.enabled ? 'Włączony' : 'Wyłączony'}
                                </div>`;
                                
                                if (data.active) {
                                    button.textContent = '⏹️ Zatrzymaj SSH';
                                    button.className = 'btn-danger';
                                } else {
                                    button.textContent = '▶️ Uruchom SSH';
                                    button.className = 'btn-success';
                                }
                            } catch (error) {
                                console.error('Error loading SSH status:', error);
                            }
                        }
                        
                        async function scanWifi() {
                            try {
                                const response = await fetch('/api/wifi/scan');
                                const networks = await response.json();
                                const container = document.getElementById('wifi-list');
                                
                                if (networks.length === 0) {
                                    container.innerHTML = '<p>Brak dostępnych sieci</p>';
                                    return;
                                }
                                
                                let html = '';
                                networks.forEach(network => {
                                    html += `<div class="wifi-item" onclick="selectWifi('${network.ssid}')">
                                        <div>
                                            <strong>${network.ssid}</strong><br>
                                            <small>${network.security}</small>
                                        </div>
                                        <div>
                                            ${signalBars(network.signal)}
                                            <small>${network.signal}%</small>
                                        </div>
                                    </div>`;
                                });
                                container.innerHTML = html;
                            } catch (error) {
                                console.error('Error scanning WiFi:', error);
                            }
                        }
                        
                        function selectWifi(ssid) {
                            document.getElementById('ssid').value = ssid;
                        }
                        
                        async function connectWifi(event) {
                            event.preventDefault();
                            const formData = new FormData(event.target);
                            
                            try {
                                const response = await fetch('/api/network', {
                                    method: 'POST',
                                    body: new URLSearchParams({
                                        action: 'wifi',
                                        ssid: formData.get('ssid'),
                                        psk: formData.get('psk')
                                    })
                                });
                                
                                const result = await response.json();
                                alert(result.ok ? 'Połączono pomyślnie!' : 'Błąd: ' + result.message);
                                if (result.ok) {
                                    loadStatus();
                                }
                            } catch (error) {
                                alert('Błąd połączenia: ' + error.message);
                            }
                        }
                        
                        async function changePassword(event) {
                            event.preventDefault();
                            const newPass = document.getElementById('new-password').value;
                            const confirmPass = document.getElementById('confirm-password').value;
                            
                            if (newPass !== confirmPass) {
                                alert('Hasła nie są zgodne');
                                return;
                            }
                            
                            try {
                                const response = await fetch('/api/password', {
                                    method: 'POST',
                                    body: new URLSearchParams({ password: newPass })
                                });
                                
                                const result = await response.json();
                                alert(result.message);
                                if (result.ok) {
                                    event.target.reset();
                                }
                            } catch (error) {
                                alert('Błąd zmiany hasła: ' + error.message);
                            }
                        }
                        
                        async function toggleSSH() {
                            const button = document.getElementById('ssh-toggle');
                            const isActive = button.textContent.includes('Zatrzymaj');
                            const action = isActive ? 'stop' : 'start';
                            
                            try {
                                const response = await fetch('/api/ssh/control', {
                                    method: 'POST',
                                    body: new URLSearchParams({ action })
                                });
                                
                                const result = await response.json();
                                alert(result.message);
                                updateSSHStatus();
                            } catch (error) {
                                alert('Błąd kontroli SSH: ' + error.message);
                            }
                        }
                        
                        // Initialize
                        updateTime();
                        setInterval(updateTime, 1000);
                        loadStatus();
                        setInterval(loadStatus, 5000);
                    </script>
                </body>
                </html>
                """
                data = body.encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/api/status"):
                user = self._require_auth()
                if not user:
                    return
                payload = {
                    "time": now_payload(),
                    "gps": get_gps_status(),
                    "ntp": get_ntp_status(),
                    "network": get_network_status(),
                }
                self._set_headers(200)
                data = json.dumps(payload).encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/api/system"):
                user = self._require_auth()
                if not user:
                    return
                payload = get_system_info()
                self._set_headers(200)
                data = json.dumps(payload).encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/api/ssh/status"):
                user = self._require_auth()
                if not user:
                    return
                payload = get_ssh_status()
                self._set_headers(200)
                data = json.dumps(payload).encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/api/wifi/scan"):
                user = self._require_auth()
                if not user:
                    return
                networks = scan_wifi_networks()
                self._set_headers(200)
                data = json.dumps(networks).encode("utf-8")
                self.wfile.write(data)
                self.log_access(200, len(data))
                return

            if self.path.startswith("/api/ethernet/status"):
                user = self._require_auth()
                if not user:
                    return
                config = get_ethernet_config()
                self._set_headers(200)
                data = json.dumps(config).encode("utf-8")
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

    def do_POST(self):  # noqa: N802
        try:
            if self.path == "/login":
                body = read_body(self)
                form = parse_form_urlencoded(body)
                user_in = form.get("username", "")
                pw_in = form.get("password", "")
                user_cfg, pw_cfg = self._auth_creds()
                if user_in == user_cfg and pw_in == pw_cfg:
                    cookie = make_session_cookie(user_in)
                    headers = {"Set-Cookie": f"session={cookie}; HttpOnly; Path=/"}
                    self._set_headers(302, "text/plain", {**headers, "Location": "/admin"})
                    data = b"OK\n"
                    self.wfile.write(data)
                    self.log_access(302, len(data))
                    return
                self._set_headers(401, "text/html; charset=utf-8")
                html = "<html><body>Nieprawidlowe dane logowania. <a href=\"/login\">Spróbuj ponownie</a>.</body></html>"
                data = html.encode("utf-8")
                self.wfile.write(data)
                self.log_access(401, len(data))
                return

            if self.path == "/api/network":
                user = self._require_auth()
                if not user:
                    return
                form = parse_form_urlencoded(read_body(self))
                action = form.get("action", "")
                if action == "wifi":
                    ssid = form.get("ssid", "")
                    psk = form.get("psk", "")
                    ok, msg = apply_wifi_settings(ssid, psk)
                    status = 200 if ok else 400
                    self._set_headers(status)
                    data = json.dumps({"ok": ok, "message": msg}).encode("utf-8")
                    self.wfile.write(data)
                    self.log_access(status, len(data))
                    return
                self._set_headers(400)
                data = json.dumps({"ok": False, "error": "unknown action"}).encode("utf-8")
                self.wfile.write(data)
                self.log_access(400, len(data))
                return

            if self.path == "/api/password":
                user = self._require_auth()
                if not user:
                    return
                form = parse_form_urlencoded(read_body(self))
                password = form.get("password", "")
                ok, msg = change_admin_password(password)
                status = 200 if ok else 400
                self._set_headers(status)
                data = json.dumps({"ok": ok, "message": msg}).encode("utf-8")
                self.wfile.write(data)
                self.log_access(status, len(data))
                return

            if self.path == "/api/ssh/control":
                user = self._require_auth()
                if not user:
                    return
                form = parse_form_urlencoded(read_body(self))
                action = form.get("action", "")
                ok, msg = control_ssh_service(action)
                status = 200 if ok else 400
                self._set_headers(status)
                data = json.dumps({"ok": ok, "message": msg}).encode("utf-8")
                self.wfile.write(data)
                self.log_access(status, len(data))
                return

            if self.path == "/api/ethernet/config":
                user = self._require_auth()
                if not user:
                    return
                form = parse_form_urlencoded(read_body(self))
                method = form.get("method", "")
                ip = form.get("ip", "")
                mask = form.get("mask", "")
                gateway = form.get("gateway", "")
                dns = form.get("dns", "")
                ok, msg = configure_ethernet(method, ip, mask, gateway, dns)
                status = 200 if ok else 400
                self._set_headers(status)
                data = json.dumps({"ok": ok, "message": msg}).encode("utf-8")
                self.wfile.write(data)
                self.log_access(status, len(data))
                return

            self._set_headers(404)
            data = json.dumps({"error": "Not Found"}).encode("utf-8")
            self.wfile.write(data)
            self.log_access(404, len(data))
        except Exception:
            logging.getLogger("timeserver").exception("Unhandled error in POST")
            try:
                self._set_headers(500)
                data = json.dumps({"error": "Internal Server Error"}).encode("utf-8")
                self.wfile.write(data)
                self.log_access(500, len(data))
            except Exception:
                pass


def main():
    setup_logging()
    log = logging.getLogger("timeserver")
    host = os.environ.get("HOST", "0.0.0.0")
    try:
        port = int(os.environ.get("PORT", "80"))
    except ValueError:
        port = 80

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
