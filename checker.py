import os
import json
import time
import subprocess
import base64
import requests
import re
import random
from urllib.parse import urlparse, parse_qs, unquote
from config import (
    XRAY_PATH, LIBRESPEED_PATH, UTLS_FINGERPRINTS, CHECK_URL, 
    CONNECT_TIMEOUT, DISTINCTIVE_FEATURE, DOWNLOAD_TIMEOUT, MIN_SPEED_MBPS
)
from utils import get_free_port

def download_binaries():
    """
    Checks for the presence of binary files and sets execution permissions.
    Handles system paths correctly (e.g., /usr/local/bin/xray).
    Silent for production, but prints initial setup logs.
    """
    import platform
    # This remains in checker for initial diagnostic
    actual_xray_path = XRAY_PATH
    if XRAY_PATH == "./xray" and not os.path.exists("./xray"):
        if os.path.exists("/usr/local/bin/xray"):
            actual_xray_path = "/usr/local/bin/xray"
    
    paths_to_check = [
        ("Xray", actual_xray_path),
        ("Librespeed", LIBRESPEED_PATH)
    ]
    
    status = True
    for name, path in paths_to_check:
        if os.path.exists(path):
            try:
                os.chmod(path, 0o755)
            except:
                pass
        else:
            status = False
    return status

class ProxyChecker:
    def __init__(self, link):
        self.link = link
        self.port = get_free_port()
        self.process: subprocess.Popen | None = None
        self.fingerprint = "chrome"
        self.fail_reason = ""
        
        # Determine actual binary path
        self.xray_bin = XRAY_PATH
        if self.xray_bin == "./xray" and not os.path.exists("./xray"):
            if os.path.exists("/usr/local/bin/xray"):
                self.xray_bin = "/usr/local/bin/xray"
        
    def _parse_vmess(self, link):
        try:
            data = link.replace("vmess://", "").strip()
            data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            decoded = base64.b64decode(data).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def generate_xray_config(self):
        """Generates Xray JSON config without any prints."""
        try:
            config = {
                "log": {"loglevel": "none"},
                "inbounds": [{
                    "port": self.port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                }],
                "outbounds": []
            }
            
            self.fingerprint = random.choice(UTLS_FINGERPRINTS)
            if self.fingerprint == "randomized": 
                self.fingerprint = "chrome"
            
            link_lower = self.link.lower()
            outbound = {"protocol": "vless", "settings": {}, "streamSettings": {}}
            
            if "vmess://" in link_lower:
                v_data = self._parse_vmess(self.link)
                if not v_data: return None
                outbound = {
                    "protocol": "vmess",
                    "settings": {"vnext": [{"address": v_data.get("add"), "port": int(v_data.get("port")), 
                                           "users": [{"id": v_data.get("id"), "security": "auto"}]}]},
                    "streamSettings": {
                        "network": v_data.get("net", "tcp"),
                        "security": v_data.get("tls", "none"),
                        "tlsSettings": {"serverName": v_data.get("sni", ""), "fingerprint": self.fingerprint},
                        "wsSettings": {"path": v_data.get("path", "/")} if v_data.get("net") == "ws" else {}
                    }
                }
            elif "vless://" in link_lower or "trojan://" in link_lower:
                parsed = urlparse(self.link)
                params = parse_qs(parsed.query)
                proto = "vless" if "vless://" in link_lower else "trojan"
                security = params.get("security", ["none"])[0]
                sni = params.get("sni", [""])[0]
                fp = params.get("fp", [self.fingerprint])[0]
                
                user_id = parsed.username or ""
                if not user_id and "@" in parsed.netloc:
                    user_id = parsed.netloc.split("@")[0]
                
                outbound = {
                    "protocol": proto,
                    "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port or 443, 
                                             "users": [{"id": user_id if proto=="vless" else "", 
                                                       "password": unquote(user_id) if proto=="trojan" else "",
                                                       "encryption": "none" if proto=="vless" else None}]}]},
                    "streamSettings": {
                        "network": params.get("type", ["tcp"])[0],
                        "security": security,
                        "tlsSettings": {"serverName": sni, "fingerprint": fp} if security == "tls" else {},
                        "realitySettings": {
                            "serverName": sni, "fingerprint": fp,
                            "publicKey": params.get("pbk", [""])[0],
                            "shortId": params.get("sid", [""])[0],
                            "spiderX": params.get("spx", [""])[0]
                        } if security == "reality" else {},
                        "wsSettings": {"path": params.get("path", ["/"])[0], "headers": {"Host": sni}} if params.get("type") == ["ws"] else {},
                        "grpcSettings": {"serviceName": params.get("serviceName", [""])[0]} if params.get("type") == ["grpc"] else {}
                    }
                }
            elif "ss://" in link_lower:
                parsed = urlparse(self.link)
                if "@" in parsed.netloc:
                    user_pass_b64 = parsed.netloc.split("@")[0]
                    try:
                        decoded = base64.b64decode(user_pass_b64 + "==").decode('utf-8')
                        method, password = decoded.split(":", 1)
                        outbound = {
                            "protocol": "shadowsocks",
                            "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "method": method, "password": password}]}
                        }
                    except: return None
                else: return None
            elif "hysteria2://" in link_lower or "tuic://" in link_lower:
                parsed = urlparse(self.link)
                proto = "hysteria2" if "hysteria2" in link_lower else "tuic"
                outbound = {
                    "protocol": proto,
                    "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "users": [{"password": parsed.username}]}]},
                    "streamSettings": {"network": "udp"}
                }
            
            config["outbounds"] = [outbound, {"protocol": "freedom", "tag": "direct"}]
            return config
        except Exception as e:
            self.fail_reason = f"Config creation error: {e}"
            return None

    def start_xray(self):
        """Starts Xray silently."""
        config = self.generate_xray_config()
        if not config:
            if not self.fail_reason: self.fail_reason = "Parsing link failed"
            return False
            
        config_path = f"config_{self.port}.json"
        with open(config_path, "w") as f:
            json.dump(config, f)
            
        try:
            self.process = subprocess.Popen([self.xray_bin, "run", "-c", config_path], 
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            if self.process.poll() is not None:
                self.fail_reason = "Xray core crashed on start"
                return False
            return True
        except Exception as e:
            self.fail_reason = f"Execution error: {e}"
            return False

    def stop_xray(self):
        """Stops Xray silently and cleans up."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                try: self.process.kill()
                except: pass
        config_path = f"config_{self.port}.json"
        if os.path.exists(config_path):
            try: os.remove(config_path)
            except: pass

    def check_availability(self):
        """Checks availability without printing to console."""
        proxies = {'http': f'socks5h://127.0.0.1:{self.port}', 'https': f'socks5h://127.0.0.1:{self.port}'}
        try:
            start_time = time.time()
            resp = requests.get(CHECK_URL, proxies=proxies, timeout=CONNECT_TIMEOUT)
            duration = time.time() - start_time
            
            if resp.status_code == 200:
                has_feature = DISTINCTIVE_FEATURE.lower() in resp.text.lower()
                if not has_feature:
                    self.fail_reason = f"Feature '{DISTINCTIVE_FEATURE}' not found"
                return True, has_feature, duration
            else:
                self.fail_reason = f"HTTP Status {resp.status_code}"
        except requests.exceptions.Timeout:
            self.fail_reason = f"Connection Timeout ({CONNECT_TIMEOUT}s)"
        except Exception as e:
            self.fail_reason = f"Network Error: {str(e).split(')')[-1].strip() or 'No connection'}"
            
        return False, False, 0

    def check_speed(self):
        """Checks speed without printing to console."""
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{self.port}", "--json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                download_mbps = data.get("download", 0) / 125000
                if download_mbps < MIN_SPEED_MBPS:
                    self.fail_reason = f"Speed too low: {download_mbps:.2f} Mbps"
                return download_mbps
            else:
                self.fail_reason = "Librespeed test failed"
        except subprocess.TimeoutExpired:
            self.fail_reason = f"Speedtest timed out ({DOWNLOAD_TIMEOUT}s)"
        except Exception as e:
            self.fail_reason = f"Speedtest error: {e}"
        return 0
