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
    Проверяет наличие бинарных файлов и устанавливает права на исполнение.
    В GitHub Actions или Linux это критически важно для работы subprocess.
    """
    import platform
    print(f"[LOG] Проверка платформы: {platform.system()} {platform.machine()}")
    
    # Проверка Xray
    if os.path.exists(XRAY_PATH):
        try:
            os.chmod(XRAY_PATH, 0o755)
            print(f"[LOG] Права на выполнение для {XRAY_PATH} установлены.")
        except Exception as e:
            print(f"[ERROR] Не удалось установить права для {XRAY_PATH}: {e}")
    else:
        print(f"[WARNING] Бинарный файл {XRAY_PATH} не найден по указанному пути.")
        
    # Проверка Librespeed
    if os.path.exists(LIBRESPEED_PATH):
        try:
            os.chmod(LIBRESPEED_PATH, 0o755)
            print(f"[LOG] Права на выполнение для {LIBRESPEED_PATH} установлены.")
        except Exception as e:
            print(f"[ERROR] Не удалось установить права для {LIBRESPEED_PATH}: {e}")
    else:
        print(f"[WARNING] Бинарный файл {LIBRESPEED_PATH} не найден по указанному пути.")

class ProxyChecker:
    def __init__(self, link):
        self.link = link
        self.port = get_free_port()
        self.process: subprocess.Popen | None = None
        self.fingerprint = "chrome"
        
    def _parse_vmess(self, link):
        try:
            data = link.replace("vmess://", "").strip()
            # Очистка от возможных пробелов или символов новой строки
            data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            decoded = base64.b64decode(data).decode('utf-8')
            return json.loads(decoded)
        except:
            return None

    def generate_xray_config(self):
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
            
            # Настройка Outbound в зависимости от протокола
            outbound = {"protocol": "vless", "settings": {}, "streamSettings": {}}
            self.fingerprint = random.choice(UTLS_FINGERPRINTS)
            if self.fingerprint == "randomized": 
                self.fingerprint = "chrome"
            
            link_lower = self.link.lower()
            
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
                if not user_id and ":" in parsed.netloc:
                    user_id = parsed.netloc.split("@")[0].split(":")[0]
                
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
                user_info = parsed.username or ""
                if "@" not in self.link.split("://")[-1] or (not user_info and ":" not in parsed.netloc):
                    try:
                        b64_part = self.link.split("://")[-1].split("#")[0]
                        decoded_full = base64.b64decode(b64_part + "==").decode('utf-8', errors='ignore')
                        if "@" in decoded_full:
                            user_pass_part, host_port_part = decoded_full.split("@", 1)
                            method, password = user_pass_part.split(":", 1)
                            if ":" in host_port_part:
                                host, port = host_port_part.split(":", 1)
                                port = int(port.split("/")[0])
                            else: host, port = host_port_part, 8388
                        else: return None
                    except: return None
                else:
                    user_pass = (parsed.netloc.split("@")[0])
                    try:
                        if ":" in user_pass: 
                            method, password = user_pass.split(":", 1)
                        else:
                            decoded = base64.b64decode(user_pass + "==").decode('utf-8', errors='ignore')
                            method, password = decoded.split(":", 1)
                        host = parsed.hostname
                        port = parsed.port or 8388
                    except: return None
                
                outbound = {
                    "protocol": "shadowsocks",
                    "settings": {"servers": [{"address": host, "port": int(port), "method": method, "password": password}]}
                }
            elif "hysteria2://" in link_lower or "tuic://" in link_lower:
                parsed = urlparse(self.link)
                proto = "hysteria2" if "hysteria2" in link_lower else "tuic"
                outbound = {
                    "protocol": proto,
                    "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "users": [{"password": parsed.username}]}]},
                    "streamSettings": {"network": "udp"}
                }
            
            outbounds: list[dict] = [outbound]
            outbounds.append({"protocol": "freedom", "tag": "direct"})
            config["outbounds"] = outbounds
            return config
        except Exception as e:
            print(f"[DEBUG] Ошибка генерации конфига: {e}")
            return None

    def start_xray(self):
        config = self.generate_xray_config()
        if not config: return False
        config_path = f"config_{self.port}.json"
        with open(config_path, "w") as f:
            json.dump(config, f)
        try:
            self.process = subprocess.Popen([XRAY_PATH, "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.2) # Даем время на бинд порта
            if self.process.poll() is not None:
                self.stop_xray()
                return False
            return True
        except Exception as e:
            print(f"[ERROR] Не удалось запустить Xray: {e}")
            return False

    def stop_xray(self):
        if self.process is not None:
            try:
                self.process.terminate()
                try: self.process.wait(timeout=2)
                except: self.process.kill()
            except: pass
        config_path = f"config_{self.port}.json"
        if os.path.exists(config_path):
            try: os.remove(config_path)
            except: pass

    def check_availability(self):
        proxies = {'http': f'socks5h://127.0.0.1:{self.port}', 'https': f'socks5h://127.0.0.1:{self.port}'}
        try:
            start_time = time.time()
            resp = requests.get(CHECK_URL, proxies=proxies, timeout=CONNECT_TIMEOUT)
            duration = time.time() - start_time
            if resp.status_code == 200:
                has_feature = DISTINCTIVE_FEATURE.lower() in resp.text.lower()
                return True, has_feature, duration
        except: pass
        return False, False, 0

    def check_speed(self):
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{self.port}", "--json"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                download = data.get("download", 0) / 125000 # Convert to Mbps
                ping = data.get("ping", 999)
                if download >= MIN_SPEED_MBPS:
                    return download
        except: pass
        return 0
