import os
import json
import re
import subprocess
import time
import requests
import concurrent.futures
import socket
import base64
import random
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

# ==============================================================================
# CONFIGURATION
# ==============================================================================

SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/ceergo/parss/refs/heads/main/my_stable_configs.txt"
]

# Validation settings
CHECK_URL = "https://gemini.google.com/app?hl=ru"
DISTINCTIVE_FEATURE = "app"

# Output files
WORKING_APP = "working_app.txt"
WORKING_FAST = "working_fast.txt"
OUR_SUBSCRIPTION = "our_subscription.txt"

# Performance & Environment
MAX_WORKERS = 15
MIN_SPEED_MBPS = 0.5
CONNECT_TIMEOUT = 10
DOWNLOAD_TIMEOUT = 30

# Binary paths from Environment (matched with workflow.yml)
XRAY_PATH = os.getenv("XRAY_PATH", "/usr/local/bin/xray")
LIBRESPEED_PATH = os.getenv("LIBRESPEED_PATH", "./librespeed-cli")

PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria2", "tuic"]
UTLS_FINGERPRINTS = ["chrome", "firefox", "safari", "edge", "randomized"]

# ==============================================================================
# PARSING LOGIC
# ==============================================================================

def fetch_remote_subscriptions() -> str:
    """Download data from remote sources."""
    contents = []
    for url in SUBSCRIPTION_URLS:
        try:
            print(f"[LOG] Fetching: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                contents.append(resp.text)
        except Exception as e:
            print(f"[ERROR] Failed to fetch {url}: {e}")
    return "\n".join(contents)

def clean_link(link: str) -> str:
    """Clean proxy link from anchors and joined protocols."""
    if "#" in link:
        link = link.split("#")[0]
    link = link.strip()
    pattern = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    matches = list(re.finditer(pattern, link))
    if len(matches) > 1:
        link = link[:matches[1].start()]
    return link.strip()

def parse_subscriptions(content: str) -> list[str]:
    """Extract proxy links from text and Base64 recursively."""
    found_links = []
    pattern_proto = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    
    def process_text(text: str):
        text = text.strip()
        if not text: return
        starts = [m.start() for m in re.finditer(pattern_proto, text)]
        if starts:
            for i in range(len(starts)):
                s_idx = starts[i]
                e_idx = starts[i+1] if i + 1 < len(starts) else len(text)
                cleaned = clean_link(text[s_idx:e_idx].strip())
                if cleaned: found_links.append(cleaned)
            return
        try:
            b64_data = re.sub(r'[^a-zA-Z0-9+/=]', '', text)
            if len(b64_data) > 10:
                missing_padding = len(b64_data) % 4
                if missing_padding: b64_data += '=' * (4 - missing_padding)
                decoded_str = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
                if re.search(pattern_proto, decoded_str):
                    for line in decoded_str.splitlines(): process_text(line)
        except: pass

    for chunk in content.split():
        process_text(chunk)
    return sorted(list(set(filter(None, found_links))))

def get_free_port():
    """Find an available port on the system."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def setup_binaries():
    """Ensure binaries have execution permissions."""
    for path in [XRAY_PATH, LIBRESPEED_PATH]:
        if os.path.exists(path):
            try:
                os.chmod(path, 0o755)
            except: pass

# ==============================================================================
# CORE CHECKER CLASS
# ==============================================================================

class ProxyChecker:
    def __init__(self, link):
        self.link = link
        self.port = get_free_port()
        self.process = None
        self.config_path = f"c_{self.port}.json"

    def _parse_vmess(self, link):
        try:
            data = link.replace("vmess://", "").strip()
            decoded = base64.b64decode(data + "==").decode('utf-8')
            return json.loads(decoded)
        except: return None

    def generate_xray_config(self):
        """Build Xray JSON configuration from proxy link."""
        try:
            fp = random.choice(UTLS_FINGERPRINTS)
            if fp == "randomized": fp = "chrome"
            
            config = {
                "log": {"loglevel": "none"},
                "inbounds": [{
                    "port": self.port,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True}
                }],
                "outbounds": []
            }

            link_lower = self.link.lower()
            if "vmess://" in link_lower:
                v = self._parse_vmess(self.link)
                if not v: return None
                outbound = {
                    "protocol": "vmess",
                    "settings": {"vnext": [{"address": v["add"], "port": int(v["port"]), "users": [{"id": v["id"]}]}]},
                    "streamSettings": {
                        "network": v.get("net", "tcp"),
                        "security": v.get("tls", "none"),
                        "tlsSettings": {"serverName": v.get("sni", ""), "fingerprint": fp},
                        "wsSettings": {"path": v.get("path", "/")} if v.get("net") == "ws" else {}
                    }
                }
            elif "vless://" in link_lower or "trojan://" in link_lower:
                parsed = urlparse(self.link)
                params = parse_qs(parsed.query)
                proto = "vless" if "vless" in link_lower else "trojan"
                user_id = parsed.username or (parsed.netloc.split("@")[0] if "@" in parsed.netloc else "")
                
                outbound = {
                    "protocol": proto,
                    "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port or 443, 
                                             "users": [{"id": user_id if proto=="vless" else "", 
                                                       "password": unquote(user_id) if proto=="trojan" else "",
                                                       "encryption": "none"}]}]},
                    "streamSettings": {
                        "network": params.get("type", ["tcp"])[0],
                        "security": params.get("security", ["none"])[0],
                        "tlsSettings": {"serverName": params.get("sni", [""])[0], "fingerprint": fp},
                        "realitySettings": {"serverName": params.get("sni", [""])[0], "fingerprint": fp,
                                           "publicKey": params.get("pbk", [""])[0], "shortId": params.get("sid", [""])[0]}
                    }
                }
            elif "ss://" in link_lower:
                parsed = urlparse(self.link)
                outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port or 8388}]}}
            else:
                return None

            config["outbounds"] = [outbound, {"protocol": "freedom", "tag": "direct"}]
            return config
        except: return None

    def start(self):
        cfg = self.generate_xray_config()
        if not cfg: return False
        with open(self.config_path, "w") as f: json.dump(cfg, f)
        try:
            self.process = subprocess.Popen([XRAY_PATH, "-c", self.config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.2)
            return self.process.poll() is None
        except: return False

    def check(self):
        """Verify availability, 'app' feature, and download speed."""
        proxies = {'http': f'socks5h://127.0.0.1:{self.port}', 'https': f'socks5h://127.0.0.1:{self.port}'}
        try:
            resp = requests.get(CHECK_URL, proxies=proxies, timeout=CONNECT_TIMEOUT)
            if resp.status_code == 200:
                is_app = DISTINCTIVE_FEATURE.lower() in resp.text.lower()
                
                # Speed test via Librespeed CLI
                cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{self.port}", "--json"]
                spd_proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT)
                speed = 0
                if spd_proc.returncode == 0:
                    speed = json.loads(spd_proc.stdout).get("download", 0) / 125000 
                
                return True, is_app, speed
        except: pass
        return False, False, 0

    def stop(self):
        if self.process:
            self.process.terminate()
            try: self.process.wait(timeout=2)
            except: self.process.kill()
        if os.path.exists(self.config_path):
            try: os.remove(self.config_path)
            except: pass

def process_link(link):
    """Wrapper for thread-safe proxy checking."""
    checker = ProxyChecker(link)
    try:
        if checker.start():
            alive, is_app, speed = checker.check()
            if alive and speed >= MIN_SPEED_MBPS:
                return {"link": link, "type": "app" if is_app else "fast"}
    except: pass
    finally: checker.stop()
    return None

def update_file(filename, links):
    """Save unique links to a specified file."""
    content = sorted(list(set(filter(None, links))))
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(content) + "\n")

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    print(f"[*] Starting Proxy Checker Bot: {datetime.now()}")
    setup_binaries()
    
    # 1. Collect Links
    raw_data = fetch_remote_subscriptions()
    all_links = parse_subscriptions(raw_data)
    print(f"[*] Total unique links found: {len(all_links)}")
    
    update_file(OUR_SUBSCRIPTION, all_links)
    
    app_results = []
    fast_results = []
    
    # 2. Parallel Processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_link, link): link for link in all_links}
        
        count = 0
        for future in concurrent.futures.as_completed(futures):
            count += 1
            res = future.result()
            if res:
                if res["type"] == "app": app_results.append(res["link"])
                else: fast_results.append(res["link"])
            
            if count % 10 == 0 or count == len(all_links):
                print(f"[PROGRESS] {count}/{len(all_links)} | APP: {len(app_results)} | FAST: {len(fast_results)}")

    # 3. Save Results
    update_file(WORKING_APP, app_results)
    update_file(WORKING_FAST, fast_results)
    
    print(f"[*] Done. Filtered: APP({len(app_results)}), FAST({len(fast_results)})")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[CRITICAL] Main failure: {e}")
