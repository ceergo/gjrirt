import os
import sys
import re
import base64
import json
import random
import time
import socket
import subprocess
import threading
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Безопасный импорт конфига
try:
    import config
except ImportError:
    print("Error: config.py not found!")
    sys.exit(1)

def get_cfg(attr, default=None):
    return getattr(config, attr, default)

# ================================================================
# IDENTITY & EXTRACTION
# ================================================================

def extract_server_identity(node_string):
    try:
        url_part = node_string.split('#')[0]
        parsed = urlparse(url_part)
        if parsed.netloc:
            netloc = parsed.netloc
            return netloc.split('@')[1] if '@' in netloc else netloc
        match = re.search(r'@([^:/]+):(\d+)', node_string)
        if match: return f"{match.group(1)}:{match.group(2)}"
    except: pass
    return node_string

def industrial_extractor(source_text):
    patterns = {
        'vless': r'vless://[^\s]+',
        'vmess': r'vmess://[^\s]+',
        'trojan': r'trojan://[^\s]+',
        'ss': r'ss://[^\s]+',
        'hy2': r'hy2://[^\s]+',
        'tuic': r'tuic://[^\s]+'
    }
    found_configs = []
    for proto, pattern in patterns.items():
        found_configs.extend(re.findall(pattern, source_text))
    
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{50,}=*', source_text)
    for block in b64_blocks:
        try:
            missing_padding = len(block) % 4
            if missing_padding: block += '=' * (4 - missing_padding)
            decoded = base64.b64decode(block).decode('utf-8', errors='ignore')
            if "://" in decoded: found_configs.extend(industrial_extractor(decoded))
        except: continue
            
    unique_nodes = {}
    for node in found_configs:
        node = node.strip().strip(',')
        identity = extract_server_identity(node)
        if identity not in unique_nodes: unique_nodes[identity] = node
    return list(unique_nodes.values())

# ================================================================
# XRAY CONFIG GENERATOR
# ================================================================

class XrayWrapper:
    @staticmethod
    def get_free_port():
        port_range = get_cfg('XRAY_PORT_RANGE', (12000, 20000))
        for _ in range(15):
            port = random.randint(port_range[0], port_range[1])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(('127.0.0.1', port)) != 0: return port
        return None

    @staticmethod
    def parse_link(link):
        try:
            parsed = urlparse(link)
            scheme = parsed.scheme
            fp = random.choice(get_cfg('TLS_FINGERPRINTS', ["chrome", "firefox", "safari"]))
            outbound = {"protocol": scheme, "settings": {}, "streamSettings": {}}
            
            if scheme == "vmess":
                data = json.loads(base64.b64decode(link[8:].split('#')[0]).decode('utf-8'))
                outbound = {
                    "protocol": "vmess",
                    "settings": {"vnext": [{"address": data["add"], "port": int(data["port"]), "users": [{"id": data["id"], "alterId": int(data.get("aid", 0)), "security": "auto"}]}]},
                    "streamSettings": {
                        "network": data.get("net", "tcp"),
                        "security": "tls" if data.get("tls") == "tls" else "none",
                        "tlsSettings": {"serverName": data.get("sni", ""), "fingerprint": fp} if data.get("tls") == "tls" else {}
                    }
                }
                if data.get("net") == "ws":
                    outbound["streamSettings"]["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", data.get("add"))}}
            elif scheme == "vless":
                query = parse_qs(parsed.query)
                outbound["settings"] = {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [{"id": parsed.username, "encryption": query.get("encryption", ["none"])[0]}]}]}
                outbound["streamSettings"] = {"network": query.get("type", ["tcp"])[0], "security": query.get("security", ["none"])[0]}
                sec = outbound["streamSettings"]["security"]
                if sec in ["tls", "reality"]:
                    key = f"{sec}Settings"
                    outbound["streamSettings"][key] = {"serverName": query.get("sni", [""])[0], "fingerprint": fp}
                    if sec == "reality":
                        outbound["streamSettings"][key].update({"publicKey": query.get("pbk", [""])[0], "shortId": query.get("sid", [""])[0], "spiderX": query.get("spx", ["/"])[0]})
                if outbound["streamSettings"]["network"] == "ws":
                    outbound["streamSettings"]["wsSettings"] = {"path": query.get("path", ["/"])[0], "headers": {"Host": query.get("host", [""])[0]}}
            elif scheme == "trojan":
                query = parse_qs(parsed.query)
                outbound["settings"] = {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": parsed.username}]}
                outbound["streamSettings"] = {"security": "tls", "tlsSettings": {"serverName": query.get("sni", [""])[0], "fingerprint": fp}}
            elif scheme == "ss":
                try:
                    import base64
                    decoded_ss = base64.b64decode(parsed.netloc.split('@')[0]).decode('utf-8')
                    method, passwd = decoded_ss.split(':')
                    outbound["protocol"] = "shadowsocks"
                    outbound["settings"] = {"servers": [{"address": parsed.hostname, "port": parsed.port, "method": method, "password": passwd}]}
                except: return None

            outbound["streamSettings"]["sockopt"] = {"mark": 255}
            return outbound
        except: return None

    @staticmethod
    def run_check(link, tid, total_count):
        log_prefix = f"[{tid}/{total_count}]"
        print(f"\n{log_prefix} >>> NEW CHECK START <<<")
        print(f"{log_prefix} [BEFORE]: {link[:80]}...")
        
        port = XrayWrapper.get_free_port()
        if not port: 
            print(f"{log_prefix} ❌ Error: No available ports found.")
            return {"id": tid, "working": False, "reason": "No ports"}
            
        outbound = XrayWrapper.parse_link(link)
        if not outbound: 
            print(f"{log_prefix} ❌ Error: Parsing/Wrapping failed.")
            return {"id": tid, "working": False, "reason": "Parse error"}

        print(f"{log_prefix} [WRAPPED]: Protocol: {outbound.get('protocol')}, Target: {outbound.get('settings', {}).get('vnext', [{'address': 'N/A'}])[0].get('address')}")
        
        cfg_path = f"temp_cfg_{port}.json"
        with open(cfg_path, 'w') as f:
            json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks"}], "outbounds": [outbound]}, f)

        proc = None
        result = {"id": tid, "raw": link, "working": False, "app_found": False, "ping": 0, "speed": 0.0}
        try:
            print(f"{log_prefix} [XRAY]: Starting process on port {port}...")
            proc = subprocess.Popen(["xray", "-config", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.5)

            targets = get_cfg('CHECK_TARGETS', [{"url": "https://www.google.com", "marker": "google"}])
            target = random.choice(targets)
            proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
            
            print(f"{log_prefix} [CHECK]: Pinging {target['url']} via SOCKS5...")
            start_t = time.time()
            try:
                resp = requests.get(target["url"], proxies=proxies, timeout=10)
                result["ping"] = int((time.time() - start_t) * 1000)
                print(f"{log_prefix} [RESPONSE]: Status: {resp.status_code}, Time: {result['ping']}ms")
                
                if resp.status_code == 200:
                    result["working"] = True
                    if target["marker"] in resp.text.lower():
                        print(f"{log_prefix} [MARKER]: Found '{target['marker']}' in response! (✅ WORKING + APP)")
                        result["app_found"] = True
                    else:
                        print(f"{log_prefix} [MARKER]: Not found. (⚡ FAST ONLY)")
                else:
                    print(f"{log_prefix} [RESPONSE]: Failed (Code {resp.status_code}).")
            except Exception as e:
                print(f"{log_prefix} [CHECK ERROR]: {str(e)[:50]}")

            if result["working"]:
                print(f"{log_prefix} [SPEEDTEST]: Running 1MB download test...")
                if get_cfg('USE_LIBRESPEED', False):
                    try:
                        args = get_cfg('LIBRESPEED_ARGS', "--json")
                        ls_cmd = f"librespeed-cli {args} --proxy \"socks5://127.0.0.1:{port}\""
                        ls_proc = subprocess.run(ls_cmd, shell=True, capture_output=True, text=True, timeout=15)
                        if ls_proc.returncode == 0:
                            data = json.loads(ls_proc.stdout)
                            result["speed"] = round(data.get("download", 0) / 8, 2)
                            print(f"{log_prefix} [SPEED-LS]: {result['speed']} MB/s")
                    except: pass
                
                if result["speed"] <= 0.0:
                    try:
                        s_t = time.time()
                        r = requests.get("https://speed.hetzner.de/100MB.bin", proxies=proxies, timeout=10, stream=True)
                        for chunk in r.iter_content(1024 * 1024):
                            if chunk: break
                        dur = time.time() - s_t
                        result["speed"] = round(1.0 / dur, 2) if dur > 0 else 0.1
                        print(f"{log_prefix} [SPEED-RAW]: {result['speed']} MB/s")
                    except: pass

        except Exception as e:
            print(f"{log_prefix} [FATAL]: {str(e)}")
        finally:
            if proc: 
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except: pass
            if os.path.exists(cfg_path): 
                try: os.remove(cfg_path)
                except: pass
        
        final_status = "✅" if result["working"] else "❌"
        app_tag = " [APP]" if result["app_found"] else ""
        print(f"{log_prefix} [FINAL]: {final_status}{app_tag} Speed: {result['speed']} MB/s, Ping: {result['ping']}ms")
        return result

def main():
    start_time = datetime.now()
    print(f"\n================================================================")
    print(f"[{start_time}] >>> EXTREME PROXY CHECKER SESSION START <<<")
    print(f"================================================================\n")
    
    run_count_path = get_cfg('RUN_COUNT_PATH', '.run_count')
    temp_setup_path = get_cfg('TEMP_SETUP_PATH', 'temp_setup.txt')

    if os.path.exists(run_count_path):
        try:
            with open(run_count_path, 'r') as f: count = int(f.read().strip())
        except: count = 0
        count += 1
    else: count = 1
    with open(run_count_path, 'w') as f: f.write(str(count))
    
    if count >= 2 and os.path.exists(temp_setup_path):
        os.remove(temp_setup_path)
        print(f"--- Cleanup: {temp_setup_path} deleted (Run #{count}) ---\n")

    os.makedirs("subscriptions", exist_ok=True)
    all_text = ""
    for url in get_cfg('SUBSCRIPTION_URLS', []):
        try:
            print(f"Fetching source: {url}...")
            r = requests.get(url, timeout=20)
            all_text += r.text + "\n"
        except: print(f"Failed to fetch content from {url}")
    
    links = industrial_extractor(all_text)
    total_found = len(links)
    print(f"\n[INFO]: Total unique links discovered: {total_found}")
    
    with open(get_cfg('RAW_PATH', 'subscriptions/raw.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(links))

    results = []
    max_workers = get_cfg('MAX_WORKERS', 12)
    print(f"[INFO]: Starting parallel verification using {max_workers} threads...\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {executor.submit(XrayWrapper.run_check, l, i+1, total_found): l for i, l in enumerate(links)}
        
        for future in as_completed(future_to_link):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                print(f"CRITICAL THREAD ERROR: {e}")

    # Sorting
    working, fast = [], []
    current_date = datetime.now().strftime('%d/%m %H:%M')
    for r in results:
        if not r["working"]: continue
        tag = f"ping:{r['ping']}ms spd:{r['speed']}MB/s date:{current_date}"
        entry = f"{r['raw'].split('#')[0]}#{tag}"
        if r["app_found"] and r["speed"] >= get_cfg('MIN_SPEED_MBPS', 0.5):
            working.append(entry)
        elif r["speed"] >= get_cfg('MIN_SPEED_FAST', 0.2):
            fast.append(entry)

    with open(get_cfg('WORKING_PATH', 'subscriptions/working.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(working))
    with open(get_cfg('FAST_PATH', 'subscriptions/fast.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(fast))
    
    end_time = datetime.now()
    duration = (end_time - start_time).seconds
    print(f"\n================================================================")
    print(f"[{end_time}] >>> SESSION FINISHED in {duration}s <<<")
    print(f"Total: {total_found} | Working: {len(working)} | Fast: {len(fast)} | Dead: {total_found - len(working) - len(fast)}")
    print(f"================================================================\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
    except Exception as e:
        print(f"FATAL REBOOT ERROR: {e}")
        sys.exit(1)
