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
import urllib3

# Отключаем предупреждения о SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Безопасный импорт конфига
try:
    import config
except ImportError:
    print("Error: config.py not found!")
    sys.exit(1)

def get_cfg(attr, default=None):
    return getattr(config, attr, default)

# Глобальный Lock для логов
log_lock = threading.Lock()

def atomic_log(msg_list):
    with log_lock:
        print("\n".join(msg_list))
        sys.stdout.flush()

# ================================================================
# IDENTITY & EXTRACTION
# ================================================================

def extract_server_identity(node_string):
    try:
        url_part = node_string.split('#')[0]
        parsed = urlparse(url_part)
        if parsed.scheme == "ss":
            netloc = parsed.netloc
            if "@" in netloc: return netloc.split("@")[1]
            try:
                b64 = netloc
                pad = len(b64) % 4
                if pad: b64 += '=' * (4 - pad)
                dec = base64.b64decode(b64).decode('utf-8', errors='ignore')
                if "@" in dec: return dec.split("@")[1]
            except: pass
        if parsed.hostname and parsed.port: return f"{parsed.hostname}:{parsed.port}"
    except: pass
    return node_string

def industrial_extractor(source_text):
    patterns = {
        'vless': r'vless://[^\s,"]+',
        'vmess': r'vmess://[^\s,"]+',
        'trojan': r'trojan://[^\s,"]+',
        'ss': r'ss://[^\s,"]+',
        'hy2': r'hy2://[^\s,"]+',
        'tuic': r'tuic://[^\s,"]+'
    }
    found = []
    for proto, pattern in patterns.items():
        found.extend(re.findall(pattern, source_text))
    
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{80,}=*', source_text)
    for block in b64_blocks:
        try:
            pad = len(block) % 4
            if pad: block += '=' * (4 - pad)
            decoded = base64.b64decode(block).decode('utf-8', errors='ignore')
            if "://" in decoded: found.extend(industrial_extractor(decoded))
        except: continue
            
    unique = {}
    for node in found:
        node = node.strip().strip(',').strip('"')
        identity = extract_server_identity(node)
        if identity not in unique: unique[identity] = node
    return list(unique.values())

# ================================================================
# XRAY & CHECKER
# ================================================================

class Processor:
    @staticmethod
    def get_free_port():
        pr = get_cfg('XRAY_PORT_RANGE', (12000, 20000))
        for _ in range(20):
            p = random.randint(pr[0], pr[1])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(('127.0.0.1', p)) != 0: return p
        return None

    @staticmethod
    def parse_to_outbound(link):
        try:
            parsed = urlparse(link)
            scheme = parsed.scheme
            fp = random.choice(get_cfg('TLS_FINGERPRINTS', ["chrome", "firefox", "safari"]))
            if scheme == "vmess":
                b64 = link[8:].split('#')[0]
                pad = len(b64) % 4
                if pad: b64 += '=' * (4 - pad)
                data = json.loads(base64.b64decode(b64).decode('utf-8'))
                return {
                    "protocol": "vmess",
                    "settings": {"vnext": [{"address": data["add"], "port": int(data["port"]), "users": [{"id": data["id"], "alterId": int(data.get("aid", 0)), "security": "auto"}]}]},
                    "streamSettings": {
                        "network": data.get("net", "tcp"), "security": "tls" if data.get("tls") == "tls" else "none",
                        "tlsSettings": {"serverName": data.get("sni", ""), "fingerprint": fp} if data.get("tls") == "tls" else {}
                    }
                }
            elif scheme in ["vless", "trojan"]:
                query = parse_qs(parsed.query)
                out = {"protocol": scheme, "settings": {}, "streamSettings": {}}
                if scheme == "vless": out["settings"] = {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [{"id": parsed.username, "encryption": query.get("encryption", ["none"])[0]}]}]}
                else: out["settings"] = {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": parsed.username}]}
                out["streamSettings"] = {"network": query.get("type", ["tcp"])[0], "security": query.get("security", ["none"])[0]}
                sec = out["streamSettings"]["security"]
                if sec in ["tls", "reality"]:
                    key = f"{sec}Settings"
                    out["streamSettings"][key] = {"serverName": query.get("sni", [""])[0], "fingerprint": fp}
                    if sec == "reality": out["streamSettings"][key].update({"publicKey": query.get("pbk", [""])[0], "shortId": query.get("sid", [""])[0], "spiderX": query.get("spx", ["/"])[0]})
                return out
            elif scheme == "ss":
                net = parsed.netloc
                if "@" in net:
                    u, s = net.split("@")
                    pad = len(u) % 4
                    if pad: u += '=' * (4 - pad)
                    try: dec = base64.b64decode(u).decode('utf-8')
                    except: dec = u
                    m, p = dec.split(":") if ":" in dec else (dec, "")
                    h = s.split(":")[0]; pt = int(s.split(":")[1]) if ":" in s else 443
                    return {"protocol": "shadowsocks", "settings": {"servers": [{"address": h, "port": pt, "method": m, "password": p}]}}
        except: pass
        return None

    @staticmethod
    def run_check(link, tid, total):
        ll = []
        def log(m): ll.append(f"[{tid}/{total}] {m}")
        log(f">>> ПРОВЕРКА v8 <<<")
        log(f"[ДО]: {link}")
        
        port = Processor.get_free_port()
        outbound = Processor.parse_to_outbound(link)
        if not port or not outbound:
            log(f"❌ ПРЕРВАНО")
            atomic_log(ll)
            return {"raw": link, "working": False}

        cfg_path = f"temp_{port}.json"
        with open(cfg_path, 'w') as f:
            json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks"}], "outbounds": [outbound]}, f)

        res = {"raw": link, "working": False, "app": False, "ping": 0, "speed": 0.0}
        proc = None
        try:
            proc = subprocess.Popen(["xray", "-config", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2.0)
            proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
            target = random.choice(get_cfg('CHECK_TARGETS', [{"url": "https://gemini.google.com/app?hl=ru", "marker": "app"}]))
            
            # 1. ДОСТУПНОСТЬ
            st = time.time()
            try:
                r = requests.get(target["url"], proxies=proxies, timeout=12, verify=False)
                res["ping"] = int((time.time() - st) * 1000)
                if r.status_code == 200:
                    res["working"] = True
                    if target["marker"] in r.text.lower() or target["marker"] in r.url.lower(): res["app"] = True
            except: pass

            # 2. СКОРОСТЬ
            if res["working"]:
                # Librespeed
                if get_cfg('USE_LIBRESPEED', False):
                    try:
                        args = get_cfg('LIBRESPEED_ARGS', "--json --bytes")
                        ls_cmd = f"librespeed-cli {args} --proxy \"socks5://127.0.0.1:{port}\""
                        ls_res = subprocess.run(ls_cmd, shell=True, capture_output=True, text=True, timeout=20)
                        if ls_res.returncode == 0:
                            data = json.loads(ls_res.stdout)
                            res["speed"] = round(data.get("download", 0), 2)
                    except: pass
                
                # RAW (Используем HTTP для Hetzner во избежание SSL багов)
                if res["speed"] <= 0.0:
                    try:
                        stt = time.time()
                        # Перешли на HTTP
                        r_raw = requests.get("http://speed.hetzner.de/100MB.bin", proxies=proxies, timeout=15, stream=True)
                        size = 0
                        for chunk in r_raw.iter_content(chunk_size=1024*1024):
                            if chunk:
                                size += len(chunk); break
                        dur = time.time() - stt
                        if size > 0 and dur > 0: res["speed"] = round((size / (1024*1024)) / dur, 2)
                    except: pass
        finally:
            if proc:
                try: proc.kill(); proc.wait(timeout=1)
                except: pass
            if os.path.exists(cfg_path):
                try: os.remove(cfg_path)
                except: pass
        
        status = "✅ ЭЛИТА" if res["app"] else ("⚡ РАБОЧИЙ" if res["working"] else "❌ МЕРТВЫЙ")
        log(f"[ИТОГ]: {status} | {res['speed']} MB/s | {res['ping']}ms")
        base = res["raw"].split('#')[0]
        res["final"] = f"{base}#ping:{res['ping']}ms_spd:{res['speed']}MB/s_date:{datetime.now().strftime('%d/%m')}"
        atomic_log(ll)
        return res

def main():
    start = datetime.now()
    safe_log(f"\nСЕССИЯ v8 (Root Files): {start}\n")
    
    all_raw = ""
    # Подписки
    for url in get_cfg('SUBSCRIPTION_URLS', []):
        try:
            r = requests.get(url, timeout=20)
            all_raw += r.text + "\n"
        except: pass
    
    # Локальные файлы из конфига
    for f_path in [get_cfg('RAW_PATH', 'raw.txt'), get_cfg('WORKING_PATH', 'working.txt'), get_cfg('FAST_PATH', 'fast.txt')]:
        if os.path.exists(f_path):
            with open(f_path, 'r', encoding='utf-8') as f: all_raw += f.read() + "\n"

    links = industrial_extractor(all_raw)
    total = len(links)
    safe_log(f"[БАЗА]: {total} уникальных ссылок.\n")

    results = []
    with ThreadPoolExecutor(max_workers=get_cfg('MAX_WORKERS', 12)) as ex:
        futures = [ex.submit(Processor.run_check, l, i+1, total) for i, l in enumerate(links)]
        for f in as_completed(futures):
            try: results.append(f.result())
            except: pass

    elite, work, raw_a = [], [], []
    for r in results:
        if not r.get("working"): continue
        raw_a.append(r["raw"].split('#')[0])
        if r["app"] and r["speed"] >= get_cfg('MIN_SPEED_MBPS', 0.5): elite.append(r["final"])
        elif r["speed"] >= get_cfg('MIN_SPEED_FAST', 0.1): work.append(r["final"])

    with open(get_cfg('RAW_PATH', 'raw.txt'), "w", encoding="utf-8") as f: f.write("\n".join(raw_a))
    with open(get_cfg('WORKING_PATH', 'working.txt'), "w", encoding="utf-8") as f: f.write("\n".join(work))
    with open(get_cfg('FAST_PATH', 'fast.txt'), "w", encoding="utf-8") as f: f.write("\n".join(elite))
    
    safe_log(f"\nЗАВЕРШЕНО ЗА {(datetime.now() - start).seconds}с. Элита: {len(elite)}, Рабочих: {len(work)}")

if __name__ == "__main__":
    main()
