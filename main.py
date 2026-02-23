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

# Отключаем предупреждения об SSL (для замера скорости без проверки сертификата)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Безопасный импорт конфига
try:
    import config
except ImportError:
    print("Error: config.py not found!")
    sys.exit(1)

def get_cfg(attr, default=None):
    return getattr(config, attr, default)

# Lock для чистого логирования
log_lock = threading.Lock()

def safe_log(msg):
    with log_lock:
        print(msg)
        sys.stdout.flush()

# ================================================================
# IDENTITY & EXTRACTION
# ================================================================

def extract_server_identity(node_string):
    """Извлечение хоста и порта для предотвращения дублей."""
    try:
        url_part = node_string.split('#')[0]
        parsed = urlparse(url_part)
        
        # Shadowsocks специальная обработка
        if parsed.scheme == "ss":
            netloc = parsed.netloc
            if "@" in netloc:
                server_info = netloc.split("@")[1]
                return server_info
            else:
                # Возможно ss://base64(method:pass@host:port)
                try:
                    b64 = netloc
                    missing_padding = len(b64) % 4
                    if missing_padding: b64 += '=' * (4 - missing_padding)
                    decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                    if "@" in decoded: return decoded.split("@")[1]
                except: pass
        
        if parsed.hostname and parsed.port:
            return f"{parsed.hostname}:{parsed.port}"
        if parsed.netloc:
            netloc = parsed.netloc
            if '@' in netloc:
                return netloc.split('@')[1]
            return netloc
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
    found_configs = []
    for proto, pattern in patterns.items():
        found_configs.extend(re.findall(pattern, source_text))
    
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{80,}=*', source_text)
    for block in b64_blocks:
        try:
            missing_padding = len(block) % 4
            if missing_padding: block += '=' * (4 - missing_padding)
            decoded = base64.b64decode(block).decode('utf-8', errors='ignore')
            if "://" in decoded: found_configs.extend(industrial_extractor(decoded))
        except: continue
            
    # Дедупликация по Host:Port
    unique_nodes = {}
    for node in found_configs:
        node = node.strip().strip(',').strip('"')
        identity = extract_server_identity(node)
        if identity not in unique_nodes: 
            unique_nodes[identity] = node
    return list(unique_nodes.values())

# ================================================================
# XRAY CONFIG GENERATOR
# ================================================================

class XrayWrapper:
    @staticmethod
    def get_free_port():
        port_range = get_cfg('XRAY_PORT_RANGE', (12000, 20000))
        for _ in range(20):
            port = random.randint(port_range[0], port_range[1])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex(('127.0.0.1', port)) != 0: return port
        return None

    @staticmethod
    def parse_link(link):
        try:
            parsed = urlparse(link)
            scheme = parsed.scheme
            fp = random.choice(get_cfg('TLS_FINGERPRINTS', ["chrome", "firefox", "safari"]))
            outbound = {"protocol": scheme, "settings": {}, "streamSettings": {}}
            
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

            if scheme == "vmess":
                # VMESS base64 part
                b64_part = link[8:].split('#')[0]
                missing_padding = len(b64_part) % 4
                if missing_padding: b64_part += '=' * (4 - missing_padding)
                data = json.loads(base64.b64decode(b64_part).decode('utf-8'))
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
                    outbound["streamSettings"]["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", data.get("add")), "User-Agent": ua}}

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
                    outbound["streamSettings"]["wsSettings"] = {"path": query.get("path", ["/"])[0], "headers": {"Host": query.get("host", [""])[0], "User-Agent": ua}}

            elif scheme == "trojan":
                query = parse_qs(parsed.query)
                outbound["settings"] = {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": parsed.username}]}
                outbound["streamSettings"] = {"security": "tls", "tlsSettings": {"serverName": query.get("sni", [""])[0], "fingerprint": fp}}
            
            elif scheme == "ss":
                netloc = parsed.netloc
                if "@" in netloc:
                    user_info, server_info = netloc.split("@")
                    try:
                        missing_padding = len(user_info) % 4
                        if missing_padding: user_info += '=' * (4 - missing_padding)
                        decoded_user = base64.b64decode(user_info).decode('utf-8')
                        method, passwd = decoded_user.split(":")
                    except:
                        # Возможно user_info это plain method:pass
                        if ":" in user_info:
                            method, passwd = user_info.split(":")
                        else: return None
                    host = server_info.split(":")[0]
                    port = int(server_info.split(":")[1]) if ":" in server_info else 443
                else:
                    # Возможно ss://base64(method:pass@host:port)
                    try:
                        b64 = netloc
                        missing_padding = len(b64) % 4
                        if missing_padding: b64 += '=' * (4 - missing_padding)
                        data = base64.b64decode(b64).decode('utf-8')
                        user, server = data.split("@")
                        method, passwd = user.split(":")
                        host, port = server.split(":")
                        port = int(port)
                    except: return None

                outbound["protocol"] = "shadowsocks"
                outbound["settings"] = {"servers": [{"address": host, "port": port, "method": method, "password": passwd}]}

            outbound["streamSettings"]["sockopt"] = {"mark": 255}
            return outbound
        except: return None

    @staticmethod
    def run_check(link, tid, total_count):
        log_lines = []
        def log(msg): log_lines.append(f"[{tid}/{total_count}] {msg}")

        log(f">>> ПРОВЕРКА НАЧАТА <<<")
        log(f"[ПОЛНАЯ ССЫЛКА ДО]: {link}")
        
        port = XrayWrapper.get_free_port()
        if not port: 
            log("❌ Ошибка: Нет свободных портов.")
            safe_log("\n".join(log_lines))
            return {"id": tid, "working": False}
            
        outbound = XrayWrapper.parse_link(link)
        if not outbound: 
            log("❌ Ошибка: Парсинг не удался.")
            safe_log("\n".join(log_lines))
            return {"id": tid, "working": False}

        log(f"[ЗАВЕРНУТО]: {outbound.get('protocol')}")
        
        cfg_path = f"temp_cfg_{port}.json"
        with open(cfg_path, 'w') as f:
            json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks"}], "outbounds": [outbound]}, f)

        proc = None
        result = {"id": tid, "raw": link, "working": False, "app_found": False, "ping": 0, "speed": 0.0}
        try:
            proc = subprocess.Popen(["xray", "-config", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2.0)

            targets = get_cfg('CHECK_TARGETS', [{"url": "https://gemini.google.com/app?hl=ru", "marker": "app"}])
            target = random.choice(targets)
            proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
            
            start_t = time.time()
            try:
                s = requests.Session()
                s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
                resp = s.get(target["url"], proxies=proxies, timeout=12)
                result["ping"] = int((time.time() - start_t) * 1000)
                log(f"[ОТВЕТ]: {resp.status_code}, {result['ping']}ms")
                
                if resp.status_code == 200:
                    result["working"] = True
                    if target["marker"] in resp.text.lower() or target["marker"] in resp.url.lower():
                        log(f"[МАРКЕР]: Нашел '{target['marker']}'! ✅")
                        result["app_found"] = True
            except Exception as e:
                log(f"[ОШИБКА ЗАПРОСА]: {str(e)[:100]}")

            if result["working"]:
                # ТЕСТ СКОРОСТИ
                if get_cfg('USE_LIBRESPEED', False):
                    try:
                        args = get_cfg('LIBRESPEED_ARGS', "--json --bytes")
                        ls_cmd = f"librespeed-cli {args} --proxy \"socks5://127.0.0.1:{port}\""
                        ls_proc = subprocess.run(ls_cmd, shell=True, capture_output=True, text=True, timeout=20)
                        if ls_proc.returncode == 0:
                            data = json.loads(ls_proc.stdout)
                            result["speed"] = round(data.get("download", 0), 2)
                            log(f"[СКОРОСТЬ-LS]: {result['speed']} MB/s")
                    except: pass
                
                if result["speed"] <= 0.0:
                    try:
                        s_t = time.time()
                        # Hetzner SSL fix: verify=False
                        r = requests.get("https://speed.hetzner.de/100MB.bin", proxies=proxies, timeout=12, stream=True, verify=False)
                        downloaded = 0
                        for chunk in r.iter_content(chunk_size=1024*1024):
                            if chunk:
                                downloaded += len(chunk)
                                break
                        dur = time.time() - s_t
                        if downloaded > 0 and dur > 0:
                            result["speed"] = round((downloaded / (1024*1024)) / dur, 2)
                            log(f"[СКОРОСТЬ-RAW]: {result['speed']} MB/s")
                    except: pass

        finally:
            if proc: 
                try: proc.kill(); proc.wait(timeout=1)
                except: pass
            if os.path.exists(cfg_path):
                try: os.remove(cfg_path)
                except: pass
        
        status_tag = "✅ WORKING+APP" if result["app_found"] else ("⚡ FAST" if result["working"] else "❌ DEAD")
        log(f"[ИТОГ]: {status_tag} | {result['speed']} MB/s | {result['ping']}ms")
        log(f"[ПОЛНАЯ ССЫЛКА ПОСЛЕ]: {result['raw']}")
        
        safe_log("\n".join(log_lines))
        return result

def main():
    start_time = datetime.now()
    safe_log(f"\n{'='*70}\nСЕССИЯ {start_time}\n{'='*70}\n")
    
    os.makedirs("subscriptions", exist_ok=True)
    
    # 1. Загрузка всех источников
    all_content = ""
    for url in get_cfg('SUBSCRIPTION_URLS', []):
        try:
            r = requests.get(url, timeout=25)
            all_content += r.text + "\n"
        except: pass
    
    # Загружаем текущие файлы ПЕРЕД очисткой (для пополнения базы)
    for f_path in [get_cfg('RAW_PATH', 'subscriptions/raw.txt'), 
                  get_cfg('WORKING_PATH', 'subscriptions/working.txt'), 
                  get_cfg('FAST_PATH', 'subscriptions/fast.txt')]:
        if os.path.exists(f_path):
            with open(f_path, 'r', encoding='utf-8') as f:
                all_content += f.read() + "\n"

    # 2. Очистка и дедупликация (удаление мертвых по факту перезаписи)
    links = industrial_extractor(all_content)
    total_found = len(links)
    safe_log(f"\n[БАЗА]: {total_found} уникальных прокси.\n")

    # 3. Проверка
    results = []
    max_workers = get_cfg('MAX_WORKERS', 12)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {executor.submit(XrayWrapper.run_check, l, i+1, total_found): l for i, l in enumerate(links)}
        for future in as_completed(future_to_link):
            try:
                res = future.result()
                results.append(res)
            except: pass

    # 4. Сохранение (Перезапись = удаление нерабочих)
    working, fast, raw_new = [], [], []
    current_date = datetime.now().strftime('%d/%m %H:%M')
    
    for r in results:
        if not r.get("working"): continue
        base = r["raw"].split('#')[0]
        tag = f"ping:{r['ping']}ms spd:{r['speed']}MB/s date:{current_date}"
        full = f"{base}#{tag}"
        
        raw_new.append(base) # В raw храним базу без тегов
        if r.get("app_found") and r["speed"] >= get_cfg('MIN_SPEED_MBPS', 0.5):
            working.append(full)
        elif r["speed"] >= get_cfg('MIN_SPEED_FAST', 0.1):
            fast.append(full)

    with open(get_cfg('RAW_PATH', 'subscriptions/raw.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(raw_new))
    with open(get_cfg('WORKING_PATH', 'subscriptions/working.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(working))
    with open(get_cfg('FAST_PATH', 'subscriptions/fast.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(fast))
    
    end_time = datetime.now()
    safe_log(f"\n{'='*70}\nЗАВЕРШЕНО ЗА {(end_time - start_time).seconds}s\nРабочих: {len(working)}, Быстрых: {len(fast)}\n{'='*70}\n")

if __name__ == "__main__":
    main()
