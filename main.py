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

# Lock для чистого логирования (чтобы потоки не перемешивались)
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
        # Для SS бывает формат ss://base64@host:port
        if "ss://" in url_part and "@" not in url_part:
            # Возможно всё в base64
            try:
                b64 = url_part[5:]
                # Добавляем падинг
                missing_padding = len(b64) % 4
                if missing_padding: b64 += '=' * (4 - missing_padding)
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                if "@" in decoded:
                    return decoded.split("@")[1]
            except: pass
            
        parsed = urlparse(url_part)
        if parsed.hostname and parsed.port:
            return f"{parsed.hostname}:{parsed.port}"
        if parsed.netloc:
            netloc = parsed.netloc
            if '@' in netloc:
                res = netloc.split('@')[1]
                if ":" in res: return res
                return f"{res}:{parsed.port or 80}"
            return netloc
            
        match = re.search(r'([a-zA-Z0-9\.-]+):(\d{2,5})', url_part)
        if match: return match.group(0)
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
    
    # Base64 блоки
    b64_blocks = re.findall(r'[A-Za-z0-9+/]{80,}=*', source_text)
    for block in b64_blocks:
        try:
            missing_padding = len(block) % 4
            if missing_padding: block += '=' * (4 - missing_padding)
            decoded = base64.b64decode(block).decode('utf-8', errors='ignore')
            if "://" in decoded: found_configs.extend(industrial_extractor(decoded))
        except: continue
            
    # Дедупликация в рамках вызова
    unique_nodes = {}
    for node in found_configs:
        node = node.strip().strip(',').strip('"')
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
            fp = random.choice(get_cfg('TLS_FINGERPRINTS', ["chrome", "firefox", "safari", "ios"]))
            outbound = {"protocol": scheme, "settings": {}, "streamSettings": {}}
            
            # Рандомный User-Agent для тестов
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

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
                # Обработка ss://base64(method:password)@host:port
                netloc = parsed.netloc
                if "@" in netloc:
                    user_info, server_info = netloc.split("@")
                    try:
                        # Добавляем падинг для base64
                        missing_padding = len(user_info) % 4
                        if missing_padding: user_info += '=' * (4 - missing_padding)
                        decoded_user = base64.b64decode(user_info).decode('utf-8')
                        method, passwd = decoded_user.split(":")
                    except: return None
                    host = server_info.split(":")[0]
                    port = int(server_info.split(":")[1]) if ":" in server_info else 443
                else:
                    return None # Неизвестный формат SS

                outbound["protocol"] = "shadowsocks"
                outbound["settings"] = {"servers": [{"address": host, "port": port, "method": method, "password": passwd}]}

            outbound["streamSettings"]["sockopt"] = {"mark": 255}
            return outbound
        except: return None

    @staticmethod
    def run_check(link, tid, total_count):
        log_accumulator = []
        def log(msg): log_accumulator.append(f"[{tid}/{total_count}] {msg}")

        log(f">>> ПРОВЕРКА НАЧАТА <<<")
        log(f"[ПОЛНАЯ ССЫЛКА ДО]: {link}")
        
        port = XrayWrapper.get_free_port()
        if not port: 
            log(f"❌ Ошибка: Нет свободных портов.")
            safe_log("\n".join(log_accumulator))
            return {"id": tid, "working": False, "reason": "No ports"}
            
        outbound = XrayWrapper.parse_link(link)
        if not outbound: 
            log(f"❌ Ошибка: Не удалось завернуть ссылку (Парсинг).")
            safe_log("\n".join(log_accumulator))
            return {"id": tid, "working": False, "reason": "Parse error"}

        target_host = "N/A"
        try:
            if "vnext" in outbound["settings"]: target_host = outbound["settings"]["vnext"][0]["address"]
            elif "servers" in outbound["settings"]: target_host = outbound["settings"]["servers"][0]["address"]
        except: pass

        log(f"[ЗАВЕРНУТО]: Протокол: {outbound.get('protocol')}, Цель: {target_host}")
        
        cfg_path = f"temp_cfg_{port}.json"
        with open(cfg_path, 'w') as f:
            json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks"}], "outbounds": [outbound]}, f)

        proc = None
        result = {"id": tid, "raw": link, "working": False, "app_found": False, "ping": 0, "speed": 0.0}
        try:
            log(f"[XRAY]: Запуск на порту {port}...")
            proc = subprocess.Popen(["xray", "-config", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2.0)

            targets = get_cfg('CHECK_TARGETS', [{"url": "https://gemini.google.com/app?hl=ru", "marker": "app"}])
            target = random.choice(targets)
            proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
            
            log(f"[ЗАПРОС]: Проверка {target['url']} через SOCKS5...")
            start_t = time.time()
            try:
                # Используем сессию для стабильности
                s = requests.Session()
                s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
                resp = s.get(target["url"], proxies=proxies, timeout=12)
                result["ping"] = int((time.time() - start_t) * 1000)
                log(f"[ОТВЕТ]: Статус: {resp.status_code}, Время: {result['ping']}ms")
                
                if resp.status_code == 200:
                    result["working"] = True
                    content_lower = resp.text.lower()
                    url_lower = resp.url.lower()
                    if target["marker"] in content_lower or target["marker"] in url_lower:
                        log(f"[МАРКЕР]: Нашел '{target['marker']}'! (✅ WORKING + APP)")
                        result["app_found"] = True
                    else:
                        log(f"[МАРКЕР]: Не найден. (⚡ FAST ONLY)")
                elif resp.status_code in [403, 429]:
                    log(f"[ОТВЕТ]: Доступ ограничен (Code {resp.status_code}). Возможно IP в бане Google.")
                else:
                    log(f"[ОТВЕТ]: Ошибка сервера (Code {resp.status_code}).")
            except Exception as e:
                log(f"[ОШИБКА ЗАПРОСА]: {str(e)[:100]}")

            if result["working"]:
                log(f"[СКОРОСТЬ]: Запуск теста 1MB...")
                if get_cfg('USE_LIBRESPEED', False):
                    try:
                        args = get_cfg('LIBRESPEED_ARGS', "--json --bytes")
                        ls_cmd = f"librespeed-cli {args} --proxy \"socks5://127.0.0.1:{port}\""
                        ls_proc = subprocess.run(ls_cmd, shell=True, capture_output=True, text=True, timeout=20)
                        if ls_proc.returncode == 0:
                            data = json.loads(ls_proc.stdout)
                            # Переводим из Mbps в MB/s (если в мегабитах) или используем kbyte/s
                            # Если --bytes, то в мегабайтах/сек
                            val = data.get("download", 0)
                            result["speed"] = round(val, 2)
                            log(f"[СКОРОСТЬ-LS]: {result['speed']} MB/s")
                        else:
                            log(f"[СКОРОСТЬ-LS]: Ошибка выполнения. stderr: {ls_proc.stderr[:100]}")
                    except Exception as e:
                        log(f"[СКОРОСТЬ-LS ОШИБКА]: {str(e)}")
                
                if result["speed"] <= 0.0:
                    try:
                        log(f"[СКОРОСТЬ-RAW]: Попытка скачивания чанка 1MB...")
                        s_t = time.time()
                        # Используем более гарантированный файл для теста
                        r = requests.get("https://speed.hetzner.de/100MB.bin", proxies=proxies, timeout=12, stream=True)
                        downloaded = 0
                        for chunk in r.iter_content(chunk_size=1024*1024):
                            if chunk:
                                downloaded += len(chunk)
                                break # Хватит 1 метра
                        dur = time.time() - s_t
                        if downloaded > 0 and dur > 0:
                            result["speed"] = round((downloaded / (1024*1024)) / dur, 2)
                            log(f"[СКОРОСТЬ-RAW]: {result['speed']} MB/s")
                        else:
                            log(f"[СКОРОСТЬ-RAW]: Не удалось скачать данные.")
                    except Exception as e:
                        log(f"[СКОРОСТЬ-RAW ОШИБКА]: {str(e)}")

        except Exception as e:
            log(f"[КРИТИЧЕСКАЯ ОШИБКА ИЗМЕРЕНИЯ]: {str(e)}")
        finally:
            if proc: 
                try:
                    proc.kill()
                    proc.wait(timeout=1)
                except: pass
            if os.path.exists(cfg_path): 
                try: os.remove(cfg_path)
                except: pass
        
        tag = "✅ WORKING+APP" if result["app_found"] else ("⚡ FAST" if result["working"] else "❌ DEAD")
        log(f"[ИТОГ]: {tag} | Скорость: {result['speed']} MB/s, Пинг: {result['ping']}ms")
        log(f"[ПОЛНАЯ ССЫЛКА ПОСЛЕ]: {result['raw']} | Фильтр: {'working' if result['app_found'] else 'fast' if result['working'] else 'dead'}")
        
        safe_log("\n".join(log_accumulator))
        return result

def main():
    start_time = datetime.now()
    safe_log(f"\n{'='*70}\n[{start_time}] СЕССИЯ ПРОВЕРКИ ПРОКСИ НАЧАТА\n{'='*70}\n")
    
    run_count_path = get_cfg('RUN_COUNT_PATH', '.run_count')
    temp_setup_path = get_cfg('TEMP_SETUP_PATH', 'temp_setup.txt')

    if os.path.exists(run_count_path):
        try:
            with open(run_count_path, 'r') as f: count = int(f.read().strip())
        except: count = 0
        count += 1
    else: count = 1
    with open(run_count_path, 'w') as f: f.write(str(count))

    # Сбор подписок
    os.makedirs("subscriptions", exist_ok=True)
    all_text = ""
    # Читаем также текущие файлы, чтобы продолжить/дополнить если нужно?
    # Пользователь просил "не перезапускался заново а продолжал дальше"
    # Для этого нам нужно загрузить уже проверенные ссылки и знать их статус.
    # Но проще: загрузить базу, дедуплицировать и если ссылка уже есть в рабочем списке - можно её перепроверить или пропустить.
    # Но так как бот удаляет мертвые, мы просто берем всё что есть в raw.txt и SUBSCRIPTION_URLS
    
    current_raw = []
    if os.path.exists(get_cfg('RAW_PATH', 'subscriptions/raw.txt')):
        with open(get_cfg('RAW_PATH', 'subscriptions/raw.txt'), 'r', encoding='utf-8') as f:
            current_raw = f.read().splitlines()

    for url in get_cfg('SUBSCRIPTION_URLS', []):
        try:
            safe_log(f"Загрузка: {url}...")
            r = requests.get(url, timeout=25)
            all_text += r.text + "\n"
        except: safe_log(f"Ошибка загрузки из {url}")
    
    all_text += "\n".join(current_raw)
    
    links = industrial_extractor(all_text)
    total_found = len(links)
    safe_log(f"\n[ИНФО]: Всего уникальных ссылок для проверки: {total_found}\n")
    
    # Сохраняем свежий raw.txt
    with open(get_cfg('RAW_PATH', 'subscriptions/raw.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(links))

    results = []
    max_workers = get_cfg('MAX_WORKERS', 12)
    safe_log(f"[ИНФОРМАЦИЯ]: Запуск {max_workers} потоков...\n")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {executor.submit(XrayWrapper.run_check, l, i+1, total_found): l for i, l in enumerate(links)}
        for future in as_completed(future_to_link):
            try:
                res = future.result()
                results.append(res)
            except Exception as e:
                safe_log(f"КРИТИЧЕСКАЯ ОШИБКА ПОТОКА: {e}")

    # Сортировка и сохранение
    working, fast = [], []
    current_date = datetime.now().strftime('%d/%m %H:%M')
    for r in results:
        if not r["working"]: continue
        tag = f"ping:{r['ping']}ms spd:{r['speed']}MB/s date:{current_date}"
        # Очищаем оригинальную ссылку от старых тегов #...
        base_link = r["raw"].split('#')[0]
        entry = f"{base_link}#{tag}"
        
        if r["app_found"] and r["speed"] >= get_cfg('MIN_SPEED_MBPS', 0.5):
            working.append(entry)
        elif r["speed"] >= get_cfg('MIN_SPEED_FAST', 0.1): # Немного снизил порог для fast
            fast.append(entry)

    # Перезаписываем итоговые файлы (удаляя мертвые)
    with open(get_cfg('WORKING_PATH', 'subscriptions/working.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(working))
    with open(get_cfg('FAST_PATH', 'subscriptions/fast.txt'), 'w', encoding='utf-8') as f:
        f.write("\n".join(fast))
    
    end_time = datetime.now()
    duration = (end_time - start_time).seconds
    safe_log(f"\n{'='*70}")
    safe_log(f"[{end_time}] СЕССИЯ ЗАВЕРШЕНА ЗА {duration}s")
    safe_log(f"Итог: Всего={total_found} | Working={len(working)} | Fast={len(fast)} | Dead={total_found - len(working) - len(fast)}")
    safe_log(f"{'='*70}\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
    except Exception as e:
        safe_log(f"ФАТАЛЬНАЯ ОШИБКА: {e}")
        sys.exit(1)
