import os
import json
import re
import subprocess
import time
import requests
import concurrent.futures
import socket
import base64
import platform
import random
import threading
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
# ==============================================================================
# КОНФИГУРАЦИЯ (Редактируйте здесь)
# ==============================================================================
# Список ссылок на подписки (можно через запятую в кавычках)
SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/ceergo/parss/refs/heads/main/my_stable_configs.txt"
]
# Ссылка для проверки доступности домена
CHECK_URL = "https://gemini.google.com/app?hl=ru"
# Отличительная черта для разделения файлов (ищем это слово в контенте страницы)
DISTINCTIVE_FEATURE = "app"
# Файлы подписок
RAW_SUBSCRIPTION_FILE = "subscription_raw.txt"   # Основной источник (всегда чистится)
OUR_SUBSCRIPTION = "our_subscription.txt"       # Наша копия для обработки
WORKING_APP = "working_app.txt"                 # Результат: есть "app" + скорость
WORKING_FAST = "working_fast.txt"               # Результат: нет "app", но быстрый ответ + скорость
# Параметры проверки
MAX_WORKERS = 10                                # Количество потоков
SPEED_TEST_MB = 1                               # Сколько мегабайт скачивать для теста
MIN_SPEED_MBPS = 0.5                            # Минимальная скорость для WORKING_FAST (Mbps)
UTLS_FINGERPRINTS = ["chrome", "firefox", "safari", "edge", "randomized"]
CONNECT_TIMEOUT = 10                            # Таймаут подключения (сек)
DOWNLOAD_TIMEOUT = 30                           # Таймаут замера скорости (сек)
# Пути к бинарникам
XRAY_PATH = "./xray"
LIBRESPEED_PATH = "./librespeed-cli"
# Протоколы, которые мы ищем (поиск нечувствителен к регистру)
PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria2", "tuic"]
# ==============================================================================
# Глобальные локи
print_lock = threading.Lock()
port_lock = threading.Lock()
def safe_print(msg: str):
    with print_lock:
        print(msg)
def get_free_port():
    """Находит свободный порт в системе (потокобезопасно)."""
    with port_lock:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]
def fetch_remote_subscriptions() -> str:
    """Скачивает подписки из внешних источников и объединяет их."""
    contents: list[str] = []
    for url in SUBSCRIPTION_URLS:
        try:
            safe_print(f"[LOG] Загрузка: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                contents.append(resp.text)
        except Exception as e:
            safe_print(f"[ERROR] Не удалось загрузить {url}: {e}")
    return "\n".join(contents)
def clean_link(link):
    """
    Очищает ссылку: удаляет ВСЁ начиная с символа # (включительно) 
    и обрезает до начала следующего протокола, если они склеены.
    """
    # 1. Удаляем всё от # включительно для поиска протоколов, но сохраняем для возврата
    # Но по правилам бота мы чистим ссылки от комментариев для raw файла
    # Если нужно сохранить имя, можно убрать этот блок. Но пользователь просил "чистку".
    if "#" in link:
        link = link.split("#")[0]
    
    link = link.strip()
    
    # 2. Если в ссылке "прилип" другой протокол в конце, обрезаем его
    pattern = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    matches = list(re.finditer(pattern, link))
    if len(matches) > 1:
        link = link[:matches[1].start()]
    
    return link.strip()
def parse_subscriptions(content: str) -> list[str]:
    """
    Разбирает текст, находит в нём прокси-ссылки. 
    Устойчив к пробелам и переносам строк внутри ссылок (Base64 блоки).
    """
    found_links: list[str] = []
    pattern_proto = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    # Сначала проверяем, не является ли весь контент одним Base64 блоком
    try:
        # Убираем все пробелы и пробуем декодировать
        test_content = re.sub(r'\s+', '', content)
        if not re.search(pattern_proto, content) and len(test_content) > 10:
            missing_padding = len(test_content) % 4
            if missing_padding: test_content += '=' * (4 - missing_padding)
            decoded = base64.b64decode(test_content).decode('utf-8', errors='ignore')
            if re.search(pattern_proto, decoded):
                content = decoded
    except: pass
    # Находим все начала протоколов
    starts = [m.start() for m in re.finditer(pattern_proto, content)]
    
    for i in range(len(starts)):
        s_idx = starts[i]
        e_idx = starts[i+1] if i + 1 < len(starts) else len(content)
        raw_part = content[s_idx:e_idx].strip()
        
        # Если внутри ссылки есть пробелы/переносы (часто в VMESS), убираем их до знака #
        if "#" in raw_part:
            main_part, name_part = raw_part.split("#", 1)
            main_part = re.sub(r'\s+', '', main_part).strip()
            link = main_part + "#" + name_part.strip()
        else:
            link = re.sub(r'\s+', '', raw_part).strip()
            
        cleaned = clean_link(link)
        if cleaned:
            found_links.append(cleaned)
    final_links = sorted(list(set(filter(None, found_links))))
    safe_print(f"[LOG] Извлечено уникальных ссылок: {len(final_links)}")
    return final_links
def download_binaries():
    """Проверка и установка прав на бинарники."""
    safe_print(f"[LOG] Проверка платформы: {platform.system()} {platform.machine()}")
    
    for path in [XRAY_PATH, LIBRESPEED_PATH]:
        if os.path.exists(path):
            try:
                os.chmod(path, 0o755)
                safe_print(f"[LOG] Права 755 установлены для {path}")
            except Exception as e:
                safe_print(f"[ERROR] Ошибка chmod {path}: {e}")
        else:
            safe_print(f"[WARNING] Бинарник {path} не найден!")
class ProxyChecker:
    def __init__(self, link):
        self.link = link
        self.port = get_free_port()
        self.process = None
        self.fingerprint = random.choice(UTLS_FINGERPRINTS)
        if self.fingerprint == "randomized": self.fingerprint = "chrome"
    def _parse_vmess(self, link):
        """Парсинг vmess:// (Base64 JSON)"""
        try:
            data = link.replace("vmess://", "").strip()
            data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
            missing_padding = len(data) % 4
            if missing_padding: data += '=' * (4 - missing_padding)
            decoded = base64.b64decode(data).decode('utf-8')
            return json.loads(decoded)
        except: return None
    def generate_xray_config(self):
        """Генерация конфига Xray для различных протоколов."""
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
            link_lower = self.link.lower()
            outbound = None
            # VMESS
            if "vmess://" in link_lower:
                v = self._parse_vmess(self.link)
                if v:
                    outbound = {
                        "protocol": "vmess",
                        "settings": {"vnext": [{"address": v.get("add"), "port": int(v.get("port", 443)), 
                                               "users": [{"id": v.get("id"), "security": "auto"}]}]},
                        "streamSettings": {
                            "network": v.get("net", "tcp"),
                            "security": v.get("tls", "none"),
                            "tlsSettings": {"serverName": v.get("sni", ""), "fingerprint": self.fingerprint},
                            "wsSettings": {
                                "path": v.get("path", "/"),
                                "headers": {"Host": v.get("host", v.get("sni", ""))}
                            } if v.get("net") == "ws" else {}
                        }
                    }
            # VLESS / Trojan
            elif "vless://" in link_lower or "trojan://" in link_lower:
                parsed = urlparse(self.link)
                params = parse_qs(parsed.query)
                proto = "vless" if "vless://" in link_lower else "trojan"
                
                user_id = parsed.username or ""
                if not user_id and ":" in parsed.netloc:
                    user_id = parsed.netloc.split("@")[0].split(":")[0]
                
                security = params.get("security", ["none"])[0]
                sni = params.get("sni", [parsed.hostname])[0]
                flow = params.get("flow", [""])[0]
                
                outbound = {
                    "protocol": proto,
                    "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port or 443, 
                                             "users": [{"id": user_id if proto=="vless" else "", 
                                                       "password": unquote(user_id) if proto=="trojan" else "",
                                                       "encryption": "none" if proto=="vless" else None,
                                                       "flow": flow if flow else None}]}]},
                    "streamSettings": {
                        "network": params.get("type", ["tcp"])[0],
                        "security": security,
                        "tlsSettings": {"serverName": sni, "fingerprint": self.fingerprint} if security == "tls" else {},
                        "realitySettings": {
                            "serverName": sni,
                            "fingerprint": self.fingerprint,
                            "publicKey": params.get("pbk", [""])[0],
                            "shortId": params.get("sid", [""])[0],
                            "spiderX": params.get("spx", [""])[0]
                        } if security == "reality" else {},
                        "wsSettings": {
                            "path": params.get("path", ["/"])[0],
                            "headers": {"Host": sni}
                        } if params.get("type") == ["ws"] else {}
                    }
                }
            # Shadowsocks
            elif "ss://" in link_lower:
                parsed = urlparse(self.link)
                # Упрощенный парсинг SS (стандарт + b64)
                user_part = parsed.netloc.split("@")[0]
                try:
                    if ":" in user_part:
                        method, password = user_part.split(":", 1)
                    else:
                        decoded = base64.b64decode(user_part + "==").decode('utf-8', errors='ignore')
                        method, password = decoded.split(":", 1)
                    outbound = {
                        "protocol": "shadowsocks",
                        "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port or 8388, 
                                                 "method": method, "password": password}]}
                    }
                except: return None
            if not outbound: return None
            
            config["outbounds"] = [outbound, {"protocol": "freedom", "tag": "direct"}]
            return config
        except Exception as e:
            safe_print(f"[DEBUG] Ошибка генерации конфига: {e}")
            return None
    def start_xray(self):
        config = self.generate_xray_config()
        if not config: return False
        
        config_path = f"config_{self.port}.json"
        with open(config_path, "w") as f:
            json.dump(config, f)
            
        try:
            self.process = subprocess.Popen(
                [XRAY_PATH, "-c", config_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(2.0)
            if self.process.poll() is not None:
                self.stop_xray()
                return False
            return True
        except: return False
    def stop_xray(self):
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                try: self.process.kill()
                except: pass
        
        cp = f"config_{self.port}.json"
        if os.path.exists(cp):
            try: os.remove(cp)
            except: pass
    def check_availability(self):
        proxies = {'http': f'socks5h://127.0.0.1:{self.port}', 'https': f'socks5h://127.0.0.1:{self.port}'}
        try:
            st = time.time()
            resp = requests.get(CHECK_URL, proxies=proxies, timeout=CONNECT_TIMEOUT)
            if resp.status_code == 200:
                return True, DISTINCTIVE_FEATURE.lower() in resp.text.lower(), time.time() - st
        except: pass
        return False, False, 0
    def check_speed(self):
        cmd = [LIBRESPEED_PATH, "--proxy", f"socks5://127.0.0.1:{self.port}", "--json"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT)
            if res.returncode == 0:
                data = json.loads(res.stdout)
                down = data.get("download", 0) / 125000
                if down >= MIN_SPEED_MBPS: return down
        except: pass
        return 0
def process_single_link(link):
    checker = ProxyChecker(link)
    try:
        if not checker.start_xray():
            return {"link": link, "status": "dead"}
        
        alive, has_app, lat = checker.check_availability()
        if alive:
            speed = checker.check_speed()
            if speed > 0:
                status = "working_app" if has_app else "working_fast"
                cat = "APP" if has_app else "FAST"
                file = WORKING_APP if has_app else WORKING_FAST
                safe_print(f"[LIVE] {link.strip()} | {cat} | Ping: {lat*1000:.0f}ms | Speed: {speed:.2f} Mbps -> {file}")
                return {"link": link, "status": status}
            else:
                safe_print(f"[LIVE] {link.strip()} | Медленный | Ping: {lat*1000:.0f}ms")
        else:
            safe_print(f"[LIVE] {link.strip()} | Недоступен (Dead)")
        return {"link": link, "status": "dead"}
    except:
        return {"link": link, "status": "error"}
    finally:
        checker.stop_xray()
def update_file(filename, links):
    existing = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            existing = f.read().splitlines()
    updated = sorted(list(set(filter(None, existing + links))))
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(updated) + "\n")
def main():
    safe_print(f"[LOG] Старт бота: {datetime.now()}")
    download_binaries()
    
    remote = fetch_remote_subscriptions()
    local = ""
    if os.path.exists(RAW_SUBSCRIPTION_FILE):
        with open(RAW_SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            local = f.read()
    
    all_links = parse_subscriptions(remote + "\n" + local)
    update_file(OUR_SUBSCRIPTION, all_links)
    
    results_app, results_fast, working = [], [], []
    count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_link, l): l for l in all_links}
        for future in concurrent.futures.as_completed(futures):
            count += 1
            res = future.result()
            if res and res.get("status") in ["working_app", "working_fast"]:
                l = res.get("link")
                working.append(l)
                if res["status"] == "working_app": results_app.append(l)
                else: results_fast.append(l)
            
            if count % 5 == 0 or count == len(all_links):
                safe_print(f"\n[STATS] {count}/{len(all_links)} | Живых: {len(working)} (APP: {len(results_app)}, FAST: {len(results_fast)})\n")
    update_file(WORKING_APP, results_app)
    update_file(WORKING_FAST, results_fast)
    with open(RAW_SUBSCRIPTION_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(working) + "\n")
if __name__ == "__main__":
    try: main()
    except Exception as e: safe_print(f"[CRITICAL] {e}")
