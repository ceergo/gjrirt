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
def fetch_remote_subscriptions() -> str:
    """Скачивает подписки из внешних источников и объединяет их."""
    contents: list[str] = []
    for url in SUBSCRIPTION_URLS:
        try:
            print(f"[LOG] Загрузка: {url}")
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                contents.append(resp.text)
        except Exception as e:
            print(f"[ERROR] Не удалось загрузить {url}: {e}")
    return "\n".join(contents)
def clean_link(link):
    """
    Очищает ссылку: удаляет ВСЁ начиная с символа # (включительно) 
    и обрезает до начала следующего протокола, если они склеены.
    """
    # 1. Удаляем всё от # включительно
    if "#" in link:
        link = link.split("#")[0]
    
    link = link.strip()
    
    # 2. Если в ссылке "прилип" другой протокол в конце, обрезаем его
    # Пример: vmess://...vless://... -> берем только vmess://...
    pattern = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    matches = list(re.finditer(pattern, link))
    if len(matches) > 1:
        # Если найдено больше одного начала протокола, обрезаем вторую часть
        link = link[:matches[1].start()]
    
    return link.strip()
def parse_subscriptions(content: str) -> list[str]:
    """
    Разбирает текст, находит в нём прокси-ссылки. 
    Поддерживает: прямое перечисление, Base64 (включая вложенные блоки).
    """
    found_links: list[str] = []
    
    # Регулярка для поиска начала протокола
    pattern_proto = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    def process_text(text: str):
        text = text.strip()
        if not text:
            return
        # 1. Если в тексте есть явные ссылки, вырезаем их
        starts = [m.start() for m in re.finditer(pattern_proto, text)]
        if starts:
            for i in range(len(starts)):
                s_idx = starts[i]
                # Гарантируем, что e_idx всегда определен
                if i + 1 < len(starts):
                    e_idx = starts[i+1]
                else:
                    e_idx = len(text)
                
                chunk = text[s_idx:e_idx].strip()
                cleaned = clean_link(chunk)
                if cleaned:
                    found_links.append(cleaned)
            return
        # 2. Если ссылок нет, возможно это Base64 блок
        # Пробуем декодировать (убираем лишние пробелы и добавляем паддинг)
        try:
            # Очищаем от мусорных символов, которые могут быть в Base64
            b64_data = re.sub(r'[^a-zA-Z0-9+/=]', '', text)
            if len(b64_data) > 10:
                missing_padding = len(b64_data) % 4
                if missing_padding:
                    b64_data += '=' * (4 - missing_padding)
                
                decoded_bytes = base64.b64decode(b64_data)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
                # Если после декодирования нашли ссылки - отлично
                if re.search(pattern_proto, decoded_str):
                    # Рекурсивно обрабатываем декодированный текст (на случай новых b64 внутри)
                    # Разрезаем по строкам, чтобы не уйти в бесконечную рекурсию на плохих данных
                    for line in decoded_str.splitlines():
                        process_text(line)
        except:
            pass
    # Первоначальный разбор (делим по пробелам и переносам, чтобы ловить блоки b64)
    chunks = content.split()
    for c in chunks:
        process_text(c)
    final_links = sorted(list(set(filter(None, found_links))))
    return final_links
# Импорты перенесены в начало файла
def get_free_port():
    """Находит свободный порт в системе."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]
def download_binaries():
    """
    Автоматически скачивает xray и librespeed-cli под текущую систему.
    """
    import platform
    print(f"[LOG] Проверка платформы: {platform.system()} {platform.machine()}")
    # В GitHub Actions эти файлы обычно добавляются через setup-xray или curl в yml
    # Здесь мы просто проверяем их наличие.
    if os.path.exists(XRAY_PATH):
        try:
            os.chmod(XRAY_PATH, 0o755)
            print(f"[LOG] Права на выполнение для {XRAY_PATH} установлены.")
        except Exception as e:
            print(f"[ERROR] Не удалось установить права для {XRAY_PATH}: {e}")
    else:
        print(f"[WARNING] {XRAY_PATH} не найден.")
        
    if os.path.exists(LIBRESPEED_PATH):
        try:
            os.chmod(LIBRESPEED_PATH, 0o755)
            print(f"[LOG] Права на выполнение для {LIBRESPEED_PATH} установлены.")
        except Exception as e:
            print(f"[ERROR] Не удалось установить права для {LIBRESPEED_PATH}: {e}")
    else:
        print(f"[WARNING] {LIBRESPEED_PATH} не найден.")
class ProxyChecker:
    def __init__(self, link):
        self.link = link
        self.port = get_free_port()
        self.process: subprocess.Popen | None = None
        self.fingerprint = "chrome"
        
    def _parse_vmess(self, link):
        """Парсинг vmess:// links (Base64 JSON)"""
        try:
            data = link.replace("vmess://", "").strip()
            # Очищаем от мусора и исправляем паддинг
            data = re.sub(r'[^a-zA-Z0-9+/=]', '', data)
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(data).decode('utf-8')
            return json.loads(decoded)
        except Exception as e:
            # print(f"[DEBUG] VMESS parse error: {e}")
            return None
    def generate_xray_config(self):
        """
        Генерирует конфиг для Xray. 
        Поддерживает VLESS, VMESS, Trojan, Shadowsocks, Hysteria2, TUIC.
        """
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
            # Логика обертки (базовая реализация для примера, 
            # в реальности требует тщательного маппинга полей)
            outbound = {"protocol": "vless", "settings": {}, "streamSettings": {}}
            
            # Рандомизация отпечатка
            import random
            self.fingerprint = random.choice(UTLS_FINGERPRINTS)
            if self.fingerprint == "randomized": self.fingerprint = "chrome"
            # Определение протокола
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
                
                # Базовые настройки безопасности
                security = params.get("security", ["none"])[0]
                sni = params.get("sni", [""])[0]
                fp = params.get("fp", [self.fingerprint])[0]
                
                # Попытка извлечь UUID / Пароль
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
                            "serverName": sni,
                            "fingerprint": fp,
                            "publicKey": params.get("pbk", [""])[0],
                            "shortId": params.get("sid", [""])[0],
                            "spiderX": params.get("spx", [""])[0]
                        } if security == "reality" else {},
                        "wsSettings": {"path": params.get("path", ["/"])[0], "headers": {"Host": sni}} if params.get("type") == ["ws"] else {},
                        "grpcSettings": {"serviceName": params.get("serviceName", [""])[0]} if params.get("type") == ["grpc"] else {}
                    }
                }
            # Shadowsocks
            elif "ss://" in link_lower:
                # ss://method:password@host:port#name
                # Могут быть ссылки ss://BASE64(method:password@host:port)
                # или ss://BASE64(method:password)@host:port
                parsed = urlparse(self.link)
                user_info = parsed.username or ""
                
                if "@" not in self.link.split("://")[-1] or (not user_info and ":" not in parsed.netloc):
                    # Похоже на полный Base64 ss://BASE64
                    try:
                        b64_part = self.link.split("://")[-1].split("#")[0]
                        decoded_full = base64.b64decode(b64_part + "==").decode('utf-8', errors='ignore')
                        if "@" in decoded_full:
                            # Теперь это method:password@host:port
                            user_pass_part, host_port_part = decoded_full.split("@", 1)
                            method, password = user_pass_part.split(":", 1)
                            if ":" in host_port_part:
                                host, port = host_port_part.split(":", 1)
                                port = int(port.split("/")[0])
                            else:
                                host, port = host_port_part, 8388
                        else:
                            return None
                    except: return None
                else:
                    # Стандартный формат или b64-userinfo
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
                    "settings": {"servers": [{"address": host, "port": int(port), 
                                             "method": method, "password": password}]}
                }
            
            # Hysteria2 / TUIC (упрощенно)
            elif "hysteria2://" in link_lower or "tuic://" in link_lower:
                parsed = urlparse(self.link)
                proto = "hysteria2" if "hysteria2" in link_lower else "tuic"
                outbound = {
                    "protocol": proto,
                    "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, 
                                             "users": [{"password": parsed.username}]}]},
                    "streamSettings": {"network": "udp"}
                }
            
            # Собираем список outbound-объектов
            outbounds: list[dict] = [outbound]
            outbounds.append({"protocol": "freedom", "tag": "direct"})
            
            config["outbounds"] = outbounds
            return config
        except Exception as e:
            print(f"[DEBUG] Ошибка генерации конфига: {e}")
            return None
    def start_xray(self):
        """Запуск процесса Xray"""
        config = self.generate_xray_config()
        if not config: return False
        
        config_path = f"config_{self.port}.json"
        with open(config_path, "w") as f:
            json.dump(config, f)
            
        try:
            xray_bin = os.getenv("XRAY_PATH", XRAY_PATH)
            # Пытаемся запустить
            self.process = subprocess.Popen(
                [xray_bin, "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Ждем и проверяем, не упал ли он сразу
            time.sleep(2.0) 
            if self.process is None or self.process.poll() is not None:
                # Процесс не запустился или упал
                self.stop_xray()
                return False
                
            return True
        except Exception as e:
            print(f"[ERROR] Не удалось запустить Xray ({xray_bin}): {e}")
            return False
    def stop_xray(self):
        """Остановка и удаление мусора"""
        if self.process is not None:
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except:
                    if self.process is not None:
                        self.process.kill()
            except Exception as e:
                print(f"[DEBUG] Ошибка при остановке Xray: {e}")
        
        config_path: str = f"config_{self.port}.json"
        if os.path.exists(config_path):
            try: os.remove(config_path)
            except: pass
    def check_availability(self):
        proxies = {
            'http': f'socks5h://127.0.0.1:{self.port}',
            'https': f'socks5h://127.0.0.1:{self.port}'
        }
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
        """Замер скорости через librespeed-cli."""
        cmd = [
            os.getenv("LIBRESPEED_PATH", LIBRESPEED_PATH),
            "--proxy", f"socks5://127.0.0.1:{self.port}",
            "--json"
        ]
        try:
            # Запускаем тест скорости
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                # Извлекаем скорость в Mbps и пинг
                download = data.get("download", 0) / 125000 # Перевод в Mbps
                ping = data.get("ping", 999)
                
                if download >= MIN_SPEED_MBPS:
                    print(f"[SPEED] {self.link[:15]}... | {download:.2f} Mbps | Ping: {ping}ms")
                    return download
        except Exception as e:
            # Если librespeed не установлен или упал, возвращаем заглушку, 
            # если домен был доступен (alive=True в process_single_link)
            pass
        return 0
def process_single_link(link):
    """
    Полный цикл проверки одной ссылки.
    """
    checker = ProxyChecker(link)
    try:
        if not checker.start_xray():
            return {"link": link, "status": "dead"}
        
        alive, has_app, latency = checker.check_availability()
        
        if alive:
            # Если домен доступен, проверяем на скорость
            speed = checker.check_speed()
            # Если speed > 0, значит прошел порог MIN_SPEED_MBPS
            if speed > 0:
                status = "working_app" if has_app else "working_fast"
                category_name = "APP" if has_app else "FAST"
                filename = WORKING_APP if has_app else WORKING_FAST
                print(f"[LIVE] {link} | {category_name} | Ping: {latency*1000:.0f}ms ({latency:.2f}s) | Speed: {speed:.2f} Mbps -> {filename}")
                return {"link": link, "status": status}
            else:
                print(f"[LIVE] {link} | Низкая скорость или ошибка замера | Ping: {latency*1000:.0f}ms")
        else:
            print(f"[LIVE] {link} | Недоступен (Dead)")
        
        return {"link": link, "status": "dead"}
    except Exception as e:
        return {"link": link, "status": "error"}
    finally:
        checker.stop_xray()
def update_file(filename, new_links):
    """Обновляет файл: добавляет новые, удаляет дубли, сохраняет только свежее."""
    existing = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            existing = f.read().splitlines()
    
    # Объединяем, удаляем дубли, очищаем
    updated = sorted(list(set(filter(None, existing + new_links))))
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(updated) + "\n")
def main():
    print(f"[LOG] Бот запущен: {datetime.now()}")
    
    # 1. Загрузка бинарников
    download_binaries()
    # 2. Получение ссылок из внешних источников и локального файла
    print("[LOG] Сбор ссылок из всех источников...")
    remote_content = fetch_remote_subscriptions()
    
    local_content = ""
    if os.path.exists(RAW_SUBSCRIPTION_FILE):
        with open(RAW_SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            local_content = f.read()
            
    # Объединяем всё в одну "кашу" для парсера
    total_content = remote_content + "\n" + local_content
    
    all_links = parse_subscriptions(total_content)
    print(f"[LOG] Всего уникальных ссылок после слияния и очистки: {len(all_links)}")
    # 3. Обновляем нашу рабочую подписку
    update_file(OUR_SUBSCRIPTION, all_links)
    # 4. Проверка (Многопоточность)
    results_app = []
    results_fast = []
    working_links = []
    print(f"[LOG] Запуск проверки {len(all_links)} ссылок...")
    print(f"[INFO] Цель: {CHECK_URL} | Поток: {MAX_WORKERS} | Мин. скорость: {MIN_SPEED_MBPS} Mbps")
    
    count_finished = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Передаем ссылки в пул потоков
        future_to_link = {executor.submit(process_single_link, link): link for link in all_links}
        for future in concurrent.futures.as_completed(future_to_link):
            count_finished += 1
            try:
                res = future.result()
                if res and isinstance(res, dict):
                    status = res.get("status")
                    link = res.get("link")
                    
                    if status == "working_app" and link:
                        results_app.append(link)
                        working_links.append(link)
                    elif status == "working_fast" and link:
                        results_fast.append(link)
                        working_links.append(link)
                
                # Каждые 5 ссылок или в конце выводим статистику
                if count_finished % 5 == 0 or count_finished == len(all_links):
                    remaining = len(all_links) - count_finished
                    print(f"\n[STATS] Прогресс: {count_finished}/{len(all_links)} (Осталось: {remaining})")
                    print(f"[STATS] Живых всего: {len(working_links)} (APP: {len(results_app)}, FAST: {len(results_fast)})\n")
            except Exception as e:
                print(f"[ERROR] Ошибка в потоке: {e}")
    # 5. Итоговое сохранение и ОЧИСТКА ВСЕХ ФАЙЛОВ
    # Мы перезаписываем файлы, оставляя только те ссылки, которые прошли текущую проверку
    
    # 5.1 Результаты по категориям
    update_file(WORKING_APP, results_app)   # Здесь будут ТОЛЬКО работающие сейчас с app
    update_file(WORKING_FAST, results_fast) # Здесь будут ТОЛЬКО работающие сейчас быстрые
    
    # 5.2 Очистка основного источника (subscription_raw.txt)
    with open(RAW_SUBSCRIPTION_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(working_links) + "\n")
    
    # 5.3 Очистка нашей копии
    with open(OUR_SUBSCRIPTION, "w", encoding="utf-8") as f:
        f.write("\n".join(working_links) + "\n")
    
    print(f"[LOG] Проверка завершена. Найдено живых: {len(working_links)}")
    print(f"[LOG] Сохранено в WORKING_APP: {len(results_app)}")
    print(f"[LOG] Сохранено в WORKING_FAST: {len(results_fast)}")
    print(f"[LOG] Файлы {RAW_SUBSCRIPTION_FILE} и {OUR_SUBSCRIPTION} очищены от нерабочих ссылок.")
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[CRITICAL] Ошибка: {e}")
