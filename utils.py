import re
import socket
import requests
import base64
import os
from config import SUBSCRIPTION_URLS, PROTOCOLS

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
    pattern = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    matches = list(re.finditer(pattern, link))
    if len(matches) > 1:
        link = link[:matches[1].start()]
    
    return link.strip()

def parse_subscriptions(content: str) -> list[str]:
    """
    Разбирает текст, находит в нём прокси-ссылки. 
    Поддерживает: прямое перечисление, Base64 (включая вложенные блоки).
    """
    found_links: list[str] = []
    pattern_proto = r'(?i)(' + '|'.join(PROTOCOLS) + r')://'
    
    def process_text(text: str):
        text = text.strip()
        if not text:
            return
        starts = [m.start() for m in re.finditer(pattern_proto, text)]
        if starts:
            for i in range(len(starts)):
                s_idx = starts[i]
                if i + 1 < len(starts):
                    e_idx = starts[i+1]
                else:
                    e_idx = len(text)
                
                chunk = text[s_idx:e_idx].strip()
                cleaned = clean_link(chunk)
                if cleaned:
                    found_links.append(cleaned)
            return
        try:
            b64_data = re.sub(r'[^a-zA-Z0-9+/=]', '', text)
            if len(b64_data) > 10:
                missing_padding = len(b64_data) % 4
                if missing_padding:
                    b64_data += '=' * (4 - missing_padding)
                
                decoded_bytes = base64.b64decode(b64_data)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
                if re.search(pattern_proto, decoded_str):
                    for line in decoded_str.splitlines():
                        process_text(line)
        except:
            pass

    chunks = content.split()
    for c in chunks:
        process_text(c)
    
    final_links = sorted(list(set(filter(None, found_links))))
    return final_links

def get_free_port():
    """Находит свободный порт в системе."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def update_file(filename, new_links):
    """Обновляет файл: добавляет новые, удаляет дубли, сохраняет только свежее."""
    existing = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            existing = f.read().splitlines()
    
    updated = sorted(list(set(filter(None, existing + new_links))))
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(updated) + "\n")
