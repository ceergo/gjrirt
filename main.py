import os
import concurrent.futures
from datetime import datetime

# Импорты из наших новых файлов
from config import (
    RAW_SUBSCRIPTION_FILE, OUR_SUBSCRIPTION, WORKING_APP, WORKING_FAST, 
    MAX_WORKERS, MIN_SPEED_MBPS, CHECK_URL
)
from utils import fetch_remote_subscriptions, parse_subscriptions, update_file
from checker import download_binaries, ProxyChecker

def process_single_link(link):
    """Полный цикл проверки одной ссылки."""
    checker = ProxyChecker(link)
    try:
        if not checker.start_xray():
            return {"link": link, "status": "dead"}
        
        alive, has_app, latency = checker.check_availability()
        
        if alive:
            speed = checker.check_speed()
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
    except Exception:
        return {"link": link, "status": "error"}
    finally:
        checker.stop_xray()

def main():
    print(f"[LOG] Бот запущен: {datetime.now()}")
    
    # 1. Загрузка бинарников
    download_binaries()
    
    # 2. Сбор ссылок
    print("[LOG] Сбор ссылок из всех источников...")
    remote_content = fetch_remote_subscriptions()
    
    local_content = ""
    if os.path.exists(RAW_SUBSCRIPTION_FILE):
        with open(RAW_SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            local_content = f.read()
            
    total_content = remote_content + "\n" + local_content
    all_links = parse_subscriptions(total_content)
    print(f"[LOG] Всего уникальных ссылок после слияния и очистки: {len(all_links)}")
    
    # 3. Обновляем рабочую подписку
    update_file(OUR_SUBSCRIPTION, all_links)
    
    # 4. Проверка
    results_app = []
    results_fast = []
    working_links = []
    print(f"[LOG] Запуск проверки {len(all_links)} ссылок...")
    print(f"[INFO] Цель: {CHECK_URL} | Поток: {MAX_WORKERS} | Мин. скорость: {MIN_SPEED_MBPS} Mbps")
    
    count_finished = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
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
                
                if count_finished % 5 == 0 or count_finished == len(all_links):
                    remaining = len(all_links) - count_finished
                    print(f"\n[STATS] Прогресс: {count_finished}/{len(all_links)} (Осталось: {remaining})")
                    print(f"[STATS] Живых всего: {len(working_links)} (APP: {len(results_app)}, FAST: {len(results_fast)})\n")
            except Exception as e:
                print(f"[ERROR] Ошибка в потоке: {e}")

    # 5. Сохранение и очистка
    update_file(WORKING_APP, results_app)
    update_file(WORKING_FAST, results_fast)
    
    with open(RAW_SUBSCRIPTION_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(working_links) + "\n")
    
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
