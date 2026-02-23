import os
import concurrent.futures
from datetime import datetime

# Импорты из нашей структуры
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
        # 1. Запуск Xray
        if not checker.start_xray():
            return {"link": link, "status": "dead"}
        
        # 2. Проверка доступности и "фичи" (app)
        alive, has_app, latency = checker.check_availability()
        
        if alive:
            # 3. Замер скорости только для живых
            speed = checker.check_speed()
            if speed > 0:
                status = "working_app" if has_app else "working_fast"
                category_name = "APP" if has_app else "FAST"
                filename = WORKING_APP if has_app else WORKING_FAST
                # Форматированный вывод
                print(f"[LIVE] {link[:30]}... | {category_name} | {latency*1000:.0f}ms | {speed:.2f} Mbps")
                return {"link": link, "status": status}
            else:
                # Живой, но медленный
                pass
        
        return {"link": link, "status": "dead"}
    except Exception:
        return {"link": link, "status": "error"}
    finally:
        checker.stop_xray()

def main():
    print(f"[LOG] Бот запущен: {datetime.now()}")
    
    # 1. Подготовка окружения
    download_binaries()
    
    # 2. Сбор и парсинг ссылок
    print("[LOG] Сбор ссылок из источников...")
    remote_data = fetch_remote_subscriptions()
    
    local_data = ""
    if os.path.exists(RAW_SUBSCRIPTION_FILE):
        with open(RAW_SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            local_data = f.read()
            
    all_links = parse_subscriptions(remote_data + "\n" + local_data)
    print(f"[LOG] Найдено уникальных ссылок: {len(all_links)}")
    
    # Резервное сохранение всех найденных
    update_file(OUR_SUBSCRIPTION, all_links)
    
    # 3. Многопоточная проверка
    results_app = []
    results_fast = []
    working_all = []
    
    print(f"[LOG] Начинаю проверку в {MAX_WORKERS} потоков...")
    
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_link, link): link for link in all_links}
        for future in concurrent.futures.as_completed(futures):
            count += 1
            res = future.result()
            if res and res["status"] != "dead":
                working_all.append(res["link"])
                if res["status"] == "working_app":
                    results_app.append(res["link"])
                else:
                    results_fast.append(res["link"])
            
            if count % 10 == 0 or count == len(all_links):
                print(f"[STATS] Обработано: {count}/{len(all_links)} | Рабочих: {len(working_all)}")

    # 4. Сохранение результатов
    update_file(WORKING_APP, results_app)
    update_file(WORKING_FAST, results_fast)
    
    # Очистка основных списков от мертвых ссылок
    update_file(RAW_SUBSCRIPTION_FILE, working_all)
    update_file(OUR_SUBSCRIPTION, working_all)
    
    print(f"\n[FINISH] Проверка окончена.")
    print(f"[INFO] Найдено APP: {len(results_app)}")
    print(f"[INFO] Найдено FAST: {len(results_fast)}")
    print(f"[LOG] Данные в файлах обновлены.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[CRITICAL] Ошибка выполнения: {e}")
