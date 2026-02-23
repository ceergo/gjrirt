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
                print(f"[LIVE] {link[:40]}... | {category_name} | Ping: {latency*1000:.0f}ms | Speed: {speed:.2f} Mbps -> {filename}")
                return {"link": link, "status": status}
            else:
                print(f"[LIVE] {link[:40]}... | Низкая скорость или ошибка замера")
        else:
            # Не логируем каждый мертвый прокси, чтобы не засорять консоль
            pass
        
        return {"link": link, "status": "dead"}
    except Exception:
        return {"link": link, "status": "error"}
    finally:
        checker.stop_xray()

def main():
    print(f"[LOG] Бот запущен: {datetime.now()}")
    
    # 1. Инициализация окружения (фикс прав доступа и путей)
    download_binaries()
    
    # 2. Сбор ссылок из всех источников
    print("[LOG] Сбор ссылок из всех источников...")
    remote_content = fetch_remote_subscriptions()
    
    local_content = ""
    if os.path.exists(RAW_SUBSCRIPTION_FILE):
        with open(RAW_SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            local_content = f.read()
            
    total_content = remote_content + "\n" + local_content
    all_links = parse_subscriptions(total_content)
    print(f"[LOG] Всего уникальных ссылок после слияния и очистки: {len(all_links)}")
    
    # 3. Сохраняем промежуточную копию
    update_file(OUR_SUBSCRIPTION, all_links)
    
    # 4. Проверка через пул потоков
    results_app = []
    results_fast = []
    working_links = []
    
    print(f"[LOG] Запуск проверки {len(all_links)} ссылок...")
    print(f"[INFO] Цель: {CHECK_URL} | Потоков: {MAX_WORKERS}")
    
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
                    if status == "working_app":
                        results_app.append(link)
                        working_links.append(link)
                    elif status == "working_fast":
                        results_fast.append(link)
                        working_links.append(link)
                
                # Периодическая статистика
                if count_finished % 10 == 0 or count_finished == len(all_links):
                    print(f"[STATS] Прогресс: {count_finished}/{len(all_links)} | Живых: {len(working_links)}")
            except Exception as e:
                print(f"[ERROR] Критическая ошибка в потоке: {e}")

    # 5. Итоговое сохранение результатов
    update_file(WORKING_APP, results_app)
    update_file(WORKING_FAST, results_fast)
    
    # Обновляем основные файлы, оставляя только живые
    with open(RAW_SUBSCRIPTION_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(working_links) + "\n")
    
    with open(OUR_SUBSCRIPTION, "w", encoding="utf-8") as f:
        f.write("\n".join(working_links) + "\n")
    
    print(f"\n[LOG] Проверка завершена.")
    print(f"[RESULT] Найдено рабочих: {len(working_links)}")
    print(f"[RESULT] WORKING_APP: {len(results_app)}")
    print(f"[RESULT] WORKING_FAST: {len(results_fast)}")
    print(f"[LOG] Файлы обновлены.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[LOG] Остановка пользователем.")
    except Exception as e:
        print(f"[CRITICAL] Фатальная ошибка: {e}")
