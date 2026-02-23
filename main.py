import os
import concurrent.futures
from datetime import datetime

# Импорты
from config import (
    RAW_SUBSCRIPTION_FILE, OUR_SUBSCRIPTION, WORKING_APP, WORKING_FAST, 
    MAX_WORKERS, MIN_SPEED_MBPS, CHECK_URL
)
from utils import fetch_remote_subscriptions, parse_subscriptions, update_file
from checker import download_binaries, ProxyChecker

def process_single_link(link):
    """
    Полный цикл проверки одной ссылки. 
    Все логи в реальном времени теперь ТОЛЬКО здесь.
    """
    checker = ProxyChecker(link)
    
    # 1. Начало проверки
    print(f"🔍 [SCAN] {link}")
    
    try:
        # 2. Запуск Xray
        if not checker.start_xray():
            print(f"❌ [DEAD] {link} | Ошибка Xray: {checker.fail_reason}")
            return {"link": link, "status": "dead"}
        
        # 3. Пинг и Ключевое слово (Gemini)
        # checker.check_availability теперь работает молча и возвращает результат
        alive, has_feature, latency = checker.check_availability()
        
        if not alive:
            print(f"💀 [FAIL] {link[:50]}... | Ошибка сети: {checker.fail_reason}")
            return {"link": link, "status": "dead"}
            
        ping_ms = int(latency * 1000)
        feature_icon = "✅" if has_feature else "❌"
        print(f"📡 [PING] {link[:50]}... | 📶 {ping_ms}ms | Фича: {feature_icon}")
        
        # 4. Замер скорости
        print(f"🚀 [TEST] {link[:50]}... | Замер скорости...")
        speed = checker.check_speed()
        
        if speed >= MIN_SPEED_MBPS:
            status = "working_app" if has_feature else "working_fast"
            label = "💎 APP-MODE" if has_feature else "⚡ FAST-ONLY"
            
            print(f"✨ [LIVE] {link}")
            print(f"      └─ {label} | 🛰️ {ping_ms}ms | 🏎️  {speed:.2f} Mbps")
            
            return {"link": link, "status": status}
        else:
            reason = checker.fail_reason or f"Медленно ({speed:.2f} Mbps)"
            print(f"🐌 [SLOW] {link[:50]}... | {reason}")
            return {"link": link, "status": "dead"}
            
    except Exception as e:
        print(f"⚠️  [ERR ] {link[:50]}... | Фатально: {e}")
        return {"link": link, "status": "error"}
    finally:
        # Остановка тоже должна быть тихой внутри checker
        checker.stop_xray()

def main():
    print(f"\n🚀 === ЗАПУСК ПРОВЕРКИ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
    # 1. Подготовка бинарников
    download_binaries()
    
    # 2. Сбор ссылок
    print("\n📥 [LOG] Сбор ссылок из источников...")
    remote_data = fetch_remote_subscriptions()
    
    local_data = ""
    if os.path.exists(RAW_SUBSCRIPTION_FILE):
        with open(RAW_SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
            local_data = f.read()
            
    all_links = parse_subscriptions(remote_data + "\n" + local_data)
    print(f"📊 [LOG] Уникальных ссылок: {len(all_links)}\n")
    
    # Сохраняем черновик всех найденных ссылок
    update_file(OUR_SUBSCRIPTION, all_links)
    
    # 3. Многопоточный "Прямой Эфир"
    results_app = []
    results_fast = []
    working_all = []
    
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_single_link, link): link for link in all_links}
        for future in concurrent.futures.as_completed(futures):
            count += 1
            res = future.result()
            if res and res["status"] != "dead" and res["status"] != "error":
                working_all.append(res["link"])
                if res["status"] == "working_app":
                    results_app.append(res["link"])
                else:
                    results_fast.append(res["link"])
            
            # Статистика каждые 20 проверок
            if count % 20 == 0 or count == len(all_links):
                print(f"\n📈 [STAT] Проверено: {count}/{len(all_links)} | Живых: {len(working_all)}")

    # 4. Сохранение результатов
    update_file(WORKING_APP, results_app)
    update_file(WORKING_FAST, results_fast)
    update_file(RAW_SUBSCRIPTION_FILE, working_all)
    update_file(OUR_SUBSCRIPTION, working_all)
    
    print(f"\n🏁 === ЦИКЛ ЗАВЕРШЕН ===")
    print(f"✅ APP-MODE: {len(results_app)}")
    print(f"⚡ FAST-ONLY: {len(results_fast)}")
    print(f"💾 Базы обновлены. Ожидание...\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Работа прервана пользователем.")
    except Exception as e:
        print(f"🚨 [FATAL] Ошибка в основном цикле: {e}")
