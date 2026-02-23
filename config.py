# ================================================================
# НАСТРОЙКИ - РЕГУЛИРУЙТЕ ВСЁ ЗДЕСЬ
# ================================================================

# Список URL для получения RAW ссылок прокси
SUBSCRIPTION_URLS = [
    "https://raw.githubusercontent.com/ceergo/parss/refs/heads/main/my_stable_configs.txt",
]

# Целевые URL для проверки (ищем маркер в теле ответа)
CHECK_TARGETS = [
    {
        "url": "https://gemini.google.com/app?hl=ru",
        "marker": "app"
    }
]

# Лимиты
MIN_SPEED_MBPS = 0.5  # Для working.txt
MIN_SPEED_FAST = 0.2  # Для fast.txt
CONNECT_TIMEOUT = 10  # Ожидание ответа порта xray
MAX_WORKERS = 6       # Потоки (GitHub выдерживает до 10-15)

# Xray Настройки
XRAY_PORT_RANGE = (12000, 18000)
TLS_FINGERPRINTS = ["chrome", "firefox", "safari", "edge", "qq", "360", "android", "ios"]

# Пути к файлам
RAW_PATH = "subscriptions/raw.txt"
WORKING_PATH = "subscriptions/working.txt"
FAST_PATH = "subscriptions/fast.txt"
TEMP_SETUP_PATH = "temp_setup.txt"
LOG_PATH = "checker.log"
RUN_COUNT_PATH = ".run_count"

# Настройка замера скорости через librespeed-cli
USE_LIBRESPEED = True
LIBRESPEED_ARGS = "--json --bytes --no-upload --no-telemetry"

