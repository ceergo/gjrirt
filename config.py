import os

# ==============================================================================
# КОНФИГУРАЦИЯ
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
WORKING_APP = "working_app.txt"                  # Результат: есть "app" + скорость
WORKING_FAST = "working_fast.txt"                # Результат: нет "app", но быстрый ответ + скорость

# Параметры проверки
MAX_WORKERS = 10                                 # Количество потоков
SPEED_TEST_MB = 1                                # Сколько мегабайт скачивать для теста
MIN_SPEED_MBPS = 0.5                             # Минимальная скорость для WORKING_FAST (Mbps)
UTLS_FINGERPRINTS = ["chrome", "firefox", "safari", "edge", "randomized"]
CONNECT_TIMEOUT = 10                             # Таймаут подключения (сек)
DOWNLOAD_TIMEOUT = 30                            # Таймаут замера скорости (сек)

# Пути к бинарникам
XRAY_PATH = "./xray"
LIBRESPEED_PATH = "./librespeed-cli"

# Протоколы, которые мы ищем (поиск нечувствителен к регистру)
PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria2", "tuic"]
