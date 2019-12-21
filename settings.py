# -*- coding: utf-8 -*-

# Путь к файлу кеша карт (для работы без связи с Lyrix)
CARD_CACHE_FILE = "/var/lib/yourappname/card_cache.p"

# Количество бит в коде организации (0 - нет кода организации, только номер)
CARD_FACILITY_BITS = 8
# Количество бит в номере карты
CARD_NUMBER_BITS = 16

# Ссылка на сервис WSDL Lyrix
LYRIX_WSDL_URL = \
"http://172.16.50.113:1234/AxisWebApp/services/CardlibIntegrationService2Port?wsdl"
# Имя пользователя
LYRIX_USER = "user"
# Пароль
LYRIX_PASSWORD = "password"
# Тайм-аут соединения с Lyrix (с)
LYRIX_TIMEOUT_S = 10
# Интервал переподключения (с)
LYRIX_RECONNECT_INTERVAL_S = 300
# Интервал обновления кеша карт (м)
LYRIX_CACHE_LIVETIME_M = 720
# Идентификатор объекта Lyrix для отправки сообщений
LYRIX_SOURCE_OBJECT_ID = "4d8d47bcac10016b589991bb4484a2"
# Название объекта Lyrix для отправки сообщений. Префикс 'u' обязателен.
LYRIX_SOURCE_OBJECT_NAME = u"Моё приложение"
# Список кодов организации (не используется, если CARD_FACILITY_BITS = 0)
LYRIX_FACILITY_CODES = [10, 110]
# Включить проверку уровня доступа (True - да, False - нет)
LYRIX_ACCESS_LEVEL_ENABLE = True
# Список разрешённых уровней доступа. Префикс 'u' обязателен.
LYRIX_ACCESS_LEVELS = [u"Глобальный уровень доступа 1",
                       u"Глобальный уровень доступа 2"]
