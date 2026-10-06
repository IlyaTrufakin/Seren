from dataclasses import dataclass, field
from typing import List, Dict, Optional
import time

@dataclass
class ThreatStatus:
    """Текущее состояние угроз, сформированное анализатором."""
    level_code: int = 0          # 0: Безопасно, 1: Мин., 2: Потенц. город, 3: Потенц. район, 4: Крит. город, 5: Крит. район
    level_title: str = "Безопасно"
    description: str = "Угроз не зафиксировано, обстановка спокойная"
    is_city_threat: bool = False
    is_district_threat: bool = False
    has_rocket: bool = False
    has_kab: bool = False
    has_drone: bool = False
    no_data_link: bool = False
    last_event_time: float = 0.0
    last_event_source: str = ""
    last_event_text: str = ""
    modbus_word: int = 1         # Битовая маска для отправки в %MW0 (по умолчанию Бит 0 = SAFE)

@dataclass
class DistrictConfig:
    """Конфигурация отслеживаемого сектора / района."""
    name: str = "Основянский / Слободской / Немышля"
    # Ключевые слова района и ориентиров направления
    district_keywords: List[str] = field(default_factory=lambda: [
        # Районы
        "основян", "основ'ян", "основа", "основи",
        "слободск", "слобідськ",
        "немышл", "немишл", "турбоатом", "малышев", "малишев",
        # Ориентиры и направления
        "новые дома", "нові дома", "новых домов", "нових домів", "бульвар юрьева", "юрьева", "дворец спорта", "палац спорту",
        "одесск", "одеськ", "класс на одесской", "гагарин", "аэрокосмическ", "аерокосмічн",
        "аэропорт", "аеропорт", "основа/аэропорт", "безлюдовк", "безлюдівк"
    ])
    # Общеклиентские маркеры города
    city_keywords: List[str] = field(default_factory=lambda: [
        "харьков", "харків", "городу", "місту", "центр", "шевро", "салтов", "салтів", "алексеев", "олексіїв"
    ])
    # Маркеры экстренной опасности / призывы в укрытие
    critical_alert_keywords: List[str] = field(default_factory=lambda: [
        "в укриття", "в укрытие", "всі в укриття", "все в укрытие",
        "негайно в укриття", "срочно в укрытие", "терміново в укриття",
        "перебувайте в укриттях", "находитесь в укрытиях",
        "в безпечні місця", "в безопасные места"
    ])
    ttl_seconds: int = 600       # Время удержания угрозы (10 минут)

@dataclass
class PlcFeedbackConfig:
    """Биты слова обратной связи, возвращаемого из ПЛК (%MW1)."""
    bit_plc_running: int = 15       # Бит: ПЛК работает / в работе
    bit_alarm_reset: int = 1        # Бит: Кнопка сброса текущей тревоги с ПЛК

@dataclass
class BitMappingConfig:
    """Привязка статусов к 16 битам слова передачи в ПЛК (%MW0)."""
    bit_safe: int = 0                    # Бит 0: Безопасно
    bit_threat_minimal: int = 1          # Бит 1: Опасность минимальна
    bit_threat_city_potential: int = 2   # Бит 2: Опасность потенциальная для города
    bit_threat_district_potential: int = 3# Бит 3: Опасность потенциальная для района
    bit_threat_city_critical: int = 4    # Бит 4: Опасность критическая для города
    bit_threat_district_critical: int = 5# Бит 5: Опасность критическая для района
    bit_type_rocket: int = 6             # Бит 6: Тип угрозы: Ракета
    bit_type_kab: int = 7                # Бит 7: Тип угрозы: КАБ
    bit_type_drone: int = 8              # Бит 8: Тип угрозы: Дрон / Шахед
    bit_no_link: int = 9                 # Бит 9: Нет связи с источниками
    bit_heartbeat: int = 15              # Бит 15: Heartbeat (жизнь ПО)

@dataclass
class ThreatSystemConfig:
    """Полная конфигурация системы анализа угроз."""
    enabled: bool = True
    # Настройки AlarmMap API
    alarmmap_enabled: bool = True
    alarmmap_key_file: str = "API/alarmmap.online.txt"
    alarmmap_katottg: str = "UA63120270010096107" # г. Харьков
    alarmmap_poll_interval_s: int = 15

    # Настройки Telegram
    telegram_enabled: bool = True
    telegram_mode: str = "web"          # "telethon" или "web" (fallback без авторизации)
    telegram_api_id: Optional[int] = None
    telegram_api_hash: Optional[str] = None
    telegram_phone: Optional[str] = None
    telegram_channels: List[str] = field(default_factory=lambda: ["monitor1654", "radar_kharkov"])
    telegram_poll_interval_s: int = 4   # Интервал проверки для веб-режима

    # Районы и правила
    district: DistrictConfig = field(default_factory=DistrictConfig)
    bit_mapping: BitMappingConfig = field(default_factory=BitMappingConfig)
    plc_feedback: PlcFeedbackConfig = field(default_factory=PlcFeedbackConfig)
    auto_transfer_to_plc: bool = True   # Автоматически отправлять вычисленное слово в %MW0

    @classmethod
    def load(cls, path: str = "config_threats.json") -> "ThreatSystemConfig":
        import os, json
        cfg = cls()
        if not os.path.exists(path):
            return cfg
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            cfg.alarmmap_enabled = d.get("alarmmap_enabled", cfg.alarmmap_enabled)
            cfg.alarmmap_key_file = d.get("alarmmap_key_file", cfg.alarmmap_key_file)
            cfg.alarmmap_poll_interval_s = d.get("alarmmap_poll_interval_s", cfg.alarmmap_poll_interval_s)
            cfg.telegram_enabled = d.get("telegram_enabled", cfg.telegram_enabled)
            cfg.telegram_mode = d.get("telegram_mode", cfg.telegram_mode)
            cfg.telegram_api_id = d.get("telegram_api_id", cfg.telegram_api_id)
            cfg.telegram_api_hash = d.get("telegram_api_hash", cfg.telegram_api_hash)
            cfg.telegram_channels = d.get("telegram_channels", cfg.telegram_channels)
            cfg.auto_transfer_to_plc = d.get("auto_transfer_to_plc", cfg.auto_transfer_to_plc)

            if "district" in d:
                dist = d["district"]
                cfg.district.name = dist.get("name", cfg.district.name)
                cfg.district.ttl_seconds = dist.get("ttl_seconds", cfg.district.ttl_seconds)
                cfg.district.district_keywords = dist.get("district_keywords", cfg.district.district_keywords)
                cfg.district.city_keywords = dist.get("city_keywords", cfg.district.city_keywords)
                cfg.district.critical_alert_keywords = dist.get("critical_alert_keywords", cfg.district.critical_alert_keywords)

            if "bit_mapping" in d:
                bm = d["bit_mapping"]
                for k, v in bm.items():
                    if hasattr(cfg.bit_mapping, k):
                        setattr(cfg.bit_mapping, k, int(v))

            if "plc_feedback" in d:
                pf = d["plc_feedback"]
                for k, v in pf.items():
                    if hasattr(cfg.plc_feedback, k):
                        setattr(cfg.plc_feedback, k, int(v))
        except Exception as e:
            print(f"[ThreatConfig] Error loading {path}: {e}")
        return cfg
