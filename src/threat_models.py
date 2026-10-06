from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import time

@dataclass
class SoundProfile:
    """Параметры звукового оповещения (гудков) для конкретного состояния."""
    code: int = 0                # Код профиля (для %MW2)
    name: str = ""               # Название
    beep_count: int = 1          # Количество гудков (шт) (%MW3)
    beep_duration_ms: int = 1000 # Длительность гудка (мс) (%MW4)
    pause_between_ms: int = 500  # Пауза между гудками в серии (мс) (%MW5)
    interval_series_ms: int = 5000# Пауза между сериями гудков (мс) (%MW6)

@dataclass
class SoundProfilesConfig:
    """Таблица звуковых профилей оповещения."""
    # 0: Нормальное состояние / Heartbeat (когда нет тревог)
    safe_heartbeat: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=0, name="Норма (Heartbeat)", beep_count=1, beep_duration_ms=200, pause_between_ms=0, interval_series_ms=30000
    ))
    # 1: Ракета: Критическая для города
    rocket_critical: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=1, name="Ракета: Критическая", beep_count=3, beep_duration_ms=1200, pause_between_ms=400, interval_series_ms=4000
    ))
    # 2: Ракета: Потенциальная для города
    rocket_potential: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=2, name="Ракета: Потенциальная", beep_count=2, beep_duration_ms=800, pause_between_ms=600, interval_series_ms=8000
    ))
    # 3: КАБ: Критическая для района объекта
    kab_district_critical: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=3, name="КАБ: Критическая (Район)", beep_count=4, beep_duration_ms=1000, pause_between_ms=300, interval_series_ms=3000
    ))
    # 4: КАБ: Критическая для города
    kab_city_critical: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=4, name="КАБ: Критическая (Город)", beep_count=2, beep_duration_ms=1000, pause_between_ms=500, interval_series_ms=6000
    ))
    # 5: КАБ: Потенциальная
    kab_potential: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=5, name="КАБ: Потенциальная", beep_count=1, beep_duration_ms=800, pause_between_ms=500, interval_series_ms=10000
    ))
    # 6: Дроны Группа 1 (Тяжелые/ударные): Критическая для района
    drone_g1_district_critical: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=6, name="Дрон Гр.1: Критическая (Район)", beep_count=3, beep_duration_ms=800, pause_between_ms=400, interval_series_ms=4000
    ))
    # 7: Дроны Группа 1 (Тяжелые/ударные): Город
    drone_g1_city: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=7, name="Дрон Гр.1: Опасность (Город)", beep_count=2, beep_duration_ms=700, pause_between_ms=500, interval_series_ms=7000
    ))
    # 8: Дроны Группа 2 (Тактические/разведчики): Район/Город
    drone_g2_tactical: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=8, name="Дрон Гр.2: Тактические", beep_count=1, beep_duration_ms=600, pause_between_ms=500, interval_series_ms=10000
    ))
    # 9: Дроны Группа 3 (Ложные цели/фанера/имитаторы) / Мин. тревога
    drone_g3_decoy: SoundProfile = field(default_factory=lambda: SoundProfile(
        code=9, name="Дрон Гр.3: Ложные цели / Минимальная", beep_count=1, beep_duration_ms=300, pause_between_ms=500, interval_series_ms=15000
    ))

@dataclass
class DroneDictionaryConfig:
    """Словарь названий беспилотников, разбитый на 3 группы опасности."""
    # Группа 1: Высокая опасность (Тяжелые камикадзе с мощной БЧ)
    group1_keywords: List[str] = field(default_factory=lambda: [
        "шахед", "шахід", "герань", "гербера", "италмас", "ударный бпла", "дрон-камикадзе", "ударні бпла"
    ])
    # Группа 2: Средняя опасность (Тактические ударные, FPV, разведчики)
    group2_keywords: List[str] = field(default_factory=lambda: [
        "молния", "блискавка", "ланцет", "суперкам", "зала", "орлан", "fpv", "фпв", "разведчик", "розвідник"
    ])
    # Группа 3: Низкая опасность (Ложные цели, имитаторы, легкие приманки без БЧ)
    group3_keywords: List[str] = field(default_factory=lambda: [
        "пародия", "пародія", "фанера", "фальш-цель", "фальш-ціль", "фальш", "имитатор", "імітатор", "приманка", "мишень", "ложная цель", "без бч"
    ])

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
    drone_group: int = 0         # 0: нет, 1: Тяжелые, 2: Тактические, 3: Ложные цели
    matched_drone_name: str = "" # Распознанное название БпЛА
    no_data_link: bool = False
    is_muted: bool = False       # Сигналы тревог на ПЛК подавлены по расписанию
    analysis_disabled_by_plc: bool = False # Анализ отключен физическим тумблером на ПЛК
    last_event_time: float = 0.0
    last_event_source: str = ""
    last_event_text: str = ""
    modbus_word: int = 1         # Битовая маска для отправки в %MW0 (по умолчанию Бит 0 = SAFE)
    # Динамический звуковой профиль для передачи в %MW2..%MW6
    sound_code: int = 0          # %MW2: Код профиля
    sound_beep_count: int = 0    # %MW3: Кол-во гудков
    sound_duration_ms: int = 0   # %MW4: Длительность гудка
    sound_pause_ms: int = 0      # %MW5: Пауза между гудками
    sound_interval_ms: int = 0   # %MW6: Пауза между сериями
    sound_profile_name: str = "Тишина"

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
class ScheduleConfig:
    """Расписание тихого часа / блокировки выдачи тревог на контроллер."""
    enabled: bool = False
    start_time: str = "23:40"      # ЧЧ:ММ
    end_time: str = "05:00"        # ЧЧ:ММ

    def is_in_schedule(self, dt: Optional[datetime] = None) -> bool:
        """Проверяет, попадает ли текущее время в интервал расписания."""
        if not self.enabled:
            return False
        if dt is None:
            dt = datetime.now()
        cur_min = dt.hour * 60 + dt.minute

        try:
            sh, sm = map(int, self.start_time.split(":"))
            start_min = sh * 60 + sm
            eh, em = map(int, self.end_time.split(":"))
            end_min = eh * 60 + em
        except Exception:
            return False

        if start_min <= end_min:
            # Дневной интервал (например 08:00 - 17:00)
            return start_min <= cur_min < end_min
        else:
            # Переход через полночь (например 23:40 - 05:00)
            return cur_min >= start_min or cur_min < end_min

@dataclass
class PlcFeedbackConfig:
    """Биты слова обратной связи, возвращаемого из ПЛК (%MW1)."""
    bit_plc_running: int = 15       # Бит: ПЛК работает / в работе
    bit_alarm_reset: int = 1        # Бит: Кнопка сброса текущей тревоги с ПЛК
    bit_analysis_switch: int = 2    # Бит: Переключатель вкл/выкл анализ тревог (1 = Вкл, 0 = Выкл)

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
    bit_muted_by_schedule: int = 10      # Бит 10: Режим тишины по расписанию (тревоги на ПЛК подавлены)
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
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    drone_dict: DroneDictionaryConfig = field(default_factory=DroneDictionaryConfig)
    sound_profiles: SoundProfilesConfig = field(default_factory=SoundProfilesConfig)
    auto_transfer_to_plc: bool = True   # Автоматически отправлять вычисленные регистры в ПЛК

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

            if "schedule" in d:
                sch = d["schedule"]
                cfg.schedule.enabled = sch.get("enabled", cfg.schedule.enabled)
                cfg.schedule.start_time = sch.get("start_time", cfg.schedule.start_time)
                cfg.schedule.end_time = sch.get("end_time", cfg.schedule.end_time)

            if "drone_dict" in d:
                dd = d["drone_dict"]
                cfg.drone_dict.group1_keywords = dd.get("group1_keywords", cfg.drone_dict.group1_keywords)
                cfg.drone_dict.group2_keywords = dd.get("group2_keywords", cfg.drone_dict.group2_keywords)
                cfg.drone_dict.group3_keywords = dd.get("group3_keywords", cfg.drone_dict.group3_keywords)

            if "sound_profiles" in d:
                sp_data = d["sound_profiles"]
                for prof_name in [
                    "safe_heartbeat", "rocket_critical", "rocket_potential",
                    "kab_district_critical", "kab_city_critical", "kab_potential",
                    "drone_g1_district_critical", "drone_g1_city", "drone_g2_tactical", "drone_g3_decoy"
                ]:
                    if prof_name in sp_data and hasattr(cfg.sound_profiles, prof_name):
                        p_obj: SoundProfile = getattr(cfg.sound_profiles, prof_name)
                        p_dict = sp_data[prof_name]
                        p_obj.beep_count = int(p_dict.get("beep_count", p_obj.beep_count))
                        p_obj.beep_duration_ms = int(p_dict.get("beep_duration_ms", p_obj.beep_duration_ms))
                        p_obj.pause_between_ms = int(p_dict.get("pause_between_ms", p_obj.pause_between_ms))
                        p_obj.interval_series_ms = int(p_dict.get("interval_series_ms", p_obj.interval_series_ms))
        except Exception as e:
            print(f"[ThreatConfig] Error loading {path}: {e}")
        return cfg

    def save(self, path: str = "config_threats.json") -> bool:
        """Сохраняет текущую конфигурацию в файл JSON."""
        import json
        sound_profiles_dict = {}
        for prof_name in [
            "safe_heartbeat", "rocket_critical", "rocket_potential",
            "kab_district_critical", "kab_city_critical", "kab_potential",
            "drone_g1_district_critical", "drone_g1_city", "drone_g2_tactical", "drone_g3_decoy"
        ]:
            if hasattr(self.sound_profiles, prof_name):
                p: SoundProfile = getattr(self.sound_profiles, prof_name)
                sound_profiles_dict[prof_name] = {
                    "beep_count": p.beep_count,
                    "beep_duration_ms": p.beep_duration_ms,
                    "pause_between_ms": p.pause_between_ms,
                    "interval_series_ms": p.interval_series_ms
                }

        data = {
            "alarmmap_enabled": self.alarmmap_enabled,
            "alarmmap_key_file": self.alarmmap_key_file,
            "alarmmap_poll_interval_s": self.alarmmap_poll_interval_s,
            "telegram_enabled": self.telegram_enabled,
            "telegram_mode": self.telegram_mode,
            "telegram_api_id": self.telegram_api_id,
            "telegram_api_hash": self.telegram_api_hash,
            "telegram_channels": self.telegram_channels,
            "district": {
                "name": self.district.name,
                "ttl_seconds": self.district.ttl_seconds,
                "district_keywords": self.district.district_keywords,
                "critical_alert_keywords": self.district.critical_alert_keywords,
                "city_keywords": self.district.city_keywords
            },
            "bit_mapping": {
                "bit_safe": self.bit_mapping.bit_safe,
                "bit_threat_minimal": self.bit_mapping.bit_threat_minimal,
                "bit_threat_city_potential": self.bit_mapping.bit_threat_city_potential,
                "bit_threat_district_potential": self.bit_mapping.bit_threat_district_potential,
                "bit_threat_city_critical": self.bit_mapping.bit_threat_city_critical,
                "bit_threat_district_critical": self.bit_mapping.bit_threat_district_critical,
                "bit_type_rocket": self.bit_mapping.bit_type_rocket,
                "bit_type_kab": self.bit_mapping.bit_type_kab,
                "bit_type_drone": self.bit_mapping.bit_type_drone,
                "bit_no_link": self.bit_mapping.bit_no_link,
                "bit_muted_by_schedule": self.bit_mapping.bit_muted_by_schedule,
                "bit_heartbeat": self.bit_mapping.bit_heartbeat
            },
            "plc_feedback": {
                "bit_plc_running": self.plc_feedback.bit_plc_running,
                "bit_alarm_reset": self.plc_feedback.bit_alarm_reset,
                "bit_analysis_switch": self.plc_feedback.bit_analysis_switch
            },
            "schedule": {
                "enabled": self.schedule.enabled,
                "start_time": self.schedule.start_time,
                "end_time": self.schedule.end_time
            },
            "drone_dict": {
                "group1_keywords": self.drone_dict.group1_keywords,
                "group2_keywords": self.drone_dict.group2_keywords,
                "group3_keywords": self.drone_dict.group3_keywords
            },
            "sound_profiles": sound_profiles_dict,
            "auto_transfer_to_plc": self.auto_transfer_to_plc
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[ThreatConfig] Error saving {path}: {e}")
            return False

