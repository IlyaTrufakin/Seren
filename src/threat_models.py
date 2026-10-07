from dataclasses import dataclass, field, asdict
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
class SignificantEvent:
    """Значимое оперативное событие из Telegram (мусор отфильтрован)."""
    time_str: str = ""
    timestamp: float = 0.0
    channel: str = ""
    category: str = "alert"      # "rocket", "kab", "drone", "shelter", "clear", "alert"
    badge_threat: str = ""       # "🚀 РАКЕТА", "💣 КАБ", "🛸 ДРОН: ШАХЕД (Гр.1)", "⚠️ В УКРЫТИЕ", "🟢 ОТБОЙ"
    badge_target: str = ""       # "🎯 РАЙОН: Одесская", "🏙️ ГОРОД", "🗺️ ОБЛАСТЬ"
    sector_name: str = ""        # Распознанный ориентир / район
    drone_name: str = ""
    drone_group: int = 0
    text: str = ""
    is_critical: bool = False

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

    # === Детализация источника 1: API (alarmmap.online) ===
    alarmmap_online: bool = False
    alarmmap_last_poll_time: float = 0.0
    alarmmap_status_text: str = "Ожидание данных"
    alarmmap_level: int = 0
    alarmmap_has_air: bool = False
    alarmmap_has_kab: bool = False
    alarmmap_has_drone: bool = False
    alarmmap_has_artillery: bool = False
    alarmmap_active_count: int = 0
    alarmmap_decoded_details: List[Dict] = field(default_factory=list)
    alarmmap_types_summary: str = ""
    alarmmap_duration_summary: str = ""
    alarmmap_full_text: str = ""

    # === Детализация источника 2: Telegram каналы ===
    tg_online: bool = False
    tg_mode: str = "web"
    tg_channels: List[str] = field(default_factory=list)
    tg_last_msg_time: float = 0.0
    tg_city_threat: str = ""          # "rocket", "kab", "drone", ""
    tg_city_level: int = 0            # 0, 2, 4
    tg_city_ttl_remain_s: int = 0     # оставшееся время действия угрозы городу
    tg_district_threat: str = ""      # "rocket", "kab", "drone", ""
    tg_district_level: int = 0        # 0, 3, 5
    tg_district_landmarks: str = ""   # "Одесская, Новые дома"
    tg_district_ttl_remain_s: int = 0 # оставшееся время действия угрозы району
    tg_drone_name: str = ""
    tg_drone_group: int = 0

    # === Список последних значимых оперативных сообщений (без мусора) ===
    significant_events: List[SignificantEvent] = field(default_factory=list)
    severity: str = "safe"
    active_rule_id: str = ""
    active_threat_type: str = ""
    reason: str = "Ожидание данных источников"
    matched_sources: List[str] = field(default_factory=list)
    source_health: Dict = field(default_factory=dict)
    alarmmap_catalog: List[Dict] = field(default_factory=list)
    last_resolution: str = ""
    selected_event_ids: List[str] = field(default_factory=list)


SEVERITIES = {"critical": "Критическая", "high": "Высокая", "low": "Низкая"}
THREAT_TYPES = {"rocket": "Ракетная", "kab": "Бомбовая", "drone": "Дроновая"}
APPROACHES = {"launch": "Пуск", "city": "Над городом",
              "district": "Над районом", "toward_district": "Направление на район",
              "toward_city": "Направление на город"}


@dataclass
class EndCondition:
    name: str = ""
    enabled: bool = True
    keywords: List[str] = field(default_factory=list)
    action: str = "shorten"  # clear, shorten, ignore
    hold_seconds: int = 60
    threat_types: List[str] = field(default_factory=lambda: list(THREAT_TYPES))
    sources: List[str] = field(default_factory=lambda: ["telegram:*"])
    context_seconds: int = 180
    allow_without_location: bool = False
    require_confirmed: bool = True
    regional_clear: bool = False
    reject_keywords: List[str] = field(default_factory=list)


def default_end_conditions():
    return [
        EndCondition("Отбой", True, ["відбій", "отбой", "чисто", "угроза миновала", "загроза минула"],
                     "clear", 0, allow_without_location=True, context_seconds=600, regional_clear=True),
        EndCondition("Падение / прилёт", True,
                     ["вибух", "вибухи", "взрыв", "взрывы", "приліт", "прилет", "прилёт", "упал", "упали", "впав", "впали"],
                     "shorten", 60, allow_without_location=True,
                     reject_keywords=["не упал", "не впав", "не впали", "работа пво", "робота ппо"]),
        EndCondition("Цель уничтожена", True, ["збито", "збитий", "сбит", "сбита", "сбито", "минус", "мінус", "знищено"],
                     "shorten", 30, allow_without_location=True, reject_keywords=["не сбит", "не збито"]),
        EndCondition("Потеря фиксации", True,
                     ["локаційно не фіксується", "більше не фіксується", "больше не фиксируется", "без фиксации", "без фіксації"],
                     "ignore", 120, allow_without_location=True, require_confirmed=False),
    ]


@dataclass
class TrackingConfig:
    enabled: bool = True
    context_seconds: int = 180
    movement_action: str = "shorten"
    movement_hold_seconds: int = 60
    movement_keywords: List[str] = field(default_factory=lambda: [
        "на", "курс", "через", "далі", "далее", "рухається", "движется", "прямує", "летит", "над"])
    uncertain_keywords: List[str] = field(default_factory=lambda: [
        "попередньо", "предварительно", "можливо", "возможно", "ймовірно", "вероятно", "не підтверджено", "не подтверждено"])
    continuing_keywords: List[str] = field(default_factory=lambda: [
        "ще", "еще", "ещё", "другий", "второй", "наступний", "следующий", "продовжу", "продолжа",
        "новий пуск", "новый пуск", "повторні пуски", "повторные пуски", "загроза зберігається", "угроза сохраняется"])
    rocket_keywords: List[str] = field(default_factory=lambda: [
        "ракет", "баллист", "балист", "баліст", "іскандер", "искандер", "швидкісна ціль", "скоростная цель",
        "с-300", "с-400", "кинжал", "кинджал", "х-101", "х-59", "х-69", "х-22", "циркон"])
    bomb_keywords: List[str] = field(default_factory=lambda: ["каб", "каба", "кабы", "каби", "кабів", "кабов", "авіабомб", "авиабомб", "фаб"])
    rocket_launch_keywords: List[str] = field(default_factory=lambda: ["ту-95", "ту-160", "міг-31к", "миг-31к"])


@dataclass
class AlarmRule:
    id: str = ""
    severity: str = "low"
    threat_type: str = "rocket"
    enabled: bool = True
    sources: List[str] = field(default_factory=lambda: ["telegram:*", "alarmmap"])
    approaches: List[str] = field(default_factory=lambda: list(APPROACHES))
    drone_groups: List[int] = field(default_factory=lambda: [0, 1, 2, 3])
    api_types: List[str] = field(default_factory=list)
    api_levels: List[int] = field(default_factory=list)
    # API не сообщает положение цели: это отдельный фильтр по type+level.
    sound: SoundProfile = field(default_factory=SoundProfile)


def default_alarm_rules():
    rules = []
    for degree, levels, approaches in [
        ("critical", [3], ["district", "toward_district"]),
        ("high", [2], ["city", "toward_city"]),
        ("low", [1], ["launch"]),
    ]:
        for kind in THREAT_TYPES:
            code = len(rules) + 1
            rules.append(AlarmRule(
                id=f"{degree}_{kind}", severity=degree, threat_type=kind,
                approaches=(list(approaches)+["city", "toward_city"]
                            if degree == "critical" and kind in ("rocket", "kab") else list(approaches)),
                drone_groups=(([0, 1] if degree == "critical" else [0, 1, 2, 3]) if kind == "drone" else []),
                api_types={"rocket": ["air"], "kab": ["kab-bombs"],
                           "drone": ["fight-drones"]}[kind],
                api_levels=(levels if kind == "rocket" else {"critical": [2], "high": [1], "low": []}[degree]),
                sound=SoundProfile(code, f"{SEVERITIES[degree]} — {THREAT_TYPES[kind]}",
                                   {"critical": 3, "high": 2, "low": 1}[degree],
                                   {"critical": 1000, "high": 700, "low": 300}[degree],
                                   400, {"critical": 4000, "high": 8000, "low": 15000}[degree])
            ))
    return rules

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
        "харьков", "харків", "городу", "місту", "центр", "шевро", "салтов", "салтів", "алексеев", "олексіїв",
        "місто", "міста", "містом", "город", "города", "городом"
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
    alarm_rules: List[AlarmRule] = field(default_factory=default_alarm_rules)
    end_conditions: List[EndCondition] = field(default_factory=default_end_conditions)
    tracking: TrackingConfig = field(default_factory=TrackingConfig)
    approach_keywords: Dict[str, List[str]] = field(default_factory=lambda: {
        "launch": ["пуск", "запуск", "злет", "взлет", "виліт", "вылет"],
        "city": ["над", "в городе", "у місті", "в черте", "над містом"],
        "toward_city": ["на", "курс", "напрям", "в сторону", "у бік", "в бік"],
        "district": ["над", "в районе", "у районі", "в районі"],
        "toward_district": ["курс на", "напрям", "в сторону", "у бік", "в бік", "летит на", "летять на", "на "]
    })
    source_stale_seconds: int = 60
    api_stale_seconds: int = 60
    safe_sound: SoundProfile = field(default_factory=lambda: SoundProfile(
        0, "Отсутствие тревог", 1, 200, 0, 30000))
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
            cfg.enabled = d.get("enabled", True)
            cfg.alarmmap_katottg = d.get("alarmmap_katottg", cfg.alarmmap_katottg)
            cfg.source_stale_seconds = int(d.get("source_stale_seconds", 60))
            cfg.api_stale_seconds = int(d.get("api_stale_seconds", 60))
            cfg.approach_keywords = d.get("approach_keywords", cfg.approach_keywords)
            cfg.approach_keywords.setdefault("toward_city", ["на", "курс", "напрям", "в сторону", "у бік"])
            if "tracking" in d:
                cfg.tracking = TrackingConfig(**d["tracking"])
            if "end_conditions" in d:
                cfg.end_conditions = [EndCondition(**row) for row in d["end_conditions"]]
            cfg.alarmmap_enabled = d.get("alarmmap_enabled", cfg.alarmmap_enabled)
            cfg.alarmmap_key_file = d.get("alarmmap_key_file", cfg.alarmmap_key_file)
            cfg.alarmmap_poll_interval_s = d.get("alarmmap_poll_interval_s", cfg.alarmmap_poll_interval_s)
            cfg.telegram_enabled = d.get("telegram_enabled", cfg.telegram_enabled)
            cfg.telegram_mode = d.get("telegram_mode", cfg.telegram_mode)
            cfg.telegram_poll_interval_s = int(d.get("telegram_poll_interval_s", cfg.telegram_poll_interval_s))
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
            if "alarm_rules" in d:
                cfg.alarm_rules = []
                for data in d["alarm_rules"]:
                    data = dict(data)
                    data["sound"] = SoundProfile(**data["sound"])
                    cfg.alarm_rules.append(AlarmRule(**data))
            else:
                # Сохраняем прежние параметры звука при переходе на девять правил.
                from copy import deepcopy
                mapping = {
                    "critical_rocket": "rocket_critical", "high_rocket": "rocket_potential",
                    "low_rocket": "rocket_potential", "critical_kab": "kab_district_critical",
                    "high_kab": "kab_city_critical", "low_kab": "kab_potential",
                    "critical_drone": "drone_g1_district_critical", "high_drone": "drone_g1_city",
                    "low_drone": "drone_g3_decoy"}
                for rule in cfg.alarm_rules:
                    old = deepcopy(getattr(cfg.sound_profiles, mapping[rule.id]))
                    old.code, old.name = rule.sound.code, rule.sound.name
                    rule.sound = old
            cfg.safe_sound = SoundProfile(**d["safe_sound"]) if "safe_sound" in d else cfg.sound_profiles.safe_heartbeat
            cfg.safe_sound.code = 0
            cfg.validate()
        except Exception as e:
            raise ValueError(f"Не удалось загрузить настройки {path}: {e}") from e
        return cfg

    def validate(self):
        import re
        normalized_channels = [c.strip().replace("https://t.me/", "").lstrip("@").strip("/").lower()
                               for c in self.telegram_channels]
        if any(not re.fullmatch(r"[a-z0-9_]+", c) for c in normalized_channels):
            raise ValueError("Укажите имена Telegram-каналов без ссылок на сообщения")
        if self.telegram_enabled and not normalized_channels:
            raise ValueError("Для Telegram нужно указать хотя бы один канал")
        if self.telegram_enabled and self.telegram_mode == "telethon" and (not self.telegram_api_id or not self.telegram_api_hash):
            raise ValueError("Для Telethon нужны API ID и API Hash")
        if len(self.alarm_rules) != 9 or {r.id for r in self.alarm_rules} != {
                f"{degree}_{kind}" for degree in SEVERITIES for kind in THREAT_TYPES}:
            raise ValueError("Требуются все девять уникальных правил тревоги")
        for rule in self.alarm_rules:
            if rule.id != f"{rule.severity}_{rule.threat_type}":
                raise ValueError("Несогласованное название правила")
            if not set(rule.approaches) <= set(APPROACHES):
                raise ValueError("Неизвестная степень приближения")
            if not set(rule.drone_groups) <= {0, 1, 2, 3}:
                raise ValueError("Группа дрона: 0 (неизвестна), 1, 2 или 3")
            if any(not isinstance(n, int) or n < 0 for n in rule.api_levels):
                raise ValueError("Уровни API должны быть неотрицательными целыми")
            if any(src != "alarmmap" and not re.fullmatch(r"telegram:(?:\*|[A-Za-z0-9_]+)", src) for src in rule.sources):
                raise ValueError("Источник: alarmmap, telegram:* или telegram:имя_канала")
            if rule.enabled and not rule.sources:
                raise ValueError(f"Выберите источники для {rule.id}")
            for source in rule.sources:
                if source.startswith("telegram:") and source != "telegram:*" and source.split(":", 1)[1].lower() not in normalized_channels:
                    raise ValueError(f"Добавьте канал {source} во вкладку Источники")
            if rule.enabled and rule.threat_type == "drone" and not rule.drone_groups:
                raise ValueError(f"Выберите группы дронов для {rule.id}")
        if set(self.approach_keywords) != set(APPROACHES) or any(
                not isinstance(words, list) or any(not isinstance(w, str) for w in words)
                for words in self.approach_keywords.values()):
            raise ValueError("Некорректный словарь приближения")
        if self.tracking.context_seconds <= 0 or self.tracking.movement_hold_seconds < 0:
            raise ValueError("Окно контекста должно быть положительным; выдержка — неотрицательной")
        if self.tracking.movement_action not in ("keep", "replace", "shorten"):
            raise ValueError("Некорректное действие при продвижении цели")
        for condition in self.end_conditions:
            if condition.action not in ("clear", "shorten", "ignore") or condition.hold_seconds < 0 or condition.context_seconds <= 0:
                raise ValueError("Проверьте действие, выдержку и окно контекста окончания угрозы")
            if not set(condition.threat_types) <= set(THREAT_TYPES):
                raise ValueError("Неизвестный тип угрозы в условии окончания")
            if any(not re.fullmatch(r"telegram:(?:\*|[A-Za-z0-9_]+)", source) for source in condition.sources):
                raise ValueError("Условия окончания используют Telegram или отдельные каналы")
            if condition.enabled and (not condition.keywords or not condition.sources or not condition.threat_types):
                raise ValueError("Условию окончания нужны фразы, источники и типы угроз")
        bits = list(asdict(self.bit_mapping).values())
        feedback = list(asdict(self.plc_feedback).values())
        if any(not isinstance(b, int) or not 0 <= b <= 15 for b in bits + feedback):
            raise ValueError("Номера битов должны быть от 0 до 15")
        if len(set(bits)) != len(bits) or len(set(feedback)) != len(feedback):
            raise ValueError("Назначения битов в одном слове должны быть уникальными")
        if any(not isinstance(v, int) or v <= 0 for v in [self.district.ttl_seconds,
                self.alarmmap_poll_interval_s, self.telegram_poll_interval_s,
                self.source_stale_seconds, self.api_stale_seconds]):
            raise ValueError("TTL, интервалы и таймауты актуальности должны быть положительными")
        if self.api_stale_seconds < self.alarmmap_poll_interval_s:
            raise ValueError("Актуальность API должна быть не меньше интервала опроса")
        for t in [self.schedule.start_time, self.schedule.end_time]:
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", t):
                raise ValueError("Время расписания: ЧЧ:ММ")
        for p in [self.safe_sound] + [r.sound for r in self.alarm_rules]:
            if any(not isinstance(v, int) or not 0 <= v <= 65535 for v in
                   [p.code, p.beep_count, p.beep_duration_ms, p.pause_between_ms, p.interval_series_ms]):
                raise ValueError("Параметры звука должны быть в диапазоне 0..65535")
            # В ПЛК время импульса/паузы хранится в шагах 10 мс (%TM1, %TM2 TimeBase: TenMilliSeconds), серии — 1 с (%TM3).
            if p.beep_duration_ms % 10 or p.pause_between_ms % 10 or p.interval_series_ms % 1000:
                raise ValueError("Длительность/пауза: шаг 10 мс; интервал серий: шаг 1000 мс")
            if p.beep_count and (not p.beep_duration_ms or not p.interval_series_ms):
                raise ValueError("Для включенного звука задайте длительность и интервал")
        codes = [r.sound.code for r in self.alarm_rules]
        if set(codes) != set(range(1, 10)) or self.safe_sound.code != 0:
            raise ValueError("Коды тревог: 1..9; отсутствия тревог: 0")

    def save(self, path: str = "config_threats.json") -> bool:
        """Атомарное сохранение всех настроек; при ошибке исходный файл сохраняется."""
        import json, os, tempfile
        self.validate()
        target = os.path.abspath(path)
        fd, temporary = tempfile.mkstemp(dir=os.path.dirname(target), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(asdict(self), f, ensure_ascii=False, indent=2)
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return True
