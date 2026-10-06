import os
import time
import json
import urllib.request
import threading
from typing import Optional, Callable, List, Dict
from src.threat_models import ThreatSystemConfig, ThreatStatus
from src.telegram_reader import TelegramWebReader, TelegramTelethonReader

class ThreatEvaluator:
    """
    Анализатор угроз для г. Харьков и целевого сектора
    (Основянский / Слободской / Немышля / Новые Дома / Одесская / Аэропорт).
    Объединяет AlarmMap API и Telegram-каналы, формирует 16-битное слово для ПЛК.
    """
    def __init__(self, config: ThreatSystemConfig, on_status_change: Optional[Callable[[ThreatStatus], None]] = None):
        self.config = config
        self.on_status_change = on_status_change

        self.status = ThreatStatus()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Состояния источников
        self._alarmmap_online = False
        self._tg_online = False
        self._alarmmap_last_poll = 0.0
        self._alarmmap_active_alarms: List[dict] = []

        # Активные угрозы района с метками времени
        self._district_threat_expire_at = 0.0
        self._district_threat_type = ""
        self._district_threat_critical = False

        self._city_threat_expire_at = 0.0
        self._city_threat_type = ""
        self._city_threat_critical = False

        # Telegram ридер
        self.tg_reader = None
        self._init_tg_reader()

        # История сообщений для лога GUI
        self.recent_events_log: List[dict] = []

        # Heartbeat счетчик
        self._heartbeat_state = 0

    def _init_tg_reader(self):
        if not self.config.telegram_enabled:
            return

        def on_tg_msg(msg: dict):
            self._handle_telegram_message(msg)

        if self.config.telegram_mode == "telethon" and self.config.telegram_api_id and self.config.telegram_api_hash:
            self.tg_reader = TelegramTelethonReader(
                api_id=self.config.telegram_api_id,
                api_hash=self.config.telegram_api_hash,
                channels=self.config.telegram_channels,
                on_message=on_tg_msg
            )
        else:
            self.tg_reader = TelegramWebReader(
                channels=self.config.telegram_channels,
                on_message=on_tg_msg,
                poll_interval=self.config.telegram_poll_interval_s
            )

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        if self.tg_reader:
            self.tg_reader.start()
        self._thread = threading.Thread(target=self._run_loop, name="ThreatEvaluatorLoop", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self.tg_reader:
            self.tg_reader.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self):
        while not self._stop_event.is_set():
            now = time.time()

            # 1. Опрос AlarmMap API по расписанию
            if self.config.alarmmap_enabled and (now - self._alarmmap_last_poll >= self.config.alarmmap_poll_interval_s):
                self._poll_alarmmap()
                self._alarmmap_last_poll = now

            # 2. Проверка истечения TTL угроз
            self._evaluate_current_threat_state()

            # 3. Мигание Heartbeat (раз в 1 сек)
            self._heartbeat_state = 1 if (int(now) % 2 == 0) else 0

            # 4. Формирование битового слова для ПЛК
            self._build_modbus_word()

            if self.on_status_change:
                try:
                    self.on_status_change(self.status)
                except Exception as e:
                    print(f"[ThreatEvaluator] Callback error: {e}")

            time.sleep(1.0)

    def _poll_alarmmap(self):
        """Чтение статуса тревог в Харькове через AlarmMap API."""
        if not os.path.exists(self.config.alarmmap_key_file):
            self._alarmmap_online = False
            return

        try:
            with open(self.config.alarmmap_key_file, "r", encoding="utf-8") as f:
                key = f.read().strip()
            if not key:
                self._alarmmap_online = False
                return

            # Запрашиваем тревоги для города Харьков
            url = f"https://alarmmap.online/api/v1/emergencies/ua/{self.config.alarmmap_katottg}"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "User-Agent": "Seren/1.0"})
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._alarmmap_active_alarms = data.get("data", [])
                self._alarmmap_online = True
        except Exception as e:
            self._alarmmap_online = False

    def reset_threat_state(self, source: str = "ПЛК (Кнопка сброса)"):
        """Сброс текущего тревожного состояния и перезапуск анализа с чистого листа."""
        self._district_threat_expire_at = 0.0
        self._city_threat_expire_at = 0.0
        self._district_threat_type = ""
        self._city_threat_type = ""
        self._district_threat_critical = False
        self._city_threat_critical = False

        self._evaluate_current_threat_state()
        self._build_modbus_word()

        t_now = time.strftime("%H:%M:%S")
        self.recent_events_log.insert(0, {
            "channel": "СИСТЕМА",
            "text": f"Сброс тревожного состояния по команде: {source}. Запущен повторный анализ.",
            "time_str": t_now
        })
        self.status.last_event_time = time.time()
        self.status.last_event_source = "СБРОС"
        self.status.last_event_text = f"Сброс тревоги ({source}). Повторный анализ."

        if self.on_status_change:
            try:
                self.on_status_change(self.status)
            except Exception as e:
                print(f"[ThreatEvaluator] Reset callback error: {e}")

    def _handle_telegram_message(self, msg: dict):
        """Анализ входящего текста сообщения из Telegram."""
        self._tg_online = True
        text = msg.get("text", "")
        text_lower = text.lower()
        now = time.time()

        # Добавляем в историю сообщений
        self.recent_events_log.insert(0, {
            "channel": msg.get("channel", ""),
            "text": text,
            "time_str": time.strftime("%H:%M:%S", time.localtime(now))
        })
        if len(self.recent_events_log) > 50:
            self.recent_events_log.pop()

        # 1. Проверка на отбой / чисто
        clear_keywords = ["чисто", "відбій", "отбой", "больше не фиксируется", "більше не фіксується", "помилково", "угроза миновала", "ложная цель"]
        is_clear = any(w in text_lower for w in clear_keywords)

        # 2. Определение типа угрозы
        is_rocket = any(w in text_lower for w in ["ракета", "ракети", "балистика", "балістика", "іскандер", "швидкісна ціль", "скоростная цель", "с-300", "с-400"])
        is_kab = any(w in text_lower for w in ["каб", "кабы", "каби", "керовані авіабомби", "авиабомб", "пуск каб", "пуски каб", "фоб"])
        is_drone = any(w in text_lower for w in ["шахед", "шахеди", "шахеды", "мопед", "мопеды", "дрон", "дроны", "бпла", "бандероль", "молния"])

        # 3. Маркеры экстренной опасности ("в укрытие", "в укриття" и т.д.)
        is_shelter_call = any(w in text_lower for w in self.config.district.critical_alert_keywords)

        # 4. Определение привязки к району
        matched_district_kw = [kw for kw in self.config.district.district_keywords if kw in text_lower]
        is_for_district = len(matched_district_kw) > 0

        # 5. Определение привязки к городу
        matched_city_kw = [kw for kw in self.config.district.city_keywords if kw in text_lower]
        is_for_city = len(matched_city_kw) > 0 or is_for_district or is_shelter_call

        # Маркеры критичности (прямой курс / подлет)
        is_critical_words = is_shelter_call or any(w in text_lower for w in [
            "на ", "курс на", "в сторону", "подлет", "підліт", "прямо", "вектор", "в черте", "над ", "увага", "внимание", "срочно", "терміново", "укриття", "укрытия"
        ])

        if is_clear:
            if is_for_district:
                self._district_threat_expire_at = 0.0
            if is_for_city and not is_for_district:
                self._city_threat_expire_at = 0.0
            return

        threat_type = "rocket" if is_rocket else ("kab" if is_kab else ("drone" if is_drone else "air"))
        ttl = self.config.district.ttl_seconds

        # Проверяем, упоминался ли ранее целевой район (активна ли угроза или была в недавних сообщениях)
        district_already_in_threat = (now < self._district_threat_expire_at)
        if not district_already_in_threat and len(self.recent_events_log) > 1:
            # Проверим последние сообщения (до 10 предыдущих) на упоминание целевого района
            for prev_ev in self.recent_events_log[1:10]:
                prev_txt = prev_ev.get("text", "").lower()
                if any(kw in prev_txt for kw in self.config.district.district_keywords):
                    district_already_in_threat = True
                    break

        # Специфическое правило: если фраза "в укрытие" (даже общая для города),
        # но перед этим упоминались целевые районы — МАКСИМАЛЬНЫЙ УРОВЕНЬ ОПАСНОСТИ РАЙОНУ (Уровень 5 / Бит 5)!
        if is_shelter_call and district_already_in_threat:
            self._district_threat_expire_at = now + ttl
            self._district_threat_critical = True
            if not self._district_threat_type and threat_type:
                self._district_threat_type = threat_type
            self.status.last_event_time = now
            self.status.last_event_source = f"@{msg.get('channel', 'TG')}"
            self.status.last_event_text = f"Эскалация [В УКРЫТИЕ]: {text}"

        elif is_for_district:
            # Угроза именно району (Новые Дома, Одесская, Аэропорт, Основа, Слободской, Немышля)
            self._district_threat_expire_at = now + ttl
            self._district_threat_type = threat_type
            self._district_threat_critical = is_critical_words or is_rocket or is_kab or is_shelter_call
            self.status.last_event_time = now
            self.status.last_event_source = f"@{msg.get('channel', 'TG')}"
            self.status.last_event_text = text

        elif is_for_city or is_rocket or is_kab or is_drone or is_shelter_call:
            # Угроза городу в целом
            self._city_threat_expire_at = now + ttl
            self._city_threat_type = threat_type
            self._city_threat_critical = is_critical_words or is_rocket or is_shelter_call
            self.status.last_event_time = now
            self.status.last_event_source = f"@{msg.get('channel', 'TG')}"
            self.status.last_event_text = text

    def _evaluate_current_threat_state(self):
        """Перерасчет уровней опасности на основе времени и данных AlarmMap."""
        now = time.time()

        # Проверка данных AlarmMap
        alarmmap_has_air = False
        alarmmap_has_kab = False
        alarmmap_has_drone = False
        alarmmap_level = 0

        for a in self._alarmmap_active_alarms:
            t = a.get("type")
            lvl = int(a.get("level", 1))
            alarmmap_level = max(alarmmap_level, lvl)
            if t == "air":
                alarmmap_has_air = True
            elif t == "kab-bombs":
                alarmmap_has_kab = True
            elif t == "fight-drones":
                alarmmap_has_drone = True

        # Проверка актуальности угроз Telegram
        district_active = (now < self._district_threat_expire_at)
        city_active = (now < self._city_threat_expire_at)

        # Вычисляем общий уровень опасности (0..5)
        level_code = 0
        level_title = "Безопасно"
        desc = "Угроз не зафиксировано, обстановка спокойная"

        has_rocket = False
        has_kab = alarmmap_has_kab
        has_drone = alarmmap_has_drone

        if district_active:
            if self._district_threat_type == "rocket":
                has_rocket = True
            elif self._district_threat_type == "kab":
                has_kab = True
            elif self._district_threat_type == "drone":
                has_drone = True

            if self._district_threat_critical:
                level_code = 5
                level_title = "КРИТИЧЕСКАЯ ОПАСНОСТЬ: РАЙОН"
                desc = f"Прямая угроза сектору объекта ({self.config.district.name})!"
            else:
                level_code = 3
                level_title = "Потенциальная опасность: Район"
                desc = f"Цели в направлении сектора ({self.config.district.name})"

        elif city_active:
            if self._city_threat_type == "rocket":
                has_rocket = True
            elif self._city_threat_type == "kab":
                has_kab = True
            elif self._city_threat_type == "drone":
                has_drone = True

            if self._city_threat_critical or has_rocket:
                level_code = 4
                level_title = "КРИТИЧЕСКАЯ ОПАСНОСТЬ: ГОРОД"
                desc = "Ракетная опасность или подтвержденные пуски на Харьков"
            else:
                level_code = 2
                level_title = "Потенциальная опасность: Город"
                desc = "Угроза применения вооружения в направлении Харькова"

        elif alarmmap_has_air or alarmmap_has_kab or alarmmap_has_drone:
            if alarmmap_has_kab:
                level_code = 4
                level_title = "КРИТИЧЕСКАЯ ОПАСНОСТЬ: ГОРОД (КАБ)"
                desc = "В городе объявлена тревога: Угроза КАБ"
            elif alarmmap_has_drone:
                level_code = 2
                level_title = "Потенциальная опасность: Город (БпЛА)"
                desc = "В городе объявлена тревога: Ударные дроны"
            else:
                level_code = 1
                level_title = "Опасность минимальна: Тревога"
                desc = "Общая воздушная тревога по городу (превентивная)"

        # Проверка наличия связи с источниками
        no_link = False
        if self.config.alarmmap_enabled and not self._alarmmap_online:
            no_link = True

        self.status.level_code = level_code
        self.status.level_title = level_title
        self.status.description = desc
        self.status.is_city_threat = (level_code >= 2)
        self.status.is_district_threat = (level_code == 3 or level_code == 5)
        self.status.has_rocket = has_rocket
        self.status.has_kab = has_kab
        self.status.has_drone = has_drone
        self.status.no_data_link = no_link

    def _build_modbus_word(self):
        """Формирование 16-битного целого числа для %MW0 на основе BitMappingConfig."""
        cfg = self.config.bit_mapping
        val = 0
        lvl = self.status.level_code

        # Уровни опасности (биты 0..5)
        if lvl == 0:
            val |= (1 << cfg.bit_safe)
        elif lvl == 1:
            val |= (1 << cfg.bit_threat_minimal)
        elif lvl == 2:
            val |= (1 << cfg.bit_threat_city_potential)
        elif lvl == 3:
            val |= (1 << cfg.bit_threat_district_potential)
        elif lvl == 4:
            val |= (1 << cfg.bit_threat_city_critical)
        elif lvl == 5:
            val |= (1 << cfg.bit_threat_district_critical)

        # Типы угроз (биты 6..8)
        if self.status.has_rocket:
            val |= (1 << cfg.bit_type_rocket)
        if self.status.has_kab:
            val |= (1 << cfg.bit_type_kab)
        if self.status.has_drone:
            val |= (1 << cfg.bit_type_drone)

        # Нет связи (бит 9)
        if self.status.no_data_link:
            val |= (1 << cfg.bit_no_link)

        # Heartbeat (бит 15)
        if self._heartbeat_state:
            val |= (1 << cfg.bit_heartbeat)

        self.status.modbus_word = val & 0xFFFF
