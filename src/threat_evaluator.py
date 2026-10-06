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
        self._district_drone_group = 0
        self._district_drone_name = ""

        self._city_threat_expire_at = 0.0
        self._city_threat_type = ""
        self._city_threat_critical = False
        self._city_drone_group = 0
        self._city_drone_name = ""

        # Telegram ридер
        self.tg_reader = None
        self._init_tg_reader()

        # История сообщений для лога GUI
        self.recent_events_log: List[dict] = []

        # Heartbeat счетчик
        self._heartbeat_state = 0

        # Сигнал от переключателя ПЛК (True = анализ включен, False = выключен)
        self._plc_analysis_enabled = True

    def set_plc_analysis_switch(self, enabled: bool):
        """Установить состояние аппаратного переключателя с ПЛК."""
        self._plc_analysis_enabled = enabled

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

            # 2. Проверка истечения TTL угроз и расчет уровней
            self._evaluate_current_threat_state()

            # 3. Мигание Heartbeat (раз в 1 сек)
            self._heartbeat_state = 1 if (int(now) % 2 == 0) else 0

            # 4. Формирование битового слова для ПЛК и динамического звукового профиля
            self._build_modbus_word()
            self._determine_sound_profile()

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
        self._district_drone_group = 0
        self._city_drone_group = 0
        self._district_drone_name = ""
        self._city_drone_name = ""

        self._evaluate_current_threat_state()
        self._build_modbus_word()
        self._determine_sound_profile()

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

    def _match_drone_dictionary(self, text_lower: str):
        """
        Классификация беспилотников по 3 группам опасности:
        Группа 1: Тяжелые ударные (Шахед, Герань, Гербера, Италмас) - ранг 1
        Группа 2: Тактические/FPV/разведчики (Молния, Ланцет, Суперкам, Зала, Орлан) - ранг 2
        Группа 3: Ложные цели/имитаторы (Пародия, фанера, фальш-цель, приманка) - ранг 3
        Возвращает: (drone_group: 0..3, matched_name: str). Приоритет отдается наивысшей опасности (Группа 1 > 2 > 3).
        """
        dd = self.config.drone_dict

        # Проверка Группы 1 (наивысшая опасность)
        for kw in dd.group1_keywords:
            if kw and kw in text_lower:
                return 1, kw

        # Проверка Группы 2 (средняя опасность)
        for kw in dd.group2_keywords:
            if kw and kw in text_lower:
                return 2, kw

        # Проверка Группы 3 (низкая опасность)
        for kw in dd.group3_keywords:
            if kw and kw in text_lower:
                return 3, kw

        # Общие упоминания без конкретного названия
        general_drone_kws = ["шахед", "мопед", "дрон", "бпла", "бандероль"]
        for kw in general_drone_kws:
            if kw in text_lower:
                return 1, kw # по умолчанию общее упоминание считаем опасным (Шахед/дрон)

        return 0, ""

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

        # Анализ словаря БпЛА
        drone_group, drone_name = self._match_drone_dictionary(text_lower)
        is_drone = (drone_group > 0)

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

        # Проверяем, упоминался ли ранее целевой район
        district_already_in_threat = (now < self._district_threat_expire_at)
        if not district_already_in_threat and len(self.recent_events_log) > 1:
            for prev_ev in self.recent_events_log[1:10]:
                prev_txt = prev_ev.get("text", "").lower()
                if any(kw in prev_txt for kw in self.config.district.district_keywords):
                    district_already_in_threat = True
                    break

        # Специфическое правило: если фраза "в укрытие", но перед этим упоминались целевые районы — МАКСИМАЛЬНЫЙ УРОВЕНЬ ОПАСНОСТИ РАЙОНУ
        if is_shelter_call and district_already_in_threat:
            self._district_threat_expire_at = now + ttl
            self._district_threat_critical = True
            if not self._district_threat_type and threat_type:
                self._district_threat_type = threat_type
            if is_drone and drone_group > 0:
                self._district_drone_group = drone_group
                self._district_drone_name = drone_name
            self.status.last_event_time = now
            self.status.last_event_source = f"@{msg.get('channel', 'TG')}"
            self.status.last_event_text = f"Эскалация [В УКРЫТИЕ]: {text}"

        elif is_for_district:
            # Угроза именно району (Новые Дома, Одесская, Аэропорт, Основа, Слободской, Немышля)
            self._district_threat_expire_at = now + ttl
            self._district_threat_type = threat_type
            # Коррекция критичности для БпЛА: Группа 3 (ложные цели) не делает тревогу критической!
            if is_drone and drone_group == 3:
                self._district_threat_critical = False
            elif is_drone and drone_group == 2:
                # Тактический дрон/разведчик - критичен только если призыв в укрытие
                self._district_threat_critical = is_shelter_call
            else:
                self._district_threat_critical = is_critical_words or is_rocket or is_kab or is_shelter_call

            if is_drone and drone_group > 0:
                self._district_drone_group = drone_group
                self._district_drone_name = drone_name

            self.status.last_event_time = now
            self.status.last_event_source = f"@{msg.get('channel', 'TG')}"
            self.status.last_event_text = text

        elif is_for_city or is_rocket or is_kab or is_drone or is_shelter_call:
            # Угроза городу в целом (не разделяется на районы для ракет)
            self._city_threat_expire_at = now + ttl
            self._city_threat_type = threat_type
            if is_drone and drone_group == 3:
                self._city_threat_critical = False
            elif is_drone and drone_group == 2:
                self._city_threat_critical = False
            else:
                self._city_threat_critical = is_critical_words or is_rocket or is_shelter_call

            if is_drone and drone_group > 0:
                self._city_drone_group = drone_group
                self._city_drone_name = drone_name

            self.status.last_event_time = now
            self.status.last_event_source = f"@{msg.get('channel', 'TG')}"
            self.status.last_event_text = text

    def _evaluate_current_threat_state(self):
        """Перерасчет уровней опасности на основе времени, AlarmMap и словаря угроз."""
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

        level_code = 0
        level_title = "Безопасно"
        desc = "Угроз не зафиксировано, обстановка спокойная"

        has_rocket = False
        has_kab = alarmmap_has_kab
        has_drone = alarmmap_has_drone
        current_drone_group = 0
        current_drone_name = ""

        # Угрозы району
        if district_active:
            if self._district_threat_type == "rocket":
                has_rocket = True
            elif self._district_threat_type == "kab":
                has_kab = True
            elif self._district_threat_type == "drone":
                has_drone = True
                current_drone_group = self._district_drone_group or 1
                current_drone_name = self._district_drone_name

            if self._district_threat_critical:
                level_code = 5
                level_title = "КРИТИЧЕСКАЯ ОПАСНОСТЬ: РАЙОН"
                desc = f"Прямая угроза сектору объекта ({self.config.district.name})!"
            else:
                level_code = 3
                level_title = "Потенциальная опасность: Район"
                desc = f"Цели в направлении сектора ({self.config.district.name})"

        # Угрозы городу
        if city_active:
            city_has_rocket = (self._city_threat_type == "rocket")
            city_has_kab = (self._city_threat_type == "kab")
            city_has_drone = (self._city_threat_type == "drone")

            if city_has_rocket:
                has_rocket = True
            if city_has_kab:
                has_kab = True
            if city_has_drone:
                has_drone = True
                if not current_drone_group:
                    current_drone_group = self._city_drone_group or 1
                    current_drone_name = self._city_drone_name

            city_lvl = 4 if (self._city_threat_critical or city_has_rocket) else 2
            city_title = "КРИТИЧЕСКАЯ ОПАСНОСТЬ: ГОРОД" if city_lvl == 4 else "Потенциальная опасность: Город"
            city_desc = "Ракетная опасность или подтвержденные пуски на Харьков" if city_lvl == 4 else "Угроза применения вооружения в направлении Харькова"

            # Важное правило приоритета:
            # Если для района нет активной критической опасности (district_active не дал level_code == 5),
            # то городская угроза задает уровень.
            # Если же для района есть критическая опасность (level_code == 5, например КАБ или Дрон на район),
            # то преимущество отдается критической опасности РАЙОНА (level_code 5 побеждает city_lvl 4)!
            if level_code < 5:
                if city_lvl > level_code:
                    level_code = city_lvl
                    level_title = city_title
                    desc = city_desc

        elif not district_active and (alarmmap_has_air or alarmmap_has_kab or alarmmap_has_drone):
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

        # Коррекция по группе беспилотников:
        # Если тревога вызвана исключительно дронами Группы 3 (ложные цели / имитаторы / фанера),
        # снижаем статус до минимальной опасности, если не было ракет/кабов
        if has_drone and not has_rocket and not has_kab:
            if current_drone_group == 3:
                level_code = 1
                level_title = "Минимальная опасность: Ложные цели БпЛА"
                desc = f"Зафиксированы имитаторы / фальш-цели без БЧ ({current_drone_name or 'Пародия'})"
            elif current_drone_group == 2 and level_code == 5:
                # Тактический дрон понижаем с критического до потенциального района
                level_code = 3
                level_title = "Потенциальная опасность: Дрон-разведчик / FPV"
                desc = f"В секторе зафиксирован БпЛА ({current_drone_name or 'Молния/FPV'})"

        # Проверка наличия связи с источниками
        no_link = False
        if self.config.alarmmap_enabled and not self._alarmmap_online:
            no_link = True

        # Проверка переключателя анализа от ПЛК
        self.status.analysis_disabled_by_plc = not self._plc_analysis_enabled
        if self.status.analysis_disabled_by_plc:
            level_code = 0
            level_title = "Анализ приостановлен (ПЛК)"
            desc = "Тумблер анализа на контроллере выключен (передача в %MW0 заблокирована)"
            has_rocket = False
            has_kab = False
            has_drone = False
            current_drone_group = 0
            current_drone_name = ""

        # Проверка тихого часа по расписанию
        self.status.is_muted = self.config.schedule.is_in_schedule()

        self.status.level_code = level_code
        self.status.level_title = level_title
        self.status.description = desc
        self.status.is_city_threat = (level_code >= 2)
        self.status.is_district_threat = (level_code == 3 or level_code == 5)
        self.status.has_rocket = has_rocket
        self.status.has_kab = has_kab
        self.status.has_drone = has_drone
        self.status.drone_group = current_drone_group
        self.status.matched_drone_name = current_drone_name
        self.status.no_data_link = no_link

    def _determine_sound_profile(self):
        """
        Выбор динамического звукового профиля гудков (%MW2..%MW6)
        с учетом приоритетов:
        1. Если заблокировано тумблером ПЛК или тихий час -> Все параметры по 0!
        2. Если КАБ: Критическая для района (или Дрон Гр.1 на район при уровне 5) -> ПРЕИМУЩЕСТВО РАЙОНУ!
        3. Если Ракета: Критическая для города -> Профиль ракеты.
        4. Если КАБ: Критическая для города -> Профиль КАБ город.
        5. И так далее по убыванию опасности.
        6. Если Норма / Нет тревог -> safe_heartbeat (звуковой heartbeat).
        """
        sp = self.config.sound_profiles

        # 1. Если анализ заблокирован тумблером или действует ночное расписание тишины:
        if self.status.analysis_disabled_by_plc or self.status.is_muted:
            self.status.sound_code = 0
            self.status.sound_beep_count = 0
            self.status.sound_duration_ms = 0
            self.status.sound_pause_ms = 0
            self.status.sound_interval_ms = 0
            self.status.sound_profile_name = "Блокировка (Тишина 0)"
            return

        # 2. Определение активного звукового профиля по наивысшему приоритету:
        lvl = self.status.level_code
        has_rocket = self.status.has_rocket
        has_kab = self.status.has_kab
        has_drone = self.status.has_drone
        d_grp = self.status.drone_group

        active_prof: SoundProfile = sp.safe_heartbeat

        # ПРАВИЛО ПРИОРИТЕТА:
        # Уровень 5 (Критическая для района) имеет безусловный приоритет перед уровнем 4 (Критическая для города от ракеты/каба)!
        if lvl == 5:
            if has_kab:
                active_prof = sp.kab_district_critical
            elif has_drone:
                active_prof = sp.drone_g1_district_critical
            elif has_rocket:
                active_prof = sp.rocket_critical
            else:
                active_prof = sp.kab_district_critical

        elif lvl == 4:
            # Критическая для города
            if has_rocket:
                active_prof = sp.rocket_critical
            elif has_kab:
                active_prof = sp.kab_city_critical
            elif has_drone:
                active_prof = sp.drone_g1_city
            else:
                active_prof = sp.rocket_critical

        elif lvl == 3:
            # Потенциальная опасность для района
            if has_kab:
                active_prof = sp.kab_potential
            elif has_drone:
                active_prof = sp.drone_g2_tactical if d_grp == 2 else sp.drone_g1_city
            elif has_rocket:
                active_prof = sp.rocket_potential
            else:
                active_prof = sp.kab_potential

        elif lvl == 2:
            # Потенциальная опасность для города
            if has_rocket:
                active_prof = sp.rocket_potential
            elif has_kab:
                active_prof = sp.kab_potential
            elif has_drone:
                active_prof = sp.drone_g2_tactical if d_grp == 2 else sp.drone_g1_city
            else:
                active_prof = sp.rocket_potential

        elif lvl == 1:
            # Минимальная опасность
            if has_drone and d_grp == 3:
                active_prof = sp.drone_g3_decoy
            else:
                active_prof = sp.drone_g3_decoy

        else: # lvl == 0 (Безопасно / норма)
            active_prof = sp.safe_heartbeat

        # Записываем выбранный профиль в статус
        self.status.sound_code = active_prof.code
        self.status.sound_beep_count = active_prof.beep_count
        self.status.sound_duration_ms = active_prof.beep_duration_ms
        self.status.sound_pause_ms = active_prof.pause_between_ms
        self.status.sound_interval_ms = active_prof.interval_series_ms
        self.status.sound_profile_name = active_prof.name

    def _build_modbus_word(self):
        """Формирование 16-битного целого числа для %MW0 на основе BitMappingConfig."""
        cfg = self.config.bit_mapping
        val = 0
        lvl = self.status.level_code

        # Если действует расписание тихого часа, сигналы о тревогах (уровни 1..5 и типы угроз) на контроллер НЕ выдаются.
        if self.status.is_muted:
            val |= (1 << cfg.bit_safe)
            val |= (1 << cfg.bit_muted_by_schedule)
        else:
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
