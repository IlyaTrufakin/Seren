import tkinter as tk
from tkinter import ttk, messagebox
import queue
import time
import socket
from copy import deepcopy
import threading
from datetime import datetime
from typing import Optional, List, Dict

from src.config import AppConfig
from src.modbus_worker import ModbusWorker
from src.threat_models import ThreatSystemConfig, ThreatStatus, SignificantEvent
from src.threat_evaluator import ThreatEvaluator
from src.threat_config_dialog import ThreatConfigDialog
from src.ui_theme import (
    setup_ttk_styles, LedIndicator, WordBitsWidget,
    BG_MAIN, BG_CARD, BG_CARD_LIGHT, BG_INPUT, BORDER_COLOR,
    TEXT_MAIN, TEXT_MUTED, TEXT_ACCENT,
    COLOR_PRIMARY, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER,
    FONT_TITLE, FONT_SUBTITLE, FONT_REGULAR, FONT_BOLD, FONT_MONO, FONT_VALUE_BIG
)

# Мнемонические подписи для бит слова управления %MW0 (ПК ➔ ПЛК)
MW0_BIT_LABELS: Dict[int, str] = {
    15: "HB",      # Heartbeat
    10: "Тиш",     # Тихий час
    9:  "Связ",    # Нет связи
    8:  "БпЛА",    # Дрон
    7:  "КАБ",     # КАБ
    6:  "Рак",     # Ракета
    5:  "К.Рай",   # Крит. район
    4:  "К.Гор",   # Крит. город
    3:  "П.Рай",   # Потенц. район
    2:  "П.Гор",   # Потенц. город
    1:  "Мин",     # Минимальная
    0:  "Safe"     # Безопасно
}

# Мнемонические подписи для бит слова обратной связи %MW1 (ПЛК ➔ ПК)
MW1_BIT_LABELS: Dict[int, str] = {
    15: "RUN",     # ПЛК в работе
    2:  "Тумб",    # Тумблер вкл/выкл оповещение
    1:  "Сброс"    # Физическая кнопка сброса
}


class ModbusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Seren — Система мониторинга угроз и шлюз ПЛК Schneider TM221")
        self.geometry("1120x840")
        self.minsize(980, 720)
        self.configure(bg=BG_MAIN)

        # Конфигурация и воркер Modbus
        self.config = AppConfig.load()
        # Гарантируем, что опрос идет по регистру обратной связи %MW1
        if self.config.read_reg_address != 1:
            self.config.read_reg_address = 1
            self.config.save()

        self._closing = False
        self._evaluator_generation = 0
        self._latest_status = None
        self._status_lock = threading.Lock()
        self._last_control_ack = None
        self.event_queue = queue.Queue()
        self.worker = ModbusWorker(self.config, self.event_queue)

        # Анализатор угроз (AlarmMap + Telegram)
        self.threat_config = ThreatSystemConfig.load()
        self.threat_evaluator = ThreatEvaluator(
            self.threat_config,
            on_status_change=self._status_callback(self._evaluator_generation)
        )

        # Инициализация переменных интерфейса
        self._init_variables()

        # Настройка стилей
        setup_ttk_styles()

        # Построение интерфейса
        self._build_ui()

        # Запуск анализатора угроз
        self.threat_evaluator.start()

        # Привязка закрытия окна
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Запуск цикла обработки событий от воркера
        self.after(50, self._process_events)

        # Автоматическое включение связи с контроллером при запуске
        self.after(250, self._auto_connect_plc)

    def _auto_connect_plc(self):
        """Автоматический запуск связи с ПЛК по умолчанию при старте программы."""
        self._log("Автоподключение к ПЛК M221 по умолчанию...", tag="info")
        self._toggle_connection()

    def _init_variables(self):
        # Сетевые параметры
        self.var_host = tk.StringVar(value=self.config.host)
        self.var_port = tk.StringVar(value=str(self.config.port))
        self.var_unit_id = tk.StringVar(value=str(self.config.unit_id))
        self.var_poll_ms = tk.StringVar(value=str(self.config.poll_interval_ms))
        self.var_auto_reconnect = tk.BooleanVar(value=self.config.auto_reconnect)

        # Общий статус тревоги
        self.var_threat_title = tk.StringVar(value="БЕЗОПАСНО")
        self.var_threat_desc = tk.StringVar(value=f"Сектор: {self.threat_config.district.name} — обстановка спокойная")

        # Бейджи тревоги
        self.var_badge_rocket = tk.StringVar(value="")
        self.var_badge_kab = tk.StringVar(value="")
        self.var_badge_drone = tk.StringVar(value="")
        self.var_badge_muted = tk.StringVar(value="")
        self.var_badge_plc_sw = tk.StringVar(value="")

        # Звуковой профиль оповещения сирены (%MW2..%MW6)
        self.var_sound_title = tk.StringVar(value="🔊 Норма (Heartbeat)")
        self.var_sound_desc = tk.StringVar(value="Контрольный импульс сирены раз в 30 секунд (дежурный режим).")
        self.var_sound_code = tk.StringVar(value="0")
        self.var_sound_beeps = tk.StringVar(value="1 шт")
        self.var_sound_dur = tk.StringVar(value="200 мс")
        self.var_sound_pause = tk.StringVar(value="0 мс")
        self.var_sound_interval = tk.StringVar(value="30000 мс")
        self.var_sound_relay_state = tk.StringVar(value="ДЕЖУРНЫЙ")

        # Источник 1: AlarmMap API
        self.var_api_status = tk.StringVar(value="Проверка связи...")
        self.var_api_alarm_badge = tk.StringVar(value="ТРЕВОГА НЕ ОБЪЯВЛЕНА")
        self.var_api_types = tk.StringVar(value="Активные типы: нет")
        self.var_api_full_text = tk.StringVar(value="Загрузка данных с сервера alarmmap.online...")
        self.var_api_poll_time = tk.StringVar(value="Последний опрос: —")

        # Источник 2: Telegram Радар
        self.var_tg_status = tk.StringVar(value="Инициализация каналов...")
        self.var_tg_city = tk.StringVar(value="🏙️ Город: Спокойно")
        self.var_tg_district = tk.StringVar(value="🎯 Сектор: Спокойно")
        self.var_tg_drones = tk.StringVar(value="🛸 БпЛА: угроз не зафиксировано")
        self.var_tg_last_post = tk.StringVar(value="Свежих постов: —")

        # Modbus регистры %MW0 и %MW1
        self.var_mw0_info = tk.StringVar(value="Слово управления %MW0: 0x0001 (DEC: 1)")
        self.var_mw1_info = tk.StringVar(value="Слово обратной связи %MW1: ожидание ответа ПЛК...")

        # Системный статус и лог
        self.var_status_text = tk.StringVar(value="Отключено")
        self.var_stats_text = tk.StringVar(value="Запросов: 0 | Ошибок: 0 | Задержка RTT: 0.0 мс")
        self.var_autoscroll = tk.BooleanVar(value=True)
        self.var_tg_autoscroll = tk.BooleanVar(value=True)

        self._last_plc_reset_bit = False
        self._last_plc_switch_bit: Optional[bool] = None

    def _build_ui(self):
        # Главный контейнер
        viewport = tk.Frame(self, bg=BG_MAIN)
        viewport.pack(fill="both", expand=True)
        canvas = tk.Canvas(viewport, bg=BG_MAIN, highlightthickness=0)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        main_frame = tk.Frame(canvas, bg=BG_MAIN, padx=12, pady=8)
        window = canvas.create_window((0, 0), window=main_frame, anchor="nw")
        main_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))

        # 1. Верхняя панель (Header + Кнопки управления + Связь)
        self._build_header(main_frame)

        # 2. Карточка итогового уровня тревоги
        self._build_threat_status_panel(main_frame)

        # 3. Выделенная карточка текущего звукового профиля оповещения (%MW2..%MW6)
        self._build_sound_profile_panel(main_frame)

        # 4. Детализация формирования статуса из источников (API + Telegram)
        self._build_sources_panel(main_frame)

        # 5. Битовые состояния слов Modbus (%MW0 и %MW1)
        self._build_modbus_bits_panel(main_frame)

        # 6. Оперативные значимые сообщения Telegram (фильтрация мусора)
        self._build_significant_messages_panel(main_frame)

        # 7. Компактный системный журнал
        self._build_log_panel(main_frame)

    def _build_header(self, parent):
        header_frame = tk.Frame(parent, bg=BG_MAIN)
        header_frame.pack(fill="x", pady=(0, 6))

        # Левая часть — Название системы
        left = tk.Frame(header_frame, bg=BG_MAIN)
        left.pack(fill="x")

        title_lbl = tk.Label(
            left,
            text="Seren — Мониторинг угроз и шлюз ПЛК Schneider TM221",
            font=FONT_TITLE,
            fg=TEXT_MAIN,
            bg=BG_MAIN
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            left,
            text="Автоматический синтез AlarmMap API + Telegram ➔ передача статуса и звуковых профилей в ПЛК (%MW0..%MW6)",
            font=FONT_REGULAR,
            fg=TEXT_MUTED,
            bg=BG_MAIN
        )
        sub_lbl.pack(anchor="w")

        # Правая часть — Сетевой статус и быстрые кнопки управления
        right = tk.Frame(header_frame, bg=BG_MAIN)
        right.pack(fill="x", pady=(5, 0))

        # Кнопка сброса тревоги (перенесена наверх в панель инструментов)
        btn_reset = ttk.Button(
            right,
            text="Сбросить тревогу",
            style="Danger.TButton",
            command=lambda: self.threat_evaluator.reset_threat_state(source="Кнопка интерфейса ПК")
        )
        btn_reset.pack(side="right", padx=(6, 0))

        # Конфигуратор правил
        btn_cfg = ttk.Button(
            right,
            text="⚙️ Конфигуратор",
            style="Outline.TButton",
            command=self._open_threat_config
        )
        btn_cfg.pack(side="right", padx=(6, 0))

        # Кнопка пинга
        btn_ping = ttk.Button(
            right,
            text="Пинг",
            style="Outline.TButton",
            command=self._test_connection_quick
        )
        btn_ping.pack(side="right", padx=(6, 0))

        # Кнопка подключения к ПЛК
        self.btn_connect = ttk.Button(
            right,
            text="Подключить",
            style="Success.TButton",
            command=self._toggle_connection
        )
        self.btn_connect.pack(side="right", padx=(6, 0))

        state_box = tk.Frame(right, bg=BG_MAIN)
        state_box.pack(side="left", padx=(0, 10))
        self.led_analysis_switch = LedIndicator(state_box, size=20)
        self.led_analysis_switch.pack(side="left", padx=(0, 5))
        self.led_analysis_switch.set_state("connecting")
        self.var_analysis_switch = tk.StringVar(value="ОПОВЕЩЕНИЕ: НЕТ ДАННЫХ")
        tk.Label(state_box, textvariable=self.var_analysis_switch, bg=BG_MAIN,
                 fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left")

        # Индикатор связи с ПЛК
        self.led_indicator = LedIndicator(right, size=20)
        self.led_indicator.pack(side="right", padx=(0, 6))

        self.lbl_status = tk.Label(
            right,
            textvariable=self.var_status_text,
            font=FONT_BOLD,
            fg=COLOR_DANGER,
            bg=BG_MAIN
        )
        self.lbl_status.pack(side="right", padx=(0, 6))

    def _build_threat_status_panel(self, parent):
        """Карточка текущего уровня тревоги и бейджей активных угроз."""
        card = tk.LabelFrame(
            parent,
            text="  ТЕКУЩИЙ УРОВЕНЬ ТРЕВОГИ  ",
            bg=BG_CARD,
            fg="#f59e0b",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        card.pack(fill="x", pady=(0, 6))

        top_row = tk.Frame(card, bg=BG_CARD)
        top_row.pack(fill="x")

        # LED статуса тревоги
        self.led_threat = LedIndicator(top_row, size=22)
        self.led_threat.pack(side="left", padx=(0, 8))
        self.led_threat.set_state("connected")

        # Основная плашка уровня
        self.lbl_threat_badge = tk.Label(
            top_row,
            textvariable=self.var_threat_title,
            font=FONT_BOLD,
            bg="#065f46",
            fg="#34d399",
            padx=12,
            pady=3,
            bd=1,
            relief="solid"
        )
        self.lbl_threat_badge.pack(side="left", padx=(0, 10))

        # Описание сектора с динамическим переносом строк
        self.lbl_sec = tk.Label(
            top_row,
            textvariable=self.var_threat_desc,
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            wraplength=520,
            justify="left"
        )
        self.lbl_sec.pack(side="left", fill="x", expand=True)

        self.var_threat_reason = tk.StringVar(value="Ожидание данных источников")
        tk.Label(card, text="Причина текущего уровня и источники:", bg=BG_CARD,
                 fg=TEXT_ACCENT, font=FONT_BOLD).pack(anchor="w", pady=(5, 0))
        self.txt_threat_reason = tk.Text(card, height=4, wrap="word", bg=BG_INPUT,
                                        fg=TEXT_MAIN, font=FONT_REGULAR, state="disabled")
        self.txt_threat_reason.pack(fill="x", pady=(2, 0))
        self.var_plc_delivery = tk.StringVar(value="Команда ПЛК: ожидает подтверждения")
        tk.Label(card, textvariable=self.var_plc_delivery, bg=BG_CARD,
                 fg=TEXT_MUTED, font=FONT_REGULAR).pack(anchor="w")

        # Контейнер бейджей угроз (Ракета, КАБ, Дрон, Режим тишины, Тумблер ПЛК)
        self.badge_box = tk.Frame(top_row, bg=BG_CARD)
        self.badge_box.pack(side="right")

        self.lbl_badge_rocket = tk.Label(self.badge_box, textvariable=self.var_badge_rocket, font=FONT_BOLD, bg="#7f1d1d", fg="#fca5a5", padx=6, pady=2)
        self.lbl_badge_kab = tk.Label(self.badge_box, textvariable=self.var_badge_kab, font=FONT_BOLD, bg="#78350f", fg="#fcd34d", padx=6, pady=2)
        self.lbl_badge_drone = tk.Label(self.badge_box, textvariable=self.var_badge_drone, font=FONT_BOLD, bg="#312e81", fg="#a5b4fc", padx=6, pady=2)
        self.lbl_badge_muted = tk.Label(self.badge_box, textvariable=self.var_badge_muted, font=FONT_BOLD, bg="#475569", fg="#e2e8f0", padx=6, pady=2)
        self.lbl_badge_plc_sw = tk.Label(self.badge_box, textvariable=self.var_badge_plc_sw, font=FONT_BOLD, bg="#374151", fg="#9ca3af", padx=6, pady=2)

    def _build_sound_profile_panel(self, parent):
        """Выделенная карточка текущего типа звукового оповещения и параметров сирены (%MW2..%MW6)."""
        card = tk.LabelFrame(
            parent,
            text="  🔊 ТЕКУЩИЙ ЗВУКОВОЙ ПРОФИЛЬ ОПОВЕЩЕНИЯ СИРЕНЫ (ПЛК %MW2..%MW6)  ",
            bg=BG_CARD,
            fg="#38bdf8",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        card.pack(fill="x", pady=(0, 6))

        content_row = tk.Frame(card, bg=BG_CARD)
        content_row.pack(fill="x")
        content_row.columnconfigure(0, weight=1)
        content_row.columnconfigure(1, weight=0)

        # Левая часть — активный профиль и текстовое пояснение
        left_box = tk.Frame(content_row, bg=BG_CARD)
        left_box.grid(row=0, column=0, sticky="w")

        prof_title_row = tk.Frame(left_box, bg=BG_CARD)
        prof_title_row.pack(anchor="w", pady=(0, 2))

        self.lbl_sound_badge = tk.Label(
            prof_title_row,
            textvariable=self.var_sound_title,
            font=FONT_BOLD,
            bg="#1e293b",
            fg="#38bdf8",
            padx=10,
            pady=2,
            bd=1,
            relief="solid"
        )
        self.lbl_sound_badge.pack(side="left", padx=(0, 8))

        self.lbl_sound_relay = tk.Label(
            prof_title_row,
            textvariable=self.var_sound_relay_state,
            font=FONT_BOLD,
            bg="#065f46",
            fg="#34d399",
            padx=8,
            pady=2,
            bd=1,
            relief="solid"
        )
        self.lbl_sound_relay.pack(side="left")

        self.lbl_sound_desc = tk.Label(
            left_box,
            textvariable=self.var_sound_desc,
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            wraplength=480,
            justify="left"
        )
        self.lbl_sound_desc.pack(anchor="w")

        # Правая часть — мини-карточки регистров %MW2..%MW6
        right_box = tk.Frame(content_row, bg=BG_CARD)
        right_box.grid(row=0, column=1, sticky="e", padx=(10, 0))

        reg_cards = [
            ("Код (%MW2)", self.var_sound_code, "#38bdf8"),
            ("Гудков (%MW3)", self.var_sound_beeps, "#facc15"),
            ("Длит. (%MW4)", self.var_sound_dur, "#60a5fa"),
            ("Пауза (%MW5)", self.var_sound_pause, "#a78bfa"),
            ("Интервал (%MW6)", self.var_sound_interval, "#34d399"),
        ]

        for lbl_name, var_val, col_fg in reg_cards:
            cell = tk.Frame(right_box, bg=BG_CARD_LIGHT, padx=6, pady=2, bd=1, relief="solid")
            cell.pack(side="left", padx=3)

            tk.Label(cell, text=lbl_name, font=("Segoe UI", 7), fg=TEXT_MUTED, bg=BG_CARD_LIGHT).pack(anchor="center")
            tk.Label(cell, textvariable=var_val, font=("Consolas", 10, "bold"), fg=col_fg, bg=BG_CARD_LIGHT).pack(anchor="center")

    def _build_sources_panel(self, parent):
        """Панель расширенной информации о формировании статуса опасности от обоих источников."""
        sources_frame = tk.Frame(parent, bg=BG_MAIN)
        sources_frame.pack(fill="x", pady=(0, 6))
        sources_frame.columnconfigure(0, weight=1)
        sources_frame.columnconfigure(1, weight=1)

        # --- Колонка 1: API (alarmmap.online) ---
        api_card = tk.LabelFrame(
            sources_frame,
            text="  🌐 Источник: API alarmmap.online  ",
            bg=BG_CARD,
            fg="#60a5fa",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        api_card.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        api_header = tk.Frame(api_card, bg=BG_CARD)
        api_header.pack(fill="x", pady=(0, 4))

        self.led_api = LedIndicator(api_header, size=16)
        self.led_api.pack(side="left", padx=(0, 6))

        tk.Label(api_header, text="Связь API:", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.lbl_api_status = tk.Label(api_header, textvariable=self.var_api_status, font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MAIN)
        self.lbl_api_status.pack(side="left", padx=4)

        self.lbl_api_poll = tk.Label(api_header, textvariable=self.var_api_poll_time, font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED)
        self.lbl_api_poll.pack(side="right")

        # Состояние тревоги API
        api_state_row = tk.Frame(api_card, bg=BG_CARD)
        api_state_row.pack(fill="x", pady=2)

        tk.Label(api_state_row, text="Статус в городе:", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
        self.lbl_api_alarm_badge = tk.Label(
            api_state_row,
            textvariable=self.var_api_alarm_badge,
            font=FONT_BOLD,
            bg="#065f46",
            fg="#34d399",
            padx=8,
            pady=1,
            bd=1,
            relief="solid"
        )
        self.lbl_api_alarm_badge.pack(side="left", padx=6)

        # Типы угроз API
        self.lbl_api_types = tk.Label(
            api_card,
            textvariable=self.var_api_types,
            font=FONT_BOLD,
            bg=BG_CARD,
            fg="#93c5fd",
            anchor="w",
            wraplength=480,
            justify="left"
        )
        self.lbl_api_types.pack(fill="x", pady=(2, 2))

        # Полная расшифровка угроз из API
        self.lbl_api_full = tk.Label(
            api_card,
            textvariable=self.var_api_full_text,
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            anchor="w",
            wraplength=480,
            justify="left"
        )
        self.lbl_api_full.pack(fill="x", pady=(2, 0))
        ttk.Button(api_card, text="Справочник типов и уровней API", command=self._show_api_catalog).pack(anchor="w", pady=3)

        # --- Колонка 2: Telegram Мониторинг ---
        tg_card = tk.LabelFrame(
            sources_frame,
            text="  📱 Источник: Telegram Радар каналов  ",
            bg=BG_CARD,
            fg="#a78bfa",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        tg_card.grid(row=0, column=1, sticky="nsew", padx=(4, 0))

        tg_header = tk.Frame(tg_card, bg=BG_CARD)
        tg_header.pack(fill="x", pady=(0, 4))

        self.led_tg = LedIndicator(tg_header, size=16)
        self.led_tg.pack(side="left", padx=(0, 6))

        tk.Label(tg_header, text="Связь Telegram:", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MUTED).pack(side="left")
        self.lbl_tg_status = tk.Label(tg_header, textvariable=self.var_tg_status, font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MAIN)
        self.lbl_tg_status.pack(side="left", padx=4)

        self.lbl_tg_last_post = tk.Label(tg_header, textvariable=self.var_tg_last_post, font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED)
        self.lbl_tg_last_post.pack(side="right")

        # Опасность для города и района
        tg_threat_row = tk.Frame(tg_card, bg=BG_CARD)
        tg_threat_row.pack(fill="x", pady=2)

        self.lbl_tg_city = tk.Label(
            tg_threat_row,
            textvariable=self.var_tg_city,
            font=FONT_BOLD,
            bg=BG_CARD,
            fg="#38bdf8",
            wraplength=230,
            justify="left"
        )
        self.lbl_tg_city.pack(side="left")

        self.lbl_tg_district = tk.Label(
            tg_threat_row,
            textvariable=self.var_tg_district,
            font=FONT_BOLD,
            bg=BG_CARD,
            fg="#fbbf24",
            wraplength=250,
            justify="left"
        )
        self.lbl_tg_district.pack(side="right")

        # Классификатор дронов
        self.lbl_tg_drones = tk.Label(
            tg_card,
            textvariable=self.var_tg_drones,
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            anchor="w",
            wraplength=480,
            justify="left"
        )
        self.lbl_tg_drones.pack(fill="x", pady=(2, 0))

    def _build_modbus_bits_panel(self, parent):
        """Битовые состояния слов данных %MW0 (ПК->ПЛК) и %MW1 (ПЛК->ПК) с безупречным выравниванием."""
        bits_card = tk.LabelFrame(
            parent,
            text="  БИТОВЫЕ СОСТОЯНИЯ СЛОВ MODBUS (%MW0 / %MW1)  ",
            bg=BG_CARD,
            fg="#34d399",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        bits_card.pack(fill="x", pady=(0, 6))

        # 1. Слово передачи %MW0
        mw0_row = tk.Frame(bits_card, bg=BG_CARD)
        mw0_row.pack(fill="x", pady=(0, 2))

        tk.Label(mw0_row, textvariable=self.var_mw0_info, font=FONT_BOLD, bg=BG_CARD, fg="#60a5fa").pack(side="left")

        self.bits_mw0 = WordBitsWidget(bits_card, row_title="%MW0 (ПК ➔ ПЛК)", editable=False, bit_labels=MW0_BIT_LABELS)
        self.bits_mw0.pack(fill="x", pady=(0, 6))

        # 2. Слово приема %MW1
        mw1_row = tk.Frame(bits_card, bg=BG_CARD)
        mw1_row.pack(fill="x", pady=(2, 2))

        self.lbl_mw1_info = tk.Label(mw1_row, textvariable=self.var_mw1_info, font=FONT_BOLD, bg=BG_CARD, fg=COLOR_SUCCESS)
        self.lbl_mw1_info.pack(side="left")

        self.bits_mw1 = WordBitsWidget(bits_card, row_title="%MW1 (ПЛК ➔ ПК)", editable=False, bit_labels=MW1_BIT_LABELS)
        self.bits_mw1.pack(fill="x", pady=(0, 2))

    def _build_significant_messages_panel(self, parent):
        """Таблица/список оперативных значимых сообщений Telegram (мусор фильтруется)."""
        card = tk.LabelFrame(
            parent,
            text="  ОПЕРАТИВНЫЕ ЗНАЧИМЫЕ СООБЩЕНИЯ TELEGRAM (ФИЛЬТРАЦИЯ МУСОРА)  ",
            bg=BG_CARD,
            fg="#f59e0b",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        card.pack(fill="both", expand=True, pady=(0, 6))

        text_container = tk.Frame(card, bg=BG_CARD)
        text_container.pack(fill="both", expand=True)

        self.txt_tg_events = tk.Text(
            text_container,
            height=6,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            font=("Consolas", 10),
            relief="flat",
            bd=0,
            padx=8,
            pady=4,
            wrap="word"
        )
        scrollbar_y = ttk.Scrollbar(text_container, orient="vertical", command=self.txt_tg_events.yview)
        self.txt_tg_events.configure(yscrollcommand=scrollbar_y.set)

        self.txt_tg_events.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")

        # Настройка цветных тегов
        self.txt_tg_events.tag_config("time", foreground="#94a3b8")
        self.txt_tg_events.tag_config("channel", foreground="#38bdf8", font=("Consolas", 10, "bold"))
        self.txt_tg_events.tag_config("badge_rocket", foreground="#f87171", font=("Consolas", 10, "bold"))
        self.txt_tg_events.tag_config("badge_kab", foreground="#fcd34d", font=("Consolas", 10, "bold"))
        self.txt_tg_events.tag_config("badge_drone", foreground="#c084fc", font=("Consolas", 10, "bold"))
        self.txt_tg_events.tag_config("badge_clear", foreground="#34d399", font=("Consolas", 10, "bold"))
        self.txt_tg_events.tag_config("badge_shelter", foreground="#ef4444", font=("Consolas", 10, "bold"))
        self.txt_tg_events.tag_config("badge_target", foreground="#fbbf24")
        self.txt_tg_events.tag_config("msg_text", foreground=TEXT_MAIN)
        self.txt_tg_events.tag_config("critical_text", foreground="#fca5a5", font=("Consolas", 10, "bold"))

        # Подвал списка сообщений
        bot_row = tk.Frame(card, bg=BG_CARD)
        bot_row.pack(fill="x", pady=(4, 0))

        tk.Label(
            bot_row,
            text="* Внимание: реклама, чат и сообщения без военных угроз автоматически игнорируются фильтром.",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD
        ).pack(side="left")

        ttk.Button(bot_row, text="Очистить", style="Outline.TButton", command=self._clear_tg_events).pack(side="right")
        ttk.Checkbutton(bot_row, text="Автопрокрутка", variable=self.var_tg_autoscroll).pack(side="right", padx=(0, 8))

    def _build_log_panel(self, parent):
        """Компактный системный журнал для сетевых и аварийных событий."""
        log_frame = tk.LabelFrame(
            parent,
            text="  Системный журнал и статистика обмена  ",
            bg=BG_CARD,
            fg=TEXT_MUTED,
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=8,
            pady=4
        )
        log_frame.pack(fill="x")

        text_container = tk.Frame(log_frame, bg=BG_CARD)
        text_container.pack(fill="x")

        self.txt_log = tk.Text(
            text_container,
            height=3,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            font=("Consolas", 9),
            relief="flat",
            bd=0,
            padx=6,
            pady=2,
            wrap="none"
        )
        scrollbar_y = ttk.Scrollbar(text_container, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scrollbar_y.set)

        self.txt_log.pack(side="left", fill="x", expand=True)
        scrollbar_y.pack(side="right", fill="y")

        self.txt_log.tag_config("info", foreground=TEXT_MAIN)
        self.txt_log.tag_config("success", foreground=COLOR_SUCCESS)
        self.txt_log.tag_config("error", foreground=COLOR_DANGER)
        self.txt_log.tag_config("warn", foreground=COLOR_WARNING)
        self.txt_log.tag_config("time", foreground=TEXT_MUTED)

        bottom_row = tk.Frame(log_frame, bg=BG_CARD)
        bottom_row.pack(fill="x", pady=(2, 0))

        lbl_stats = tk.Label(bottom_row, textvariable=self.var_stats_text, font=("Segoe UI", 8), bg=BG_CARD, fg=TEXT_MUTED)
        lbl_stats.pack(side="left")

        ttk.Button(bottom_row, text="Очистить лог", style="Outline.TButton", command=self._clear_log).pack(side="right")

    # --- Управление сетью Modbus ---

    def _update_analysis_indicator(self, enabled=None):
        if enabled is None:
            self.led_analysis_switch.set_state("connecting")
            self.var_analysis_switch.set("ОПОВЕЩЕНИЕ: НЕТ ДАННЫХ")
        else:
            self.led_analysis_switch.set_state("connected" if enabled else "error")
            self.var_analysis_switch.set("ОПОВЕЩЕНИЕ: ВКЛЮЧЕНО" if enabled else "ОПОВЕЩЕНИЕ: ВЫКЛЮЧЕНО")

    def _toggle_connection(self):
        if self.worker.is_connected() or (self.worker._thread and self.worker._thread.is_alive()):
            self.worker.disconnect()
            self.btn_connect.config(text="Подключить", style="Success.TButton")
            self._log("Отключение от ПЛК...", tag="info")
        else:
            if not self._apply_network_settings():
                return
            self.btn_connect.config(text="Отключить", style="Danger.TButton")
            self.worker.connect()
            self._log(f"Подключение к ПЛК {self.config.host}:{self.config.port}...", tag="info")

    def _apply_network_settings(self) -> bool:
        host = self.var_host.get().strip()
        if not host:
            messagebox.showerror("Ошибка", "Укажите IP-адрес контроллера.")
            return False

        try:
            self.config.host = host
            self.config.port = int(self.var_port.get().strip())
            self.config.unit_id = int(self.var_unit_id.get().strip())
            self.config.poll_interval_ms = int(self.var_poll_ms.get().strip())
            self.config.auto_reconnect = self.var_auto_reconnect.get()
            if not 1 <= self.config.port <= 65535 or not 0 <= self.config.unit_id <= 255:
                raise ValueError("Порт 1..65535; Unit ID 0..255")
            if self.config.poll_interval_ms < 20 or self.config.timeout <= 0:
                raise ValueError("Опрос от 20 мс; таймаут должен быть положительным")
            self.config.read_reg_address = 1
            self.config.write_reg_address = 0
            self.config.save()
            self.worker.update_config(self.config)
            return True
        except ValueError as e:
            messagebox.showerror("Ошибка параметров", f"Неверный формат сетевых настроек: {e}")
            return False

    def _test_connection_quick(self):
        host = self.var_host.get().strip()
        try:
            port = int(self.var_port.get().strip())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт должен быть числом.")
            return

        self._log(f"Проверка сокета {host}:{port}...", tag="info")
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            res = sock.connect_ex((host, port))
            dt = (time.perf_counter() - t0) * 1000.0
            sock.close()
            if res == 0:
                self._log(f"Сокет доступен! Задержка: {dt:.1f} мс", tag="success")
                messagebox.showinfo("Пинг успешен", f"Порт {port} на {host} открыт.\nВремя отклика: {dt:.1f} мс")
            else:
                self._log(f"Ошибка сокета: код {res}", tag="error")
                messagebox.showwarning("Ошибка связи", f"Не удалось подключиться к {host}:{port}\nКод ошибки: {res}")
        except Exception as e:
            self._log(f"Сбой проверки: {e}", tag="error")
            messagebox.showerror("Ошибка", f"Не удалось проверить подключение:\n{e}")

    # --- Обработка событий угроз и обновление UI ---

    def _show_api_catalog(self):
        window = tk.Toplevel(self)
        window.title("AlarmMap: официальный справочник уровней")
        window.geometry("850x550")
        box = tk.Text(window, wrap="word", bg=BG_INPUT, fg=TEXT_MAIN)
        scrollbar = ttk.Scrollbar(window, command=box.yview)
        scrollbar.pack(side="right", fill="y")
        box.configure(yscrollcommand=scrollbar.set)
        box.pack(fill="both", expand=True)
        with self.threat_evaluator._lock:
            catalog = deepcopy(self.threat_evaluator.status.alarmmap_catalog)
        for entry in sorted(catalog, key=lambda e: (e["type"], e["level"])):
            box.insert("end", f"{entry['type']} / {entry['level']} — {entry.get('title', '')}\n{entry.get('description', '')}\n\n")
        if not catalog:
            box.insert("end", "Справочник ещё не получен. Проверьте API-ключ и связь. Значение уровня не выводится из номера.")
        box.config(state="disabled")

    def _open_threat_config(self):
        ThreatConfigDialog(self, self.threat_config, on_save_callback=self._on_threat_config_saved)

    def _on_threat_config_saved(self, new_cfg: ThreatSystemConfig):
        self._evaluator_generation += 1
        self.threat_evaluator.stop()
        self.threat_config = new_cfg
        self.worker.clear_control_snapshot()
        self.threat_evaluator = ThreatEvaluator(self.threat_config,
            on_status_change=self._status_callback(self._evaluator_generation))
        if self._last_plc_switch_bit is not None:
            self.threat_evaluator.set_plc_analysis_switch(self._last_plc_switch_bit)
        self.threat_evaluator.start()
        self._log("Конфигуратор: девять правил обновлены.", tag="info")

    def _status_callback(self, generation):
        def callback(st):
            if self._closing or generation != self._evaluator_generation:
                return
            # Network thread updates transport directly; Tk is only touched on the GUI thread.
            if self.threat_config.auto_transfer_to_plc:
                self.worker.set_control_snapshot(st.modbus_word, [st.sound_code, st.sound_beep_count,
                    st.sound_duration_ms, st.sound_pause_ms, st.sound_interval_ms],
                    self.threat_config.bit_mapping.bit_heartbeat, reaction=vars(st))
            else:
                self.worker.clear_control_snapshot()
            with self._status_lock:
                self._latest_status = (generation, deepcopy(st))
        return callback

    def _on_threat_status_changed(self, st):
        self._status_callback(self._evaluator_generation)(st)

    def _apply_threat_status_ui(self, st: ThreatStatus):
        lvl = st.level_code
        self.txt_threat_reason.config(state="normal")
        self.txt_threat_reason.delete("1.0", "end")
        self.txt_threat_reason.insert("1.0", st.reason)
        self.txt_threat_reason.config(state="disabled")
        self.var_threat_title.set(f" {st.level_title} ")
        self.var_threat_desc.set(f"Сектор: {self.threat_config.district.name} — {st.description}")

        # Цвет плашки уровня
        if lvl == 0:
            self.led_threat.set_state("connected")
            self.lbl_threat_badge.config(bg="#065f46", fg="#34d399")
        elif lvl == 1:
            self.led_threat.set_state("connecting")
            self.lbl_threat_badge.config(bg="#78350f", fg="#fde047")
        elif lvl in (2, 3):
            self.led_threat.set_state("connecting")
            self.lbl_threat_badge.config(bg="#9a3412", fg="#fdba74")
        else: # 4, 5
            self.led_threat.set_state("error")
            self.lbl_threat_badge.config(bg="#7f1d1d", fg="#fca5a5")

        # Бейджи типов
        if st.has_rocket:
            self.var_badge_rocket.set("🚀 РАКЕТА")
            self.lbl_badge_rocket.pack(side="right", padx=2)
        else:
            self.lbl_badge_rocket.pack_forget()

        if st.has_kab:
            self.var_badge_kab.set("💣 КАБ")
            self.lbl_badge_kab.pack(side="right", padx=2)
        else:
            self.lbl_badge_kab.pack_forget()

        if st.has_drone:
            d_name_tag = f": {st.matched_drone_name.upper()}" if st.matched_drone_name else ""
            g_tag = f" (Гр.{st.drone_group})" if st.drone_group else ""
            self.var_badge_drone.set(f"🛸 ДРОН{g_tag}{d_name_tag}")
            self.lbl_badge_drone.pack(side="right", padx=2)
        else:
            self.lbl_badge_drone.pack_forget()

        # Бейдж тихого часа
        if st.is_muted:
            self.var_badge_muted.set(f"🌙 ТИХИЙ ЧАС ({self.threat_config.schedule.start_time}–{self.threat_config.schedule.end_time})")
            self.lbl_badge_muted.pack(side="right", padx=2)
        else:
            self.lbl_badge_muted.pack_forget()

        # Бейдж тумблера ПЛК
        if st.analysis_disabled_by_plc:
            self.var_badge_plc_sw.set("⛔ АНАЛИЗ ОТКЛЮЧЕН (ТУМБЛЕР ПЛК)")
            self.lbl_badge_plc_sw.pack(side="right", padx=2)
        else:
            self.lbl_badge_plc_sw.pack_forget()

        # --- Обновление выделенной карточки звукового профиля (%MW2..%MW6) ---
        if st.sound_beep_count > 0:
            dur_s = st.sound_duration_ms / 1000.0
            pause_s = st.sound_pause_ms / 1000.0
            int_s = st.sound_interval_ms / 1000.0
            self.var_sound_title.set(f"🔊 {st.sound_profile_name}")
            self.lbl_sound_badge.config(bg="#0284c7", fg="#ffffff")
            self.var_sound_desc.set(
                f"Серия: {st.sound_beep_count} имп. по {dur_s:.2f}с (пауза {pause_s:.2f}с), повтор серии каждые {int_s:.1f}с."
            )
        else:
            self.var_sound_title.set(f"🔇 {st.sound_profile_name}")
            self.lbl_sound_badge.config(bg="#334155", fg="#94a3b8")
            self.var_sound_desc.set("Команда: генерация импульсов отключена; состояние реле не считывается.")

        # Статус выходного реле звука
        if st.analysis_disabled_by_plc:
            self.var_sound_relay_state.set("ОТКЛЮЧЕНО ПЛК")
            self.lbl_sound_relay.config(bg="#451a03", fg="#f59e0b")
        elif st.is_muted:
            self.var_sound_relay_state.set("MUTE (ТИХИЙ ЧАС)")
            self.lbl_sound_relay.config(bg="#1e1b4b", fg="#a5b4fc")
        elif st.sound_beep_count > 0:
            self.var_sound_relay_state.set("КОМАНДА: ЗВУК")
            self.lbl_sound_relay.config(bg="#7f1d1d", fg="#fca5a5")
        else:
            self.var_sound_relay_state.set("ДЕЖУРНЫЙ РЕЖИМ")
            self.lbl_sound_relay.config(bg="#065f46", fg="#34d399")

        # Мини-карточки регистров %MW2..%MW6
        self.var_sound_code.set(str(st.sound_code))
        self.var_sound_beeps.set(f"{st.sound_beep_count} шт")
        self.var_sound_dur.set(f"{st.sound_duration_ms} мс")
        self.var_sound_pause.set(f"{st.sound_pause_ms} мс")
        self.var_sound_interval.set(f"{st.sound_interval_ms} мс")

        # --- Обновление карточки Источника 1: API alarmmap.online ---
        self.led_api.set_state("connected" if st.alarmmap_online else ("connecting" if self.threat_config.alarmmap_enabled else "error"))
        self.var_api_status.set("Онлайн (API активен)" if st.alarmmap_online else ("Отключено" if not self.threat_config.alarmmap_enabled else "Ошибка связи"))
        self.lbl_api_status.config(fg=COLOR_SUCCESS if st.alarmmap_online else COLOR_DANGER)

        if st.alarmmap_last_poll_time > 0:
            t_poll = time.strftime("%H:%M:%S", time.localtime(st.alarmmap_last_poll_time))
            self.var_api_poll_time.set(f"Опрос: {t_poll}")
        else:
            self.var_api_poll_time.set("Опрос: каждые 15с")

        # Статус тревоги API
        is_api_alarm = st.alarmmap_active_count > 0
        if not st.alarmmap_online:
            self.var_api_alarm_badge.set("НЕТ АКТУАЛЬНОЙ СВЯЗИ" if self.threat_config.alarmmap_enabled else "API ОТКЛЮЧЕН")
            self.lbl_api_alarm_badge.config(bg="#78350f", fg="#fde047")
        elif is_api_alarm:
            clean_badge = st.alarmmap_status_text.replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", "")
            self.var_api_alarm_badge.set(f"🔴 {clean_badge}")
            self.lbl_api_alarm_badge.config(bg="#7f1d1d", fg="#fca5a5")
        else:
            self.var_api_alarm_badge.set("🟢 ТРЕВОГА НЕ ОБЪЯВЛЕНА")
            self.lbl_api_alarm_badge.config(bg="#065f46", fg="#34d399")

        types_str = st.alarmmap_types_summary or ("нет активных записей" if st.alarmmap_online else "актуальные данные недоступны")
        self.var_api_types.set(f"Типы и уровни API: {types_str or 'активных записей нет'}")
        self.var_api_full_text.set(st.alarmmap_full_text if st.alarmmap_full_text else "Данные API получены. Угроз по территории не зафиксировано.")

        # --- Обновление карточки Источника 2: Telegram Мониторинг ---
        self.led_tg.set_state("connected" if st.tg_online else "connecting")
        ch_list_str = ", ".join(f"@{c}" for c in self.threat_config.telegram_channels[:2])
        tg_health = "Онлайн" if st.tg_online else "Нет связи / часть каналов недоступна"
        if not self.threat_config.telegram_enabled:
            tg_health = "Отключено"
        self.var_tg_status.set(f"{tg_health} ({st.tg_mode.upper()}: {ch_list_str})")
        self.lbl_tg_status.config(fg=COLOR_SUCCESS if st.tg_online else COLOR_WARNING)

        if st.tg_last_msg_time > 0:
            t_post = time.strftime("%H:%M:%S", time.localtime(st.tg_last_msg_time))
            self.var_tg_last_post.set(f"Пост: {t_post}")
        else:
            self.var_tg_last_post.set("Ожидание постов...")

        # Угрозы городу и району из Telegram
        city_desc = "Нет совпавшего правила"
        if st.tg_city_level > 0:
            city_type_str = "Ракета" if st.tg_city_threat == "rocket" else ("КАБ" if st.tg_city_threat == "kab" else ("БпЛА" if st.tg_city_threat == "drone" else "Тревога"))
            city_desc = f"{ {1: 'Низкая', 2: 'Высокая', 3: 'Высокая', 4: 'Критическая', 5: 'Критическая'}.get(st.tg_city_level, '')} ({city_type_str}) [осталось {st.tg_city_ttl_remain_s}с]"
        self.var_tg_city.set(f"🏙️ Город: {city_desc}")

        dist_desc = "Нет совпавшего правила"
        if st.tg_district_level > 0:
            lm_str = f" [{st.tg_district_landmarks}]" if st.tg_district_landmarks else ""
            dist_type_str = "КАБ" if st.tg_district_threat == "kab" else ("БпЛА" if st.tg_district_threat == "drone" else "Ракета")
            dist_desc = f"{ {1: 'Низкая', 2: 'Высокая', 3: 'Высокая', 4: 'Критическая', 5: 'Критическая'}.get(st.tg_district_level, '')} ({dist_type_str}){lm_str} [осталось {st.tg_district_ttl_remain_s}с]"
        self.var_tg_district.set(f"🎯 Сектор: {dist_desc}")

        # Дроны
        if st.tg_drone_name:
            self.var_tg_drones.set(f"🛸 БпЛА: {st.tg_drone_name.upper()} (Группа {st.tg_drone_group}: {'Ударный' if st.tg_drone_group == 1 else ('Тактический' if st.tg_drone_group == 2 else 'Ложная цель')})")
        else:
            self.var_tg_drones.set("🛸 БпЛА: активных воздушных целей не зафиксировано")

        # --- Обновление битовой матрицы %MW0 (ПК ➔ ПЛК) ---
        self.var_mw0_info.set(f"Слово управления %MW0: 0x{st.modbus_word:04X} (DEC: {st.modbus_word})")
        self.bits_mw0.set_value(st.modbus_word)

        # --- Обновление списка значимых оперативных сообщений Telegram ---
        self._render_significant_events(st.significant_events)

    def _render_significant_events(self, events: List[SignificantEvent]):
        """Отрисовка отфильтрованных значимых оперативных сообщений с цветными тегами."""
        self.txt_tg_events.delete("1.0", "end")
        if not events:
            self.txt_tg_events.insert("end", "Ожидание оперативных сообщений по обстановке...\n", "time")
            return

        for ev in events:
            # Время
            self.txt_tg_events.insert("end", f"[{ev.time_str}] ", "time")
            # Канал
            self.txt_tg_events.insert("end", f"@{ev.channel} ", "channel")

            # Бейдж угрозы
            b_tag = "badge_clear" if ev.category == "clear" else (
                "badge_rocket" if ev.category == "rocket" else (
                    "badge_kab" if ev.category == "kab" else (
                        "badge_drone" if ev.category == "drone" else (
                            "badge_shelter" if ev.category == "shelter" else "channel"
                        )
                    )
                )
            )
            self.txt_tg_events.insert("end", f"[{ev.badge_threat}] ", b_tag)

            # Бейдж цели / сектора
            if ev.badge_target:
                self.txt_tg_events.insert("end", f"[{ev.badge_target}] ", "badge_target")

            # Текст
            txt_style = "critical_text" if ev.is_critical else "msg_text"
            self.txt_tg_events.insert("end", f"{ev.text}\n", txt_style)

        if self.var_tg_autoscroll.get():
            self.txt_tg_events.see("1.0")

    def _clear_tg_events(self):
        self.txt_tg_events.delete("1.0", "end")

    # --- Обработка событий от фонового потока воркера ---

    def _process_events(self):
        if self._closing:
            return
        with self._status_lock:
            latest, self._latest_status = self._latest_status, None
        if latest and latest[0] == self._evaluator_generation:
            self._apply_threat_status_ui(latest[1])
        try:
            while True:
                item = self.event_queue.get_nowait()
                if isinstance(item, dict):
                    ev_type = item.get("type")
                    data = item.get("data", {})
                elif isinstance(item, tuple):
                    ev_type, data = item[0], item[1]
                else:
                    continue

                if ev_type == "status":
                    state = data.get("state")
                    msg = data.get("message") or data.get("msg", "")
                    self.led_indicator.set_state(state)
                    if state != "connected":
                        self._update_analysis_indicator()

                    if state == "connected":
                        self.lbl_status.config(text="На связи", fg=COLOR_SUCCESS)
                        self.var_status_text.set("На связи")
                        self.btn_connect.config(text="Отключить", style="Danger.TButton")
                        self._log(msg, tag="success")
                    elif state == "connecting":
                        self.lbl_status.config(text="Подключение...", fg=COLOR_WARNING)
                        self.var_status_text.set("Подключение...")
                        self.var_mw1_info.set("Связь прервана, ожидание ответа ПЛК...")
                        self.var_plc_delivery.set("Команда ПЛК: связь отсутствует, подтверждение ожидается")
                        self._log(msg, tag="warn")
                    else:
                        self.lbl_status.config(text="Отключено", fg=COLOR_DANGER)
                        self.var_status_text.set("Отключено")
                        self.var_mw1_info.set("Нет связи с ПЛК")
                        self._log(msg, tag="error")
                        self.btn_connect.config(text="Подключить", style="Success.TButton")

                elif ev_type == "read_ok":
                    val = data.get("value", 0)
                    addr = data.get("address", 1)
                    lat = data.get("latency_ms", 0)
                    now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                    # Проверка битов обратной связи от ПЛК (%MW1)
                    pf = self.threat_config.plc_feedback
                    bit_reset = pf.bit_alarm_reset
                    bit_run = pf.bit_plc_running
                    bit_sw = pf.bit_analysis_switch
                    is_reset_high = bool((val >> bit_reset) & 1)
                    is_run_high = bool((val >> bit_run) & 1)
                    is_sw_high = bool((val >> bit_sw) & 1)
                    self._update_analysis_indicator(is_sw_high)

                    # Фронт кнопки сброса тревоги от ПЛК (0 -> 1)
                    if is_reset_high and not self._last_plc_reset_bit:
                        self._log(f"[ПЛК] Нажата кнопка сброса тревоги (%MW{addr}, Бит {bit_reset}). Сброс тревоги.", tag="warn")
                        self.threat_evaluator.reset_threat_state(source=f"Кнопка сброса ПЛК (%MW{addr}: Бит {bit_reset})")
                    self._last_plc_reset_bit = is_reset_high

                    # Переключатель вкл/выкл анализ тревог от ПЛК
                    if self._last_plc_switch_bit != is_sw_high:
                        sw_str = "ВКЛЮЧЕН" if is_sw_high else "ВЫКЛЮЧЕН (приостановлен)"
                        self._log(f"[ПЛК] Переключатель анализа тревог (%MW{addr}, Бит {bit_sw}): {sw_str}", tag="info")
                        self.threat_evaluator.set_plc_analysis_switch(is_sw_high)
                        self._last_plc_switch_bit = is_sw_high

                    # Формирование строки статуса %MW1
                    run_txt = "В РАБОТЕ" if is_run_high else "ОСТАНОВЛЕН"
                    sw_txt = "ТУМБЛЕР ВКЛ" if is_sw_high else "ТУМБЛЕР ВЫКЛ"
                    rst_txt = "[СБРОС НАЖАТ]" if is_reset_high else "СБРОС ОТЖАТ"
                    self.var_mw1_info.set(
                        f"Слово обратной связи %MW1: 0x{val:04X} (DEC: {val}) | RTT: {lat:.1f} мс | ПЛК: {run_txt} | {sw_txt} | {rst_txt}"
                    )
                    self.lbl_mw1_info.config(fg=COLOR_SUCCESS if is_run_high else COLOR_WARNING)

                    # Обновление светодиодной матрицы бит %MW1
                    self.bits_mw1.set_value(val)

                elif ev_type == "control_ack":
                    self.var_plc_delivery.set(f"ПЛК подтвердил: %MW0=0x{data['word']:04X}; %MW2..%MW6={data['sound']}")
                    if data.get("changed"):
                        self.threat_evaluator.audit_logger.log_plc_confirmation(data)
                    self._last_control_ack = data

                elif ev_type == "write_ok":
                    pass

                elif ev_type == "error":
                    msg = data.get("message") or data.get("msg", "")
                    self._log(msg, tag="error")

                elif ev_type == "stats":
                    tot = data.get("total", 0)
                    fail = data.get("failed", 0)
                    lat = data.get("latency_ms", 0)
                    self.var_stats_text.set(f"Запросов: {tot} | Ошибок: {fail} | Задержка RTT: {lat:.1f} мс")

        except queue.Empty:
            pass

        self.after(40, self._process_events)

    def _log(self, message: str, tag: str = "info"):
        t_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.txt_log.insert("end", f"[{t_str}] ", "time")
        self.txt_log.insert("end", f"{message}\n", tag)
        if self.var_autoscroll.get():
            self.txt_log.see("end")

    def _clear_log(self):
        self.txt_log.delete("1.0", "end")

    def _on_close(self):
        self._closing = True
        try:
            self.threat_evaluator.stop()
        except Exception:
            pass
        self.worker.stop()
        self.destroy()


def main():
    app = ModbusApp()
    app.mainloop()


if __name__ == "__main__":
    main()
