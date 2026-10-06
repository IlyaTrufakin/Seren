import tkinter as tk
from tkinter import ttk, messagebox
import os
import json
from src.threat_models import ThreatSystemConfig, DistrictConfig, BitMappingConfig
from src.ui_theme import (
    BG_MAIN, BG_CARD, BG_INPUT, TEXT_MAIN, TEXT_MUTED, TEXT_ACCENT,
    COLOR_PRIMARY, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER,
    FONT_TITLE, FONT_SUBTITLE, FONT_REGULAR, FONT_BOLD, FONT_MONO
)

class ThreatConfigDialog(tk.Toplevel):
    """Окно конфигуратора анализатора угроз, районов и маппинга бит на ПЛК."""
    def __init__(self, parent, current_config: ThreatSystemConfig, on_save_callback):
        super().__init__(parent)
        self.title("Конфигуратор анализатора угроз и передачи на ПЛК")
        self.geometry("780x620")
        self.minsize(700, 550)
        self.configure(bg=BG_MAIN)
        self.transient(parent)
        self.grab_set()

        self.config = current_config
        self.on_save = on_save_callback

        self._build_ui()

    def _build_ui(self):
        # Вкладки
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        # 1. Вкладка "Источники данных"
        tab_sources = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_sources, text="  📡 Источники данных  ")
        self._build_sources_tab(tab_sources)

        # 2. Вкладка "Районы и Ключевые слова"
        tab_districts = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_districts, text="  📍 Сектор и Районы города  ")
        self._build_districts_tab(tab_districts)

        # 3. Вкладка "Битовая карта ПЛК"
        tab_plc = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_plc, text="  ⚙️ Назначение бит ПЛК (%MW0)  ")
        self._build_plc_tab(tab_plc)

        # 4. Вкладка "Расписание тишины"
        tab_sched = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_sched, text="  ⏰ Расписание тишины  ")
        self._build_schedule_tab(tab_sched)

        # 5. Вкладка "Словарь БпЛА"
        tab_drones = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_drones, text="  🛸 Словарь БпЛА  ")
        self._build_drones_tab(tab_drones)

        # 6. Вкладка "Звуковые профили ПЛК"
        tab_sounds = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_sounds, text="  🔊 Звуки (%MW2..%MW6)  ")
        self._build_sounds_tab(tab_sounds)

        # Нижняя панель с кнопками
        btn_frame = tk.Frame(self, bg=BG_MAIN, padx=12, pady=10)
        btn_frame.pack(fill="x", side="bottom")

        btn_save = ttk.Button(btn_frame, text="Сохранить настройки", style="Success.TButton", command=self._save_and_close)
        btn_save.pack(side="right", padx=(8, 0))

        btn_cancel = ttk.Button(btn_frame, text="Отмена", style="Outline.TButton", command=self.destroy)
        btn_cancel.pack(side="right")

    def _build_sources_tab(self, parent):
        # Блок AlarmMap
        card_am = tk.LabelFrame(parent, text="  AlarmMap API (г. Харьков)  ", bg=BG_CARD, fg=TEXT_ACCENT, font=FONT_SUBTITLE, padx=10, pady=8)
        card_am.pack(fill="x", pady=(0, 10))

        self.var_am_enabled = tk.BooleanVar(value=self.config.alarmmap_enabled)
        ttk.Checkbutton(card_am, text="Включить опрос AlarmMap API", variable=self.var_am_enabled).pack(anchor="w", pady=(0, 6))

        row1 = tk.Frame(card_am, bg=BG_CARD)
        row1.pack(fill="x", pady=2)
        tk.Label(row1, text="Файл API ключа:", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left")
        self.entry_am_key = ttk.Entry(row1, width=30)
        self.entry_am_key.insert(0, self.config.alarmmap_key_file)
        self.entry_am_key.pack(side="left", padx=8)

        tk.Label(row1, text="Интервал (сек):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(10, 4))
        self.entry_am_poll = ttk.Entry(row1, width=6)
        self.entry_am_poll.insert(0, str(self.config.alarmmap_poll_interval_s))
        self.entry_am_poll.pack(side="left")

        # Блок Telegram
        card_tg = tk.LabelFrame(parent, text="  Telegram-каналы (Оперативная обстановка по районам)  ", bg=BG_CARD, fg=TEXT_ACCENT, font=FONT_SUBTITLE, padx=10, pady=8)
        card_tg.pack(fill="both", expand=True)

        self.var_tg_enabled = tk.BooleanVar(value=self.config.telegram_enabled)
        ttk.Checkbutton(card_tg, text="Включить мониторинг Telegram", variable=self.var_tg_enabled).pack(anchor="w", pady=(0, 6))

        row_mode = tk.Frame(card_tg, bg=BG_CARD)
        row_mode.pack(fill="x", pady=2)
        tk.Label(row_mode, text="Режим работы:", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=(0, 8))
        self.var_tg_mode = tk.StringVar(value=self.config.telegram_mode)
        ttk.Radiobutton(row_mode, text="Быстрый Web-поток (t.me/s, без логина)", variable=self.var_tg_mode, value="web").pack(side="left", padx=(0, 10))
        ttk.Radiobutton(row_mode, text="Telethon (MTProto API)", variable=self.var_tg_mode, value="telethon").pack(side="left")

        row_ch = tk.Frame(card_tg, bg=BG_CARD)
        row_ch.pack(fill="x", pady=(8, 4))
        tk.Label(row_ch, text="Каналы (через запятую):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left")
        self.entry_tg_channels = ttk.Entry(row_ch, width=50)
        self.entry_tg_channels.insert(0, ", ".join(self.config.telegram_channels))
        self.entry_tg_channels.pack(side="left", padx=8)

        # Поля для Telethon
        tele_frame = tk.LabelFrame(card_tg, text="  Параметры Telethon (my.telegram.org)  ", bg=BG_CARD, fg=TEXT_MUTED, font=FONT_REGULAR, padx=8, pady=6)
        tele_frame.pack(fill="x", pady=(10, 0))

        row_t1 = tk.Frame(tele_frame, bg=BG_CARD)
        row_t1.pack(fill="x", pady=2)
        tk.Label(row_t1, text="API ID:", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(0, 4))
        self.entry_api_id = ttk.Entry(row_t1, width=12)
        if self.config.telegram_api_id:
            self.entry_api_id.insert(0, str(self.config.telegram_api_id))
        self.entry_api_id.pack(side="left", padx=(0, 14))

        tk.Label(row_t1, text="API Hash:", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(0, 4))
        self.entry_api_hash = ttk.Entry(row_t1, width=32)
        if self.config.telegram_api_hash:
            self.entry_api_hash.insert(0, self.config.telegram_api_hash)
        self.entry_api_hash.pack(side="left")

    def _build_districts_tab(self, parent):
        card = tk.LabelFrame(parent, text="  Конфигурация целевого сектора и ориентиров  ", bg=BG_CARD, fg=TEXT_ACCENT, font=FONT_SUBTITLE, padx=10, pady=8)
        card.pack(fill="both", expand=True)

        row_name = tk.Frame(card, bg=BG_CARD)
        row_name.pack(fill="x", pady=(0, 6))
        tk.Label(row_name, text="Название сектора:", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left")
        self.entry_sect_name = ttk.Entry(row_name, width=35)
        self.entry_sect_name.insert(0, self.config.district.name)
        self.entry_sect_name.pack(side="left", padx=8)

        tk.Label(row_name, text="Время удержания (TTL, сек):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(10, 4))
        self.entry_ttl = ttk.Entry(row_name, width=6)
        self.entry_ttl.insert(0, str(self.config.district.ttl_seconds))
        self.entry_ttl.pack(side="left")

        tk.Label(card, text="Ключевые слова района и ориентиров (стык: Основянский, Слободской, Немышля, Новые Дома, Одесская, Аэропорт):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(anchor="w", pady=(4, 2))
        self.txt_dist_kw = tk.Text(card, height=4, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_dist_kw.pack(fill="x", pady=(0, 6))
        self.txt_dist_kw.insert("1.0", ", ".join(self.config.district.district_keywords))

        tk.Label(card, text="Маркеры экстренной опасности («в укрытие», «в укриття», «негайно в укриття»):", bg=BG_CARD, fg="#f87171", font=FONT_BOLD).pack(anchor="w", pady=(2, 2))
        self.txt_shelter_kw = tk.Text(card, height=3, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_shelter_kw.pack(fill="x", pady=(0, 6))
        self.txt_shelter_kw.insert("1.0", ", ".join(self.config.district.critical_alert_keywords))

        tk.Label(card, text="Ключевые слова города Харьков (общие):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(anchor="w", pady=(2, 2))
        self.txt_city_kw = tk.Text(card, height=3, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_city_kw.pack(fill="x")
        self.txt_city_kw.insert("1.0", ", ".join(self.config.district.city_keywords))

    def _build_plc_tab(self, parent):
        card = tk.LabelFrame(parent, text="  Унифицированная битовая карта слова данных ПЛК (%MW0)  ", bg=BG_CARD, fg=TEXT_ACCENT, font=FONT_SUBTITLE, padx=10, pady=8)
        card.pack(fill="both", expand=True)

        self.var_auto_send = tk.BooleanVar(value=self.config.auto_transfer_to_plc)
        ttk.Checkbutton(card, text="Автоматически записывать вычисленное слово тревог в регистр %MW0", variable=self.var_auto_send).pack(anchor="w", pady=(0, 8))

        grid_frame = tk.Frame(card, bg=BG_CARD)
        grid_frame.pack(fill="x")

        bm = self.config.bit_mapping
        fields = [
            ("Безопасно (Отбой / Спокойно):", "bit_safe", bm.bit_safe),
            ("Опасность минимальна (Превентивная тревога):", "bit_threat_minimal", bm.bit_threat_minimal),
            ("Опасность потенциальная для города:", "bit_threat_city_potential", bm.bit_threat_city_potential),
            ("Опасность потенциальная для района объекта:", "bit_threat_district_potential", bm.bit_threat_district_potential),
            ("Опасность критическая для города:", "bit_threat_city_critical", bm.bit_threat_city_critical),
            ("Опасность критическая для района объекта:", "bit_threat_district_critical", bm.bit_threat_district_critical),
            ("Флаг типа: Ракеты / Баллистика:", "bit_type_rocket", bm.bit_type_rocket),
            ("Флаг типа: Управляемые авиабомбы (КАБ):", "bit_type_kab", bm.bit_type_kab),
            ("Флаг типа: Ударные БпЛА (Шахеды / дроны):", "bit_type_drone", bm.bit_type_drone),
            ("Нет связи с источниками данных (AlarmMap/TG):", "bit_no_link", bm.bit_no_link),
            ("Режим тишины по расписанию (тревоги заглушены):", "bit_muted_by_schedule", bm.bit_muted_by_schedule),
            ("Heartbeat (мигающий бит жизни программы):", "bit_heartbeat", bm.bit_heartbeat),
        ]

        self.bit_entries = {}
        for idx, (label_text, attr_name, default_val) in enumerate(fields):
            r = idx // 2
            c = (idx % 2) * 2
            tk.Label(grid_frame, text=label_text, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).grid(row=r, column=c, sticky="w", padx=(6, 4), pady=2)
            ent = ttk.Entry(grid_frame, width=5)
            ent.insert(0, str(default_val))
            ent.grid(row=r, column=c+1, sticky="w", padx=(0, 14), pady=2)
            self.bit_entries[attr_name] = ent

        # Блок обратной связи от ПЛК (%MW1)
        card_fb = tk.LabelFrame(card, text="  Обратная связь от ПЛК (чтение из слова %MW1)  ", bg=BG_CARD, fg="#38bdf8", font=FONT_BOLD, padx=8, pady=6)
        card_fb.pack(fill="x", pady=(10, 0))

        pf = self.config.plc_feedback
        row_fb = tk.Frame(card_fb, bg=BG_CARD)
        row_fb.pack(fill="x")

        tk.Label(row_fb, text="Бит «ПЛК работает» (Run):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(0, 4))
        self.entry_fb_run = ttk.Entry(row_fb, width=5)
        self.entry_fb_run.insert(0, str(pf.bit_plc_running))
        self.entry_fb_run.pack(side="left", padx=(0, 12))

        tk.Label(row_fb, text="Бит «Сброс тревоги» (Reset):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(0, 4))
        self.entry_fb_reset = ttk.Entry(row_fb, width=5)
        self.entry_fb_reset.insert(0, str(pf.bit_alarm_reset))
        self.entry_fb_reset.pack(side="left", padx=(0, 12))

        tk.Label(row_fb, text="Бит «Тумблер анализа угроз» (Вкл/Выкл):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR).pack(side="left", padx=(0, 4))
        self.entry_fb_switch = ttk.Entry(row_fb, width=5)
        self.entry_fb_switch.insert(0, str(pf.bit_analysis_switch))
        self.entry_fb_switch.pack(side="left")

    def _build_schedule_tab(self, parent):
        card = tk.LabelFrame(
            parent,
            text="  Расписание контроля тревог (Тихий час / Блокировка выдачи на ПЛК)  ",
            bg=BG_CARD,
            fg=TEXT_ACCENT,
            font=FONT_SUBTITLE,
            padx=12,
            pady=10
        )
        card.pack(fill="both", expand=True)

        self.var_sched_enabled = tk.BooleanVar(value=self.config.schedule.enabled)
        chk_sched = ttk.Checkbutton(
            card,
            text="Включить расписание контроля тревог (подавление сигналов на ПЛК)",
            variable=self.var_sched_enabled
        )
        chk_sched.pack(anchor="w", pady=(0, 10))

        info_lbl = tk.Label(
            card,
            text="При включении расписания: в указанный интервал времени (например, ночью)\n"
                 "анализ в программе продолжает непрерывно вестись (вы будете видеть статус в окне),\n"
                 "но на контроллер НЕ выдаются сигналы тревог (выдается статус Безопасно / Бит 0),\n"
                 "а на ПЛК передается выделенный бит режима тишины (по умолчанию Бит 10).",
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left"
        )
        info_lbl.pack(anchor="w", pady=(0, 14))

        row_time = tk.Frame(card, bg=BG_CARD)
        row_time.pack(fill="x", pady=4)

        tk.Label(row_time, text="Время начала тишины (ЧЧ:ММ):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=(0, 6))
        self.entry_sched_start = ttk.Entry(row_time, width=8, font=FONT_MONO)
        self.entry_sched_start.insert(0, self.config.schedule.start_time)
        self.entry_sched_start.pack(side="left", padx=(0, 20))

        tk.Label(row_time, text="Время окончания тишины (ЧЧ:ММ):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=(0, 6))
        self.entry_sched_end = ttk.Entry(row_time, width=8, font=FONT_MONO)
        self.entry_sched_end.insert(0, self.config.schedule.end_time)
        self.entry_sched_end.pack(side="left")

    def _build_drones_tab(self, parent):
        card = tk.LabelFrame(
            parent,
            text="  Классификатор названий беспилотников (3 группы опасности)  ",
            bg=BG_CARD,
            fg=TEXT_ACCENT,
            font=FONT_SUBTITLE,
            padx=10,
            pady=8
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text="При фиксации нескольких типов БпЛА одновременно в одном сообщении преобладает наиболее опасная группа (Группа 1 > Группа 2 > Группа 3).\n"
                 "Слова вносите через запятую (например: шахед, герань, гербера):",
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left"
        ).pack(anchor="w", pady=(0, 6))

        # Группа 1: Тяжелые ударные (Критическая)
        tk.Label(card, text="🔴 Группа 1: Высокая опасность (Тяжелые ударные камикадзе с мощной БЧ):", bg=BG_CARD, fg="#f87171", font=FONT_BOLD).pack(anchor="w", pady=(2, 2))
        self.txt_drone_g1 = tk.Text(card, height=3, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g1.pack(fill="x", pady=(0, 6))
        self.txt_drone_g1.insert("1.0", ", ".join(self.config.drone_dict.group1_keywords))

        # Группа 2: Тактические / Разведчики (Средняя)
        tk.Label(card, text="🟡 Группа 2: Средняя опасность (Тактические ударные, FPV дальнего действия, разведчики):", bg=BG_CARD, fg="#fcd34d", font=FONT_BOLD).pack(anchor="w", pady=(2, 2))
        self.txt_drone_g2 = tk.Text(card, height=3, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g2.pack(fill="x", pady=(0, 6))
        self.txt_drone_g2.insert("1.0", ", ".join(self.config.drone_dict.group2_keywords))

        # Группа 3: Ложные цели / Имитаторы (Низкая)
        tk.Label(card, text="🟢 Группа 3: Низкая опасность (Ложные цели, имитаторы, приманки без БЧ):", bg=BG_CARD, fg="#34d399", font=FONT_BOLD).pack(anchor="w", pady=(2, 2))
        self.txt_drone_g3 = tk.Text(card, height=3, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g3.pack(fill="x", pady=(0, 2))
        self.txt_drone_g3.insert("1.0", ", ".join(self.config.drone_dict.group3_keywords))

    def _build_sounds_tab(self, parent):
        card = tk.LabelFrame(
            parent,
            text="  Динамические профили оповещения звуков (%MW2..%MW6)  ",
            bg=BG_CARD,
            fg=TEXT_ACCENT,
            font=FONT_SUBTITLE,
            padx=10,
            pady=8
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text="ПЛК принимает параметры активного звука: %MW2 (Код профиля), %MW3 (Кол-во гудков),\n"
                 "%MW4 (Длительность гудка, мс), %MW5 (Пауза между гудками, мс), %MW6 (Интервал между сериями, мс).\n"
                 "При блокировке тумблером с ПЛК или в тихий час на ПЛК передаются все нули.",
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left"
        ).pack(anchor="w", pady=(0, 6))

        # Заголовки таблицы
        headers_frame = tk.Frame(card, bg=BG_CARD)
        headers_frame.pack(fill="x", pady=(2, 4))
        tk.Label(headers_frame, text="Событие оповещения", width=34, anchor="w", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left")
        tk.Label(headers_frame, text="Код", width=5, bg=BG_CARD, fg=TEXT_MUTED, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Гудков (шт)", width=11, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Длительность (мс)", width=16, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Пауза в серии (мс)", width=16, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Пауза серии (мс)", width=16, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)

        self.sound_profile_entries = {}
        sp = self.config.sound_profiles
        profiles_list = [
            ("safe_heartbeat", "0: Норма (Звуковой Heartbeat)", sp.safe_heartbeat),
            ("rocket_critical", "1: Ракета: Критическая (Город)", sp.rocket_critical),
            ("rocket_potential", "2: Ракета: Потенциальная (Город)", sp.rocket_potential),
            ("kab_district_critical", "3: КАБ: Критическая (Район)", sp.kab_district_critical),
            ("kab_city_critical", "4: КАБ: Критическая (Город)", sp.kab_city_critical),
            ("kab_potential", "5: КАБ: Потенциальная", sp.kab_potential),
            ("drone_g1_district_critical", "6: Дрон Гр.1: Критическая (Район)", sp.drone_g1_district_critical),
            ("drone_g1_city", "7: Дрон Гр.1: Опасность (Город)", sp.drone_g1_city),
            ("drone_g2_tactical", "8: Дрон Гр.2: Тактические / FPV", sp.drone_g2_tactical),
            ("drone_g3_decoy", "9: Дрон Гр.3: Ложные цели / Мин.", sp.drone_g3_decoy),
        ]

        # Контейнер для строк со скроллом если нужно
        container = tk.Frame(card, bg=BG_CARD)
        container.pack(fill="both", expand=True)

        for prof_key, prof_label, p_obj in profiles_list:
            row = tk.Frame(container, bg=BG_CARD)
            row.pack(fill="x", pady=1)

            lbl_color = TEXT_MAIN
            if "Критическая (Район)" in prof_label:
                lbl_color = "#f87171"
            elif "Критическая" in prof_label:
                lbl_color = "#fb923c"
            elif "Heartbeat" in prof_label:
                lbl_color = "#34d399"

            tk.Label(row, text=prof_label, width=34, anchor="w", bg=BG_CARD, fg=lbl_color, font=FONT_REGULAR).pack(side="left")
            tk.Label(row, text=str(p_obj.code), width=5, bg=BG_CARD, fg=TEXT_MUTED, font=FONT_MONO).pack(side="left", padx=2)

            e_cnt = ttk.Entry(row, width=10, font=FONT_MONO)
            e_cnt.insert(0, str(p_obj.beep_count))
            e_cnt.pack(side="left", padx=3)

            e_dur = ttk.Entry(row, width=15, font=FONT_MONO)
            e_dur.insert(0, str(p_obj.beep_duration_ms))
            e_dur.pack(side="left", padx=3)

            e_pau = ttk.Entry(row, width=15, font=FONT_MONO)
            e_pau.insert(0, str(p_obj.pause_between_ms))
            e_pau.pack(side="left", padx=3)

            e_int = ttk.Entry(row, width=15, font=FONT_MONO)
            e_int.insert(0, str(p_obj.interval_series_ms))
            e_int.pack(side="left", padx=3)

            self.sound_profile_entries[prof_key] = (e_cnt, e_dur, e_pau, e_int)

    def _save_and_close(self):
        try:
            # Парсинг источников
            self.config.alarmmap_enabled = self.var_am_enabled.get()
            self.config.alarmmap_key_file = self.entry_am_key.get().strip()
            self.config.alarmmap_poll_interval_s = int(self.entry_am_poll.get().strip())

            self.config.telegram_enabled = self.var_tg_enabled.get()
            self.config.telegram_mode = self.var_tg_mode.get()
            channels = [c.strip() for c in self.entry_tg_channels.get().split(",") if c.strip()]
            self.config.telegram_channels = channels

            api_id_str = self.entry_api_id.get().strip()
            self.config.telegram_api_id = int(api_id_str) if api_id_str else None
            self.config.telegram_api_hash = self.entry_api_hash.get().strip() or None

            # Парсинг районов
            self.config.district.name = self.entry_sect_name.get().strip()
            self.config.district.ttl_seconds = int(self.entry_ttl.get().strip())

            dist_kws = [k.strip().lower() for k in self.txt_dist_kw.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            self.config.district.district_keywords = dist_kws

            shelter_kws = [k.strip().lower() for k in self.txt_shelter_kw.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            self.config.district.critical_alert_keywords = shelter_kws

            city_kws = [k.strip().lower() for k in self.txt_city_kw.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            self.config.district.city_keywords = city_kws

            # Парсинг бит передачи в ПЛК
            self.config.auto_transfer_to_plc = self.var_auto_send.get()
            for attr_name, ent in self.bit_entries.items():
                val = int(ent.get().strip())
                if not (0 <= val <= 15):
                    raise ValueError(f"Номер бита должен быть от 0 до 15: {attr_name}")
                setattr(self.config.bit_mapping, attr_name, val)

            # Парсинг бит обратной связи от ПЛК
            self.config.plc_feedback.bit_plc_running = int(self.entry_fb_run.get().strip())
            self.config.plc_feedback.bit_alarm_reset = int(self.entry_fb_reset.get().strip())
            self.config.plc_feedback.bit_analysis_switch = int(self.entry_fb_switch.get().strip())

            # Парсинг расписания тишины
            self.config.schedule.enabled = self.var_sched_enabled.get()
            self.config.schedule.start_time = self.entry_sched_start.get().strip()
            self.config.schedule.end_time = self.entry_sched_end.get().strip()

            # Парсинг словаря беспилотников
            g1_kws = [k.strip().lower() for k in self.txt_drone_g1.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            g2_kws = [k.strip().lower() for k in self.txt_drone_g2.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            g3_kws = [k.strip().lower() for k in self.txt_drone_g3.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            self.config.drone_dict.group1_keywords = g1_kws
            self.config.drone_dict.group2_keywords = g2_kws
            self.config.drone_dict.group3_keywords = g3_kws

            # Парсинг звуковых профилей
            for prof_key, (e_cnt, e_dur, e_pau, e_int) in self.sound_profile_entries.items():
                if hasattr(self.config.sound_profiles, prof_key):
                    p_obj = getattr(self.config.sound_profiles, prof_key)
                    p_obj.beep_count = int(e_cnt.get().strip())
                    p_obj.beep_duration_ms = int(e_dur.get().strip())
                    p_obj.pause_between_ms = int(e_pau.get().strip())
                    p_obj.interval_series_ms = int(e_int.get().strip())

            # Сохранение конфигурации в JSON
            self._save_to_json()

            if self.on_save:
                self.on_save(self.config)

            messagebox.showinfo("Сохранено", "Настройки анализатора угроз, словаря БпЛА и звуковых профилей сохранены!")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка ввода", f"Проверьте корректность введенных данных:\n{e}")

    def _save_to_json(self):
        """Сохранение конфигурации в config_threats.json."""
        sp = self.config.sound_profiles
        sound_profiles_dict = {}
        for k in [
            "safe_heartbeat", "rocket_critical", "rocket_potential",
            "kab_district_critical", "kab_city_critical", "kab_potential",
            "drone_g1_district_critical", "drone_g1_city", "drone_g2_tactical", "drone_g3_decoy"
        ]:
            if hasattr(sp, k):
                obj = getattr(sp, k)
                sound_profiles_dict[k] = {
                    "code": obj.code,
                    "name": obj.name,
                    "beep_count": obj.beep_count,
                    "beep_duration_ms": obj.beep_duration_ms,
                    "pause_between_ms": obj.pause_between_ms,
                    "interval_series_ms": obj.interval_series_ms
                }

        data = {
            "alarmmap_enabled": self.config.alarmmap_enabled,
            "alarmmap_key_file": self.config.alarmmap_key_file,
            "alarmmap_poll_interval_s": self.config.alarmmap_poll_interval_s,
            "telegram_enabled": self.config.telegram_enabled,
            "telegram_mode": self.config.telegram_mode,
            "telegram_api_id": self.config.telegram_api_id,
            "telegram_api_hash": self.config.telegram_api_hash,
            "telegram_channels": self.config.telegram_channels,
            "district": {
                "name": self.config.district.name,
                "ttl_seconds": self.config.district.ttl_seconds,
                "district_keywords": self.config.district.district_keywords,
                "critical_alert_keywords": self.config.district.critical_alert_keywords,
                "city_keywords": self.config.district.city_keywords
            },
            "bit_mapping": {
                "bit_safe": self.config.bit_mapping.bit_safe,
                "bit_threat_minimal": self.config.bit_mapping.bit_threat_minimal,
                "bit_threat_city_potential": self.config.bit_mapping.bit_threat_city_potential,
                "bit_threat_district_potential": self.config.bit_mapping.bit_threat_district_potential,
                "bit_threat_city_critical": self.config.bit_mapping.bit_threat_city_critical,
                "bit_threat_district_critical": self.config.bit_mapping.bit_threat_district_critical,
                "bit_type_rocket": self.config.bit_mapping.bit_type_rocket,
                "bit_type_kab": self.config.bit_mapping.bit_type_kab,
                "bit_type_drone": self.config.bit_mapping.bit_type_drone,
                "bit_no_link": self.config.bit_mapping.bit_no_link,
                "bit_muted_by_schedule": self.config.bit_mapping.bit_muted_by_schedule,
                "bit_heartbeat": self.config.bit_mapping.bit_heartbeat
            },
            "plc_feedback": {
                "bit_plc_running": self.config.plc_feedback.bit_plc_running,
                "bit_alarm_reset": self.config.plc_feedback.bit_alarm_reset,
                "bit_analysis_switch": self.config.plc_feedback.bit_analysis_switch
            },
            "schedule": {
                "enabled": self.config.schedule.enabled,
                "start_time": self.config.schedule.start_time,
                "end_time": self.config.schedule.end_time
            },
            "drone_dict": {
                "group1_keywords": self.config.drone_dict.group1_keywords,
                "group2_keywords": self.config.drone_dict.group2_keywords,
                "group3_keywords": self.config.drone_dict.group3_keywords
            },
            "sound_profiles": sound_profiles_dict,
            "auto_transfer_to_plc": self.config.auto_transfer_to_plc
        }
        with open("config_threats.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
