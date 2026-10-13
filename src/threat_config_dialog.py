import re
import tkinter as tk
from tkinter import ttk, messagebox
import os
import json
from copy import deepcopy
from src.threat_models import ThreatSystemConfig, DistrictConfig, BitMappingConfig, SEVERITIES, THREAT_TYPES, APPROACHES, EndCondition
from src.ui_theme import (
    BG_MAIN, BG_CARD, BG_INPUT, TEXT_MAIN, TEXT_MUTED, TEXT_ACCENT,
    COLOR_PRIMARY, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER,
    FONT_TITLE, FONT_SUBTITLE, FONT_REGULAR, FONT_BOLD, FONT_MONO
)

def parse_duration_ms(val_str, min_ms=10, step_ms=10):
    """Парсит длительность: поддерживает как мс (50, 800), так и сек (0.05, 0.1, 0.8 с точкой или запятой)."""
    s = str(val_str).strip().replace(',', '.')
    s = re.sub(r'[a-zA-Zа-яА-Я]+', '', s).strip()
    if not s:
        return 0
    val = float(s)
    if '.' in str(val_str) or ',' in str(val_str) or (0 < val < 10):
        ms = int(round(val * 1000))
    else:
        ms = int(round(val))
    if step_ms > 1:
        ms = int(round(ms / step_ms)) * step_ms
    if ms < min_ms and ms > 0:
        ms = min_ms
    return ms

def parse_interval_series_ms(val_str):
    """Парсит интервал серий: поддерживает как сек (4, 8, 15, 30), так и мс (4000, 8000)."""
    s = str(val_str).strip().replace(',', '.')
    s = re.sub(r'[a-zA-Zа-яА-Я]+', '', s).strip()
    if not s:
        return 0
    val = float(s)
    if '.' in str(val_str) or ',' in str(val_str) or val < 100:
        ms = int(round(val * 1000))
    else:
        ms = int(round(val))
    ms = int(round(ms / 1000)) * 1000
    return max(1000, ms)

class DictionaryEditor(tk.Frame):
    """Word-wrapped dictionary field with adaptive height and visible scrolling."""
    def __init__(self, parent, height=3, **options):
        super().__init__(parent, bg=options.get('bg', BG_MAIN))
        self.minimum_lines = max(3, height)
        defaults = dict(bg=BG_INPUT, fg=TEXT_MAIN, insertbackground=TEXT_MAIN,
                        font=FONT_MONO, bd=1, relief='solid')
        defaults.update(options)
        self.text = tk.Text(self, width=1, height=self.minimum_lines, wrap='word', **defaults)
        self.scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.text.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.text.pack(side='left', fill='both', expand=True)
        self.text.configure(yscrollcommand=self.scrollbar.set)
        self.text.bind('<Configure>', self._fit_height)
        self.text.bind('<<Modified>>', self._modified)

    def _modified(self, event=None):
        if self.text.edit_modified():
            self.text.edit_modified(False)
            self._fit_height()

    def _fit_height(self, event=None):
        if self.text.winfo_width() < 20:
            return
        count = self.text.count('1.0', 'end-1c', 'displaylines')
        lines = min(8, max(self.minimum_lines, (count[0] if count else 0) + 1))
        if int(self.text.cget('height')) != lines:
            self.text.configure(height=lines)

    def get(self, *indices):
        if indices:
            return self.text.get(*indices)
        return self.text.get('1.0', 'end-1c').replace('\n', ',')

    def insert(self, index, value):
        self.text.insert('1.0' if index == 0 else index, value)

    def delete(self, first, last=None):
        self.text.delete('1.0' if first == 0 else first, last)


class ThreatConfigDialog(tk.Toplevel):
    """Окно конфигуратора анализатора угроз, районов и маппинга бит на ПЛК."""
    def __init__(self, parent, current_config: ThreatSystemConfig, on_save_callback, persist=True, channel_only=False):
        super().__init__(parent)
        self.title("Конфигуратор анализатора угроз и передачи на ПЛК")
        width = min(1120, max(600, self.winfo_screenwidth() - 80))
        height = min(780, max(480, self.winfo_screenheight() - 100))
        self.geometry(f"{width}x{height}")
        self.minsize(min(760, width), min(540, height))
        self.resizable(True, True)
        self.configure(bg=BG_MAIN)
        self.transient(parent)
        self.grab_set()

        self.config = deepcopy(current_config)
        self.on_save = on_save_callback
        self.persist = persist
        self.channel_only = channel_only

        self._build_ui()
        if self.channel_only:
            self._hide_main_module_controls()

    def _build_ui(self):
        # Reserve the footer before expandable notebooks, even on a short display.
        btn_frame = tk.Frame(self, bg=BG_MAIN, padx=12, pady=10)
        btn_frame.pack(fill="x", side="bottom")
        # Вкладки
        notebook = ttk.Notebook(self)
        self.notebook = notebook
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        # 1. Вкладка "Источники данных"
        tab_sources = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_sources, text="Источники")
        self._build_sources_tab(tab_sources)

        # 2. Вкладка "Районы и Ключевые слова"
        tab_districts = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_districts, text="Районы")
        self._build_districts_tab(tab_districts)

        # 3. Вкладка "Битовая карта ПЛК"
        tab_plc = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_plc, text="Биты ПЛК")
        self._build_plc_tab(tab_plc)

        # 4. Вкладка "Расписание тишины"
        tab_sched = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_sched, text="Тихий час")
        self._build_schedule_tab(tab_sched)

        # 5. Вкладка "Словарь БпЛА"
        tab_drones = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_drones, text="Группы БпЛА")
        self._build_drones_tab(tab_drones)

        # 6. Вкладка "Звуковые профили ПЛК"
        tab_sounds = tk.Frame(notebook, bg=BG_MAIN, padx=10, pady=10)
        notebook.add(tab_sounds, text="Звуковые профили")
        self._build_sounds_tab(tab_sounds)

        tab_rules = tk.Frame(notebook, bg=BG_MAIN)
        notebook.add(tab_rules, text="12 правил тревог")
        self._build_rules_tab(tab_rules)
        tab_end = tk.Frame(notebook, bg=BG_MAIN)
        notebook.add(tab_end, text="Эвристика / окончание")
        self._build_heuristics_tab(tab_end)
        notebook.select(tab_rules)

        # Нижняя панель с кнопками
        btn_save = ttk.Button(btn_frame, text="Сохранить настройки", style="Success.TButton", command=self._save_and_close)
        btn_save.pack(side="right", padx=(8, 0))

        btn_cancel = ttk.Button(btn_frame, text="Отмена", style="Outline.TButton", command=self.destroy)
        btn_cancel.pack(side="right")

    def _hide_main_module_controls(self):
        self.title('Анализатор Telegram-канала — словари, фильтры и правила')
        for tab in list(self.notebook.tabs()):
            title=self.notebook.tab(tab,'text')
            if title in ('Биты ПЛК','Тихий час','Звуковые профили'):
                self.notebook.forget(tab)
            elif title=='Источники':
                self.notebook.tab(tab,text='Telegram-канал')
        self.var_am_enabled.set(False)
        self.var_auto_send.set(False)
        def hide(widget):
            for child in widget.winfo_children():
                if isinstance(child,tk.LabelFrame) and 'AlarmMap' in child.cget('text'):
                    child.pack_forget()
                if isinstance(child,tk.Label):
                    text=child.cget('text')
                    if text.startswith('API — типы:') or text.startswith('API air без уточнения'):
                        child.master.pack_forget()
                    elif 'Типы и номера уровней API' in text or text.startswith('air — общая воздушная тревога'):
                        child.pack_forget()
                    elif 'Источники' in text and 'API' in text:
                        child.configure(text='Источники Telegram (@канал):')
                    elif text.startswith('Сначала степень:'):
                        child.configure(text='Степень: критическая → высокая → низкая. Правила используют только сообщения выбранного Telegram-канала.')
                    elif 'типы и номера API' in text.lower():
                        child.configure(text='Маркеры через запятую. Для района требуется слово из вкладки «Районы».')
                hide(child)
        hide(self)

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

        extra = tk.Frame(card_am, bg=BG_CARD)
        extra.pack(fill="x", pady=4)
        for label, attr, initial, width in [
            ("КАТОТТГ:", "entry_katottg", self.config.alarmmap_katottg, 26),
            ("Актуальность API, с:", "entry_api_stale", self.config.api_stale_seconds, 6),
            ("Актуальность Telegram, с:", "entry_source_stale", self.config.source_stale_seconds, 6)]:
            tk.Label(extra, text=label, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=4)
            entry = ttk.Entry(extra, width=width)
            entry.insert(0, str(initial))
            entry.pack(side="left")
            setattr(self, attr, entry)

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
        tele_frame = tk.LabelFrame(card_tg, text="  Параметры Telethon (my.telegram.org)  ", bg=BG_CARD, fg=TEXT_MUTED, font=FONT_SUBTITLE, padx=8, pady=6)
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
        parent = self._scroll_body(parent)
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

        tk.Label(card, text="Ключевые слова района и ориентиров (стык: Основянский, Слободской, Немышля, Новые Дома, Одесская, Аэропорт):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD, wraplength=700, justify="left").pack(anchor="w", pady=(4, 2))
        self.txt_dist_kw = DictionaryEditor(card, height=4, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_dist_kw.pack(fill="x", pady=(0, 6))
        self.txt_dist_kw.insert("1.0", ", ".join(self.config.district.district_keywords))

        tk.Label(card, text="Приближение и степень опасности настраиваются во вкладке 9 правил тревог. "
                 "Призыв в укрытие сам по себе не определяет положение и тип цели.",
                 bg=BG_CARD, fg=TEXT_MUTED, wraplength=900, justify="left").pack(anchor="w", pady=6)

        tk.Label(card, text="Ключевые слова города Харьков (общие):", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_REGULAR, wraplength=700, justify="left").pack(anchor="w", pady=(2, 2))
        self.txt_city_kw = DictionaryEditor(card, height=3, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_city_kw.pack(fill="x")
        self.txt_city_kw.insert("1.0", ", ".join(self.config.district.city_keywords))

        self.extra_location_inputs={}
        for key,label in [('regional_keywords','Областные направления (без нахождения над городом)'),
                          ('ignored_location_keywords','Дальние населённые пункты: не повышать тревогу города'),
                          ('urban_keywords','Ориентиры внутри городской застройки'),
                          ('ignored_message_keywords','Информационные сообщения: исключающие маркеры')]:
            tk.Label(card,text=label,bg=BG_CARD,fg=TEXT_ACCENT).pack(anchor='w',pady=(8,2))
            entry=DictionaryEditor(card)
            entry.insert(0,', '.join(getattr(self.config.district,key)))
            entry.pack(fill='x')
            self.extra_location_inputs[key]=entry

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
            ("Низкая опасность:", "bit_threat_minimal", bm.bit_threat_minimal),
            ("Высокая (город / API):", "bit_threat_city_potential", bm.bit_threat_city_potential),
            ("Высокая (район):", "bit_threat_district_potential", bm.bit_threat_district_potential),
            ("Критическая (город / API):", "bit_threat_city_critical", bm.bit_threat_city_critical),
            ("Критическая (район):", "bit_threat_district_critical", bm.bit_threat_district_critical),
            ("Флаг типа: Ракеты / Баллистика:", "bit_type_rocket", bm.bit_type_rocket),
            ("Флаг типа: Управляемые авиабомбы (КАБ):", "bit_type_kab", bm.bit_type_kab),
            ("Флаг типа: Ударные БпЛА (Шахеды / дроны):", "bit_type_drone", bm.bit_type_drone),
            ("Флаг типа: Неопознанная угроза:", "bit_type_unknown", getattr(bm, "bit_type_unknown", 11)),
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
        card_fb = tk.LabelFrame(card, text="  Обратная связь от ПЛК (чтение из слова %MW1)  ", bg=BG_CARD, fg="#38bdf8", font=FONT_SUBTITLE, padx=8, pady=6)
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
            text="При включении расписания: в указанный интервал времени (например, ночью) "
                 "анализ в программе продолжает непрерывно вестись (вы будете видеть статус в окне), "
                 "но на контроллер НЕ выдаются сигналы тревог (выдается статус Безопасно / Бит 0), "
                 "а на ПЛК передается выделенный бит режима тишины (по умолчанию Бит 10).",
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left",
            wraplength=700
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
        parent = self._scroll_body(parent)
        card = tk.LabelFrame(
            parent,
            text="  Классификатор названий беспилотников (4 группы опасности: 0 = мин., 3 = макс.)  ",
            bg=BG_CARD,
            fg=TEXT_ACCENT,
            font=FONT_SUBTITLE,
            padx=10,
            pady=8
        )
        card.pack(fill="both", expand=True)

        tk.Label(
            card,
            text="При фиксации нескольких типов БпЛА преобладает наиболее опасная группа (Гр.3 > Гр.2 > Гр.1 > Гр.0).\n"
                 "Слова вносите через запятую (например: шахед, герань, молния):",
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left",
            wraplength=700
        ).pack(anchor="w", pady=(0, 6))

        # Группа 3: Тяжелые камикадзе (Самая высокая)
        tk.Label(card, text="🔴 Группа 3: Самая высокая опасность (Тяжелые ударные камикадзе: Шахед, Герань, Гербера, Италмас...):", bg=BG_CARD, fg="#f87171", font=FONT_BOLD, wraplength=700, justify="left").pack(anchor="w", pady=(2, 2))
        self.txt_drone_g3 = DictionaryEditor(card, height=2, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g3.pack(fill="x", pady=(0, 4))
        self.txt_drone_g3.insert("1.0", ", ".join(self.config.drone_dict.group3_keywords))

        # Группа 2: Тактические ударные / FPV (Средняя)
        tk.Label(card, text="🟠 Группа 2: Средняя опасность (Тактические ударные: Молния, Ланцет, FPV):", bg=BG_CARD, fg="#fb923c", font=FONT_BOLD, wraplength=700, justify="left").pack(anchor="w", pady=(2, 2))
        self.txt_drone_g2 = DictionaryEditor(card, height=2, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g2.pack(fill="x", pady=(0, 4))
        self.txt_drone_g2.insert("1.0", ", ".join(self.config.drone_dict.group2_keywords))

        # Группа 1: Разведчики (Низкая)
        tk.Label(card, text="🟡 Группа 1: Низкая опасность (Разведчики: Суперкам, Зала, Орлан):", bg=BG_CARD, fg="#fcd34d", font=FONT_BOLD, wraplength=700, justify="left").pack(anchor="w", pady=(2, 2))
        self.txt_drone_g1 = DictionaryEditor(card, height=2, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g1.pack(fill="x", pady=(0, 4))
        self.txt_drone_g1.insert("1.0", ", ".join(self.config.drone_dict.group1_keywords))

        # Группа 0: Ложные цели / Неопознанные БпЛА (Самая низкая)
        tk.Label(card, text="🟢 Группа 0: Самая низкая опасность (Ложные цели, фанера, приманки без БЧ, неопознанные / общий БпЛА):", bg=BG_CARD, fg="#34d399", font=FONT_BOLD, wraplength=700, justify="left").pack(anchor="w", pady=(2, 2))
        self.txt_drone_g0 = DictionaryEditor(card, height=2, bg=BG_INPUT, fg=TEXT_MAIN, font=FONT_MONO, bd=1, relief="solid")
        self.txt_drone_g0.pack(fill="x", pady=(0, 2))
        self.txt_drone_g0.insert("1.0", ", ".join(getattr(self.config.drone_dict, "group0_keywords", [])))

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
            text="ПЛК принимает параметры активного звука: %MW2 (Код профиля), %MW3 (Кол-во гудков), %MW4 (Длительность гудка, мс), %MW5 (Пауза между гудками, мс), %MW6 (Интервал между сериями, мс).\n"
                 "Длительность гудка и паузы можно задавать в мс (50, 100, 800) или сек (0.05, 0.1, 0.8), шаг 10 мс (мин. 10 мс). "
                 "Интервал серий кратен 1 с (1000 мс).",
            font=FONT_REGULAR,
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify="left",
            wraplength=850
        ).pack(anchor="w", pady=(0, 6))

        # Заголовки таблицы
        headers_frame = tk.Frame(card, bg=BG_CARD)
        headers_frame.pack(fill="x", pady=(2, 4))
        tk.Label(headers_frame, text="Событие оповещения", width=34, anchor="w", bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left")
        tk.Label(headers_frame, text="Код", width=5, bg=BG_CARD, fg=TEXT_MUTED, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Гудков (шт)", width=10, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Длительность (мс/с)", width=18, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Пауза в серии (мс/с)", width=18, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)
        tk.Label(headers_frame, text="Пауза серий (с/мс)", width=16, bg=BG_CARD, fg=TEXT_MAIN, font=FONT_BOLD).pack(side="left", padx=2)

        self.sound_profile_entries = {}
        profiles_list = [("safe", "0: Отсутствие тревог", self.config.safe_sound),
                         ("no_link", "Нет связи с онлайн-источниками", self.config.no_link_sound)] + [
            (rule.id, f"{rule.sound.code}: {rule.sound.name}", rule.sound)
            for rule in self.config.alarm_rules
        ]

        # Контейнер для строк со скроллом если нужно
        sound_canvas = tk.Canvas(card, bg=BG_CARD, highlightthickness=0)
        sound_scroll = ttk.Scrollbar(card, orient="vertical", command=sound_canvas.yview)
        sound_canvas.configure(yscrollcommand=sound_scroll.set)
        sound_scroll.pack(side="right", fill="y")
        sound_canvas.pack(side="left", fill="both", expand=True)
        container = tk.Frame(sound_canvas, bg=BG_CARD)
        sound_window = sound_canvas.create_window((0, 0), window=container, anchor="nw")
        container.bind("<Configure>", lambda event: sound_canvas.configure(scrollregion=sound_canvas.bbox("all")))
        sound_canvas.bind("<Configure>", lambda event: sound_canvas.itemconfigure(sound_window, width=event.width))

        for prof_key, prof_label, p_obj in profiles_list:
            row = tk.Frame(container, bg=BG_CARD)
            row.pack(fill="x", pady=1)

            lbl_color = TEXT_MAIN
            if "Критическая (Район)" in prof_label or "Критическая" in prof_label:
                lbl_color = "#f87171"
            elif "Опасность" in prof_label or "Потенциальная" in prof_label:
                lbl_color = "#fb923c"
            elif "Heartbeat" in prof_label or "Отсутствие" in prof_label:
                lbl_color = "#34d399"

            tk.Label(row, text=prof_label, width=34, anchor="w", bg=BG_CARD, fg=lbl_color, font=FONT_REGULAR).pack(side="left")
            tk.Label(row, text=str(p_obj.code), width=5, bg=BG_CARD, fg=TEXT_MUTED, font=FONT_MONO).pack(side="left", padx=2)

            e_cnt = ttk.Entry(row, width=8, font=FONT_MONO)
            e_cnt.insert(0, str(p_obj.beep_count))
            e_cnt.pack(side="left", padx=3)

            e_dur = ttk.Entry(row, width=12, font=FONT_MONO)
            e_dur.insert(0, str(p_obj.beep_duration_ms))
            e_dur.pack(side="left", padx=3)

            e_pau = ttk.Entry(row, width=12, font=FONT_MONO)
            e_pau.insert(0, str(p_obj.pause_between_ms))
            e_pau.pack(side="left", padx=3)

            e_int = ttk.Entry(row, width=12, font=FONT_MONO)
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

            city_kws = [k.strip().lower() for k in self.txt_city_kw.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            self.config.district.city_keywords = city_kws
            for key,entry in self.extra_location_inputs.items():
                setattr(self.config.district,key,[v.strip().lower() for v in entry.get().split(',') if v.strip()])

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

            # Парсинг словаря беспилотников (4 группы 0..3)
            g3_kws = [k.strip().lower() for k in self.txt_drone_g3.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            g2_kws = [k.strip().lower() for k in self.txt_drone_g2.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            g1_kws = [k.strip().lower() for k in self.txt_drone_g1.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            g0_kws = [k.strip().lower() for k in self.txt_drone_g0.get("1.0", "end").replace("\n", ",").split(",") if k.strip()]
            self.config.drone_dict.group3_keywords = g3_kws
            self.config.drone_dict.group2_keywords = g2_kws
            self.config.drone_dict.group1_keywords = g1_kws
            self.config.drone_dict.group0_keywords = g0_kws

            for rule in self.config.alarm_rules:
                inputs = self.rule_inputs[rule.id]
                rule.enabled = inputs["enabled"].get()
                raw_sources = [v.strip() for v in inputs["sources"].get().split(",") if v.strip()]
                rule.sources = []
                for value in raw_sources:
                    if value.lower() in ("api", "alarmmap"):
                        rule.sources.append("alarmmap")
                    elif value.lower() in ("telegram", "telegram:*"):
                        rule.sources.append("telegram:*")
                    else:
                        rule.sources.append("telegram:" + value.removeprefix("telegram:").lstrip("@").lower())
                rule.approaches = [k for k, v in inputs["approaches"].items() if v.get()]
                if rule.threat_type == "drone":
                    rule.drone_groups = [k for k, v in inputs["groups"].items() if v.get()]
                rule.api_types = [v.strip() for v in inputs["api_types"].get().split(",") if v.strip()]
                rule.api_levels = [int(v.strip()) for v in inputs["api_levels"].get().split(",") if v.strip()]
                if "air_levels" in inputs:
                    rule.api_levels_by_type["air"] = [int(v.strip()) for v in inputs["air_levels"].get().split(",") if v.strip()]
            for approach, entry in self.approach_entries.items():
                self.config.approach_keywords[approach] = [v.strip().lower() for v in entry.get().split(",") if v.strip()]
            self.config.source_stale_seconds = int(self.entry_source_stale.get())
            self.config.api_stale_seconds = int(self.entry_api_stale.get())
            self.config.alarmmap_katottg = self.entry_katottg.get().strip()
            for key, entries in self.sound_profile_entries.items():
                if key == "safe":
                    p_obj = self.config.safe_sound
                elif key == "no_link":
                    p_obj = self.config.no_link_sound
                else:
                    p_obj = next(r.sound for r in self.config.alarm_rules if r.id == key)
                e_cnt, e_dur, e_pau, e_int = entries
                p_obj.beep_count = int(e_cnt.get().strip())
                p_obj.beep_duration_ms = parse_duration_ms(e_dur.get(), min_ms=10)
                p_obj.pause_between_ms = parse_duration_ms(e_pau.get(), min_ms=0)
                p_obj.interval_series_ms = parse_interval_series_ms(e_int.get())
            self._save_heuristics()
            if self.channel_only:
                self.config.alarmmap_enabled=False
                self.config.auto_transfer_to_plc=False
                for rule in self.config.alarm_rules:
                    rule.sources=[source for source in rule.sources if source.startswith('telegram:')]
                    rule.api_types=[];rule.api_levels=[];rule.api_levels_by_type={}
                    if not rule.sources:
                        rule.enabled=False
            self.config.validate()

            # Сохранение конфигурации в JSON
            self._save_to_json()

            if self.on_save:
                self.on_save(self.config)

            messagebox.showinfo("Сохранено" if self.persist else "Применено в тесте",
                "Настройки сохранены!" if self.persist else "Правила применены к архивному тесту; рабочие настройки не изменены.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка ввода", f"Проверьте корректность введенных данных:\n{e}")

    def _save_to_json(self):
        if self.persist:
            self.config.save()
        else:
            self.config.validate()

    def _build_rules_tab(self, parent):
        tk.Label(parent, text="Сначала степень: критическая → высокая → низкая. Внутри степени: ракета → бомба → дрон.\n"
                 "Источники и значения внутри одного поля объединены по ИЛИ; разные поля — по И. "
                 "API: явный тип имеет приоритет над air; без уточнения air/3 — ракета, air/1–2 — дрон.\n"
                 "Telegram использует приближение + группу. Неопознанный тип сохраняется для Telegram.",
                 bg=BG_MAIN, fg=TEXT_MAIN, justify="left", wraplength=1020).pack(anchor="w", padx=12, pady=8)
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True, padx=8, pady=4)
        self.rule_inputs = {}
        for degree, title in SEVERITIES.items():
            outer = tk.Frame(notebook, bg=BG_MAIN)
            notebook.add(outer, text=title + " опасность")
            canvas = tk.Canvas(outer, bg=BG_MAIN, highlightthickness=0)
            scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=scroll.set)
            scroll.pack(side="right", fill="y")
            canvas.pack(side="left", fill="both", expand=True)
            body = tk.Frame(canvas, bg=BG_MAIN)
            window = canvas.create_window((0, 0), window=body, anchor="nw")
            body.bind("<Configure>", lambda event, c=canvas: c.configure(scrollregion=c.bbox("all")))
            canvas.bind("<Configure>", lambda event, c=canvas, w=window: c.itemconfigure(w, width=event.width))
            for rule in [r for r in self.config.alarm_rules if r.severity == degree]:
                card = tk.LabelFrame(body, text=f"{THREAT_TYPES[rule.threat_type]} — звук {rule.sound.code}",
                                     bg=BG_CARD, fg=TEXT_ACCENT, padx=8, pady=6)
                card.pack(fill="x", padx=4, pady=5)
                values = {}
                values["enabled"] = tk.BooleanVar(value=rule.enabled)
                ttk.Checkbutton(card, text="Правило включено", variable=values["enabled"]).pack(anchor="w")
                row = tk.Frame(card, bg=BG_CARD); row.pack(fill="x", pady=3)
                tk.Label(row, text="Источники (API, Telegram, @канал):", bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
                values["sources"] = ttk.Entry(row, width=64)
                values["sources"].insert(0, ", ".join("API" if v == "alarmmap" else "Telegram" if v == "telegram:*" else "@"+v.split(":",1)[1] for v in rule.sources))
                values["sources"].pack(side="left", padx=6, fill="x", expand=True)
                row = tk.Frame(card, bg=BG_CARD); row.pack(fill="x", pady=3)
                tk.Label(row, text="Telegram — приближение:", bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
                values["approaches"] = {}
                for index, (key, label) in enumerate(APPROACHES.items()):
                    if index % 3 == 0:
                        options_row = tk.Frame(card, bg=BG_CARD)
                        options_row.pack(fill="x", pady=2)
                    var = tk.BooleanVar(value=key in rule.approaches)
                    values["approaches"][key] = var
                    ttk.Checkbutton(options_row, text=label, variable=var).pack(side="left", padx=5)
                values["groups"] = {}
                if rule.threat_type == "drone":
                    row = tk.Frame(card, bg=BG_CARD); row.pack(fill="x", pady=3)
                    tk.Label(row, text="Telegram — группы дронов (0 = неизвестна):", bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
                    for group in (0, 1, 2, 3):
                        var = tk.BooleanVar(value=group in rule.drone_groups)
                        values["groups"][group] = var
                        ttk.Checkbutton(row, text=str(group), variable=var).pack(side="left", padx=8)
                row = tk.Frame(card, bg=BG_CARD); row.pack(fill="x", pady=3)
                tk.Label(row, text="API — типы:", bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
                values["api_types"] = ttk.Entry(row, width=38)
                values["api_types"].insert(0, ", ".join(rule.api_types))
                values["api_types"].pack(side="left", padx=6)
                if rule.threat_type == "drone":
                    air_row = tk.Frame(card, bg=BG_CARD)
                    air_row.pack(fill="x", pady=3)
                    tk.Label(air_row, text="API air без уточнения — уровни (отдельно от дронов / FPV):",
                             bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
                    values["air_levels"] = ttk.Entry(air_row, width=20)
                    values["air_levels"].insert(0, ", ".join(map(str, rule.api_levels_by_type.get("air", rule.api_levels))))
                    values["air_levels"].pack(side="left", padx=6)
                tk.Label(row, text="Номера уровней (через запятую):", bg=BG_CARD, fg=TEXT_MAIN).pack(side="left")
                values["api_levels"] = ttk.Entry(row, width=16)
                values["api_levels"].insert(0, ", ".join(map(str, rule.api_levels)))
                values["api_levels"].pack(side="left", padx=6)
                if rule.threat_type == "rocket":
                    tk.Label(card, text="air — общая воздушная тревога; здесь она сопоставлена ракетному варианту, "
                             "отдельного ракетного типа в API нет.", bg=BG_CARD, fg=TEXT_MUTED,
                             wraplength=950, justify="left").pack(anchor="w")
                self.rule_inputs[rule.id] = values
        detection = tk.Frame(notebook, bg=BG_MAIN, padx=12, pady=12)
        notebook.add(detection, text="Распознавание приближения")
        detection = self._scroll_body(detection)
        tk.Label(detection, text="Маркеры — через запятую. Для района дополнительно требуется слово из вкладки Районы.\n"
                 "Упоминание района без маркера не доказывает положение цели. API не сообщает приближение или группу дрона.\n"
                 "Общая воздушная тревога air не определяет тип цели. Если включаете air в правило, это ваше явное соответствие.",
                 bg=BG_MAIN, fg=TEXT_MAIN, justify="left", wraplength=980).pack(anchor="w", pady=8)
        self.approach_entries = {}
        for key, label in APPROACHES.items():
            tk.Label(detection, text=label, bg=BG_MAIN, fg=TEXT_ACCENT).pack(anchor="w", pady=(8, 2))
            entry = DictionaryEditor(detection)
            entry.insert(0, ", ".join(self.config.approach_keywords[key]))
            entry.pack(fill="x")
            self.approach_entries[key] = entry
        tk.Label(detection, text="Типы и номера уровней API копируйте из карточки API в главном окне;\n"
                 "названия и пояснения загружаются из официального справочника. Пример типов: air, kab-bombs, fight-drones, fpv-drones (FPV).",
                 bg=BG_MAIN, fg=TEXT_MUTED, justify="left").pack(anchor="w", pady=12)

    @staticmethod
    def _parse_sources(text):
        result = []
        for value in text.split(","):
            value = value.strip().lower()
            if not value:
                continue
            if value in ("telegram", "telegram:*"):
                result.append("telegram:*")
            else:
                result.append("telegram:" + value.removeprefix("telegram:").lstrip("@"))
        return result

    def _scroll_body(self, parent):
        canvas = tk.Canvas(parent, bg=BG_MAIN, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scrollbar.set)
        body = tk.Frame(canvas, bg=BG_MAIN)
        window = canvas.create_window((0, 0), window=body, anchor="nw")
        def body_changed(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            def fit_labels(widget):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label) and int(child.cget('wraplength')) > 0:
                        child.configure(wraplength=max(160, event.width - 40))
                    fit_labels(child)
            fit_labels(body)
        body.bind("<Configure>", body_changed)
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        return body

    def _build_heuristics_tab(self, parent):
        book = ttk.Notebook(parent)
        book.pack(fill="both", expand=True, padx=8, pady=8)
        self.tracking_inputs = {}
        start = tk.Frame(book, bg=BG_MAIN, padx=12, pady=12)
        book.add(start, text="Начало атаки / тип цели")
        start = self._scroll_body(start)
        tk.Label(start, text="Словари задают признаки, а степень опасности выбирается девятью правилами. "
                 "Словарь дронов редактируется во вкладке Группы БпЛА. Маркеры — через запятую.",
                 bg=BG_MAIN, fg=TEXT_MAIN, wraplength=980, justify="left").pack(anchor="w", pady=6)
        for key, label in [("rocket_keywords", "Ракетные признаки"), ("bomb_keywords", "Бомбовые признаки"),
                           ("generic_target_keywords", "Маркеры цели без определённого типа"),
                           ("regional_city_direction_keywords", "Подтверждённое направление к городу из пригородной зоны"),
                           ("confirmed_launch_keywords", "Подтверждённый пуск / сброс — начало новой угрозы"),
                           ("hold_peak_types", "Удерживать достигнутый уровень при движении: rocket, kab, drone"),
                           ("rocket_launch_keywords", "Носители ракет (учитываются только вместе с пуском/взлётом)")]:
            tk.Label(start, text=label, bg=BG_MAIN, fg=TEXT_ACCENT).pack(anchor="w", pady=(12, 3))
            entry = DictionaryEditor(start)
            entry.insert(0, ", ".join(getattr(self.config.tracking, key)))
            entry.pack(fill="x")
            self.tracking_inputs[key] = entry
        tk.Label(start,text='Тип цели по умолчанию (если нет действующего контекста):',bg=BG_MAIN,fg=TEXT_ACCENT).pack(anchor='w',pady=(12,3))
        self.var_generic_type=tk.StringVar(value=THREAT_TYPES[self.config.tracking.generic_target_type])
        ttk.Combobox(start,textvariable=self.var_generic_type,values=[THREAT_TYPES['rocket'],THREAT_TYPES['drone']],state='readonly').pack(anchor='w')
        movement = tk.Frame(book, bg=BG_MAIN, padx=12, pady=12)
        book.add(movement, text="Движение / контекст")
        movement = self._scroll_body(movement)
        self.var_generic_city_level=tk.StringVar(value={0:'По обычным правилам',1:'Низкая',2:'Высокая',4:'Критическая'}[self.config.tracking.generic_city_level])
        level_frame=ttk.Frame(movement);level_frame.pack(anchor="w")
        ttk.Label(level_frame,text="Уровень отдельной цели на/над городом:").pack(side="left")
        ttk.Combobox(level_frame,textvariable=self.var_generic_city_level,values=['По обычным правилам','Низкая','Высокая','Критическая'],state="readonly",width=24).pack(side="left")
        self.var_generic_reply=tk.BooleanVar(value=self.config.tracking.generic_city_requires_reply_context)
        ttk.Checkbutton(movement,text="Цель на/над городом: тип из контекста только при ответе Telegram",variable=self.var_generic_reply).pack(anchor="w")
        self.var_urban_drone=tk.BooleanVar(value=self.config.tracking.urban_direction_drone_is_city)
        ttk.Checkbutton(movement,text='Направление дрона на городской ориентир считать полётом в городе',variable=self.var_urban_drone).pack(anchor='w',pady=4)
        self.var_tracking_enabled = tk.BooleanVar(value=self.config.tracking.enabled)
        ttk.Checkbutton(movement, text="Наследовать тип цели из свежего однозначного сообщения того же канала",
                        variable=self.var_tracking_enabled).pack(anchor="w", pady=4)
        tk.Label(movement, text="Короткое «на район» связывается только со свежим сообщением этого канала. "
                 "При нескольких типах контекст не наследуется. Сообщения о нескольких целях не снимают прежнюю зону автоматически.",
                 bg=BG_MAIN, fg=TEXT_MAIN, justify="left", wraplength=980).pack(anchor="w", pady=8)
        for key, label in [("context_seconds", "Окно контекста, с"), ("movement_hold_seconds", "Выдержка прежней зоны, с")]:
            row=tk.Frame(movement,bg=BG_MAIN); row.pack(fill="x",pady=4)
            tk.Label(row,text=label,bg=BG_MAIN,fg=TEXT_MAIN).pack(side="left")
            entry=ttk.Entry(row,width=10); entry.insert(0,str(getattr(self.config.tracking,key)))
            entry.pack(side="left",padx=8); self.tracking_inputs[key]=entry
        self.movement_actions={"Сохранить прежний срок": "keep", "Заменить прежнюю зону": "replace", "Выдержка прежней зоны": "shorten"}
        self.var_movement_action=tk.StringVar(value=next(k for k,v in self.movement_actions.items() if v==self.config.tracking.movement_action))
        ttk.Combobox(movement,textvariable=self.var_movement_action,values=list(self.movement_actions),state="readonly",width=35).pack(anchor="w",pady=6)
        for key,label in [("movement_keywords","Признаки движения"),("uncertain_keywords","Признаки неопределённости"),("continuing_keywords","Признаки продолжения атаки / других целей")]:
            tk.Label(movement,text=label,bg=BG_MAIN,fg=TEXT_ACCENT).pack(anchor="w",pady=(10,3))
            entry=DictionaryEditor(movement); entry.insert(0,", ".join(getattr(self.config.tracking,key)))
            entry.pack(fill="x"); self.tracking_inputs[key]=entry
        endings=tk.Frame(book,bg=BG_MAIN)
        book.add(endings,text="Окончание угрозы")
        tk.Label(endings,text="Отбой, прилёт, уничтожение и потеря фиксации — разные условия. "
                 "Каждое действует только на наблюдения своего канала. API и другие каналы сохраняются. "
                 "Без однозначной связи с целью снятие не выполняется.",
                 bg=BG_MAIN,fg=TEXT_MAIN,wraplength=980,justify="left").pack(anchor="w",padx=10,pady=6)
        self.end_actions={"Снять": "clear", "Выдержка": "shorten", "Без снятия": "ignore"}
        self.condition_inputs=[]
        toolbar=tk.Frame(endings,bg=BG_MAIN);toolbar.pack(fill="x")
        self.conditions_body=self._scroll_body(endings)
        ttk.Button(toolbar,text="Добавить условие",command=lambda:self._add_end_condition(EndCondition(name="Новое условие"))).pack(anchor="w",padx=10,pady=3)
        for condition in self.config.end_conditions:
            self._add_end_condition(condition)

    def _add_end_condition(self, condition):
        card=tk.LabelFrame(self.conditions_body,text="Условие окончания",bg=BG_CARD,fg=TEXT_ACCENT,padx=8,pady=6)
        card.pack(fill="x",padx=6,pady=6)
        values={}
        row=tk.Frame(card,bg=BG_CARD);row.pack(fill="x",pady=3)
        values["enabled"]=tk.BooleanVar(value=condition.enabled)
        ttk.Checkbutton(row,text="Включено",variable=values["enabled"]).pack(side="left")
        values["name"]=ttk.Entry(row,width=28);values["name"].insert(0,condition.name);values["name"].pack(side="left",padx=6)
        values["action"]=tk.StringVar(value=next(k for k,v in self.end_actions.items() if v==condition.action))
        ttk.Combobox(row,textvariable=values["action"],values=list(self.end_actions),state="readonly",width=15).pack(side="left")
        for key,label in [("hold_seconds","Выдержка, с"),("context_seconds","Контекст, с")]:
            tk.Label(row,text=label,bg=BG_CARD,fg=TEXT_MAIN).pack(side="left",padx=4)
            values[key]=ttk.Entry(row,width=7);values[key].insert(0,str(getattr(condition,key)));values[key].pack(side="left")
        tk.Label(card,text="Маркеры (через запятую):",bg=BG_CARD,fg=TEXT_MAIN).pack(anchor="w")
        values["keywords"]=DictionaryEditor(card);values["keywords"].insert(0,", ".join(condition.keywords));values["keywords"].pack(fill="x",pady=3)
        row=tk.Frame(card,bg=BG_CARD);row.pack(fill="x",pady=3)
        tk.Label(row,text="Источники (Telegram, @канал):",bg=BG_CARD,fg=TEXT_MAIN).pack(side="left")
        values["sources"]=ttk.Entry(row,width=45);values["sources"].insert(0,", ".join("Telegram" if v=="telegram:*" else "@"+v.split(":",1)[1] for v in condition.sources));values["sources"].pack(side="left",padx=6)
        values["types"]={}
        for key,label in THREAT_TYPES.items():
            var=tk.BooleanVar(value=key in condition.threat_types);values["types"][key]=var
            ttk.Checkbutton(row,text=label,variable=var).pack(side="left",padx=4)
        row=tk.Frame(card,bg=BG_CARD);row.pack(fill="x",pady=3)
        for key,label in [("allow_without_location","Разрешить связь по контексту без названия района"),("require_confirmed","Не применять при предварительном/неподтверждённом сообщении")]:
            var=tk.BooleanVar(value=getattr(condition,key));values[key]=var
            ttk.Checkbutton(row,text=label,variable=var).pack(side="left",padx=3)
        values["regional_clear"] = tk.BooleanVar(value=condition.regional_clear)
        ttk.Checkbutton(card, text="Региональный отбой: разрешить снятие всех наблюдений своего канала в указанной зоне",
                        variable=values["regional_clear"]).pack(anchor="w", pady=3)
        tk.Label(card,text="Исключения (отрицание падения / ПВО):",bg=BG_CARD,fg=TEXT_MAIN).pack(anchor="w")
        values["reject_keywords"]=DictionaryEditor(card)
        values["reject_keywords"].insert(0,", ".join(condition.reject_keywords))
        values["reject_keywords"].pack(fill="x",pady=3)
        values['global_without_location']=tk.BooleanVar(value=condition.global_without_location)
        ttk.Checkbutton(card,text='Явный общий отбой канала: разрешить снятие без названия города',
                        variable=values['global_without_location']).pack(anchor='w',pady=3)
        values['require_context_type']=tk.BooleanVar(value=condition.require_context_type)
        ttk.Checkbutton(card,text='Применять только к свежему однозначному типу из контекста канала',variable=values['require_context_type']).pack(anchor='w',pady=3)
        tk.Label(card,text='Дополнительные обязательные маркеры (хотя бы один; пусто — без условия):',bg=BG_CARD,fg=TEXT_MAIN).pack(anchor='w')
        values['required_keywords']=DictionaryEditor(card)
        values['required_keywords'].insert(0,', '.join(condition.required_keywords))
        values['required_keywords'].pack(fill='x',pady=3)
        values['allow_continuing']=tk.BooleanVar(value=condition.allow_continuing)
        ttk.Checkbutton(card,text='Разрешить завершение прежней группы при сообщении о новых пусках',variable=values['allow_continuing']).pack(anchor='w',pady=3)
        self.condition_inputs.append(values)
        def remove():
            self.condition_inputs.remove(values)
            card.destroy()
        ttk.Button(card,text="Удалить условие",command=remove).pack(anchor="e")

    def _save_heuristics(self):
        self.config.tracking.generic_target_type=next(k for k in ("rocket","drone") if THREAT_TYPES[k]==self.var_generic_type.get())
        self.config.tracking.enabled=self.var_tracking_enabled.get()
        self.config.tracking.generic_city_level={'По обычным правилам':0,'Низкая':1,'Высокая':2,'Критическая':4}[self.var_generic_city_level.get()]
        self.config.tracking.generic_city_requires_reply_context=self.var_generic_reply.get()
        self.config.tracking.urban_direction_drone_is_city=self.var_urban_drone.get()
        self.config.tracking.movement_action=self.movement_actions[self.var_movement_action.get()]
        for key,entry in self.tracking_inputs.items():
            value=entry.get().strip()
            setattr(self.config.tracking,key,int(value) if key.endswith("seconds") else [k.strip().lower() for k in value.split(",") if k.strip()])
        self.config.end_conditions=[]
        for inputs in self.condition_inputs:
            self.config.end_conditions.append(EndCondition(
                name=inputs["name"].get().strip(),enabled=inputs["enabled"].get(),
                keywords=[k.strip().lower() for k in inputs["keywords"].get().split(",") if k.strip()],
                action=self.end_actions[inputs["action"].get()],hold_seconds=int(inputs["hold_seconds"].get()),
                context_seconds=int(inputs["context_seconds"].get()),
                sources=self._parse_sources(inputs["sources"].get()),
                threat_types=[k for k,v in inputs["types"].items() if v.get()],
                allow_without_location=inputs["allow_without_location"].get(),require_confirmed=inputs["require_confirmed"].get(),regional_clear=inputs["regional_clear"].get(),
                global_without_location=inputs["global_without_location"].get(),
                require_context_type=inputs["require_context_type"].get(),
                required_keywords=[k.strip().lower() for k in inputs["required_keywords"].get().split(",") if k.strip()],
                allow_continuing=inputs["allow_continuing"].get(),
                reject_keywords=[k.strip().lower() for k in inputs["reject_keywords"].get().split(",") if k.strip()]))
