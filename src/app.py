import tkinter as tk
from tkinter import ttk, messagebox
import queue
import time
import socket
from datetime import datetime

from src.config import AppConfig
from src.modbus_worker import ModbusWorker
from src.ui_theme import (
    setup_ttk_styles, LedIndicator, WordBitsWidget,
    BG_MAIN, BG_CARD, BG_CARD_LIGHT, BG_INPUT, BORDER_COLOR,
    TEXT_MAIN, TEXT_MUTED, TEXT_ACCENT,
    COLOR_PRIMARY, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER,
    FONT_TITLE, FONT_SUBTITLE, FONT_REGULAR, FONT_BOLD, FONT_MONO, FONT_VALUE_BIG
)

class ModbusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Modbus TCP Gateway — Schneider M221 (%MW0 / %MW1)")
        self.geometry("980x760")
        self.minsize(860, 680)
        self.configure(bg=BG_MAIN)

        # Конфигурация и воркер
        self.config = AppConfig.load()
        self.event_queue = queue.Queue()
        self.worker = ModbusWorker(self.config, self.event_queue)

        # Переменные интерфейса
        self._init_variables()

        # Настройка стилей
        setup_ttk_styles()

        # Построение интерфейса
        self._build_ui()

        # Привязка закрытия окна
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Запуск цикла обработки событий от воркера
        self.after(50, self._process_events)

    def _init_variables(self):
        # Сеть
        self.var_host = tk.StringVar(value=self.config.host)
        self.var_port = tk.StringVar(value=str(self.config.port))
        self.var_unit_id = tk.StringVar(value=str(self.config.unit_id))
        self.var_poll_ms = tk.StringVar(value=str(self.config.poll_interval_ms))
        self.var_timeout = tk.StringVar(value=str(self.config.timeout))
        self.var_auto_reconnect = tk.BooleanVar(value=self.config.auto_reconnect)

        # Регистры
        self.var_write_addr = tk.StringVar(value=str(self.config.write_reg_address))
        self.var_read_addr = tk.StringVar(value=str(self.config.read_reg_address))
        self.var_write_addr.trace_add("write", self._on_reg_addrs_changed)
        self.var_read_addr.trace_add("write", self._on_reg_addrs_changed)

        # Запись
        self.var_write_val_dec = tk.StringVar(value=str(self.config.last_write_value))
        self.var_write_val_hex = tk.StringVar(value=f"0x{self.config.last_write_value:04X}")
        self.var_cyclic_write = tk.BooleanVar(value=self.config.cyclic_write)
        self.var_write_on_change = tk.BooleanVar(value=self.config.write_on_change)

        # Чтение
        self.var_read_dec_u = tk.StringVar(value="—")
        self.var_read_dec_s = tk.StringVar(value="—")
        self.var_read_hex = tk.StringVar(value="0x0000")
        self.var_read_bin = tk.StringVar(value="0000 0000 0000 0000")
        self.var_read_time = tk.StringVar(value="Ожидание данных...")

        # Статистика
        self.var_status_text = tk.StringVar(value="Отключено")
        self.var_stats_text = tk.StringVar(value="Запросов: 0 | Ошибок: 0 | Задержка: 0.0 мс")
        self.var_autoscroll = tk.BooleanVar(value=True)

        self._updating_write_inputs = False
        self._last_sent_val = -1

    def _build_ui(self):
        # Главный контейнер
        main_frame = tk.Frame(self, bg=BG_MAIN, padx=14, pady=10)
        main_frame.pack(fill="both", expand=True)

        # 1. Верхняя панель (Header)
        self._build_header(main_frame)

        # 2. Сетевая панель (Network Settings)
        self._build_network_panel(main_frame)

        # 3. Основная рабочая зона (2 колонки: Запись %MW и Чтение %MW)
        work_frame = tk.Frame(main_frame, bg=BG_MAIN)
        work_frame.pack(fill="x", pady=(10, 8))
        work_frame.columnconfigure(0, weight=1)
        work_frame.columnconfigure(1, weight=1)

        self._build_write_card(work_frame)
        self._build_read_card(work_frame)

        # 4. Журнал событий (Log)
        self._build_log_panel(main_frame)

    def _build_header(self, parent):
        header_frame = tk.Frame(parent, bg=BG_MAIN)
        header_frame.pack(fill="x", pady=(0, 8))

        # Левая часть - Заголовок
        left = tk.Frame(header_frame, bg=BG_MAIN)
        left.pack(side="left")

        title_lbl = tk.Label(
            left,
            text="ПЛК TM221 — Шлюз Modbus TCP",
            font=FONT_TITLE,
            fg=TEXT_MAIN,
            bg=BG_MAIN
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            left,
            text="Двусторонний обмен словами данных %MW0 (ПК → ПЛК) и %MW1 (ПЛК → ПК)",
            font=FONT_REGULAR,
            fg=TEXT_MUTED,
            bg=BG_MAIN
        )
        sub_lbl.pack(anchor="w")

        # Правая часть - Индикатор состояния
        right = tk.Frame(header_frame, bg=BG_MAIN)
        right.pack(side="right")

        self.led_indicator = LedIndicator(right, size=20)
        self.led_indicator.pack(side="left", padx=(0, 8))

        status_lbl = tk.Label(
            right,
            textvariable=self.var_status_text,
            font=FONT_BOLD,
            fg=COLOR_DANGER,
            bg=BG_MAIN
        )
        status_lbl.pack(side="left")
        self.lbl_status = status_lbl

    def _build_network_panel(self, parent):
        card = tk.LabelFrame(
            parent,
            text="  Сетевая конфигурация Modbus TCP  ",
            bg=BG_CARD,
            fg=TEXT_ACCENT,
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=8
        )
        card.pack(fill="x", pady=(0, 6))

        row1 = tk.Frame(card, bg=BG_CARD)
        row1.pack(fill="x", pady=2)

        # IP адрес
        tk.Label(row1, text="IP-адрес:", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        self.entry_host = ttk.Entry(row1, textvariable=self.var_host, width=15)
        self.entry_host.pack(side="left", padx=(0, 14))

        # Порт
        tk.Label(row1, text="Порт:", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        self.entry_port = ttk.Entry(row1, textvariable=self.var_port, width=7)
        self.entry_port.pack(side="left", padx=(0, 14))

        # Slave ID
        tk.Label(row1, text="Unit ID:", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        self.entry_unit_id = ttk.Entry(row1, textvariable=self.var_unit_id, width=5)
        self.entry_unit_id.pack(side="left", padx=(0, 14))

        # Период опроса
        tk.Label(row1, text="Опрос (мс):", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        self.entry_poll = ttk.Entry(row1, textvariable=self.var_poll_ms, width=6)
        self.entry_poll.pack(side="left", padx=(0, 14))

        # Авто-переподключение
        chk_recon = ttk.Checkbutton(row1, text="Авто-повтор", variable=self.var_auto_reconnect)
        chk_recon.pack(side="left", padx=(0, 14))

        # Кнопки управления
        self.btn_connect = ttk.Button(
            row1,
            text="Подключить",
            style="Success.TButton",
            command=self._toggle_connection
        )
        self.btn_connect.pack(side="right", padx=(6, 0))

        btn_ping = ttk.Button(
            row1,
            text="Проверить пинг",
            style="Outline.TButton",
            command=self._test_connection_quick
        )
        btn_ping.pack(side="right", padx=(6, 0))

    def _build_write_card(self, parent):
        card = tk.LabelFrame(
            parent,
            text="  ПЕРЕДАЧА В ПЛК (ПК  ➔  ПЛК)  ",
            bg=BG_CARD,
            fg="#60a5fa",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=8
        )
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # Строка 1: Регистр назначения
        reg_row = tk.Frame(card, bg=BG_CARD)
        reg_row.pack(fill="x", pady=(0, 6))

        tk.Label(reg_row, text="Регистр ПЛК:", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        tk.Label(reg_row, text="%MW", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_ACCENT).pack(side="left")
        self.entry_w_addr = ttk.Entry(reg_row, textvariable=self.var_write_addr, width=6)
        self.entry_w_addr.pack(side="left", padx=(2, 10))

        chk_cyclic = ttk.Checkbutton(
            reg_row,
            text="Циклически",
            variable=self.var_cyclic_write,
            command=self._on_cyclic_write_toggle
        )
        chk_cyclic.pack(side="right")

        chk_change = ttk.Checkbutton(
            reg_row,
            text="При изменении",
            variable=self.var_write_on_change
        )
        chk_change.pack(side="right", padx=(0, 8))

        # Строка 2: Ввод значения DEC и HEX
        val_row = tk.Frame(card, bg=BG_CARD)
        val_row.pack(fill="x", pady=(4, 6))

        tk.Label(val_row, text="DEC (0..65535):", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        self.entry_w_dec = ttk.Entry(val_row, textvariable=self.var_write_val_dec, width=10, font=FONT_MONO)
        self.entry_w_dec.pack(side="left", padx=(0, 10))
        self.entry_w_dec.bind("<KeyRelease>", self._on_dec_input_change)

        tk.Label(val_row, text="HEX:", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        self.entry_w_hex = ttk.Entry(val_row, textvariable=self.var_write_val_hex, width=9, font=FONT_MONO)
        self.entry_w_hex.pack(side="left", padx=(0, 10))
        self.entry_w_hex.bind("<KeyRelease>", self._on_hex_input_change)

        # Кнопка ручной отправки
        self.btn_send = ttk.Button(
            val_row,
            text="Отправить ➔",
            style="TButton",
            command=self._send_write_value
        )
        self.btn_send.pack(side="right")

        # Строка 3: Интерактивная панель битов 0..15
        tk.Label(card, text="Битовое слово (клик для переключения бит 15..0):", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w", pady=(4, 2))
        self.write_bits_widget = WordBitsWidget(card, editable=True, on_change=self._on_bits_widget_changed)
        self.write_bits_widget.pack(fill="x", pady=(0, 6))

        # Строка 4: Быстрые действия
        act_row = tk.Frame(card, bg=BG_CARD)
        act_row.pack(fill="x", pady=2)

        ttk.Button(act_row, text="0x0000", style="Outline.TButton", width=7, command=lambda: self._set_write_val(0)).pack(side="left", padx=2)
        ttk.Button(act_row, text="0xFFFF", style="Outline.TButton", width=7, command=lambda: self._set_write_val(0xFFFF)).pack(side="left", padx=2)
        ttk.Button(act_row, text="+1", style="Outline.TButton", width=4, command=lambda: self._adjust_write_val(1)).pack(side="left", padx=2)
        ttk.Button(act_row, text="-1", style="Outline.TButton", width=4, command=lambda: self._adjust_write_val(-1)).pack(side="left", padx=2)

        # Статус отправки
        self.lbl_write_status = tk.Label(act_row, text="Готово к отправке", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED)
        self.lbl_write_status.pack(side="right", padx=4)

    def _build_read_card(self, parent):
        card = tk.LabelFrame(
            parent,
            text="  ПРИЕМ ИЗ ПЛК (ПЛК  ➔  ПК)  ",
            bg=BG_CARD,
            fg="#34d399",
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=8
        )
        card.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        # Строка 1: Регистр источника
        reg_row = tk.Frame(card, bg=BG_CARD)
        reg_row.pack(fill="x", pady=(0, 4))

        tk.Label(reg_row, text="Регистр ПЛК:", font=FONT_BOLD, bg=BG_CARD, fg=TEXT_MAIN).pack(side="left", padx=(0, 4))
        tk.Label(reg_row, text="%MW", font=FONT_BOLD, bg=BG_CARD, fg=COLOR_SUCCESS).pack(side="left")
        self.entry_r_addr = ttk.Entry(reg_row, textvariable=self.var_read_addr, width=6)
        self.entry_r_addr.pack(side="left", padx=(2, 10))

        self.lbl_read_stamp = tk.Label(reg_row, textvariable=self.var_read_time, font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED)
        self.lbl_read_stamp.pack(side="right")

        # Строка 2: Крупное табло значения
        display_frame = tk.Frame(card, bg=BG_INPUT, bd=1, relief="solid", padx=8, pady=4)
        display_frame.pack(fill="x", pady=(2, 6))

        d_top = tk.Frame(display_frame, bg=BG_INPUT)
        d_top.pack(fill="x")

        # Большое значение DEC
        lbl_dec = tk.Label(
            d_top,
            textvariable=self.var_read_dec_u,
            font=FONT_VALUE_BIG,
            fg=COLOR_SUCCESS,
            bg=BG_INPUT
        )
        lbl_dec.pack(side="left", padx=4)

        d_details = tk.Frame(d_top, bg=BG_INPUT)
        d_details.pack(side="right", padx=4)

        tk.Label(d_details, text="HEX:", font=FONT_BOLD, fg=TEXT_MUTED, bg=BG_INPUT).grid(row=0, column=0, sticky="e", padx=4)
        tk.Label(d_details, textvariable=self.var_read_hex, font=FONT_MONO, fg=TEXT_MAIN, bg=BG_INPUT).grid(row=0, column=1, sticky="w")

        tk.Label(d_details, text="Signed:", font=FONT_BOLD, fg=TEXT_MUTED, bg=BG_INPUT).grid(row=1, column=0, sticky="e", padx=4)
        tk.Label(d_details, textvariable=self.var_read_dec_s, font=FONT_MONO, fg=TEXT_MAIN, bg=BG_INPUT).grid(row=1, column=1, sticky="w")

        # Двоичное представление текстом
        d_bin = tk.Frame(display_frame, bg=BG_INPUT)
        d_bin.pack(fill="x", pady=(2, 0))
        tk.Label(d_bin, text="BIN:", font=FONT_BOLD, fg=TEXT_MUTED, bg=BG_INPUT).pack(side="left", padx=4)
        tk.Label(d_bin, textvariable=self.var_read_bin, font=FONT_MONO, fg=TEXT_ACCENT, bg=BG_INPUT).pack(side="left")

        # Строка 3: Индикация бит 0..15 (лампы)
        tk.Label(card, text="Битовое состояние (индикаторы бит 15..0):", font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="w", pady=(4, 2))
        self.read_bits_widget = WordBitsWidget(card, editable=False)
        self.read_bits_widget.pack(fill="x", pady=(0, 4))

    def _build_log_panel(self, parent):
        log_frame = tk.LabelFrame(
            parent,
            text="  Журнал обмена и статистика  ",
            bg=BG_CARD,
            fg=TEXT_MAIN,
            font=FONT_SUBTITLE,
            bd=1,
            relief="solid",
            padx=10,
            pady=6
        )
        log_frame.pack(fill="both", expand=True)

        # Текстовое поле для лога
        text_container = tk.Frame(log_frame, bg=BG_CARD)
        text_container.pack(fill="both", expand=True)

        self.txt_log = tk.Text(
            text_container,
            height=8,
            bg=BG_INPUT,
            fg=TEXT_MAIN,
            font=FONT_MONO,
            relief="flat",
            bd=0,
            padx=6,
            pady=4,
            wrap="none"
        )
        scrollbar_y = ttk.Scrollbar(text_container, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=scrollbar_y.set)

        self.txt_log.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")

        # Теги стилей для лога
        self.txt_log.tag_config("info", foreground=TEXT_MAIN)
        self.txt_log.tag_config("success", foreground=COLOR_SUCCESS)
        self.txt_log.tag_config("error", foreground=COLOR_DANGER)
        self.txt_log.tag_config("warn", foreground=COLOR_WARNING)
        self.txt_log.tag_config("time", foreground=TEXT_MUTED)

        # Подвал лога: статистика и кнопки
        bottom_row = tk.Frame(log_frame, bg=BG_CARD)
        bottom_row.pack(fill="x", pady=(6, 0))

        lbl_stats = tk.Label(bottom_row, textvariable=self.var_stats_text, font=FONT_REGULAR, bg=BG_CARD, fg=TEXT_MUTED)
        lbl_stats.pack(side="left")

        ttk.Button(bottom_row, text="Очистить лог", style="Outline.TButton", command=self._clear_log).pack(side="right", padx=(4, 0))
        ttk.Checkbutton(bottom_row, text="Автопрокрутка", variable=self.var_autoscroll).pack(side="right", padx=(4, 8))

    # --- Обработка ввода значений записи ---

    def _on_reg_addrs_changed(self, *args):
        try:
            self.config.write_reg_address = int(self.var_write_addr.get().strip())
        except ValueError:
            pass
        try:
            self.config.read_reg_address = int(self.var_read_addr.get().strip())
        except ValueError:
            pass

    def _on_dec_input_change(self, event=None):
        if self._updating_write_inputs:
            return
        val_str = self.var_write_val_dec.get().strip()
        try:
            val = int(val_str)
            if 0 <= val <= 65535:
                self._update_write_views(val, source="dec")
                if self.var_write_on_change.get() and val != self._last_sent_val and self.worker.is_connected():
                    self._send_write_value()
        except ValueError:
            pass

    def _on_hex_input_change(self, event=None):
        if self._updating_write_inputs:
            return
        hex_str = self.var_write_val_hex.get().strip()
        try:
            val = int(hex_str, 16)
            if 0 <= val <= 65535:
                self._update_write_views(val, source="hex")
                if self.var_write_on_change.get() and val != self._last_sent_val and self.worker.is_connected():
                    self._send_write_value()
        except ValueError:
            pass

    def _on_bits_widget_changed(self, new_val: int):
        self._update_write_views(new_val, source="bits")
        if self.var_write_on_change.get() and new_val != self._last_sent_val and self.worker.is_connected():
            self._send_write_value()

    def _set_write_val(self, val: int):
        self._update_write_views(val & 0xFFFF)
        if self.var_write_on_change.get() and self.worker.is_connected():
            self._send_write_value()

    def _adjust_write_val(self, delta: int):
        try:
            curr = int(self.var_write_val_dec.get())
        except ValueError:
            curr = 0
        new_val = (curr + delta) & 0xFFFF
        self._set_write_val(new_val)

    def _update_write_views(self, val: int, source: str = "all"):
        self._updating_write_inputs = True
        val = val & 0xFFFF
        if source != "dec":
            self.var_write_val_dec.set(str(val))
        if source != "hex":
            self.var_write_val_hex.set(f"0x{val:04X}")
        if source != "bits":
            self.write_bits_widget.set_value(val)
        self.worker.current_write_val = val
        self._updating_write_inputs = False

    def _on_cyclic_write_toggle(self):
        enabled = self.var_cyclic_write.get()
        try:
            val = int(self.var_write_val_dec.get())
        except ValueError:
            val = 0
        self.worker.set_cyclic_write(enabled, val)
        mode_text = "включена" if enabled else "выключена"
        self._log(f"Циклическая запись {mode_text}", tag="info")

    def _send_write_value(self):
        try:
            val = int(self.var_write_val_dec.get())
            if not (0 <= val <= 65535):
                raise ValueError()
        except ValueError:
            messagebox.showwarning("Ошибка ввода", "Введите число от 0 до 65535.")
            return

        try:
            target_addr = int(self.var_write_addr.get().strip())
        except ValueError:
            target_addr = 0

        self._last_sent_val = val
        self.worker.queue_write(val, target_addr)
        self.lbl_write_status.config(text=f"Отправка: {val} (0x{val:04X})...", fg=TEXT_ACCENT)

    # --- Управление соединением ---

    def _toggle_connection(self):
        if self.worker.is_connected() or (self.worker._thread and self.worker._thread.is_alive()):
            # Отключение
            self.worker.stop()
            self.btn_connect.config(text="Подключить", style="Success.TButton")
            self._set_inputs_state(True)
            self._log("Отключение по запросу пользователя.", tag="info")
        else:
            # Применение настроек и запуск
            if not self._apply_settings():
                return
            self._set_inputs_state(False)
            self.btn_connect.config(text="Отключить", style="Danger.TButton")
            self.worker.start()

    def _apply_settings(self) -> bool:
        host = self.var_host.get().strip()
        if not host:
            messagebox.showerror("Ошибка", "Укажите IP-адрес контроллера.")
            return False

        try:
            port = int(self.var_port.get().strip())
            unit_id = int(self.var_unit_id.get().strip())
            poll_ms = int(self.var_poll_ms.get().strip())
            timeout = float(self.var_timeout.get().strip())
            w_addr = int(self.var_write_addr.get().strip())
            r_addr = int(self.var_read_addr.get().strip())
        except ValueError:
            messagebox.showerror("Ошибка", "Проверьте числовые параметры (порт, Unit ID, период, адреса).")
            return False

        self.config.host = host
        self.config.port = port
        self.config.unit_id = unit_id
        self.config.poll_interval_ms = poll_ms
        self.config.timeout = timeout
        self.config.auto_reconnect = self.var_auto_reconnect.get()
        self.config.write_reg_address = w_addr
        self.config.read_reg_address = r_addr
        self.config.cyclic_write = self.var_cyclic_write.get()
        self.config.write_on_change = self.var_write_on_change.get()
        try:
            self.config.last_write_value = int(self.var_write_val_dec.get())
        except ValueError:
            self.config.last_write_value = 0

        self.config.save()
        return True

    def _set_inputs_state(self, enabled: bool):
        st = "normal" if enabled else "disabled"
        self.entry_host.config(state=st)
        self.entry_port.config(state=st)
        self.entry_unit_id.config(state=st)
        self.entry_poll.config(state=st)

    def _test_connection_quick(self):
        host = self.var_host.get().strip()
        try:
            port = int(self.var_port.get().strip())
        except ValueError:
            port = 502

        self._log(f"Проверка сетевого сокета {host}:{port}...", tag="info")
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((host, port), timeout=2.0)
            s.close()
            dt = (time.perf_counter() - t0) * 1000
            self._log(f"Соединение успешно! Порт {port} открыт на {host} (время отклика: {dt:.1f} мс)", tag="success")
            messagebox.showinfo("Проверка связи", f"Контроллер доступен!\nIP: {host}:{port}\nОтклик сокета: {dt:.1f} мс")
        except Exception as e:
            self._log(f"Сбой соединения с {host}:{port}: {e}", tag="error")
            messagebox.showerror("Проверка связи", f"Не удалось подключиться к {host}:{port}\nОшибка: {e}")

    # --- Обработка сообщений из очереди воркера ---

    def _process_events(self):
        try:
            while True:
                item = self.event_queue.get_nowait()
                ev_type = item.get("type")
                data = item.get("data", {})

                if ev_type == "status":
                    state = data.get("state")
                    msg = data.get("message")
                    self.led_indicator.set_state(state)
                    if state == "connected":
                        self.lbl_status.config(text="На связи", fg=COLOR_SUCCESS)
                        self.var_status_text.set("На связи")
                        self._log(msg, tag="success")
                    elif state == "connecting":
                        self.lbl_status.config(text="Подключение...", fg=COLOR_WARNING)
                        self.var_status_text.set("Подключение...")
                        self._log(msg, tag="warn")
                    else:
                        self.lbl_status.config(text="Отключено", fg=COLOR_DANGER)
                        self.var_status_text.set("Отключено")
                        self._log(msg, tag="error")

                elif ev_type == "read_ok":
                    val = data.get("value", 0)
                    addr = data.get("address", 1)
                    lat = data.get("latency_ms", 0)
                    now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                    # Обновляем табло
                    self.var_read_dec_u.set(str(val))
                    signed_val = val if val < 32768 else val - 65536
                    self.var_read_dec_s.set(str(signed_val))
                    self.var_read_hex.set(f"0x{val:04X}")
                    
                    bin_raw = f"{val:016b}"
                    bin_formatted = f"{bin_raw[0:4]} {bin_raw[4:8]} {bin_raw[8:12]} {bin_raw[12:16]}"
                    self.var_read_bin.set(bin_formatted)
                    self.var_read_time.set(f"Обновлено: {now_str} ({lat:.1f} мс)")

                    self.read_bits_widget.set_value(val)

                elif ev_type == "write_ok":
                    val = data.get("value", 0)
                    addr = data.get("address", 0)
                    lat = data.get("latency_ms", 0)
                    self.lbl_write_status.config(
                        text=f"Записано: %MW{addr} = {val} ({lat:.1f} мс)",
                        fg=COLOR_SUCCESS
                    )

                elif ev_type == "error":
                    msg = data.get("msg", "")
                    self._log(msg, tag="error")
                    self.lbl_write_status.config(text="Ошибка отправки", fg=COLOR_DANGER)

                elif ev_type == "stats":
                    tot = data.get("total", 0)
                    fail = data.get("failed", 0)
                    lat = data.get("latency_ms", 0)
                    self.var_stats_text.set(f"Запросов: {tot} | Ошибок: {fail} | Задержка RTT: {lat:.1f} мс")

        except queue.Empty:
            pass

        # Планируем следующий вызов
        self.after(40, self._process_events)

    def _log(self, message: str, tag: str = "info"):
        t_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        line = f"[{t_str}] {message}\n"
        self.txt_log.insert("end", f"[{t_str}] ", "time")
        self.txt_log.insert("end", f"{message}\n", tag)
        if self.var_autoscroll.get():
            self.txt_log.see("end")

    def _clear_log(self):
        self.txt_log.delete("1.0", "end")

    def _on_close(self):
        self.worker.stop()
        self.destroy()
