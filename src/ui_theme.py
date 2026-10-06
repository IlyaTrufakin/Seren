import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

# Цветовая палитра в стиле современной промышленной панели (Dark Industrial Theme)
BG_MAIN = "#18181b"          # Основной фон окна
BG_CARD = "#232328"          # Фон карточек/блоков
BG_CARD_LIGHT = "#2a2b32"    # Светлый оттенок карточек
BG_INPUT = "#131316"         # Поля ввода
BORDER_COLOR = "#3b3c45"     # Рамки

TEXT_MAIN = "#f4f4f6"        # Основной текст
TEXT_MUTED = "#9ca3af"       # Второстепенный текст
TEXT_ACCENT = "#38bdf8"      # Акцентный бирюзовый

COLOR_PRIMARY = "#2563eb"    # Синий
COLOR_PRIMARY_HOVER = "#1d4ed8"
COLOR_SUCCESS = "#10b981"    # Зеленый (Норма / Связь есть)
COLOR_SUCCESS_DIM = "#064e3b"
COLOR_WARNING = "#f59e0b"    # Желтый (Ожидание)
COLOR_DANGER = "#ef4444"     # Красный (Ошибка / Отключено)
COLOR_DANGER_DIM = "#450a0a"

BIT_ON = "#10b981"           # Активный бит
BIT_OFF = "#2d2e37"          # Неактивный бит
BIT_TEXT_OFF = "#6b7280"     # Цифра неактивного бита

FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_SUBTITLE = ("Segoe UI", 10, "bold")
FONT_REGULAR = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 9, "bold")
FONT_MONO = ("Consolas", 10)
FONT_VALUE_BIG = ("Consolas", 22, "bold")
FONT_BIT = ("Consolas", 8, "bold")


def setup_ttk_styles():
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    # Базовые стили TFrame
    style.configure("TFrame", background=BG_MAIN)
    style.configure("Card.TFrame", background=BG_CARD, relief="flat")
    style.configure("CardInner.TFrame", background=BG_CARD_LIGHT, relief="flat")

    # Стили TLabel
    style.configure("TLabel", background=BG_MAIN, foreground=TEXT_MAIN, font=FONT_REGULAR)
    style.configure("Card.TLabel", background=BG_CARD, foreground=TEXT_MAIN, font=FONT_REGULAR)
    style.configure("CardTitle.TLabel", background=BG_CARD, foreground=TEXT_MAIN, font=FONT_SUBTITLE)
    style.configure("CardMuted.TLabel", background=BG_CARD, foreground=TEXT_MUTED, font=FONT_REGULAR)
    style.configure("Header.TLabel", background=BG_MAIN, foreground=TEXT_MAIN, font=FONT_TITLE)

    # Стили TEntry
    style.configure(
        "TEntry",
        fieldbackground=BG_INPUT,
        foreground=TEXT_MAIN,
        insertcolor=TEXT_MAIN,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        font=FONT_REGULAR,
        padding=4
    )

    # Стили TButton
    style.configure(
        "TButton",
        background=COLOR_PRIMARY,
        foreground=TEXT_MAIN,
        bordercolor=COLOR_PRIMARY,
        focuscolor="none",
        font=FONT_BOLD,
        padding=(10, 6)
    )
    style.map(
        "TButton",
        background=[("active", COLOR_PRIMARY_HOVER), ("disabled", "#374151")],
        foreground=[("disabled", "#6b7280")]
    )

    style.configure(
        "Success.TButton",
        background=COLOR_SUCCESS,
        foreground="#ffffff",
        font=FONT_BOLD,
        padding=(10, 6)
    )
    style.map("Success.TButton", background=[("active", "#059669")])

    style.configure(
        "Danger.TButton",
        background=COLOR_DANGER,
        foreground="#ffffff",
        font=FONT_BOLD,
        padding=(10, 6)
    )
    style.map("Danger.TButton", background=[("active", "#dc2626")])

    style.configure(
        "Outline.TButton",
        background=BG_CARD_LIGHT,
        foreground=TEXT_MAIN,
        font=FONT_REGULAR,
        padding=(8, 4)
    )
    style.map("Outline.TButton", background=[("active", "#3f404d")])

    # TCheckbutton
    style.configure(
        "TCheckbutton",
        background=BG_CARD,
        foreground=TEXT_MAIN,
        font=FONT_REGULAR,
        focuscolor="none"
    )
    style.map(
        "TCheckbutton",
        background=[("active", BG_CARD)],
        foreground=[("active", TEXT_MAIN)]
    )

    # TCombobox
    style.configure(
        "TCombobox",
        fieldbackground=BG_INPUT,
        background=BG_CARD_LIGHT,
        foreground=TEXT_MAIN,
        arrowcolor=TEXT_MAIN,
        font=FONT_REGULAR
    )


class LedIndicator(tk.Canvas):
    """Круглый индикатор состояния (LED лампа)."""
    def __init__(self, parent, size=18, **kwargs):
        super().__init__(parent, width=size, height=size, bg=BG_MAIN, highlightthickness=0, **kwargs)
        self.size = size
        self.oval_id = self.create_oval(2, 2, size - 2, size - 2, fill=COLOR_DANGER, outline="#1f2937", width=1)

    def set_color(self, color: str, outline: str = ""):
        self.itemconfig(self.oval_id, fill=color, outline=outline if outline else color)

    def set_state(self, state: str):
        if state == "connected":
            self.set_color(COLOR_SUCCESS, "#059669")
        elif state == "connecting":
            self.set_color(COLOR_WARNING, "#d97706")
        else:
            self.set_color(COLOR_DANGER, "#b91c1c")


class WordBitsWidget(tk.Frame):
    """
    16-битная интерактивная панель для отображения и (опционально) переключения битов 0..15.
    Отображает биты от 15 (старший) до 0 (младший) слева направо.
    """
    def __init__(self, parent, editable: bool = False, on_change: Optional[Callable[[int], None]] = None, **kwargs):
        super().__init__(parent, bg=BG_CARD_LIGHT, **kwargs)
        self.editable = editable
        self.on_change = on_change
        self.current_value = 0
        self.bit_buttons = []

        # Заголовок и сетка
        # Отображаем биты от 15 down to 0
        grid_frame = tk.Frame(self, bg=BG_CARD_LIGHT)
        grid_frame.pack(padx=4, pady=4, fill="x")

        for bit in range(15, -1, -1):
            col = 15 - bit
            # Добавим разделитель между байтами (после 8 бит)
            pad_r = 6 if bit == 8 else 1

            col_frame = tk.Frame(grid_frame, bg=BG_CARD_LIGHT)
            col_frame.grid(row=0, column=col, padx=(1, pad_r), pady=2)

            lbl_idx = tk.Label(col_frame, text=str(bit), font=FONT_BIT, fg=TEXT_MUTED, bg=BG_CARD_LIGHT)
            lbl_idx.pack(side="top")

            btn = tk.Button(
                col_frame,
                text="0",
                font=FONT_BIT,
                width=2,
                height=1,
                bg=BIT_OFF,
                fg=BIT_TEXT_OFF,
                activebackground=BIT_OFF,
                activeforeground=TEXT_MAIN,
                relief="flat",
                bd=0,
                cursor="hand2" if editable else "arrow",
                command=lambda b=bit: self._on_bit_clicked(b) if self.editable else None
            )
            btn.pack(side="top", pady=1)
            self.bit_buttons.append((bit, btn))

    def _on_bit_clicked(self, bit: int):
        if not self.editable:
            return
        new_val = self.current_value ^ (1 << bit)
        self.set_value(new_val)
        if self.on_change:
            self.on_change(self.current_value)

    def set_value(self, value: int):
        self.current_value = value & 0xFFFF
        for bit, btn in self.bit_buttons:
            is_set = bool(self.current_value & (1 << bit))
            if is_set:
                btn.config(text="1", bg=BIT_ON, fg="#ffffff")
            else:
                btn.config(text="0", bg=BIT_OFF, fg=BIT_TEXT_OFF)
