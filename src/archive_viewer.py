"""Standalone archive viewer: python -m src.archive_viewer [history.jsonl ...]."""
import argparse
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from src.archive_replay import ArchiveReplay, KYIV_ARCHIVE, load_archives
from src.threat_composition import level_name
from src.threat_models import ThreatSystemConfig, THREAT_TYPES
from src.threat_config_dialog import ThreatConfigDialog
from src.channel_panels import ChannelPanels


class ArchiveViewer(tk.Tk):
    def __init__(self, paths=None):
        super().__init__()
        self.title('Seren — архив Telegram · ТЕСТ БЕЗ ПЛК')
        self.geometry('1180x900')
        self.config_data = ThreatSystemConfig.load()
        self.messages = []
        self.engine = None
        self.running = False
        self.job = None
        top = ttk.Frame(self, padding=8)
        top.pack(fill='x')
        ttk.Label(top, text='Архивный режим: онлайн-источники и ПЛК не подключаются', foreground='#b45309').pack(anchor='w')
        buttons = ttk.Frame(top)
        buttons.pack(fill='x', pady=5)
        ttk.Button(buttons, text='Открыть архивы', command=self.choose).pack(side='left')
        ttk.Button(buttons, text='Начало', command=self.restart).pack(side='left', padx=4)
        ttk.Button(buttons, text='Шаг', command=self.step).pack(side='left', padx=4)
        self.play_button = ttk.Button(buttons, text='Воспроизвести', command=self.toggle)
        self.play_button.pack(side='left', padx=4)
        ttk.Button(buttons, text='К концу', command=lambda: self.seek(len(self.messages))).pack(side='left', padx=4)
        self.speed = tk.StringVar(value='20')
        ttk.Label(buttons, text='Сообщений/с:').pack(side='left', padx=4)
        ttk.Combobox(buttons, textvariable=self.speed, values=['1', '5', '20', '100'], width=5, state='readonly').pack(side='left')
        ttk.Button(buttons, text='Правила теста', command=self.rules).pack(side='right')
        ttk.Button(buttons, text='Экспорт CSV', command=self.export).pack(side='right', padx=4)
        scenario = ttk.Frame(top)
        scenario.pack(fill='x')
        self.with_api = tk.BooleanVar(value=False)
        self.air_level = tk.StringVar(value='2')
        self.api_type = tk.StringVar(value='Нет')
        self.type_level = tk.StringVar(value='1')
        ttk.Checkbutton(scenario, text='Задать тестовую базу API', variable=self.with_api).pack(side='left')
        for label, var, values in [('Общая тревога', self.air_level, ['Нет', '1', '2', '3']),
                                   ('Тип', self.api_type, ['Нет', 'Дроны', 'FPV', 'КАБ']),
                                   ('Уровень типа', self.type_level, ['1', '2'])]:
            ttk.Label(scenario, text=label).pack(side='left', padx=5)
            ttk.Combobox(scenario, textvariable=var, values=values, width=8, state='readonly').pack(side='left')
        ttk.Button(scenario, text='Применить и начать заново', command=self.restart).pack(side='left', padx=6)
        ttk.Label(top, text='Без истории API база не восстанавливается: тестовая база — отдельный сценарий.').pack(anchor='w', pady=3)
        progress_row = ttk.Frame(top)
        progress_row.pack(fill='x')
        self.progress = tk.StringVar(value='Откройте JSONL, JSON или CSV с архивом сообщений')
        ttk.Label(progress_row, textvariable=self.progress).pack(side='left', fill='x', expand=True)
        self.position = tk.StringVar(value='1')
        ttk.Entry(progress_row, textvariable=self.position, width=8).pack(side='left')
        ttk.Button(progress_row, text='К сообщению', command=self.seek_entry).pack(side='left', padx=4)
        ttk.Button(progress_row, text='+60 с', command=self.advance_minute).pack(side='left')
        canvas = tk.Canvas(self, highlightthickness=0)
        scroll = ttk.Scrollbar(self, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        canvas.pack(fill='both', expand=True)
        body = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=body, anchor='nw')
        body.bind('<Configure>', lambda event: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda event: canvas.itemconfigure(window, width=event.width))
        self.final_title = tk.StringVar(value='Нет данных архива')
        ttk.Label(body, textvariable=self.final_title, font=('Segoe UI', 14, 'bold')).pack(anchor='w', padx=8, pady=5)
        self.formation = tk.Text(body, height=10, wrap='word', bg='#20252c', fg='#dde3eb')
        self.formation.pack(fill='x', padx=8)
        self.channels = ChannelPanels(body, time_zone=KYIV_ARCHIVE)
        self.channels.pack(fill='both', expand=True, padx=4, pady=6)
        self.protocol('WM_DELETE_WINDOW', self.close)
        if paths:
            self.after_idle(lambda: self.load(paths))

    def baseline(self):
        if not self.with_api.get():
            return None
        entries = []
        if self.air_level.get() != 'Нет':
            entries.append(dict(type='air', level=int(self.air_level.get())))
        if self.api_type.get() != 'Нет':
            kind = {'Дроны': 'fight-drones', 'FPV': 'fpv-drones', 'КАБ': 'kab-bombs'}[self.api_type.get()]
            entries.append(dict(type=kind, level=int(self.type_level.get())))
        return entries

    def choose(self):
        paths = filedialog.askopenfilenames(
            title='Открыть архив сообщений Telegram',
            initialdir=str(Path(__file__).resolve().parents[1] / 'logs'),
            filetypes=[('Архивы сообщений', ('*.jsonl', '*.json', '*.csv')),
                       ('Архив JSONL', '*.jsonl'), ('Архив JSON', '*.json'),
                       ('Архив CSV', '*.csv'), ('Все файлы', '*.*')])
        if paths:
            self.load(paths)

    def load(self, paths):
        try:
            self.messages = load_archives(paths)
            self.restart()
        except Exception as error:
            messagebox.showerror('Архив', str(error))

    def pause(self):
        self.running = False
        if self.job:
            self.after_cancel(self.job)
            self.job = None
        self.play_button.configure(text='Воспроизвести')

    def restart(self):
        self.pause()
        if self.messages:
            self.engine = ArchiveReplay(self.messages, self.config_data, self.baseline())
            self.render()

    def render(self):
        if not self.engine:
            return
        state = self.engine.evaluator.status
        self.final_title.set(state.level_title + ' · звуковой профиль ' + str(state.sound_code) + ' (только расчёт)')
        self.progress.set(f"Сообщение {self.engine.index}/{len(self.messages)} · " + datetime.fromtimestamp(self.engine.now, KYIV_ARCHIVE).strftime('%d.%m.%Y %H:%M:%S'))
        self.formation.configure(state='normal')
        self.formation.delete('1.0', 'end')
        self.formation.insert('end', state.reason)
        self.formation.configure(state='disabled')
        self.channels.render(state.channel_states)

    def step(self):
        if self.engine:
            self.engine.step()
            self.render()

    def toggle(self):
        if self.running:
            self.pause()
        elif self.engine:
            self.running = True
            self.play_button.configure(text='Пауза')
            self.play_tick()

    def play_tick(self):
        self.job = None
        if not self.running or not self.engine:
            return
        if self.engine.step() is None:
            self.pause()
            return
        self.render()
        self.job = self.after(max(1, 1000 // int(self.speed.get())), self.play_tick)

    def seek_entry(self):
        try:
            self.seek(int(self.position.get()))
        except ValueError:
            messagebox.showerror('Переход', 'Укажите номер сообщения')

    def seek(self, target):
        if not self.engine:
            return
        self.pause()
        target = min(max(0, target), len(self.messages))
        if target < self.engine.index:
            self.engine.reset()
        self.seek_batch(target)

    def seek_batch(self, target):
        self.job = None
        for _ in range(min(40, target-self.engine.index)):
            self.engine.step()
        self.render()
        if self.engine.index < target:
            self.job = self.after(1, lambda: self.seek_batch(target))

    def advance_minute(self):
        self.pause()
        if self.engine:
            target = self.engine.now + 60
            while self.engine.index < len(self.messages) and self.messages[self.engine.index]["timestamp"] <= target:
                self.engine.step()
            self.engine.advance(target)
            self.render()

    def rules(self):
        def saved(config):
            self.config_data = config
            self.restart()
        ThreatConfigDialog(self, self.config_data, saved, persist=False)

    def export(self):
        if not self.engine:
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if path:
            self.engine.export_csv(path)

    def close(self):
        self.pause()
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description='Offline Telegram archive test, no PLC connections')
    parser.add_argument('archives', nargs='*')
    args = parser.parse_args()
    ArchiveViewer(args.archives).mainloop()


if __name__ == '__main__':
    main()
