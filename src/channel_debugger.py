"""Channel algorithm debugger: chronological messages linked to coloured level charts."""
from bisect import bisect_left, bisect_right
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
import csv
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from src.archive_replay import KYIV_ARCHIVE, load_archives
from src.channel_debug_model import COLORS, analyze_messages, channel_name, date_window, fetch_public_history, context_lookback
from src.threat_models import ThreatSystemConfig, THREAT_TYPES
from src.threat_config_dialog import ThreatConfigDialog
from src.channel_levels import level_name, LEVEL_NAMES
from src.channel_tuning import ChannelProfile, evaluate_criteria
from dataclasses import asdict


class ThreatPlot(tk.Canvas):
    def __init__(self, parent, selected):
        super().__init__(parent, height=340, bg='#111827', highlightthickness=0)
        self.model = None
        self.marker = None
        self.select_message = selected
        self.view = None
        self.series = {}
        self.bind('<Configure>', lambda event: self.draw())
        self.bind('<Button-1>', self.click)
        self.bind('<MouseWheel>', self.zoom)

    def set_model(self, model):
        self.model = model
        self.view = (model.start, model.end)
        self.marker = None
        self.series = {}
        for kind in THREAT_TYPES:
            transitions = []
            for point in model.points:
                value = point['levels'][kind]
                if not transitions or transitions[-1][1] != value:
                    transitions.append((point['timestamp'], value))
            self.series[kind] = ([item[0] for item in transitions], [item[1] for item in transitions])
        self.draw()

    def reset_zoom(self):
        if self.model:
            self.view = (self.model.start, self.model.end)
            self.draw()

    def geometry(self):
        return 150, 35, max(220, self.winfo_width()-20), max(100, self.winfo_height()-40)

    def draw(self):
        self.delete('all')
        if not self.model:
            self.create_text(20, 25, anchor='w', fill='#cbd5e1', text='После анализа здесь появятся графики уровней угроз')
            return
        left, top, right, bottom = self.geometry()
        start, end = self.view
        span = max(1, end-start)
        rows = list(THREAT_TYPES)
        panel_height = (bottom-top)/4
        for index, kind in enumerate(rows):
            y0 = top + panel_height*index
            y1 = y0 + panel_height - 10
            self.create_text(8, (y0+y1)/2, text=THREAT_TYPES[kind], anchor='w', fill=COLORS[kind], font=('Segoe UI', 10, 'bold'))
            def x(stamp):
                return left + (stamp-start)/span*(right-left)
            def y(level):
                return y1 - list(LEVEL_NAMES).index(level)/3*(y1-y0)
            for level in LEVEL_NAMES:
                self.create_line(left, y(level), right, y(level), fill='#263244')
                self.create_text(left-10, y(level), text=LEVEL_NAMES[level], anchor='e', fill='#94a3b8', font=('Segoe UI', 8))
            times, values = self.series[kind]
            first = bisect_right(times, start)
            last = bisect_right(times, end)
            current = values[first-1] if first else 0
            coordinates = [left, y(current)]
            for stamp, value in zip(times[first:last], values[first:last]):
                if value == current:
                    continue
                coordinates.extend((x(stamp), y(current), x(stamp), y(value)))
                current = value
            coordinates.extend((right, y(current)))
            self.create_line(*coordinates, fill=COLORS[kind], width=2)
            if self.marker:
                marker_x = x(self.marker['message']['timestamp'])
                if left <= marker_x <= right:
                    self.create_line(marker_x, y0, marker_x, y1, fill='#f8fafc', dash=(4, 3))
                    marker_y = y(self.marker['levels'][kind])
                    self.create_oval(marker_x-4, marker_y-4, marker_x+4, marker_y+4, fill=COLORS[kind], outline='white')
        for fraction in (0, .25, .5, .75, 1):
            stamp = start+span*fraction
            position = left+(right-left)*fraction
            self.create_text(position, bottom+18, text=datetime.fromtimestamp(stamp, KYIV_ARCHIVE).strftime('%d.%m %H:%M'), fill='#cbd5e1', font=('Segoe UI', 9))
        self.create_text(left, 13, anchor='w', text='X: время · Y: нет тревоги, низкая, высокая, критическая', fill='#cbd5e1')

    def click(self, event):
        if not self.model or not self.model.rows:
            return
        left, _, right, _ = self.geometry()
        stamp = self.view[0] + min(1, max(0, (event.x-left)/max(1, right-left)))*(self.view[1]-self.view[0])
        times = [row['message']['timestamp'] for row in self.model.rows]
        index = bisect_left(times, stamp)
        candidates = [item for item in (index-1, index) if 0 <= item < len(times)]
        self.select_message(min(candidates, key=lambda item: abs(times[item]-stamp)))

    def zoom(self, event):
        if not self.model:
            return
        left, _, right, _ = self.geometry()
        fraction = min(1, max(0, (event.x-left)/max(1, right-left)))
        begin, end = self.view
        focus = begin+(end-begin)*fraction
        span = min(self.model.end-self.model.start, max(60, (end-begin)*(0.7 if event.delta > 0 else 1.4)))
        begin = max(self.model.start, min(focus-span*fraction, self.model.end-span))
        self.view = (begin, begin+span)
        self.draw()


class ChannelDebugger(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Seren — отладка алгоритма Telegram-канала · без ПЛК')
        self.geometry('1250x940')
        self.minsize(950, 700)
        self.config_data = ThreatSystemConfig.load()
        self.profile = None
        self.archive_paths = []
        self.result = None
        self.last_selection = None
        self.history_cache = None
        self.worker = None
        self.cancel = threading.Event()
        self.events = queue.Queue()
        self.closed = False
        controls = ttk.Frame(self, padding=8)
        controls.pack(fill='x')
        self.channel = tk.StringVar(value=self.config_data.telegram_channels[0] if self.config_data.telegram_channels else '')
        archive_files = sorted((Path(__file__).resolve().parents[1]/'logs').glob('telegram_*_*.jsonl'))
        defaults = __import__('re').findall(r'\d{4}-\d{2}-\d{2}', archive_files[0].stem) if archive_files else []
        self.start_date = tk.StringVar(value=defaults[0] if defaults else (datetime.now(KYIV_ARCHIVE)-timedelta(days=7)).strftime('%Y-%m-%d'))
        self.end_date = tk.StringVar(value=datetime.now(KYIV_ARCHIVE).strftime('%Y-%m-%d'))
        self.provider = tk.StringVar(value='Локальные архивы')
        for label, variable, width in [('Канал', self.channel, 23), ('Начало YYYY-MM-DD', self.start_date, 13), ('Конец YYYY-MM-DD', self.end_date, 13)]:
            ttk.Label(controls, text=label).pack(side='left', padx=4)
            ttk.Entry(controls, textvariable=variable, width=width).pack(side='left')
        ttk.Combobox(controls, textvariable=self.provider, values=['Локальные архивы', 'Telegram: публичная история'], state='readonly', width=26).pack(side='left', padx=8)
        buttons = ttk.Frame(self, padding=(8, 0, 8, 4))
        buttons.pack(fill='x')
        self.analyze_button = ttk.Button(buttons, text='Анализировать', command=self.analyze)
        self.analyze_button.pack(side='left')
        ttk.Button(buttons, text='Отменить', command=self.cancel.set).pack(side='left', padx=4)
        ttk.Button(buttons, text='Открыть архив', command=self.choose_archives).pack(side='left', padx=4)
        ttk.Button(buttons, text='Словари и правила', command=self.edit_dictionaries).pack(side='left', padx=4)
        profile_button = ttk.Menubutton(buttons, text='Профиль / файлы')
        profile_menu = tk.Menu(profile_button, tearoff=False)
        for label, command in [('Открыть профиль канала', self.open_profile),
                               ('Создать профиль канала', self.create_profile),
                               ('Сохранить настройки в профиль', self.save_profile),
                               ('Перечитать профиль с диска', self.reload_profile)]:
            profile_menu.add_command(label=label, command=command)
        profile_menu.add_separator()
        profile_menu.add_command(label='Сохранить словари отдельно', command=self.save_config)
        profile_menu.add_command(label='Загрузить словари отдельно', command=self.load_config)
        profile_button.configure(menu=profile_menu)
        profile_button.pack(side='left', padx=4)
        criteria_button = ttk.Menubutton(buttons, text='Критерии')
        criteria_menu = tk.Menu(criteria_button, tearoff=False)
        criteria_menu.add_command(label='Задать ожидаемые уровни выбранного сообщения', command=self.annotate_message)
        criteria_menu.add_command(label='Проверить все критерии на текущем результате', command=self.check_criteria)
        criteria_button.configure(menu=criteria_menu)
        criteria_button.pack(side='left', padx=4)
        ttk.Button(buttons, text='Экспорт CSV', command=self.export).pack(side='right')
        self.status = tk.StringVar(value='Выберите канал и даты. Расчёт использует анализатор основного приложения; подключений к ПЛК нет.')
        ttk.Label(self, textvariable=self.status, wraplength=1200).pack(fill='x', padx=12, pady=4)
        split = ttk.Panedwindow(self, orient='vertical')
        split.pack(fill='both', expand=True, padx=8, pady=4)
        table_frame = ttk.Frame(split)
        self.table = ttk.Treeview(table_frame, columns=('time', 'level', 'types', 'reaction', 'text'), show='headings', height=11, selectmode='browse')
        for name, label, width in [('time', 'Время', 140), ('level', 'Итог', 70), ('types', 'Действующие типы', 190), ('reaction', 'Реакция сообщения', 260), ('text', 'Сообщение', 420)]:
            self.table.heading(name, text=label)
            self.table.column(name, width=width, minwidth=55, stretch=name in ('text', 'reaction'))
        table_scroll = ttk.Scrollbar(table_frame, command=self.table.yview)
        self.table.configure(yscrollcommand=table_scroll.set)
        table_scroll.pack(side='right', fill='y')
        self.table.pack(fill='both', expand=True)
        self.table.bind('<<TreeviewSelect>>', self.on_select)
        split.add(table_frame, weight=3)
        detail_frame = ttk.Frame(split)
        self.details = tk.Text(detail_frame, height=9, wrap='word', bg='#20252c', fg='#e2e8f0')
        detail_scroll = ttk.Scrollbar(detail_frame, command=self.details.yview)
        self.details.configure(yscrollcommand=detail_scroll.set)
        detail_scroll.pack(side='right', fill='y')
        self.details.pack(fill='both', expand=True)
        split.add(detail_frame, weight=2)
        chart_frame = ttk.Frame(split)
        chart_tools = ttk.Frame(chart_frame)
        chart_tools.pack(fill='x')
        ttk.Label(chart_tools, text='Выбор сообщения перемещает маркер. Щелчок по графику выбирает ближайшее сообщение; колесо — масштаб.').pack(side='left')
        ttk.Button(chart_tools, text='Весь диапазон', command=lambda: self.plot.reset_zoom()).pack(side='right')
        self.plot = ThreatPlot(chart_frame, self.select_index)
        self.plot.pack(fill='both', expand=True)
        split.add(chart_frame, weight=4)
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.after(100, self.poll)

    def prepare_archive(self,paths,start,end):
        date_window(start,end)
        selected=[Path(path).resolve() for path in paths]
        if not selected or any(not path.is_file() for path in selected):raise ValueError('Архив не найден')
        self.archive_paths=[str(path) for path in selected]
        self.start_date.set(start);self.end_date.set(end);self.provider.set('Локальные архивы')
        self.history_cache=None
        self.status.set('Архив выбран; даты '+start+' — '+end)

    def choose_archives(self):
        paths = filedialog.askopenfilenames(
            title='Открыть архив сообщений Telegram',
            initialdir=str(Path(__file__).resolve().parents[1] / 'logs'),
            filetypes=[('Архивы сообщений', ('*.jsonl', '*.json', '*.csv')),
                       ('Архив JSONL', '*.jsonl'), ('Архив JSON', '*.json'),
                       ('Архив CSV', '*.csv'), ('Все файлы', '*.*')])
        if paths:
            self.archive_paths = list(paths)
            self.provider.set('Локальные архивы')
            self.status.set(f'Выбрано архивов: {len(paths)}')

    def analyze(self):
        if self.worker and self.worker.is_alive():
            return
        try:
            channel = channel_name(self.channel.get())
            if self.profile and channel != self.profile.channel:
                raise ValueError('Канал должен соответствовать открытому профилю. Откройте профиль нужного канала.')
            start, end = date_window(self.start_date.get(), self.end_date.get())
        except ValueError as error:
            messagebox.showerror('Параметры анализа', str(error))
            return
        self.cancel.clear()
        self.analyze_button.configure(state='disabled')
        self.status.set('Подготовка истории…')
        cfg = deepcopy(self.config_data)
        paths = list(self.archive_paths)
        provider = self.provider.get()
        lookback = context_lookback(cfg)
        cache_key = (channel, start, end, provider, tuple(paths), lookback)
        cached = self.history_cache
        def work():
            try:
                progress = lambda text: self.events.put(('progress', text))
                coverage = ''
                if cached and cached[0] == cache_key and provider != 'Локальные архивы':
                    messages, coverage = cached[1], cached[2]
                elif provider == 'Локальные архивы':
                    files = paths or list((Path(__file__).resolve().parents[1]/'logs').glob(f'telegram_{channel}_*.jsonl'))
                    if not files:
                        raise ValueError('Локальный архив не найден. Откройте файл или выберите публичную историю Telegram.')
                    messages = load_archives(files)
                    source_times = [item['timestamp'] for item in messages if channel_name(item['channel']) == channel]
                    coverage = ('Данные архива: ' + datetime.fromtimestamp(min(source_times), KYIV_ARCHIVE).strftime('%Y-%m-%d %H:%M') + ' — ' + datetime.fromtimestamp(max(source_times), KYIV_ARCHIVE).strftime('%Y-%m-%d %H:%M') + '; за пределами архива полнота не подтверждена.') if source_times else 'В архиве нет указанного канала.'
                else:
                    messages, complete = fetch_public_history(channel, start-lookback, end, self.cancel, progress)
                    coverage = 'Публичные страницы: достигнута начальная дата.' if complete else 'Внимание: публичная история неполная; используйте экспорт Telegram.'
                self.events.put(('cache', (cache_key, messages, coverage)))
                result = analyze_messages(messages, channel, start, end, cfg, self.cancel, progress)
                self.events.put(('result', (result, coverage)))
            except Exception as error:
                self.events.put(('error', str(error)))
        self.worker = threading.Thread(target=work, name='ChannelDebugAnalysis', daemon=True)
        self.worker.start()

    def poll(self):
        if self.closed:
            return
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'progress':
                    self.status.set(value)
                elif kind == 'cache':
                    self.history_cache = value
                elif kind == 'error':
                    self.analyze_button.configure(state='normal')
                    self.status.set(value)
                elif kind == 'result':
                    self.analyze_button.configure(state='normal')
                    self.show_result(*value)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def show_result(self, result, coverage=''):
        self.result = result
        self.last_selection = None
        self.table.delete(*self.table.get_children())
        for index, row in enumerate(result.rows):
            event = row['event']
            reaction = event['outcome'] if event else 'Не породило ключевого наблюдения'
            types = ', '.join(THREAT_TYPES[k] for k, value in row['levels'].items() if value)
            self.table.insert('', 'end', iid=str(index), values=(datetime.fromtimestamp(row['message']['timestamp'], KYIV_ARCHIVE).strftime('%d.%m %H:%M:%S'), level_name(row['level']), types or 'нет', reaction, row['message']['text'][:160]))
        self.plot.set_model(result)
        self.status.set(f'@{result.channel}: {len(result.rows)} сообщений; {result.warmup_messages} сообщений до начала для восстановления контекста. ' + coverage)
        if result.rows:
            self.select_index(0)

    def select_index(self, index):
        self.table.selection_set(str(index))
        self.table.see(str(index))
        self.on_select()

    def on_select(self, event=None):
        selected = self.table.selection()
        if not selected or not self.result:
            return
        index = int(selected[0])
        if self.last_selection == index:
            return
        self.last_selection = index
        row = self.result.rows[index]
        message = row['message']
        recognized = row['event'] or {}
        lines = [message['id'] + ' · ' + datetime.fromtimestamp(message['timestamp'], KYIV_ARCHIVE).strftime('%Y-%m-%d %H:%M:%S'),
                 message['text'], '', 'Реакция: ' + recognized.get('outcome', 'Не породило ключевого наблюдения'),
                 'Пуск: ' + ('да' if recognized.get('launch_detected') else 'не указан') + '; направление: '
                 + recognized.get('direction', 'не указано') + '; приближение: ' + recognized.get('proximity', 'не определено'),
                 'После сообщения: ' + level_name(row['level']), '', 'Вхождения слов из словарей (сами по себе не означают тревогу):']
        lines += [name + ': ' + ', '.join(words) for name, words in row['dictionary_matches'].items()]
        lines += ['', row['reason']]
        self.details.delete('1.0', 'end')
        self.details.insert('end', '\n'.join(lines))
        self.plot.marker = row
        stamp = row['message']['timestamp']
        begin, end = self.plot.view
        if not begin <= stamp <= end:
            span = end-begin
            begin = max(self.result.start, min(stamp-span/2, self.result.end-span))
            self.plot.view = (begin, begin+span)
        self.plot.draw()

    def _profile_idle(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo('Профиль', 'Сначала завершите или отмените анализ.')
            return False
        return True

    def _use_profile(self, directory):
        profile = ChannelProfile(directory)
        config = profile.load_config()
        profile.cases()
        self.profile = profile
        self.config_data = config
        self.channel.set(profile.channel)
        self.result = None
        self.last_selection = None
        self.table.delete(*self.table.get_children())
        self.details.delete('1.0', 'end')
        self.plot.model = None
        self.plot.marker = None
        self.plot.draw()
        self.title(f'Seren — отладка @{profile.channel} · профиль {profile.directory.name} · без ПЛК')
        self.status.set(f'Профиль: {profile.directory}. Настройки загружены; нажмите «Анализировать».')

    def open_profile(self):
        if not self._profile_idle():
            return
        path = filedialog.askopenfilename(initialdir=str(Path(__file__).resolve().parents[1]/'profiles'),
                                         filetypes=[('Профиль канала', 'profile.json')])
        if path:
            try:
                self._use_profile(Path(path).parent)
            except (ValueError, OSError, KeyError, TypeError) as error:
                messagebox.showerror('Профиль', str(error))

    def create_profile(self):
        if not self._profile_idle():
            return
        directory = filedialog.askdirectory(title='Выберите папку: внутри будет создан профиль с именем канала')
        if directory:
            try:
                channel = channel_name(self.channel.get())
                profile = ChannelProfile.create(Path(directory)/channel, channel, self.config_data)
                self._use_profile(profile.directory)
            except (ValueError, OSError, KeyError, TypeError) as error:
                messagebox.showerror('Профиль', str(error))

    def save_profile(self):
        if not self._profile_idle():
            return
        if not self.profile:
            messagebox.showinfo('Профиль', 'Сначала откройте или создайте профиль канала.')
            return
        try:
            self.profile.save_config(self.config_data)
            self.config_data = self.profile.load_config()
            self.status.set('Профиль сохранён. Предыдущие настройки находятся в revisions. Повторите анализ.')
        except (ValueError, OSError) as error:
            messagebox.showerror('Профиль', str(error))

    def reload_profile(self):
        if self.profile and self._profile_idle():
            try:
                self._use_profile(self.profile.directory)
            except (ValueError, OSError, KeyError, TypeError) as error:
                messagebox.showerror('Профиль', str(error))

    def check_criteria(self):
        if not self.profile or not self.result:
            messagebox.showinfo('Критерии', 'Откройте профиль и выполните анализ.')
            return
        try:
            if (asdict(self.result.config) != asdict(self.config_data)
                    or asdict(self.config_data) != asdict(self.profile.load_config())):
                raise ValueError('Сохраните текущие настройки в профиль и повторите анализ перед проверкой.')
            evaluation = evaluate_criteria(self.result, self.profile.cases())
            lines = [f"Проверено: {evaluation['checked']}; совпало: {evaluation['passed']}; ошибок: {evaluation['failed']}.",
                     evaluation['note']]
            for detail in evaluation['details']:
                if not detail['passed']:
                    selector = detail['case'].get('message_id', detail['case'].get('at'))
                    lines.append(str(selector) + ': ' + '; '.join(detail['problems']))
            self.details.delete('1.0', 'end')
            self.details.insert('end', '\n'.join(lines))
            self.status.set(lines[0])
        except (ValueError, OSError, KeyError, TypeError) as error:
            messagebox.showerror('Критерии', str(error))

    def annotate_message(self):
        selected = self.table.selection()
        if not self.profile or not self.result or not selected:
            messagebox.showinfo('Критерии', 'Откройте профиль, выполните анализ и выберите сообщение.')
            return
        row = self.result.rows[int(selected[0])]
        if self.result.channel != self.profile.channel:
            return
        try:
            previous = next((c for c in self.profile.cases() if c.get('message_id') == row['message']['id']), {})
        except (ValueError, OSError) as error:
            messagebox.showerror('Критерии', str(error))
            return
        window = tk.Toplevel(self)
        window.title('Ожидаемая реакция: ' + row['message']['id'])
        window.transient(self)
        window.grab_set()
        ttk.Label(window, text=row['message']['text'], wraplength=620).pack(fill='x', padx=12, pady=10)
        ttk.Label(window, text='Выберите требуемые уровни. Пустое поле — не проверять. Указаны состояния после сообщения.').pack(padx=12)
        fields = {}
        for key, label in [('total', 'Итог канала'), *THREAT_TYPES.items()]:
            frame = ttk.Frame(window)
            frame.pack(fill='x', padx=12, pady=3)
            ttk.Label(frame, text=label, width=24).pack(side='left')
            expected = previous.get('expected_level', '') if key == 'total' else previous.get('expected_levels', {}).get(key, '')
            variable = tk.StringVar(value=LEVEL_NAMES.get(expected, ''))
            ttk.Combobox(frame, textvariable=variable, values=['', *LEVEL_NAMES.values()], state='readonly', width=18).pack(side='left')
            current = row['level'] if key == 'total' else row['levels'][key]
            ttk.Label(frame, text=f'Сейчас: {level_name(current)}').pack(side='left', padx=10)
            fields[key] = variable
        split = tk.StringVar(value=previous.get('split', 'tuning'))
        ttk.Combobox(window, textvariable=split, values=['tuning', 'validation'], state='readonly').pack(padx=12, pady=6)
        ttk.Label(window, text='Комментарий к требованию:').pack(anchor='w', padx=12)
        note = tk.Text(window, height=3, width=70, wrap='word')
        note.pack(fill='both', expand=True, padx=12)
        note.insert('1.0', previous.get('note', ''))
        def save():
            try:
                total = fields['total'].get()
                codes={name:code for code,name in LEVEL_NAMES.items()}
                levels = {k: codes[v.get()] for k, v in fields.items() if k != 'total' and v.get() != ''}
                self.profile.set_message_case(row['message'], codes[total] if total != '' else None,
                                              levels, note.get('1.0', 'end').strip(), split.get())
                self.status.set('Критерий сохранён в ' + str(self.profile.criteria_path))
                window.destroy()
            except (ValueError, OSError) as error:
                messagebox.showerror('Критерии', str(error), parent=window)
        ttk.Button(window, text='Сохранить критерий', command=save).pack(padx=12, pady=12)

    def edit_dictionaries(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo('Анализ', 'Сначала завершите или отмените текущий анализ')
            return
        def saved(config):
            self.config_data = config
            self.status.set('Словари изменены. Нажмите «Анализировать», чтобы перестроить графики.')
        ThreatConfigDialog(self, self.config_data, saved, persist=False, channel_only=True)

    def save_config(self):
        path = filedialog.asksaveasfilename(initialfile='config_debugger.json', defaultextension='.json')
        if path:
            if Path(path).resolve() == (Path(__file__).resolve().parents[1]/'config_threats.json').resolve():
                messagebox.showerror('Словари', 'Рабочий config_threats.json защищён: сохраните эксперимент под другим именем.')
                return
            self.config_data.save(path)

    def load_config(self):
        path = filedialog.askopenfilename(filetypes=[('Конфигурация словарей', '*.json')])
        if path:
            try:
                self.config_data = ThreatSystemConfig.load(path)
                self.status.set('Словари загружены. Повторите анализ.')
            except ValueError as error:
                messagebox.showerror('Словари', str(error))

    def export(self):
        if not self.result:
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('Результаты', '*.csv')])
        if path:
            with Path(path).open('w', encoding='utf-8-sig', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=['id', 'timestamp', 'text', 'level', *THREAT_TYPES, 'reaction'])
                writer.writeheader()
                for row in self.result.rows:
                    writer.writerow(dict(id=row['message']['id'], timestamp=row['message']['timestamp'], text=row['message']['text'], level=row['level'], reaction=(row['event'] or {}).get('outcome', ''), **row['levels']))

    def close(self):
        self.closed = True
        self.cancel.set()
        self.destroy()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Архивная настройка канала без ПЛК')
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--archives',nargs='+',type=Path)
    parser.add_argument('--start')
    parser.add_argument('--end')
    parser.add_argument('--analyze',action='store_true')
    args = parser.parse_args()
    window = ChannelDebugger()
    if args.profile:
        try:
            window._use_profile(args.profile)
        except (ValueError, OSError, KeyError, TypeError) as error:
            window.close()
            parser.error(str(error))
    if args.archives or args.start or args.end:
        if not (args.archives and args.start and args.end):
            window.close();parser.error('For prepared archive use --archives, --start and --end together')
        try:window.prepare_archive(args.archives,args.start,args.end)
        except (ValueError,OSError) as error:
            window.close();parser.error(str(error))
    def show_window():
        window.withdraw();window.update_idletasks();window.deiconify();window.lift()
    window.after(150,show_window)
    if args.analyze:window.after(250,window.analyze)
    window.mainloop()
