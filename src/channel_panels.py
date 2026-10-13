"""Shared read-only channel diagnostics for live and archive views."""
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from src.threat_composition import level_name
from src.threat_models import THREAT_TYPES


class ChannelPanels(ttk.Frame):
    def __init__(self, parent, time_zone=None):
        super().__init__(parent)
        self.panels = {}
        self.time_zone = time_zone
        self.chat_signatures = {}
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    def render(self, states):
        for channel in list(self.panels):
            if channel not in states:
                self.panels.pop(channel)[0].destroy()
        for index, (channel, state) in enumerate(states.items()):
            if channel not in self.panels:
                card = ttk.LabelFrame(self, text='@' + channel, padding=8)
                summary = tk.Text(card, height=5, wrap='word', bg='#20252c', fg='#dde3eb')
                summary.pack(fill='x')
                chat_box = ttk.Frame(card)
                chat_box.pack(fill='both', expand=True, pady=(6, 0))
                chat = tk.Text(chat_box, height=10, wrap='word', bg='#131820', fg='#dde3eb')
                scroll = ttk.Scrollbar(chat_box, command=chat.yview)
                chat.configure(yscrollcommand=scroll.set)
                scroll.pack(side='right', fill='y')
                chat.pack(fill='both', expand=True)
                chat.tag_configure('time', foreground='#93c5fd')
                chat.tag_configure('change', foreground='#fde68a')
                self.panels[channel] = (card, summary, chat)
            card, summary, chat = self.panels[channel]
            card.grid(row=index // 2, column=index % 2, sticky='nsew', padx=4, pady=4)
            health = state.get('health', {})
            connection = 'онлайн' if health.get('ok') else 'нет связи / ожидание данных'
            lines = ['Источник: ' + connection, 'Уровень канала: ' + level_name(state['level_code']),
                     'Типы: ' + (', '.join(THREAT_TYPES[k] for k in state['types']) or 'нет активных дополнений')]
            if state['raises_level']:
                lines.append('Повышает уровень относительно API')
            if state['adds_types']:
                lines.append('Добавляет типы: ' + ', '.join(THREAT_TYPES[k] for k in state['adds_types']))
            for track in state['tracks']:
                lines.append(THREAT_TYPES[track['threat_type']] + ': пуск ' + ('да' if track.get('launch_detected') else 'не указан')
                    + '; направление ' + track.get('direction', 'Не указано') + '; приближение '
                    + track.get('proximity', 'Не определено') + '; ' + track['reaction']
                    + f" (ещё {track['remaining_seconds']} с)")
            summary_position = summary.yview()[0]
            summary.configure(state='normal')
            summary.delete('1.0', 'end')
            summary.insert('end', '\n'.join(lines))
            summary.configure(state='disabled')
            summary.yview_moveto(summary_position)
            signature = repr((state['messages'], state['changes']))
            if self.chat_signatures.get(channel) == signature:
                continue
            self.chat_signatures[channel] = signature
            chat_position = chat.yview()[0]
            chat.configure(state='normal')
            chat.delete('1.0', 'end')
            timeline = [(item['timestamp'], 'message', item) for item in state['messages']]
            timeline += [(item['timestamp'], 'change', item) for item in state['changes']]
            for stamp, kind, item in sorted(timeline, key=lambda entry: entry[0], reverse=True)[:100]:
                chat.insert('end', datetime.fromtimestamp(stamp, self.time_zone).strftime('%d.%m %H:%M:%S') + ' ', 'time')
                if kind == 'change':
                    chat.insert('end', item['summary'] + '\n\n', 'change')
                else:
                    chat.insert('end', '[' + item.get('event_id', '') + '] ' + item['text'] + '\n')
                    chat.insert('end', 'Пуск: ' + ('да' if item.get('launch_detected') else 'не указан')
                                + '; ' + item.get('direction', 'Не указано') + '; '
                                + item.get('proximity', 'Не определено') + '\n')
                    chat.insert('end', 'Реакция: ' + item.get('outcome', '') + '\n\n')
            if not timeline:
                chat.insert('end', 'Ожидание ключевых сообщений этого канала')
            chat.configure(state='disabled')
            chat.yview_moveto(chat_position)


