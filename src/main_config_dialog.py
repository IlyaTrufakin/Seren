"""Main application's API rules and sound profiles; no dictionary controls."""
from copy import deepcopy
import json
import tkinter as tk
from tkinter import ttk, messagebox
from src.threat_config_dialog import ThreatConfigDialog, parse_duration_ms, parse_interval_series_ms
from src.threat_models import SEVERITIES, THREAT_TYPES
from src.ui_theme import BG_MAIN, BG_CARD, TEXT_MAIN, TEXT_MUTED, TEXT_ACCENT


class MainConfigDialog(tk.Toplevel):
    _scroll_body = ThreatConfigDialog._scroll_body
    _build_plc_tab = ThreatConfigDialog._build_plc_tab
    _build_schedule_tab = ThreatConfigDialog._build_schedule_tab

    def __init__(self, parent, current_config, on_save_callback, persist=True, path='config_main.json'):
        super().__init__(parent)
        self.config = deepcopy(current_config)
        self.on_save, self.persist, self.path = on_save_callback, persist, path
        self.title('Основное приложение — API, уровни тревог и звуковые профили')
        width = min(1120, max(700, self.winfo_screenwidth()-80))
        height = min(780, max(500, self.winfo_screenheight()-100))
        self.geometry(f'{width}x{height}')
        self.minsize(min(760,width), min(540,height))
        self.configure(bg=BG_MAIN)
        self.transient(parent)
        self.grab_set()
        footer = ttk.Frame(self, padding=10)
        footer.pack(side='bottom', fill='x')
        ttk.Button(footer, text='Сохранить настройки', command=self._save_and_close).pack(side='right')
        ttk.Button(footer, text='Отмена', command=self.destroy).pack(side='right', padx=8)
        book = ttk.Notebook(self)
        book.pack(fill='both', expand=True, padx=10, pady=10)
        self.notebook = book
        for title, builder in [('API',self._build_api), ('Уровни по API',self._build_rules),
                               ('Звуковые профили',self._build_sounds), ('ПЛК',self._build_plc_tab),
                               ('Тихий час',self._build_schedule_tab)]:
            frame = tk.Frame(book,bg=BG_MAIN)
            book.add(frame,text=title)
            builder(self._scroll_body(frame))

    def _build_api(self, body):
        self.var_enabled = tk.BooleanVar(value=self.config.enabled)
        self.var_api_enabled = tk.BooleanVar(value=self.config.alarmmap_enabled)
        ttk.Checkbutton(body,text='Обработка тревог включена',variable=self.var_enabled).pack(anchor='w',pady=6)
        ttk.Checkbutton(body,text='Получать базовый уровень от API',variable=self.var_api_enabled).pack(anchor='w',pady=6)
        ttk.Label(body,text='API задаёт базу. Независимый monitor1654 может повысить уровень и добавить тип угрозы.\nУсловия вкладки «Уровни по API» относятся к API; звук дополнения берётся из соответствующего звукового профиля.',wraplength=950).pack(anchor='w',pady=8)
        self.api_entries = {}
        for key,label in [('city_name','Название города'), ('alarmmap_key_file','Файл API-ключа'),
                          ('alarmmap_katottg','Код территории API (KATOTTG)'),
                          ('alarmmap_poll_interval_s','Интервал опроса, с'),
                          ('api_stale_seconds','Срок актуальности данных API, с'),
                          ('rocket_message_ttl_s','Срок действия ракетного сообщения, с (0 — отключено)')]:
            ttk.Label(body,text=label).pack(anchor='w',pady=(10,2))
            entry=ttk.Entry(body)
            entry.insert(0,str(getattr(self.config,key)))
            entry.pack(fill='x',padx=6)
            self.api_entries[key]=entry
        self.var_rocket_global=tk.BooleanVar(value=self.config.rocket_messages_global)
        ttk.Checkbutton(body,text='Учитывать ракетные сообщения global при действующей общей тревоге',variable=self.var_rocket_global).pack(anchor='w',pady=8)
        ttk.Label(body,text='На этом этапе используется только API. Подключение внешних анализаторов ещё не включено.',
                  wraplength=680).pack(anchor='w',pady=16)

    def _build_rules(self, body):
        ttk.Label(body,text='Выходная угроза: нет угрозы, низкая, высокая или критическая.\n'
                  'Галочками выберите входные уровни API, при которых включается соответствующее правило.\n'
                  'Общая тревога: 1–3. Уточняющая угроза КАБ, дрон или FPV: 1–2.\n'
                  'Без уточнения — общая воздушная тревога. Ракетный и дроновый типы требуют подтверждения источником.',
                  wraplength=850).pack(anchor='w',padx=6,pady=8)
        ttk.Label(body,text='Для КАБ и дронов оба условия обязательны: общий уровень И уровень уточняющей угрозы.\n'
                  'Нет угрозы — когда актуальный API не сообщает действующей тревоги.\n'
                  'Без выбранных входных уровней правило не срабатывает. При совпадении выбирается более высокая степень.').pack(anchor='w',padx=6,pady=4)
        self.rule_inputs={}
        labels={'low':'Низкая','high':'Высокая','critical':'Критическая'}
        for rule in self.config.alarm_rules:
            card=ttk.LabelFrame(body,text='Выход: '+labels[rule.severity]+' — '+('Общая воздушная тревога' if rule.threat_type=='unknown' else THREAT_TYPES[rule.threat_type]),padding=8)
            card.pack(fill='x',padx=6,pady=5)
            enabled=tk.BooleanVar(value=rule.enabled)
            ttk.Checkbutton(card,text='Правило включено',variable=enabled).pack(anchor='w')
            inputs={'enabled':enabled,'api':{}}
            groups={'rocket':[('air','Общая тревога',3)],
                    'kab':[('air','Общий уровень тревоги (И)',3),('kab-bombs','КАБ (И)',2)],
                    'drone':[('air','Общий уровень тревоги (И)',3),('fight-drones','Дрон (И)',2),('fpv-drones','FPV (И)',2)],
                    'unknown':[('air','Общая тревога',3)]}[rule.threat_type]
            if rule.threat_type=='rocket':
                ttk.Label(card,text='Условие: действующая общая тревога И свежее сообщение API rocket/ballistics для выбранной территории. Отдельного ракетного уровня API не передаёт.',wraplength=800).pack(anchor='w',pady=5)
            for kind,label,maximum in groups:
                row=ttk.Frame(card)
                row.pack(fill='x',pady=4)
                ttk.Label(row,text=label,width=24).pack(side='left')
                aliases=[kind,'fpv'] if kind=='fpv-drones' else [kind]
                current=set()
                if kind=='air' and rule.threat_type in ('kab','drone'):
                    current.update(rule.general_api_levels if rule.general_api_levels is not None else [1,2,3])
                for alias in aliases if not (kind=='air' and rule.threat_type in ('kab','drone')) else []:
                    if alias in rule.api_types:
                        current.update(rule.api_levels_by_type.get(alias,rule.api_levels))
                levels={}
                for value in range(1,maximum+1):
                    variable=tk.BooleanVar(value=value in current)
                    ttk.Checkbutton(row,text=str(value),variable=variable).pack(side='left',padx=8)
                    levels[value]=variable
                inputs['api'][kind]=levels
            self.rule_inputs[rule.id]=inputs

    def _build_sounds(self, body):
        ttk.Label(body,text='Общее время — время работы профиля с момента его включения. 0 — без ограничения.\n'
                  'По окончании звук выключается, тревога сохраняется. Смена профиля сбрасывает таймер.\n'
                  'Отсчёт выполняется основным приложением; формат %MW2..%MW6 сохраняется.',
                  wraplength=850).pack(anchor='w',padx=8,pady=8)
        self.sound_profile_entries={}
        profiles=[('safe',self.config.safe_sound),('no_link',self.config.no_link_sound)]+[(r.id,r.sound) for r in self.config.alarm_rules]
        for key,profile in profiles:
            card=ttk.LabelFrame(body,text=f'{profile.code}: {profile.name}',padding=8)
            card.pack(fill='x',padx=6,pady=5)
            entries=[]
            for column,(label,value) in enumerate([
                ('Гудков, шт',profile.beep_count),('Гудок, мс/с',profile.beep_duration_ms),
                ('Пауза, мс/с',profile.pause_between_ms),('Пауза серий, с/мс',profile.interval_series_ms),
                ('Общее время, с',profile.total_duration_s)]):
                ttk.Label(card,text=label,wraplength=125).grid(row=0,column=column,sticky='w',padx=3)
                entry=ttk.Entry(card,width=7)
                entry.insert(0,str(value))
                entry.grid(row=1,column=column,sticky='ew',padx=3,pady=3)
                card.columnconfigure(column,weight=1)
                entries.append(entry)
            self.sound_profile_entries[key]=entries

    def _save_and_close(self):
        try:
            config=deepcopy(self.config)
            config.enabled=self.var_enabled.get()
            config.alarmmap_enabled=self.var_api_enabled.get()
            for key,entry in self.api_entries.items():
                value=entry.get().strip()
                setattr(config,key,int(value) if key in ('alarmmap_poll_interval_s','api_stale_seconds','rocket_message_ttl_s') else value)
            config.rocket_messages_global=self.var_rocket_global.get()
            for rule in config.alarm_rules:
                fields=self.rule_inputs[rule.id]
                rule.enabled=fields['enabled'].get()
                rule.level_code={'low':1,'high':2,'critical':4}[rule.severity]
                if fields['api']:
                    rule.api_types=[]
                    rule.api_levels=[]
                    rule.api_levels_by_type={}
                    for kind,levels in fields['api'].items():
                        selected=[level for level,variable in levels.items() if variable.get()]
                        if kind=='air' and rule.threat_type in ('kab','drone'):
                            rule.general_api_levels=selected
                            continue
                        if selected:
                            aliases=[kind,'fpv'] if kind=='fpv-drones' else [kind]
                            for alias in aliases:
                                rule.api_types.append(alias)
                                rule.api_levels_by_type[alias]=selected
            profiles=dict(safe=config.safe_sound,no_link=config.no_link_sound,
                          **{r.id:r.sound for r in config.alarm_rules})
            for key,entries in self.sound_profile_entries.items():
                count,duration,pause,interval,total=entries
                profile=profiles[key]
                profile.beep_count=int(count.get())
                profile.beep_duration_ms=parse_duration_ms(duration.get(),min_ms=10)
                profile.pause_between_ms=parse_duration_ms(pause.get(),min_ms=0)
                profile.interval_series_ms=parse_interval_series_ms(interval.get())
                profile.total_duration_s=int(total.get())
            config.schedule.enabled=self.var_sched_enabled.get()
            config.schedule.start_time=self.entry_sched_start.get().strip()
            config.schedule.end_time=self.entry_sched_end.get().strip()
            config.auto_transfer_to_plc=self.var_auto_send.get()
            for key,entry in self.bit_entries.items():
                setattr(config.bit_mapping,key,int(entry.get()))
            for key,entry in [('bit_plc_running',self.entry_fb_run),('bit_alarm_reset',self.entry_fb_reset),
                              ('bit_analysis_switch',self.entry_fb_switch)]:
                setattr(config.plc_feedback,key,int(entry.get()))
            config.validate()
            if self.persist:
                config.save(self.path)
            self.config=config
            if self.on_save:
                self.on_save(config)
            self.destroy()
        except (ValueError,TypeError,KeyError,OSError) as error:
            messagebox.showerror('Настройки',str(error),parent=self)
