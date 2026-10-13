"""Independent live channel evaluator, GUI, graphs and publisher. Never uses a PLC."""
import json
import queue
import threading
import time
import uuid
import traceback
import urllib.request
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from src.channel_tuning import ChannelProfile
from src.channel_debug_model import analyze_messages,fetch_public_history,context_lookback
from src.archive_replay import ArchiveReplay,KYIV_ARCHIVE
from src.threat_evaluator import ThreatEvaluator
from src.threat_models import THREAT_TYPES
from src.channel_levels import collapse_level,level_name
from src.channel_debugger import ThreatPlot
from src.threat_config_dialog import ThreatConfigDialog
from src.analyzer_transport import DailyLog,transport_settings,shared_token,KINDS,ROOT
from src.runtime_support import single_instance,heartbeat,request_launch,launch_request_id

class LiveEvaluator(ThreatEvaluator):
    def _init_tg_reader(self):self.tg_reader=None

class AnalyzerAudit:
    def __init__(self,log):self.log=log
    def log_diagnostic(self,title,text):self.log.write('diagnostic',title=title,text=text)
    def log_telegram_event(self,event,reaction):self.log.write('reaction',message=event,level=reaction['level_code'],reason=reaction['reason'])

class AnalyzerRuntime:
    def __init__(self,profile,events=None,publish=None):
        self.profile=ChannelProfile(profile);self.events=events or queue.Queue();self.lock=threading.RLock()
        manifest=json.loads((self.profile.directory/'profile.json').read_text(encoding='utf-8-sig'))
        self.publish=manifest.get('publish_to_main',True) if publish is None else publish
        if type(self.publish) is not bool:raise ValueError('Invalid publish mode')
        self.log=DailyLog('analyzer_'+self.profile.channel)
        self.settings=transport_settings() if self.publish else {'publish_interval_s':2}
        self.token=shared_token() if self.publish else None
        if self.publish and self.profile.channel not in self.settings['channels']:raise ValueError('Channel is not enabled for publishing')
        self.session=str(uuid.uuid4());self.sequence=0;self.stop_event=threading.Event();self.paused=False;self.requests_paused=False;self.next_poll=0;self.rebuild_pending=False
        self.rows=[];self.points=[];self.snapshot={};self.bootstrapped=False;self.cursor=None;self.seen={}
        self.connection='ожидание основного приложения' if self.publish else 'НАБЛЮДЕНИЕ — передача в основное приложение отключена';self.source_error='';self.source_online=False
        self.evaluator=self._make_evaluator();self.threads=[];self.generation=0
    def _make_evaluator(self):
        cfg=self.profile.load_config();cfg.schedule.enabled=False
        evaluator=LiveEvaluator(cfg);evaluator.audit_logger=AnalyzerAudit(self.log)
        return evaluator
    def start(self):
        for target in ((self._monitor,self._publisher) if self.publish else (self._monitor,)):
            thread=threading.Thread(target=self._run_worker,args=(target,),daemon=True);thread.start();self.threads.append(thread)
    def _run_worker(self,target):
        try:target()
        except BaseException:
            try:self.log.write('worker_exception',worker=target.__name__,traceback=traceback.format_exc())
            except OSError:pass
    def stop(self):
        self.stop_event.set()
        for thread in self.threads:thread.join(timeout=2)
    def pause(self,value=True):
        with self.lock:self.paused=value;self._update()
        self.log.write('pause',paused=value)
    def pause_requests(self,value=True):
        with self.lock:
            self.requests_paused=bool(value);self.generation+=1;self.source_online=False;self.next_poll=0
            self.source_error='Чтение Telegram приостановлено' if value else ''
            if not value:self.rebuild_pending=True;self.cursor=None;self.seen={}
            self._update()
        self.log.write('requests_pause',paused=bool(value))
    def reload(self):
        with self.lock:
            self.generation+=1;self.source_online=False;self.evaluator=self._make_evaluator();self.bootstrapped=False;self.cursor=None;self.seen={}
            self.rows=[];self.points=[];self._update()
        self.log.write('profile_reload')
    def _update(self):
        self.evaluator._refresh();state=self.evaluator.status;now=time.time()
        levels={k:0 for k in KINDS};expires={k:0 for k in KINDS};evidence={}
        if not self.paused and self.bootstrapped:
            for track in self.evaluator._composition.previous_tracks.values():
                kind=track['threat_type'];value=collapse_level(track['level_code'])
                if value and track['expires_at']>now:
                    if value>levels[kind]:expires[kind]=track['expires_at']
                    elif value==levels[kind]:expires[kind]=max(expires[kind],track['expires_at'])
                    if value>=levels[kind]:
                        levels[kind]=value;evidence[kind]=dict(message_id=track['event_id'],text=track['text'][:8000])
        reason='; '.join(THREAT_TYPES[k]+': '+e['text'] for k,e in evidence.items())[:10000]
        if self.paused:reason='Пауза настройки: дополнения временно сняты'
        elif not self.bootstrapped:reason='Инициализация истории; данные ещё не готовы'
        elif not reason:reason='Действующих угроз нет'
        self.snapshot=dict(version=1,channel=self.profile.channel,session=self.session,sequence=self.sequence,
            sent_at=now,levels=levels,expires=expires,evidence=evidence,reason=reason,
            source_online=self.source_online and now-self.evaluator._tg_health.get(self.profile.channel,{}).get('last_success',0)<30,paused=self.paused)
        point=dict(timestamp=now,levels=deepcopy(levels),level=max(levels.values()))
        if not self.points or self.points[-1]['levels']!=levels:self.points.append(point);self.log.write('state',**point,reason=reason)
        self.points=[p for p in self.points if p['timestamp']>=now-86400][-10000:]
        self.events.put(dict(snapshot=deepcopy(self.snapshot),connection=self.connection,source_error=self.source_error,
                             rows=deepcopy(self.rows),points=deepcopy(self.points),now=now))
    def _monitor(self):
        self.next_poll=0
        while not self.stop_event.is_set():
            try:
                now=time.time()
                with self.lock:paused=self.paused or self.requests_paused;cfg=deepcopy(self.evaluator.config);boot=self.bootstrapped and not self.rebuild_pending;cursor=self.cursor;generation=self.generation
                if not paused and now>=self.next_poll:
                    self.next_poll=now+5
                    messages,complete=fetch_public_history(self.profile.channel,
                        (cursor-1 if boot and cursor else now-context_lookback(cfg)),now+1,self.stop_event,
                        lambda s:self.events.put(dict(progress=s)))
                    if not complete:raise ValueError('Не подтверждено полное покрытие последних сообщений')
                    with self.lock:
                        if self.paused or self.requests_paused or generation!=self.generation:continue
                        if not self.bootstrapped or self.rebuild_pending:
                            result=analyze_messages(messages,self.profile.channel,now-context_lookback(cfg),now,cfg,self.stop_event,lambda s:None) if messages else SimpleNamespace(rows=[],points=[])
                            replay=ArchiveReplay(messages,cfg) if messages else None
                            if replay:
                                while replay.index<len(replay.messages):replay.step()
                                replay.advance(now)
                                for attr in ('_observations','_channel_context','_channel_external_context','_end_watermarks','_channel_events','_composition','_last_resolution','_last_resolution_time','_tg_last_msg_time'):
                                    setattr(self.evaluator,attr,deepcopy(getattr(replay.evaluator,attr)))
                            self.rows=result.rows[-300:];self.points=result.points[-10000:]
                            self.bootstrapped=True;self.rebuild_pending=False
                            for row in self.rows:self.log.write('bootstrap_reaction',message=row['message'],levels=row['levels'],reason=row['reason'])
                            for message in messages:self.log.write('input',message=message,bootstrap=True)
                        else:
                            for message in messages:
                                if self.seen.get(message['id'])==message['text']:continue
                                self.log.write('input',message=message)
                                self.evaluator._handle_telegram_message(message);self.evaluator._refresh()
                                events=self.evaluator._channel_events.get(self.profile.channel,[])
                                event=next((e for e in events if e.event_id==message['id']),None)
                                row=dict(message=message,levels={k:0 for k in KINDS},event=None,reason=self.evaluator.status.reason)
                                for track in self.evaluator._composition.previous_tracks.values():
                                    row['levels'][track['threat_type']]=max(row['levels'][track['threat_type']],collapse_level(track['level_code']))
                                row['level']=max(row['levels'].values());row['event']=dict(outcome=event.outcome) if event else None
                                self.rows=[r for r in self.rows if r['message']['id']!=message['id']]+[row];self.rows=self.rows[-300:]
                        for message in messages:self.seen[message['id']]=message['text']
                        self.cursor=now-60
                        if len(self.seen)>3000:self.seen={r['message']['id']:r['message']['text'] for r in self.rows}
                        self.source_online=True;self.source_error=''
                        self.evaluator._tg_health[self.profile.channel]=dict(ok=True,last_success=time.time(),error='')
                with self.lock:self._update()
            except InterruptedError:break
            except Exception as error:
                with self.lock:
                    changed=str(error)!=self.source_error;self.source_error=str(error);self.source_online=False
                    self.evaluator._tg_health[self.profile.channel]=dict(ok=False,last_success=0,error=str(error))
                    try:self._update()
                    except Exception:pass
                if changed:
                    try:self.log.write('source_error',error=str(error))
                    except OSError:pass
            self.stop_event.wait(1)
    def _publisher(self):
        if not self.publish:return
        while not self.stop_event.is_set():
            with self.lock:
                if not self.snapshot:
                    self.stop_event.wait(.1);continue
                self._update();self.sequence+=1;packet=deepcopy(self.snapshot);packet['sequence']=self.sequence;packet['sent_at']=time.time()
                for kind in KINDS:
                    if packet['expires'].get(kind,0)<=packet['sent_at']:packet['levels'][kind]=0
            try:
                request=urllib.request.Request(f"http://127.0.0.1:{self.settings['port']}/v1/state",
                    data=json.dumps(packet).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
                with urllib.request.urlopen(request,timeout=3) as response:response.read()
                connection='на связи с основным приложением'
            except Exception as error:connection='нет связи с основным приложением: '+str(error)
            with self.lock:
                if connection!=self.connection:
                    self.connection=connection
                    try:self.log.write('main_connection',status=connection)
                    except OSError:pass
            self.stop_event.wait(self.settings['publish_interval_s'])

class AnalyzerWindow(tk.Tk):
    def __init__(self,profile=ROOT/'profiles/monitor1654',autostart=True,publish=None):
        super().__init__();self.title('Seren — независимый анализатор @'+ChannelProfile(profile).channel);self.geometry(f'{min(1160,self.winfo_screenwidth()-60)}x{min(900,self.winfo_screenheight()-80)}')
        from src.background_common import enabled
        if autostart and enabled():
            from src.background_views import ViewAnalyzerRuntime
            self.runtime=ViewAnalyzerRuntime(profile,publish=publish)
            self.title(self.title()+' — интерфейс фонового процесса')
        else:self.runtime=AnalyzerRuntime(profile,publish=publish)
        self.status=tk.StringVar(value='Инициализация');self.level=tk.StringVar(value='Ожидание данных')
        toolbar=ttk.Frame(self);toolbar.pack(fill='x',padx=8,pady=6)
        self.pause_button=ttk.Button(toolbar,text='Пауза / настройка',command=self.toggle_pause);self.pause_button.pack(side='left')
        self.requests_button=ttk.Button(toolbar,text='Приостановить чтение Telegram',command=self.toggle_requests)
        self.requests_button.pack(side='left',padx=6)
        ttk.Button(toolbar,text='Словари и правила',command=self.edit).pack(side='left',padx=6)
        ttk.Button(toolbar,text='Перечитать профиль',command=self.runtime.reload).pack(side='left')
        ttk.Button(toolbar,text='Архив / критерии',command=self.open_debugger).pack(side='left',padx=6)
        self.restart_button=None
        if hasattr(self.runtime,'restart'):
            restart_bar=ttk.Frame(self);restart_bar.pack(fill='x',padx=8)
            self.restart_button=ttk.Button(restart_bar,text='Перезапустить фоновый анализатор',command=self.restart_background)
            self.restart_button.pack(side='left')
        ttk.Label(self,textvariable=self.level,font=('Segoe UI',17,'bold')).pack(anchor='w',padx=10)
        ttk.Label(self,textvariable=self.status,wraplength=1100).pack(anchor='w',padx=10,pady=6)
        self.reason=tk.Text(self,height=5,wrap='word');self.reason.pack(fill='x',padx=8)
        table_frame=ttk.Frame(self);table_frame.pack(fill='both',expand=True,padx=8,pady=6)
        self.table=ttk.Treeview(table_frame,columns=('time','level','types','text'),show='headings',height=12)
        for key,label,width in [('time','Время',90),('level','Уровень',110),('types','Типы',160),('text','Сообщение',700)]:
            self.table.heading(key,text=label);self.table.column(key,width=width)
        scroll=ttk.Scrollbar(table_frame,orient='vertical',command=self.table.yview);scroll.pack(side='right',fill='y')
        self.table.configure(yscrollcommand=scroll.set);self.table.pack(fill='both',expand=True);self.table.bind('<<TreeviewSelect>>',self.select)
        self.detail=tk.Text(self,height=4,wrap='word');self.detail.pack(fill='x',padx=8)
        self.plot=ThreatPlot(self,self.select_index);self.plot.pack(fill='both',expand=True,padx=8,pady=6)
        self.rows=[];self.row_signature=None;self.autostart=autostart;self.protocol('WM_DELETE_WINDOW',self.close)
        if autostart:self.runtime.start()
        self.last_activation=launch_request_id(self.runtime.profile.channel)
        if autostart:self.after(150,self.show_window)
        self._last_gui_error=None;self._last_gui_error_time=0
        self.after(250,self.pump)
        if autostart:self.after(500,self._heartbeat_tick)
    def show_window(self):
        # Explicit remapping also shows Tk after a hidden Windows startup launch.
        self.withdraw();self.update_idletasks();self.deiconify();self.lift();self.focus_force()
    def toggle_pause(self):
        self.runtime.pause(not self.runtime.paused);self.pause_button.configure(text='Продолжить' if self.runtime.paused else 'Пауза / настройка')
    def toggle_requests(self):
        self.runtime.pause_requests(not self.runtime.requests_paused)
        self.requests_button.configure(text='Возобновить чтение Telegram' if self.runtime.requests_paused else 'Приостановить чтение Telegram')
    def edit(self):
        self.runtime.pause(True);self.pause_button.configure(text='Продолжить')
        def saved(config):self.runtime.profile.save_config(config);self.runtime.reload()
        ThreatConfigDialog(self,self.runtime.profile.load_config(),saved,persist=False,channel_only=True)
    def open_debugger(self):
        subprocess.Popen([sys.executable,'-m','src.channel_debugger','--profile',str(self.runtime.profile.directory)],cwd=ROOT)
    def report_callback_exception(self,exc_type,exc_value,tb):
        self._record_gui_error(''.join(traceback.format_exception(exc_type,exc_value,tb)))
    def _record_gui_error(self,detail):
        now=time.monotonic()
        if detail!=self._last_gui_error or now-self._last_gui_error_time>=30:
            self._last_gui_error=detail;self._last_gui_error_time=now
            try:self.runtime.log.write('gui_exception',traceback=detail)
            except OSError:pass
    def _heartbeat_tick(self):
        try:heartbeat(self.runtime.profile.channel)
        except OSError as error:self._record_gui_error('Heartbeat file error: '+str(error))
        finally:self.after(1000,self._heartbeat_tick)
    def restart_background(self):
        try:
            self.runtime.restart()
            self.restart_button.configure(state='disabled')
            self.level.set('Перезапуск анализатора · ожидание актуального состояния')
            self.status.set('Запрошен перезапуск фонового анализатора; основной модуль продолжает работу.')
        except OSError as error:
            self.status.set('Не удалось отправить команду перезапуска: '+str(error))

    def pump(self):
        if self.restart_button is not None:
            self.restart_button.configure(state='disabled' if self.runtime.restarting else 'normal')
        try:self._render_update()
        except Exception:
            self._record_gui_error(traceback.format_exc())
            self.status.set('Ошибка обновления окна; повтор через секунду. Подробности в журнале.')
        finally:self.after(1000,self.pump)
    def _render_update(self):
        activation=launch_request_id(self.runtime.profile.channel)
        if activation and activation!=self.last_activation:
            self.last_activation=activation;self.show_window()
        if self.autostart and not self.runtime.stop_event.is_set() and any(not t.is_alive() for t in self.runtime.threads):
            import os
            try:self.runtime.log.write('worker_failed',workers=[t.name for t in self.runtime.threads if not t.is_alive()])
            except OSError:pass
            os._exit(1) # Supervisor restarts a failed worker as a fresh independent process.
        latest=None
        while not self.runtime.events.empty():
            item=self.runtime.events.get()
            if 'snapshot' in item:latest=item
            elif 'progress' in item:self.status.set(item['progress'])
        if latest:
            packet=latest['snapshot'];self.level.set(level_name(max(packet['levels'].values()))+' — '+(', '.join(THREAT_TYPES[k] for k,v in packet['levels'].items() if v) or 'нет типов'))
            self.status.set(('ПАУЗА · ' if packet['paused'] else '')+'Telegram (опрос ~5 с): '+('чтение приостановлено' if self.runtime.requests_paused else 'онлайн' if packet['source_online'] else 'нет связи')+' · '+latest['connection']+'\n'+latest['source_error'])
            self.reason.delete('1.0','end');self.reason.insert('end',packet['reason'])
            rows=latest['rows'];signature=tuple((r['message']['id'],r['message']['text'],tuple(r['levels'].items()),r['reason']) for r in rows)
            if signature!=self.row_signature:
                self.rows=rows;self.table.delete(*self.table.get_children())
                for i,r in enumerate(rows):self.table.insert('','end',iid=str(i),values=(datetime.fromtimestamp(r['message']['timestamp'],KYIV_ARCHIVE).strftime('%H:%M:%S'),level_name(r['level']),', '.join(THREAT_TYPES[k] for k,v in r['levels'].items() if v),r['message']['text']))
                self.row_signature=signature
                if rows:self.table.see(str(len(rows)-1))
            points=latest['points'] or [dict(timestamp=latest['now'],levels=packet['levels'])]
            model=SimpleNamespace(points=points,rows=rows,start=max(points[0]['timestamp'],latest['now']-21600),end=latest['now']+1)
            old_view=self.plot.view;old_model=self.plot.model
            self.plot.set_model(model)
            if old_view and old_model and old_view!=(old_model.start,old_model.end):
                self.plot.view=old_view;self.plot.draw()
            if self.table.selection():self.select()
    def select_index(self,index):
        if 0<=index<len(self.rows):self.table.selection_set(str(index));self.table.see(str(index));self.select()
    def select(self,event=None):
        if not self.table.selection():return
        row=self.rows[int(self.table.selection()[0])];self.plot.marker=row;self.plot.draw()
        self.detail.delete('1.0','end');self.detail.insert('end',row['message']['text']+'\n'+((row.get('event') or {}).get('outcome') or row['reason']))
    def close(self):self.runtime.stop();self.destroy()

def main():
    import argparse
    parser=argparse.ArgumentParser(description='Independent live Telegram analyzer')
    parser.add_argument('--profile',type=Path,default=ROOT/'profiles/monitor1654')
    parser.add_argument('--no-publish',action='store_true')
    args=parser.parse_args()
    channel=ChannelProfile(args.profile).channel
    if not single_instance(channel):
        request_launch(channel);return
    AnalyzerWindow(args.profile,publish=False if args.no_publish else None).mainloop()
if __name__=='__main__':main()
