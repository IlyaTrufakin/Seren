"""GUI adapters: show/control existing background workers, never access PLC/API."""
import queue,threading,time
from types import SimpleNamespace
from src.background_common import read_state,send_command
from src.threat_models import ThreatStatus
from src.main_evaluator import ProfileDurationTimer
from src.channel_tuning import ChannelProfile
from src.analyzer_transport import DailyLog

class ViewModbusWorker:
    def __init__(self,config,event_queue):
        self.config=config;self.event_queue=event_queue;self._thread=None;self._stop=threading.Event();self._connected=False;self.sequence=0;self.instance=None
    def is_connected(self):return self._connected
    def start(self):
        if self._thread and self._thread.is_alive():return
        self._stop.clear();self._thread=threading.Thread(target=self.run,daemon=True);self._thread.start()
    def run(self):
        while not self._stop.wait(.5):
            state=read_state('main');self._connected=bool(state and state.get('plc_connected'))
            if not state:continue
            if state.get('instance')!=self.instance:self.sequence=0;self.instance=state.get('instance')
            for event in state['events']:
                if event['seq']>self.sequence:self.event_queue.put(dict(type=event['type'],data=event['data']));self.sequence=event['seq']
    def stop(self):self._stop.set()
    def connect(self):send_command('main','plc_connection',True);self.start()
    def disconnect(self):send_command('main','plc_connection',False)
    def update_config(self,config):self.config=config
    def set_control_snapshot(self,*args,**kwargs):pass
    def clear_control_snapshot(self):pass

class ViewMainEvaluator:
    def __init__(self,config,on_status_change=None,sound_timer=None,on_debug=None):
        self.config=config.to_engine();self.on_status_change=on_status_change;self._lock=threading.RLock();self.status=ThreatStatus();self.sound_timer=sound_timer or ProfileDurationTimer();self.api_requests_paused=False
        self._stop=threading.Event();self.audit_logger=SimpleNamespace(log_plc_confirmation=lambda *a:None)
    def start(self):threading.Thread(target=self.run,daemon=True).start()
    def run(self):
        while not self._stop.is_set():
            data=read_state('main')
            with self._lock:
                if data and data['status']:
                    self.status=ThreatStatus(**data['status']);self.api_requests_paused=data['api_requests_paused']
                else:
                    self.status=ThreatStatus();self.status.level_title='Фоновый модуль недоступен';self.status.reason='Нет актуального состояния фонового модуля. Интерфейс не управляет ПЛК.'
                state=self.status
            if self.on_status_change:self.on_status_change(state)
            self._stop.wait(.5)
    def stop(self):self._stop.set()
    def inherit_api_state(self,previous):pass
    def set_api_requests_paused(self,value):send_command('main','api_pause',bool(value));self.api_requests_paused=bool(value)
    def set_plc_analysis_switch(self,value):pass
    def reset_threat_state(self,source='Интерфейс'):
        if not source.startswith('Кнопка сброса ПЛК'):send_command('main','reset')

class ViewAnalyzerRuntime:
    def __init__(self,profile,publish=None):
        self.profile=ChannelProfile(profile);self.events=queue.Queue();self.log=DailyLog('viewer_'+self.profile.channel)
        self.paused=False;self.requests_paused=False;self.stop_event=threading.Event();self.threads=[];self.publish=True;self.restarting=False;self.restart_at=0;self.restart_instance=None
    def start(self):
        thread=threading.Thread(target=self.run,daemon=True);self.threads=[thread];thread.start()
    def run(self):
        while not self.stop_event.is_set():
            data=read_state(self.profile.channel)
            if self.restarting:
                if data and data.get('instance') and data['instance']!=self.restart_instance:
                    self.restarting=False
                    self.log.write('restart_completed',instance=data['instance'])
                elif time.monotonic()-self.restart_at>45:
                    self.restarting=False
                    self.events.put(dict(progress='Перезапуск не подтверждён. Проверьте фоновый супервизор; после установки нового кода нужен первый перезапуск ОС.'))
                    self.stop_event.wait(1)
                    continue
                else:
                    self.events.put(dict(progress='Перезапуск фонового анализатора; ожидание нового процесса…'))
                    self.stop_event.wait(1)
                    continue
            if data:
                self.paused=data['analysis_paused'];self.requests_paused=data['requests_paused'];self.publish=data['publish'];self.events.put(data['view'])
            else:self.events.put(dict(progress='Фоновый анализатор недоступен; ожидание восстановления'))
            self.stop_event.wait(1)
    def pause(self,value=True):self.paused=value;send_command(self.profile.channel,'analysis_pause',bool(value))
    def pause_requests(self,value=True):self.requests_paused=value;send_command(self.profile.channel,'requests_pause',bool(value))
    def restart(self):
        if self.restarting:return
        state=read_state(self.profile.channel)
        self.restart_instance=state.get('instance') if state else None
        send_command(self.profile.channel,'restart')
        self.restart_at=time.monotonic();self.restarting=True
        self.log.write('restart_sent',channel=self.profile.channel)
        self.events.put(dict(progress='Запрошен перезапуск фонового анализатора…'))
    def reload(self):pass # Background process watches profile file changes.
    def stop(self):self.stop_event.set()
