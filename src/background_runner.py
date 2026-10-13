"""No Tk windows: API/PLC and independent Telegram engines for pre-logon startup."""
import time,queue,threading,json,os
from pathlib import Path
from dataclasses import asdict
from src.analyzer_transport import ROOT,DailyLog
from src.background_common import write_state,take_commands
from src.runtime_support import heartbeat,single_instance
from src.main_config import MainSystemConfig
from src.main_evaluator import ApiMainEvaluator
from src.config import AppConfig
from src.modbus_worker import ModbusWorker

class BackgroundMain:
    def __init__(self):
        self.log=DailyLog('background_main');self.events=queue.Queue();self.latest={};self.history=[];self.seq=0
        self.config=MainSystemConfig.load();cfg=AppConfig.load();cfg.read_reg_address=1
        self.worker=ModbusWorker(cfg,self.events);self.last_reset=False;self.last_switch=None
        self.evaluator=ApiMainEvaluator(self.config,on_status_change=self.status)
        self.stamps=self.config_stamps()
    def config_stamps(self):
        return tuple((ROOT/p).stat().st_mtime_ns for p in ('config_main.json','config.json','config_analyzers.json'))
    def status(self,st):
        if self.config.auto_transfer_to_plc:self.worker.set_control_snapshot(st.modbus_word,[st.sound_code,st.sound_beep_count,st.sound_duration_ms,st.sound_pause_ms,st.sound_interval_ms],self.config.bit_mapping.bit_heartbeat,reaction=asdict(st))
        else:self.worker.clear_control_snapshot()
        self.latest=asdict(st)
    def start(self):
        self.evaluator.start()
        if self.evaluator.external_server is None:
            self.evaluator.stop();raise RuntimeError('Controller already running or IPC port unavailable; PLC not started')
        self.worker.start();self.log.write('started')
    def tick(self):
        if not self.evaluator._thread.is_alive():raise RuntimeError('Main evaluator thread stopped')
        if self.config.alarmmap_enabled and not self.evaluator._api_thread.is_alive():raise RuntimeError('API worker stopped')
        current=self.config_stamps()
        if current!=self.stamps:
            cfg=MainSystemConfig.load();old=self.evaluator
            old.stop();self.config=cfg
            self.evaluator=ApiMainEvaluator(cfg,on_status_change=self.status,sound_timer=old.sound_timer)
            self.evaluator.inherit_api_state(old)
            if self.last_switch is not None:self.evaluator.set_plc_analysis_switch(self.last_switch)
            self.evaluator.start()
            if self.evaluator.external_server is None:raise RuntimeError('IPC receiver failed after reload')
            if current[1]!=self.stamps[1]:
                self.worker.stop();network=AppConfig.load();network.read_reg_address=1;self.worker.update_config(network);self.worker.start()
            self.stamps=current;self.log.write('config_reload')
        for command in take_commands('main'):
            action=command['action'];value=command.get('value')
            if action=='api_pause' and type(value) is bool:self.evaluator.set_api_requests_paused(value)
            elif action=='plc_connection' and type(value) is bool:self.worker.start() if value else self.worker.stop()
            elif action=='reset':self.evaluator.reset_threat_state('Интерфейс пользователя')
        while not self.events.empty():
            event=self.events.get();self.seq+=1;self.history.append(dict(seq=self.seq,**event));self.history=self.history[-100:]
            if event['type']=='read_ok':
                value=event['data']['value'];pf=self.config.plc_feedback
                reset=bool(value & (1<<pf.bit_alarm_reset));switch=bool(value & (1<<pf.bit_analysis_switch))
                if reset and not self.last_reset:self.evaluator.reset_threat_state('Кнопка сброса ПЛК')
                self.last_reset=reset
                if switch!=self.last_switch:self.evaluator.set_plc_analysis_switch(switch);self.last_switch=switch
            elif event['type']=='control_ack' and event['data'].get('changed'):self.evaluator.audit_logger.log_plc_confirmation(event['data'])
        write_state('main',dict(instance=os.getpid(),status=self.latest,api_requests_paused=self.evaluator.api_requests_paused,plc_connected=self.worker.is_connected(),events=self.history))
        heartbeat('service_main')
    def stop(self):self.evaluator.stop();self.worker.stop()

class AnalyzerRestartRequested(Exception):
    """Normal maintenance request; supervisor restarts a nonzero exit."""

def apply_analyzer_commands(role,runtime):
    for command in take_commands(role):
        action=command['action'];value=command.get('value')
        if action=='restart':
            runtime.log.write('restart_requested',channel=role,command_id=command['id'])
            raise AnalyzerRestartRequested()
        if type(value) is not bool:continue
        if action=='analysis_pause':runtime.pause(value)
        elif action=='requests_pause':runtime.pause_requests(value)

def analyzer(role):
    from src.live_analyzer import AnalyzerRuntime
    runtime=AnalyzerRuntime(ROOT/'profiles'/role);runtime.start();stamp=runtime.profile.config_path.stat().st_mtime_ns
    try:
        while True:
            if any(not t.is_alive() for t in runtime.threads):raise RuntimeError('Analyzer worker stopped')
            current=runtime.profile.config_path.stat().st_mtime_ns
            if current!=stamp:runtime.reload();stamp=current
            apply_analyzer_commands(role,runtime)
            latest=None
            while not runtime.events.empty():
                item=runtime.events.get()
                if 'snapshot' in item:latest=item
            if latest:write_state(role,dict(instance=os.getpid(),view=latest,analysis_paused=runtime.paused,requests_paused=runtime.requests_paused,publish=runtime.publish))
            heartbeat('service_'+role);time.sleep(.5)
    finally:runtime.stop()

def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--role',choices=['main','monitor1654','radar_kharkov']);parser.add_argument('--probe',action='store_true');args=parser.parse_args()
    if args.probe:
        import urllib.request,os
        try:
            cfg=MainSystemConfig.load()
            key_readable=bool(Path(cfg.alarmmap_key_file).read_text(encoding='utf-8-sig').strip())
            from src.channel_tuning import ChannelProfile
            profiles_readable=all(ChannelProfile(ROOT/'profiles'/r).load_config().telegram_enabled for r in ('monitor1654','radar_kharkov'))
            with urllib.request.urlopen('https://t.me/s/radar_kharkov',timeout=15) as response:response.read(1)
            write_state('probe',dict(ok=key_readable and profiles_readable,network=True,pid=os.getpid(),plc_connected=False))
        except Exception as error:
            write_state('probe',dict(ok=False,error=str(error),plc_connected=False))
            raise
        return
    if not args.role:parser.error('--role is required')
    if not single_instance('background_'+args.role,global_scope=True):return
    if args.role!='main':analyzer(args.role);return
    runtime=BackgroundMain()
    try:
        runtime.start()
        while True:runtime.tick();time.sleep(.2)
    finally:runtime.stop()
if __name__=='__main__':
    try:main()
    except AnalyzerRestartRequested:
        raise SystemExit(75)
    except BaseException:
        import traceback
        try:DailyLog('background_errors').write('fatal',traceback=traceback.format_exc())
        except OSError:pass
        raise
