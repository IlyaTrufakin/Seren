import json
import time
import tempfile
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch,MagicMock
from src.analyzer_transport import ExternalStateStore,AnalyzerServer,KINDS,DailyLog
from src.main_config import MainSystemConfig
from src.main_evaluator import ApiMainEvaluator
from src.live_analyzer import AnalyzerRuntime,AnalyzerWindow
from src.system_supervisor import ManagedApplication
from src.archive_replay import ArchiveReplay


def packet(now,levels=None,seq=1,paused=False):
    levels=dict.fromkeys(KINDS,0)| (levels or {})
    return dict(version=1,channel='monitor1654',session='test',sequence=seq,sent_at=now,
                levels=levels,expires={k:now+600 for k in KINDS},evidence={k:dict(text='confirmed '+k,message_id='monitor1654/'+k) for k,v in levels.items() if v},
                reason='test evidence',source_online=True,paused=paused)

class TransportTests(unittest.TestCase):
    def test_deadlines_pause_stale_and_order(self):
        now=[1000.0];store=ExternalStateStore(['monitor1654'],clock=lambda:now[0])
        p=packet(now[0],{'kab':4});p['expires']['kab']=1008;store.accept(p)
        self.assertEqual(store.snapshots()['monitor1654']['levels']['kab'],4)
        with self.assertRaises(ValueError):store.accept(p)
        now[0]=1009
        self.assertTrue(store.snapshots()['monitor1654']['connected'])
        self.assertEqual(store.snapshots()['monitor1654']['levels']['kab'],0)
        now[0]=1016;self.assertFalse(store.snapshots()['monitor1654']['connected'])
        store.accept(packet(now[0],seq=2,paused=True));self.assertTrue(store.snapshots()['monitor1654']['paused'])
        with self.assertRaises(ValueError):store.accept(packet(now[0],{'kab':2},seq=3,paused=True))
    def test_bad_type_rejected(self):
        store=ExternalStateStore(['monitor1654'])
        for levels in ({'rocket':3},{'rocket':5},{'rocket':True}):
            with self.assertRaises(ValueError):store.accept(packet(time.time(),levels))
        p=packet(time.time(),{'rocket':2});p['evidence']['rocket']['text']={}
        with self.assertRaises(ValueError):store.accept(p)
    def test_real_loopback_authenticated_http_and_file_log(self):
        with tempfile.TemporaryDirectory() as directory:
            store=ExternalStateStore(['monitor1654']);server=AnalyzerServer(store,0,'secret',DailyLog('receiver',directory))
            server.start()
            try:
                def send(token,p):
                    request=urllib.request.Request(f'http://127.0.0.1:{server.port}/v1/state',data=json.dumps(p).encode(),headers={'Authorization':'Bearer '+token})
                    with urllib.request.urlopen(request,timeout=2) as response:return response.status
                p=packet(time.time(),{'rocket':2})
                with self.assertRaises(urllib.error.HTTPError) as error:send('bad',p)
                self.assertEqual(error.exception.code,401);error.exception.close()
                self.assertEqual(send('secret',p),200)
                self.assertEqual(store.snapshots()['monitor1654']['levels']['rocket'],2)
                self.assertEqual(json.loads(next(Path(directory).glob('*.jsonl')).read_text())['event'],'snapshot')
            finally:server.stop()

class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.audit=patch('src.threat_evaluator.ThreatAuditLogger',return_value=MagicMock());self.audit.start();self.addCleanup(self.audit.stop)
        self.debug=patch('src.main_evaluator.MainAPIDebugLogger',return_value=MagicMock());self.debug.start();self.addCleanup(self.debug.stop)
        self.config=MainSystemConfig.load('config_main.json');self.config.schedule.enabled=False
        self.e=ApiMainEvaluator(self.config);self.addCleanup(self.e.stop)
        self.now=[time.time()];self.e.external_store=ExternalStateStore(['monitor1654'],clock=lambda:self.now[0])
        self.e._alarmmap_online=True;self.e._api_last_success=time.time()
    def test_raise_union_cancel_and_no_baseline(self):
        self.e._alarmmap_active_alarms=[dict(type='air',level=2)]
        self.e._refresh();base=self.e.status.level_code
        self.e.external_store.accept(packet(self.now[0],{'kab':4,'rocket':2}));self.e._refresh()
        self.assertEqual(self.e.status.level_code,4);self.assertIn('kab',self.e.status.active_threat_types)
        self.assertEqual(self.e.status.api_baseline['level_code'],base)
        self.assertTrue(self.e.status.channel_states['monitor1654']['raises_level'])
        self.e.external_store.accept(packet(self.now[0],seq=2));self.e._refresh();self.assertEqual(self.e.status.level_code,base)
        self.e._alarmmap_active_alarms=[]
        self.e.external_store.accept(packet(self.now[0],{'rocket':2},seq=3));self.e._refresh()
        self.assertEqual(self.e.status.level_code,2);self.assertEqual(self.e.status.active_threat_types,['rocket'])
    def test_loss_or_pause_removes_only_overlay(self):
        self.e._alarmmap_active_alarms=[dict(type='air',level=2)];self.e._refresh();base=self.e.status.level_code
        self.e.external_store.accept(packet(self.now[0],{'kab':4}));self.e._refresh()
        self.now[0]+=16;self.e._refresh()
        self.assertEqual(self.e.status.level_code,base);self.assertFalse(self.e.status.external_analyzers['monitor1654']['connected'])
        self.assertFalse(self.e.status.no_data_link)
        self.e.external_store.accept(packet(self.now[0],seq=2,paused=True));self.e._refresh();self.assertEqual(self.e.status.level_code,base)
    def test_api_outage_immediately_uses_analyzer_and_its_sound(self):
        self.e._alarmmap_active_alarms=[dict(type='air',level=3)]
        self.e.external_store.accept(packet(self.now[0],{'rocket':2}))
        self.e._refresh();self.assertEqual(self.e.status.level_code,4)
        self.e._alarmmap_online=False;self.e._refresh()
        st=self.e.status
        self.assertFalse(st.api_baseline['available']);self.assertEqual(st.api_baseline['level_code'],0)
        self.assertEqual(st.level_code,2);self.assertEqual(st.active_threat_types,['rocket'])
        sound=next(r.sound for r in self.config.alarm_rules if r.id=='high_rocket')
        self.assertEqual(st.sound_code,sound.code);self.assertEqual(st.sound_beep_count,sound.beep_count)
        self.assertFalse(st.no_data_link);self.assertTrue(st.modbus_word & (1<<self.e.config.bit_mapping.bit_type_rocket))
        self.e._alarmmap_online=True;self.e._api_last_success=time.time();self.e._refresh()
        self.assertEqual(self.e.status.level_code,4);self.assertTrue(self.e.status.api_baseline['available'])
    def test_online_analyzer_zero_uses_safe_sound_when_api_unavailable(self):
        self.e._alarmmap_online=False
        self.e.external_store.accept(packet(self.now[0]));self.e._refresh()
        state=self.e.status
        self.assertFalse(state.no_data_link);self.assertEqual(state.level_code,0)
        self.assertEqual(state.sound_code,self.config.safe_sound.code)
        self.assertNotIn('Нет связи',state.level_title)
        self.assertIn('расчёт по анализаторам',state.formation_text)
        self.assertFalse(state.modbus_word & (1<<self.e.config.bit_mapping.bit_no_link))
    def test_paused_or_telegram_offline_analyzer_does_not_mask_total_outage(self):
        self.e._alarmmap_online=False
        for seq,paused,source_online in ((1,True,True),(2,False,False)):
            p=packet(self.now[0],seq=seq,paused=paused);p['source_online']=source_online
            self.e.external_store.accept(p);self.e._refresh()
            self.assertTrue(self.e.status.no_data_link)
            self.assertEqual(self.e.status.sound_code,self.config.no_link_sound.code)
    def test_stale_or_never_loaded_api_still_uses_analyzer(self):
        self.e.external_store.accept(packet(self.now[0],{'kab':4}))
        for stamp in (0,time.time()-self.e.config.api_stale_seconds-1):
            self.e._api_last_success=stamp;self.e._refresh()
            self.assertEqual(self.e.status.level_code,4);self.assertEqual(self.e.status.active_rule_id,'critical_kab')
            self.assertFalse(self.e.status.api_baseline['available'])
        self.now[0]+=16;self.e._refresh()
        self.assertEqual(self.e.status.level_code,0)
        self.assertEqual(self.e.status.sound_code,self.config.no_link_sound.code)
    def test_api_requests_pause_keeps_analyzer_and_blocks_http(self):
        self.e.external_store.accept(packet(self.now[0],{'rocket':2}))
        self.e.set_api_requests_paused(True)
        self.assertEqual(self.e.status.level_code,2);self.assertFalse(self.e.status.no_data_link)
        with patch('urllib.request.urlopen',side_effect=AssertionError('HTTP must be paused')):
            self.e._poll_alarmmap()
            with self.assertRaises(InterruptedError):self.e._request_api('event/type/rocket','test')
        self.e.set_api_requests_paused(False)
        self.assertFalse(self.e.api_requests_paused);self.assertEqual(self.e._api_next_poll,0)
    def test_api_inflight_response_is_discarded_after_pause(self):
        response=MagicMock();response.__enter__.return_value=response
        def body():
            self.e.set_api_requests_paused(True)
            return b'{"data":[]}'
        response.read.side_effect=body
        with patch('urllib.request.urlopen',return_value=response):
            with self.assertRaises(InterruptedError):self.e._request_api('event/type/rocket','test')
        self.assertFalse(self.e._alarmmap_online)
    def test_two_channels_compose_independently_and_one_cancel_keeps_other(self):
        self.e.external_store=ExternalStateStore(['monitor1654','radar_kharkov'],clock=lambda:self.now[0])
        self.e._alarmmap_active_alarms=[dict(type='air',level=1)]
        monitor=packet(self.now[0],{'drone':2});radar=packet(self.now[0],{'rocket':4});radar['channel']='radar_kharkov'
        self.e.external_store.accept(monitor);self.e.external_store.accept(radar);self.e._refresh()
        self.assertEqual(self.e.status.level_code,4)
        self.assertIn('drone',self.e.status.active_threat_types);self.assertIn('rocket',self.e.status.active_threat_types)
        self.assertEqual(self.e.status.active_rule_id,'critical_rocket')
        self.e.external_store.accept(packet(self.now[0],seq=2,paused=True));self.e._refresh()
        self.assertEqual(self.e.status.level_code,4);self.assertIn('rocket',self.e.status.active_threat_types)
        radar=packet(self.now[0],seq=2);radar['channel']='radar_kharkov'
        self.e.external_store.accept(radar);self.e._refresh()
        self.assertEqual(self.e.status.level_code,self.e.status.api_baseline['level_code'])
    def test_two_channels_without_api_use_remaining_online_zero_source(self):
        self.e.external_store=ExternalStateStore(['monitor1654','radar_kharkov'],clock=lambda:self.now[0])
        self.e._alarmmap_online=False
        radar=packet(self.now[0]);radar['channel']='radar_kharkov';self.e.external_store.accept(radar);self.e._refresh()
        self.assertFalse(self.e.status.no_data_link);self.assertEqual(self.e.status.sound_code,self.config.safe_sound.code)
        self.assertFalse(self.e.status.external_analyzers['monitor1654']['connected'])
    def test_api_rule_switch_does_not_filter_independent_channel(self):
        for rule in self.config.alarm_rules:rule.enabled=False
        e=ApiMainEvaluator(self.config);self.addCleanup(e.stop)
        e.external_store.accept(packet(time.time(),{'rocket':4}));e._refresh()
        self.assertEqual(e.status.level_code,4);self.assertEqual(e.status.active_rule_id,'critical_rocket')

class RuntimeTests(unittest.TestCase):
    def test_live_replay_uses_same_profile_and_pauses(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):
            runtime=AnalyzerRuntime('profiles/monitor1654')
            now=time.time();messages=[dict(id='monitor1654/999999',channel='monitor1654',timestamp=now-10,text='Ракета!!!')]
            reference=ArchiveReplay(messages,runtime.evaluator.config);reference.step();reference.advance(now)
            original=runtime._update
            def update():
                original()
                if runtime.bootstrapped:runtime.stop_event.set()
            with patch('src.live_analyzer.fetch_public_history',return_value=(messages,True)),patch.object(runtime,'_update',side_effect=update):runtime._monitor()
            self.assertTrue(runtime.bootstrapped);self.assertEqual(runtime.snapshot['levels']['rocket'],2)
            self.assertEqual(max(runtime.snapshot['levels'].values()),reference.evaluator.status.level_code)
            runtime.pause();self.assertEqual(max(runtime.snapshot['levels'].values()),0)
    def test_empty_recent_history_is_ready(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):runtime=AnalyzerRuntime('profiles/monitor1654')
        original=runtime._update
        def update():
            original()
            if runtime.bootstrapped:runtime.stop_event.set()
        with patch('src.live_analyzer.fetch_public_history',return_value=([],True)),patch.object(runtime,'_update',side_effect=update):runtime._monitor()
        self.assertTrue(runtime.bootstrapped);self.assertFalse(runtime.source_error)
    def test_gui_without_any_sources_or_plc(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):window=AnalyzerWindow(autostart=False)
        try:
            window.withdraw();window.runtime.bootstrapped=True;window.runtime._update();window.pump()
            self.assertIn('Нет тревоги',window.level.get());self.assertIsNotNone(window.plot.model)
            self.assertIsNone(window.runtime.evaluator.tg_reader)
        finally:window.close()

class SupervisorTests(unittest.TestCase):
    def test_existing_manual_gui_is_adopted_without_a_second_process(self):
        from src.system_supervisor import adopt_recent_process
        now=[1000];log=MagicMock();app=ManagedApplication('main',['fake'],log,clock=lambda:now[0],popen=MagicMock())
        existing=MagicMock(pid=123);existing.poll.return_value=None;existing.executable.return_value=Path('C:/Python314/python.exe')
        data=dict(pid=123,at=1000)
        with patch('pathlib.Path.read_text',return_value=json.dumps(data)),patch('src.system_supervisor.ExistingProcess',return_value=existing):
            self.assertTrue(adopt_recent_process(app))
        app.tick();app.popen.assert_not_called();self.assertIs(app.process,existing)
    def test_stale_heartbeat_cannot_adopt_reused_pid(self):
        from src.system_supervisor import adopt_recent_process
        app=ManagedApplication('main',['fake'],MagicMock(),clock=lambda:1000)
        with patch('pathlib.Path.read_text',return_value=json.dumps(dict(pid=123,at=900))),patch('src.system_supervisor.ExistingProcess') as existing:
            self.assertFalse(adopt_recent_process(app));existing.assert_not_called()
    def test_three_programs_recover_independently(self):
        now=[1000];processes=[MagicMock(pid=900+i) for i in range(3)]
        for process in processes:process.poll.return_value=None
        apps=[ManagedApplication(role,['fake'],MagicMock(),clock=lambda:now[0],popen=MagicMock(return_value=process)) for role,process in zip(('main','monitor1654','radar_kharkov'),processes)]
        for app in apps:app.tick()
        processes[2].poll.return_value=1
        for app in apps:app.tick()
        now[0]+=3;processes[2].poll.return_value=None
        for app in apps:app.tick()
        self.assertEqual([app.popen.call_count for app in apps],[1,1,2])
        for app in apps:
            if app.stream:app.stream.close()
    def test_crash_restarts_and_deliberate_close_stops(self):
        now=[1000];process=MagicMock(pid=99999999);process.poll.return_value=None;popen=MagicMock(return_value=process)
        app=ManagedApplication('test_supervisor',['fake'],MagicMock(),clock=lambda:now[0],popen=popen)
        app.tick();self.assertEqual(popen.call_count,1)
        process.poll.return_value=1;app.tick();app.tick();self.assertEqual(popen.call_count,1)
        now[0]+=3;process.poll.return_value=None;app.tick();self.assertEqual(popen.call_count,2)
        process.poll.return_value=0;app.tick();now[0]+=100;app.tick();self.assertEqual(popen.call_count,2);self.assertTrue(app.closed)
    def test_venv_child_pid_and_fresh_instance_are_not_hung(self):
        now=[1000];process=MagicMock(pid=12345);process.poll.return_value=None
        app=ManagedApplication('test_supervisor',['fake'],MagicMock(),clock=lambda:now[0],popen=MagicMock(return_value=process))
        app.tick();now[0]+=100
        for data in (dict(pid=54321,launcher_pid=12345,at=now[0]),dict(pid=54321,instance=app.instance,at=now[0])):
            with patch('pathlib.Path.read_text',return_value=json.dumps(data)),patch('src.system_supervisor.terminate_process_tree') as kill:
                app.tick();kill.assert_not_called();self.assertIs(app.process,process)
        if app.stream:app.stream.close()
    def test_sleep_gap_gives_gui_time_to_resume_before_kill(self):
        now=[1000];process=MagicMock(pid=99999999);process.poll.return_value=None
        app=ManagedApplication('test_supervisor',['fake'],MagicMock(),clock=lambda:now[0],popen=MagicMock(return_value=process))
        app.tick();now[0]+=600
        with patch('src.system_supervisor.terminate_process_tree') as kill:
            app.tick();kill.assert_not_called();self.assertGreater(app.resume_grace,now[0])
        if app.stream:app.stream.close()
    def test_hung_window_is_killed_and_restarted(self):
        now=[1000];process=MagicMock(pid=99999999);process.poll.return_value=None
        app=ManagedApplication('test_supervisor',['fake'],MagicMock(),clock=lambda:now[0],popen=MagicMock(return_value=process))
        app.tick();now[0]+=91
        for i in range(23):
            app.last_check=now[0];now[0]+=2
        with patch('src.system_supervisor.terminate_process_tree') as kill:
            app.tick();kill.assert_called_once_with(process)
        self.assertIsNone(app.process)

if __name__=='__main__':unittest.main()
