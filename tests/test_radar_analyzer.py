import json
import threading
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch,MagicMock
from src.channel_tuning import ChannelProfile
from src.channel_debug_model import analyze_messages,date_window
from src.live_analyzer import AnalyzerRuntime,AnalyzerWindow
from src.analyzer_transport import DailyLog

class RadarProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile=ChannelProfile('profiles/radar_kharkov');self.cfg=self.profile.load_config()
        self.start,self.end=date_window('2026-10-11','2026-10-11')
    def analyze(self,texts,channel='radar_kharkov',config=None):
        messages=[dict(id=f'{channel}/{i+1}',channel=channel,text=text,timestamp=self.start+10+i*20) for i,text in enumerate(texts)]
        return analyze_messages(messages,channel,self.start,self.start+500,config or self.cfg,threading.Event(),lambda s:None)
    def test_same_explicit_policy_as_monitor(self):
        monitor=ChannelProfile('profiles/monitor1654').load_config()
        for text in ('В УКРЫТИЕ','КАБ над Харьковом','КАБ на Казачью Лопань','Шахед на Лесное','Fpv над Харьковом','Цель на Дергачи'):
            with self.subTest(text=text):
                radar=self.analyze([text]).rows[-1]['levels']
                baseline=self.analyze([text],'monitor1654',monitor).rows[-1]['levels']
                self.assertEqual(radar,baseline)
    def test_russian_rocket_routes_and_foreign_towns(self):
        for text,expected in [('Баллистика с Курска',1),('Ракета курсом на Сортировку',4),('Бандероль на центр - Сокольники',4),('Ракета на Чугуев',0),('Бандероль на Балаклею',0)]:
            with self.subTest(text=text):self.assertEqual(self.analyze([text]).rows[-1]['levels']['rocket'],expected)
    def test_bomb_warning_negation_and_route(self):
        for text,expected in [('СУшки в бнр, угроза КАБ',1),('Без пусков КАБ',0),('КАБ курсом на Казачью Лопань',1),('КАБ летит ближе к Слатино',2),('КАБ курсом на Волчанск',1),('КАБ курсом на Приколотное',0)]:
            with self.subTest(text=text):self.assertEqual(self.analyze([text]).rows[-1]['levels']['kab'],expected)
    def test_clear_plural_and_uncertain_end(self):
        result=self.analyze(['КАБ над Харьковом','ВОЗДУШНЫЙ ОТБОЙ'])
        self.assertEqual(result.rows[0]['levels']['kab'],4);self.assertEqual(result.rows[1]['level'],0)
        result=self.analyze(['КАБ над Харьковом','Упали'])
        self.assertEqual(result.rows[-1]['levels']['kab'],0)
        result=self.analyze(['Шахед над Харьковом','Предварительно сбит'])
        self.assertEqual(result.rows[-1]['levels']['drone'],2)
    def test_user_rocket_city_is_critical_but_monitor_stays_high(self):
        for text in ('Еще ракета на Харьков','Ракета на Харьков','Бандероль над Харьковом'):
            with self.subTest(text=text):self.assertEqual(self.analyze([text]).rows[-1]['levels']['rocket'],4)
        monitor=ChannelProfile('profiles/monitor1654').load_config()
        self.assertEqual(self.analyze(['Ракета на Харьков'],'monitor1654',monitor).rows[-1]['levels']['rocket'],2)
    def test_user_drone_direction_is_not_overflight(self):
        result=self.analyze(['Шахед берет курс на Люботин\n\n+ Ударный БпЛА на Алексеевку. - Лесопарк'])
        self.assertEqual(result.rows[-1]['levels']['drone'],1)
        result=self.analyze(['Ударный БпЛА над Алексеевкой'])
        self.assertEqual(result.rows[-1]['levels']['drone'],2)
    def test_user_bomb_course_change_keeps_peak_and_new_drop_resets(self):
        result=self.analyze(['КАБ над Харьковом','КАБ курс на Русскую Лозовую','Второй сброс КАБ на Веселое'])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[4,4,1])
    def test_user_departure_with_shelter_reminder_is_low(self):
        result=self.analyze(['Шахед над Харьковом','Реактивный Шахед покинул приделы Харькова, но не покидайте укрытие, ранее уже было такое, будет крутится и искать цель.'])
        self.assertEqual(result.rows[-1]['levels']['drone'],1)
    def test_user_bomb_group_explosion_launch_and_new_direction(self):
        result=self.analyze(['КАБ над Харьковом','Взрыв в районе Питомника','Второй сброс КАБ на Веселое','КАБ летит ближе к Проходам'])
        self.assertEqual([r['levels']['kab'] for r in result.rows],[4,0,1,2])
        self.assertTrue(result.rows[2]['event']['launch_detected'])
    def test_bomb_explosion_cannot_cancel_drone_or_uncertain_bomb(self):
        result=self.analyze(['Шахед над Харьковом','Взрыв в районе Питомника'])
        self.assertEqual(result.rows[-1]['levels']['drone'],2)
        result=self.analyze(['КАБ над Харьковом','Золочевский район взрыв'])
        self.assertEqual(result.rows[-1]['levels']['kab'],4)
        result=self.analyze(['КАБ над Харьковом','Предварительно взрыв в районе Питомника'])
        self.assertEqual(result.rows[-1]['levels']['kab'],4)
    def test_russian_lozova_near_city_is_not_distant_lozova(self):
        result=self.analyze(['КАБ курс на Русскую Лозовую'])
        self.assertEqual(result.rows[-1]['levels']['kab'],2)
        result=self.analyze(['Бандероль на Лозовую'])
        self.assertEqual(result.rows[-1]['levels']['rocket'],0)
    def test_sources_are_remapped_without_disabling_monitor_rules(self):
        monitor=ChannelProfile('profiles/monitor1654').load_config()
        self.assertEqual([r.id for r in monitor.alarm_rules if r.enabled],[r.id for r in self.cfg.alarm_rules if r.enabled])
        for row in self.cfg.alarm_rules+self.cfg.end_conditions:
            self.assertNotIn('telegram:monitor1654',row.sources)
        self.assertEqual(self.cfg.tracking.generic_target_type,'rocket')
    def test_default_radar_is_publisher_but_explicit_observation_still_available(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):runtime=AnalyzerRuntime('profiles/radar_kharkov')
        self.assertTrue(runtime.publish);self.assertIn('radar_kharkov',runtime.settings['channels'])
    def test_observation_does_not_read_key_or_send_anything(self):
        with patch('src.live_analyzer.shared_token',side_effect=AssertionError('No IPC key in observation mode')),patch('src.live_analyzer.DailyLog',return_value=MagicMock()),patch('urllib.request.urlopen',side_effect=AssertionError('No publisher request')):
            runtime=AnalyzerRuntime('profiles/radar_kharkov',publish=False)
            self.assertFalse(runtime.publish);runtime._publisher()
            with patch.object(runtime,'_monitor',return_value=None):
                runtime.start();runtime.stop()
            self.assertEqual(len(runtime.threads),1)
        allowed=json.loads(Path('config_analyzers.json').read_text())['channels']
        self.assertIn('radar_kharkov',allowed)
    def test_runtime_state_writes_real_daily_log(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('src.live_analyzer.DailyLog',return_value=DailyLog('radar',directory)):
                runtime=AnalyzerRuntime('profiles/radar_kharkov',publish=False)
            runtime._update()
            entry=json.loads(next(Path(directory).glob('*.jsonl')).read_text(encoding='utf-8'))
            self.assertEqual(entry['event'],'state');self.assertIsInstance(entry['observed_at'],float)
            self.assertIsInstance(entry['timestamp'],str)
    def test_telegram_reading_pause_blocks_fetch_and_keeps_valid_state(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):runtime=AnalyzerRuntime('profiles/radar_kharkov',publish=False)
        runtime.bootstrapped=True
        runtime.pause_requests(True)
        original=runtime._update
        def update():original();runtime.stop_event.set()
        with patch('src.live_analyzer.fetch_public_history',side_effect=AssertionError('Telegram requests paused')),patch.object(runtime,'_update',side_effect=update):runtime._monitor()
        self.assertFalse(runtime.snapshot['source_online']);self.assertFalse(runtime.paused)
        runtime.pause_requests(False)
        self.assertTrue(runtime.rebuild_pending);self.assertTrue(runtime.bootstrapped)
    def test_relaunch_request_brings_existing_gui_back(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):window=AnalyzerWindow('profiles/radar_kharkov',autostart=False,publish=False)
        try:
            window.withdraw()
            with patch('src.live_analyzer.launch_request_id',return_value='new_click'),patch.object(window,'show_window') as show:
                window.pump();window.pump();show.assert_called_once()
        finally:window.close()
    def test_supervisor_can_reopen_after_intentional_close(self):
        from src.system_supervisor import ManagedApplication
        process=MagicMock(pid=100);process.poll.return_value=None;popen=MagicMock(return_value=process)
        app=ManagedApplication('test_supervisor',['fake'],MagicMock(),popen=popen)
        app.tick();process.poll.return_value=0;app.tick();self.assertTrue(app.closed)
        app.reopen();process.poll.return_value=None;app.tick();self.assertEqual(popen.call_count,2)
        if app.stream:app.stream.close()
    def test_render_exception_is_logged_and_pump_is_rescheduled(self):
        log=MagicMock()
        with patch('src.live_analyzer.DailyLog',return_value=log):window=AnalyzerWindow('profiles/radar_kharkov',autostart=False,publish=False)
        try:
            window.withdraw()
            with patch.object(window,'_render_update',side_effect=ValueError('bad chart')),patch.object(window,'after') as after:
                window.pump();after.assert_called_once_with(1000,window.pump)
            self.assertEqual(log.write.call_args.args[0],'gui_exception')
            with patch('src.live_analyzer.heartbeat') as heartbeat,patch.object(window,'after'):
                window._heartbeat_tick();heartbeat.assert_called_once_with('radar_kharkov')
        finally:window.close()
    def test_separate_gui_and_heartbeat(self):
        with patch('src.live_analyzer.DailyLog',return_value=MagicMock()):window=AnalyzerWindow('profiles/radar_kharkov',autostart=False,publish=False)
        try:
            window.withdraw();window.runtime.bootstrapped=True;window.runtime._update()
            with patch('src.live_analyzer.heartbeat') as beat:window._heartbeat_tick();beat.assert_called_once_with('radar_kharkov')
            window.pump()
            self.assertIn('radar_kharkov',window.title());self.assertIn('передача',window.status.get())
            self.assertFalse(window.runtime.publish)
        finally:window.close()

if __name__=='__main__':unittest.main()
