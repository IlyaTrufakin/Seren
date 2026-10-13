import unittest,tempfile,json,time,queue
from pathlib import Path
from dataclasses import asdict
from unittest.mock import patch,MagicMock
from src import background_common as common
from src.background_runner import BackgroundMain,apply_analyzer_commands,AnalyzerRestartRequested
from src.background_views import ViewModbusWorker,ViewAnalyzerRuntime
from src.threat_models import ThreatStatus
from src.config import AppConfig

class BackgroundTests(unittest.TestCase):
    def test_local_commands_signed_and_consumed_once(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(common,'ROOT',Path(directory)),patch.object(common,'shared_token',return_value='test'):
            common.send_command('main','api_pause',True)
            commands=common.take_commands('main');self.assertEqual(commands[0]['action'],'api_pause');self.assertEqual(common.take_commands('main'),[])
            common.send_command('main','api_pause',False)
            file=next((Path(directory)/'runtime/commands').glob('*.json'));data=json.loads(file.read_text());data['signature']='bad';file.write_text(json.dumps(data))
            self.assertEqual(common.take_commands('main'),[])
    def test_old_background_state_is_not_used(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(common,'ROOT',Path(directory)):
            common.write_state('main',dict(level=4));self.assertEqual(common.read_state('main')['level'],4)
            file=Path(directory)/'runtime/background_main.json';data=json.loads(file.read_text());data['at']-=20;file.write_text(json.dumps(data));self.assertIsNone(common.read_state('main'))
    def test_state_replace_retries_temporary_windows_lock(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(common,'ROOT',Path(directory)):
            common.write_state('main',dict(level=1))
            replace=common.os.replace
            with patch.object(common.os,'replace',side_effect=[PermissionError(),None]) as call,patch.object(common.time,'sleep'):
                self.assertTrue(common.write_state('main',dict(level=2)))
                self.assertEqual(call.call_count,2)
            with patch.object(common.os,'replace',side_effect=PermissionError()),patch.object(common.time,'sleep'):
                self.assertFalse(common.write_state('main',dict(level=4)))
            self.assertEqual(common.read_state('main')['level'],1)
            self.assertFalse(list((Path(directory)/'runtime').glob('*.tmp')))
    def test_closing_view_never_disconnects_real_plc(self):
        worker=ViewModbusWorker(AppConfig(),queue.Queue())
        with patch('src.background_views.send_command') as command:
            worker.stop();command.assert_not_called()
            worker.disconnect();command.assert_called_once_with('main','plc_connection',False)
    def test_analyzer_restart_command_targets_only_its_channel(self):
        view=ViewAnalyzerRuntime('profiles/monitor1654')
        with patch('src.background_views.read_state',return_value={'instance':123}),patch('src.background_views.send_command') as command,patch.object(view.log,'write'):
            view.restart();view.restart()
            command.assert_called_once_with('monitor1654','restart')
            self.assertTrue(view.restarting);self.assertEqual(view.restart_instance,123)

    def test_background_restart_leaves_through_supervisor_restart_path(self):
        runtime=MagicMock()
        with patch('src.background_runner.take_commands',return_value=[dict(action='restart',id='test')]):
            with self.assertRaises(AnalyzerRestartRequested):apply_analyzer_commands('monitor1654',runtime)
        runtime.log.write.assert_called_once_with('restart_requested',channel='monitor1654',command_id='test')
        runtime.pause.assert_not_called()

    def runtime(self):
        with patch('src.background_runner.ModbusWorker',return_value=MagicMock()),patch('src.background_runner.ApiMainEvaluator',return_value=MagicMock()),patch('src.background_runner.DailyLog',return_value=MagicMock()):return BackgroundMain()
    def test_second_controller_is_refused_before_plc_start(self):
        runtime=self.runtime();runtime.evaluator.external_server=None
        with self.assertRaises(RuntimeError):runtime.start()
        runtime.worker.start.assert_not_called()
    def test_background_control_matches_gui_word_and_five_sound_values(self):
        runtime=self.runtime();st=ThreatStatus();st.modbus_word=123;st.sound_code=7;st.sound_beep_count=2;st.sound_duration_ms=100;st.sound_pause_ms=300;st.sound_interval_ms=30000
        runtime.status(st)
        args=runtime.worker.set_control_snapshot.call_args.args
        self.assertEqual(args[:2],(123,[7,2,100,300,30000]))
    def test_background_plc_feedback_switch_and_reset(self):
        runtime=self.runtime();runtime.evaluator._thread.is_alive.return_value=True;runtime.evaluator._api_thread.is_alive.return_value=True
        pf=runtime.config.plc_feedback;value=(1<<pf.bit_analysis_switch)|(1<<pf.bit_alarm_reset)
        runtime.events.put(dict(type='read_ok',data=dict(value=value,address=1)))
        with patch('src.background_runner.take_commands',return_value=[]),patch('src.background_runner.write_state'),patch('src.background_runner.heartbeat'):
            runtime.tick()
        runtime.evaluator.set_plc_analysis_switch.assert_called_with(True);runtime.evaluator.reset_threat_state.assert_called_once()

if __name__=='__main__':unittest.main()
