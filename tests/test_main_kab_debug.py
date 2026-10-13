from copy import deepcopy
import json
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import MagicMock, patch
from src.main_api_debug import MainAPIDebugLogger
from src.main_config import MainSystemConfig
from src.main_config_dialog import MainConfigDialog
from src.main_evaluator import ApiMainEvaluator
from src.threat_models import ThreatSystemConfig


class MainKabDebugTests(unittest.TestCase):
    def setUp(self):
        legacy=ThreatSystemConfig()
        legacy.schedule.enabled=False
        self.config=MainSystemConfig.from_legacy(legacy)
        for rule in self.config.alarm_rules:
            rule.enabled=rule.id=='critical_kab'
            if rule.enabled:
                rule.api_types=['kab-bombs']
                rule.api_levels_by_type={'kab-bombs':[1]}
                rule.general_api_levels=[3]
        self.audit=patch('src.threat_evaluator.ThreatAuditLogger',return_value=MagicMock())
        self.audit.start();self.addCleanup(self.audit.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.logger=MainAPIDebugLogger(self.root/'logs')

    def evaluator(self, config=None):
        evaluator=ApiMainEvaluator(config or self.config,debug_logger=self.logger)
        self.addCleanup(evaluator.stop)
        return evaluator

    def api(self, evaluator, alarms):
        evaluator._alarmmap_active_alarms=alarms
        evaluator._alarmmap_online=True
        evaluator._api_last_success=time.time()
        evaluator._refresh()
        return evaluator.status

    def records(self):
        return [json.loads(line) for p in (self.root/'logs').glob('*.jsonl') for line in p.read_text(encoding='utf-8').splitlines()]

    def test_bomb_rule_requires_both_general_and_kab_levels(self):
        evaluator=self.evaluator()
        for general,kab,expected in [(3,1,4),(2,1,0),(3,2,0),(None,1,0),(3,None,0)]:
            with self.subTest(general=general,kab=kab):
                alarms=[]
                if general is not None:alarms.append(dict(type='air',level=general))
                if kab is not None:alarms.append(dict(type='kab-bombs',level=kab))
                self.assertEqual(self.api(evaluator,alarms).level_code,expected)
        self.assertEqual(self.api(evaluator,[dict(type='air',level=2),dict(type='air',level=3),dict(type='kab-bombs',level=1)]).level_code,4)

    def test_different_bomb_rules_select_highest_matching_conjunction(self):
        config=deepcopy(self.config)
        high=next(r for r in config.alarm_rules if r.id=='high_kab')
        high.enabled=True;high.api_types=['kab-bombs'];high.api_levels_by_type={'kab-bombs':[1]};high.general_api_levels=[2,3]
        evaluator=self.evaluator(config)
        self.assertEqual(self.api(evaluator,[dict(type='air',level=2),dict(type='kab-bombs',level=1)]).level_code,2)
        self.assertEqual(self.api(evaluator,[dict(type='air',level=3),dict(type='kab-bombs',level=1)]).level_code,4)

    def test_gui_saves_bomb_general_and_specific_selections_without_json_field(self):
        root=tk.Tk();root.withdraw();saved=[]
        dialog=MainConfigDialog(root,self.config,saved.append,persist=False)
        dialog.withdraw()
        try:
            fields=dialog.rule_inputs['critical_kab']
            self.assertEqual(set(fields['api']),{'air','kab-bombs'})
            self.assertTrue(fields['api']['air'][3].get())
            self.assertFalse(fields['api']['air'][2].get())
            self.assertNotIn('by_type',fields)
            with patch('src.main_config_dialog.messagebox.showerror') as errors:
                dialog._save_and_close()
                self.assertFalse(errors.called,errors.call_args)
            rule=next(r for r in saved[0].alarm_rules if r.id=='critical_kab')
            self.assertEqual(rule.general_api_levels,[3])
            self.assertEqual(rule.api_types,['kab-bombs'])
            self.assertEqual(rule.api_levels_by_type['kab-bombs'],[1])
            self.assertEqual(self.api(self.evaluator(saved[0]),[dict(type='air',level=3),dict(type='kab-bombs',level=1)]).level_code,4)
        finally:
            if dialog.winfo_exists():dialog.destroy()
            root.destroy()

    def test_drone_rule_has_general_selector_and_requires_both_inputs(self):
        config=deepcopy(self.config)
        for rule in config.alarm_rules:
            rule.enabled=rule.id=='high_drone'
            if rule.enabled:
                rule.general_api_levels=[2]
                rule.api_types=['fight-drones','fpv-drones']
                rule.api_levels_by_type={'fight-drones':[1],'fpv-drones':[2]}
        root=tk.Tk();root.withdraw();saved=[]
        dialog=MainConfigDialog(root,config,saved.append,persist=False)
        dialog.withdraw()
        try:
            fields=dialog.rule_inputs['high_drone']['api']
            self.assertEqual(set(fields),{'air','fight-drones','fpv-drones'})
            self.assertEqual(set(fields['air']),{1,2,3})
            self.assertTrue(fields['air'][2].get())
            with patch('src.main_config_dialog.messagebox.showerror') as errors:
                dialog._save_and_close()
                self.assertFalse(errors.called,errors.call_args)
            evaluator=self.evaluator(saved[0])
            for general,kind,level,expected in [(2,'fight-drones',1,2),(3,'fight-drones',1,0),
                    (2,'fight-drones',2,0),(2,'fpv-drones',2,2),(1,'fpv-drones',2,0)]:
                self.assertEqual(self.api(evaluator,[dict(type='air',level=general),dict(type=kind,level=level)]).level_code,expected)
            self.assertNotIn('air',next(r for r in saved[0].alarm_rules if r.id=='high_drone').api_types)
        finally:
            if dialog.winfo_exists():dialog.destroy()
            root.destroy()

    def test_each_identical_poll_logs_raw_payload_and_calculated_level_without_key(self):
        key=self.root/'key.txt';key.write_text('private-api-key',encoding='utf-8')
        self.config.alarmmap_key_file=str(key)
        evaluator=self.evaluator()
        evaluator._catalog_last_success=time.time()
        payload={'data':[{'type':'air','level':3},{'type':'kab-bombs','level':1}], 'meta':{'sample':'raw'}}
        response=MagicMock();response.__enter__.return_value.read.return_value=json.dumps(payload).encode()
        with patch('urllib.request.urlopen',return_value=response):
            evaluator._poll_alarmmap();evaluator._poll_alarmmap()
        records=self.records();polls=[r for r in records if r['event']=='api_poll']
        self.assertEqual(len(polls),2)
        self.assertEqual(polls[0]['input'],payload)
        self.assertEqual(polls[0]['output']['level'],'критическая')
        self.assertEqual(polls[0]['output']['internal_level_code'],4)
        self.assertEqual(polls[0]['output']['general_api_level'],3)
        self.assertEqual(polls[0]['output']['rule_id'],'critical_kab')
        self.assertEqual(len([r for r in records if r['event']=='decision']),1)
        self.assertNotIn('private-api-key',json.dumps(records))
        self.assertIn('+03:00',polls[0]['timestamp'])

    def test_bad_payload_and_connection_failure_are_logged_and_do_not_stop_evaluation(self):
        key=self.root/'key.txt';key.write_text('secret',encoding='utf-8')
        self.config.alarmmap_key_file=str(key)
        evaluator=self.evaluator()
        response=MagicMock();response.__enter__.return_value.read.return_value=b'{"data":{"bad":true}}'
        with patch('urllib.request.urlopen',return_value=response):evaluator._poll_alarmmap()
        first=[r for r in self.records() if r['event']=='api_poll'][-1]
        self.assertEqual(first['input'],{'data':{'bad':True}})
        self.assertFalse(first['output']['api_online'])
        self.assertTrue(first['api_error'])
        with patch('urllib.request.urlopen',side_effect=OSError('offline')):evaluator._poll_alarmmap()
        self.assertEqual(len([r for r in self.records() if r['event']=='api_poll']),2)

    def test_timer_expiry_is_logged_as_decision_without_another_api_response(self):
        next(r for r in self.config.alarm_rules if r.id=='critical_kab').sound.total_duration_s=5
        evaluator=self.evaluator()
        with patch('src.main_evaluator.time.monotonic',return_value=100):
            self.api(evaluator,[dict(type='air',level=3),dict(type='kab-bombs',level=1)])
        with patch('src.main_evaluator.time.monotonic',return_value=105):evaluator._refresh()
        records=[r for r in self.records() if r['event']=='decision']
        self.assertEqual(len(records),2)
        self.assertTrue(records[-1]['output']['sound_timer_expired'])
        self.assertEqual(records[-1]['output']['level'],'критическая')
        self.assertEqual(records[-1]['output']['sound_beep_count'],0)

    def test_logging_failure_does_not_change_alarm_result(self):
        evaluator=self.evaluator()
        with patch.object(self.logger,'write',side_effect=OSError('disk unavailable')):
            state=self.api(evaluator,[dict(type='air',level=3),dict(type='kab-bombs',level=1)])
        self.assertEqual(state.level_code,4)
