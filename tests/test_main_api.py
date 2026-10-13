from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import queue
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import MagicMock, patch
from src.main_config import MainSystemConfig
from src.main_config_dialog import MainConfigDialog
from src.main_evaluator import ApiMainEvaluator, ProfileDurationTimer
from src.threat_models import ThreatSystemConfig
from src.modbus_worker import ModbusWorker
from src.config import AppConfig


class MainAPITests(unittest.TestCase):
    def setUp(self):
        self.background_patch=patch('src.background_common.enabled',return_value=False)
        self.background_patch.start();self.addCleanup(self.background_patch.stop)
        self.legacy=ThreatSystemConfig()
        self.legacy.schedule.enabled=False
        self.config=MainSystemConfig.from_legacy(self.legacy)
        self.audit=patch('src.threat_evaluator.ThreatAuditLogger',return_value=MagicMock())
        self.audit.start()
        self.addCleanup(self.audit.stop)
        self.debug_patch=patch('src.main_evaluator.MainAPIDebugLogger',return_value=MagicMock())
        self.debug_patch.start()
        self.addCleanup(self.debug_patch.stop)
        self.clock=[1000.0]
        self.clock_patch=patch('src.main_evaluator.time.monotonic',side_effect=lambda:self.clock[0])
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)

    def evaluator(self, config=None, **args):
        evaluator=ApiMainEvaluator(config or self.config, **args)
        self.addCleanup(evaluator.stop)
        return evaluator

    def api(self, evaluator, alarms):
        evaluator._alarmmap_online=True
        evaluator._api_last_success=time.time()
        evaluator._alarmmap_active_alarms=alarms
        evaluator._refresh()
        return evaluator.status

    def test_migration_preserves_sounds_and_has_no_dictionary_or_telegram_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.legacy.save(str(root/'config_threats.json'))
            config=MainSystemConfig.load(root/'config_main.json')
            payload=json.loads((root/'config_main.json').read_text(encoding='utf-8'))
            self.assertNotIn('tracking',payload)
            self.assertNotIn('district',payload)
            self.assertNotIn('drone_dict',payload)
            self.assertNotIn('telegram_channels',payload)
            self.assertNotIn('approaches',payload['alarm_rules'][0])
            self.assertEqual(len(config.alarm_rules),12)
            for rule in config.alarm_rules:
                old=next(r for r in self.legacy.alarm_rules if r.id==rule.id)
                if rule.threat_type!='unknown':
                    self.assertEqual(asdict(rule.sound),asdict(old.sound))
                else:
                    self.assertEqual(rule.sound.code,old.sound.code)
            self.assertEqual(config.safe_sound,self.legacy.safe_sound)
            self.assertEqual(config.no_link_sound,self.legacy.no_link_sound)
            self.assertEqual(asdict(MainSystemConfig.load(root/'config_main.json')),asdict(config))
        evaluator=self.evaluator()
        self.assertIsNone(evaluator.tg_reader)
        self.assertFalse(evaluator.config.telegram_enabled)
        self.assertEqual(evaluator.config.district.city_keywords,[])
        evaluator._handle_telegram_message(dict(id='alpha/1',channel='alpha',text='ракета над харьков',timestamp=time.time()))
        self.assertEqual(evaluator._observations,{})

    def test_api_classification_and_all_output_levels_stay_configurable(self):
        evaluator=self.evaluator()
        self.assertEqual(self.api(evaluator,[dict(type='air',level=3)]).active_threat_type,'unknown')
        self.assertEqual(self.api(evaluator,[dict(type='air',level=3),dict(type='fight-drones',level=2)]).active_threat_type,'drone')
        for degree,codes in [('low',[1]),('high',[2]),('critical',[4])]:
            for code in codes:
                with self.subTest(code=code):
                    config=deepcopy(self.config)
                    for rule in config.alarm_rules:
                        rule.enabled=rule.id==degree+'_drone'
                        if rule.enabled:
                            rule.level_code=code
                            rule.api_types=['fight-drones']
                            rule.api_levels=[1]
                            rule.api_levels_by_type={}
                    state=self.api(self.evaluator(config),[dict(type='air',level=2),dict(type='fight-drones',level=1)])
                    self.assertEqual(state.level_code,code)
                    self.assertEqual(state.api_baseline['level_code'],code)

    def test_lifetime_expires_without_reset_on_api_refresh_and_keeps_alarm_bits(self):
        rule=next(r for r in self.config.alarm_rules if r.id=='critical_unknown')
        rule.sound.total_duration_s=60
        evaluator=self.evaluator()
        first=self.api(evaluator,[dict(type='air',level=3)])
        self.assertGreater(first.sound_beep_count,0)
        self.clock[0]+=59
        state=self.api(evaluator,[dict(type='air',level=3)])
        self.assertEqual(state.sound_remaining_s,1)
        self.assertGreater(state.sound_beep_count,0)
        self.clock[0]+=1
        state=self.api(evaluator,[dict(type='air',level=3)])
        self.assertTrue(state.sound_timer_expired)
        self.assertEqual(state.sound_beep_count,0)
        self.assertEqual(state.sound_code,rule.sound.code)
        self.assertEqual(state.level_code,4)
        self.assertTrue(state.modbus_word & (1<<self.config.bit_mapping.bit_type_unknown))
        self.clock[0]+=120
        self.assertTrue(self.api(evaluator,[dict(type='air',level=3)]).sound_timer_expired)
        evaluator.reset_threat_state()
        self.assertEqual(evaluator.status.level_code,4)
        self.assertTrue(evaluator.status.sound_timer_expired)
        self.api(evaluator,[])
        state=self.api(evaluator,[dict(type='air',level=3)])
        self.assertEqual(state.sound_remaining_s,60)
        self.assertGreater(state.sound_beep_count,0)

    def test_zero_is_unlimited_and_timer_can_survive_config_reload(self):
        evaluator=self.evaluator()
        self.api(evaluator,[dict(type='air',level=3)])
        self.clock[0]+=500
        self.assertGreater(self.api(evaluator,[dict(type='air',level=3)]).sound_beep_count,0)
        config=deepcopy(self.config)
        next(r for r in config.alarm_rules if r.id=='critical_unknown').sound.total_duration_s=600
        replacement=self.evaluator(config,sound_timer=evaluator.sound_timer)
        self.assertEqual(self.api(replacement,[dict(type='air',level=3)]).sound_remaining_s,100)

    def test_mute_does_not_restart_selected_profile_timer_and_offline_profile_has_limit(self):
        next(r for r in self.config.alarm_rules if r.id=='critical_unknown').sound.total_duration_s=60
        self.config.no_link_sound.total_duration_s=10
        evaluator=self.evaluator()
        self.api(evaluator,[dict(type='air',level=3)])
        self.clock[0]+=30
        with patch.object(type(evaluator.config.schedule),'is_in_schedule',return_value=True):
            self.assertEqual(self.api(evaluator,[dict(type='air',level=3)]).sound_beep_count,0)
        self.clock[0]+=30
        self.assertTrue(self.api(evaluator,[dict(type='air',level=3)]).sound_timer_expired)
        evaluator._alarmmap_online=False
        evaluator._api_last_success=0
        evaluator._alarmmap_active_alarms=[]
        evaluator._refresh()
        self.assertEqual(evaluator.status.sound_code,13)
        self.clock[0]+=10
        evaluator._refresh()
        self.assertTrue(evaluator.status.sound_timer_expired)

    def test_main_dialog_has_no_dictionary_tabs_and_saves_timer_and_levels(self):
        root=tk.Tk();root.withdraw();saved=[]
        dialog=MainConfigDialog(root,self.config,saved.append,persist=False)
        dialog.withdraw()
        try:
            titles=[dialog.notebook.tab(t,'text') for t in dialog.notebook.tabs()]
            self.assertEqual(titles,['API','Уровни по API','Звуковые профили','ПЛК','Тихий час'])
            timer=dialog.sound_profile_entries['critical_unknown'][-1]
            timer.delete(0,'end');timer.insert(0,'120')
            dialog.rule_inputs['critical_unknown']['api']['air'][3].set(True)
            with patch('src.main_config_dialog.messagebox.showerror') as error:
                dialog._save_and_close()
                self.assertFalse(error.called,error.call_args)
            self.assertEqual(len(saved),1)
            rule=next(r for r in saved[0].alarm_rules if r.id=='critical_unknown')
            self.assertEqual(rule.sound.total_duration_s,120)
            self.assertEqual(rule.level_code,4)
            self.assertEqual(rule.api_levels_by_type['air'],[3])
        finally:
            if dialog.winfo_exists():dialog.destroy()
            root.destroy()

    def test_stop_sound_command_keeps_modbus_format_and_alarm_word(self):
        next(r for r in self.config.alarm_rules if r.id=='critical_unknown').sound.total_duration_s=1
        evaluator=self.evaluator()
        self.api(evaluator,[dict(type='air',level=3)])
        self.clock[0]+=1
        state=self.api(evaluator,[dict(type='air',level=3)])
        worker=ModbusWorker(AppConfig(),queue.Queue())
        worker.set_control_snapshot(state.modbus_word,[state.sound_code,state.sound_beep_count,
            state.sound_duration_ms,state.sound_pause_ms,state.sound_interval_ms])
        client=MagicMock()
        client.write_registers.return_value.isError.return_value=False
        client.write_register.return_value.isError.return_value=False
        worker._control_cycle(client,None,None)
        values=client.write_registers.call_args.kwargs['values']
        self.assertEqual(len(values),5)
        self.assertEqual(values[1],0)
        self.assertTrue(client.write_register.call_args.kwargs['value'] & (1<<self.config.bit_mapping.bit_threat_city_critical))

    def test_saving_main_settings_preserves_active_api_state_and_timer(self):
        from src.app import ModbusApp
        next(r for r in self.config.alarm_rules if r.id=='critical_unknown').sound.total_duration_s=120
        with patch('src.app.MainSystemConfig.load',return_value=self.config), \
             patch.object(ApiMainEvaluator,'start'), patch.object(ModbusApp,'_auto_connect_plc'):
            app=ModbusApp()
            app.withdraw()
            try:
                self.api(app.threat_evaluator,[dict(type='air',level=3)])
                self.clock[0]+=30
                app._on_threat_config_saved(deepcopy(self.config))
                app.threat_evaluator._refresh()
                state=app.threat_evaluator.status
                self.assertEqual(state.sound_remaining_s,90)
                self.assertEqual(state.level_code,4)
                self.assertTrue(state.alarmmap_online)
            finally:
                app._on_close()

    def test_unqualified_air_is_general_and_lower_card_does_not_invent_explicit_type(self):
        from src.app import format_api_brief
        config=deepcopy(self.config)
        for rule in config.alarm_rules:
            rule.enabled=rule.id=='high_unknown'
            if rule.enabled:
                rule.api_types=['air'];rule.api_levels_by_type={'air':[1,2,3]}
        evaluator=self.evaluator(config)
        for level in (1,2,3):
            state=self.api(evaluator,[dict(type='air',level=level)])
            self.assertEqual(state.active_threat_type,'unknown')
            self.assertFalse(state.has_drone)
            self.assertFalse(state.alarmmap_has_drone)
            self.assertEqual(state.level_code,2)
            self.assertIn('общая воздушная',state.level_title)
            brief=format_api_brief(state)
            self.assertIn('Уточнение типа от API: не указан API',brief)
            self.assertIn('Уровень уточняющей угрозы API: не указан API',brief)
            self.assertNotIn('Дроновая',brief)
        explicit=self.evaluator()
        state=self.api(explicit,[dict(type='air',level=2),dict(type='fight-drones',level=1)])
        self.assertTrue(state.has_drone)
        self.assertIn('Уточнение типа от API: Дроновая',format_api_brief(state))
        self.assertIn('Уровень уточняющей угрозы API: 1',format_api_brief(state))

    def test_migration_merges_general_air_into_rocket_and_keeps_rocket_sound_settings(self):
        legacy=deepcopy(self.legacy)
        rule=next(r for r in legacy.alarm_rules if r.id=='high_drone')
        rule.enabled=True;rule.api_types=['air','fight-drones'];rule.api_levels_by_type={'air':[2],'fight-drones':[1]}
        rule.sound.beep_count=0;rule.sound.total_duration_s=120
        config=MainSystemConfig.from_legacy(legacy)
        general=next(r for r in config.alarm_rules if r.id=='high_rocket')
        drone=next(r for r in config.alarm_rules if r.id=='high_drone')
        self.assertNotIn('air',drone.api_types)
        self.assertIn(2,general.api_levels_by_type['air'])
        old_rocket=next(r for r in legacy.alarm_rules if r.id=='high_rocket')
        self.assertEqual(asdict(general.sound),asdict(old_rocket.sound))
        self.assertNotEqual(general.sound.code,drone.sound.code)

    def test_invalid_timer_does_not_replace_saved_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'config_main.json'
            self.config.save(path)
            before=path.read_bytes()
            self.config.safe_sound.total_duration_s=-1
            with self.assertRaises(ValueError):self.config.save(path)
            self.assertEqual(path.read_bytes(),before)
