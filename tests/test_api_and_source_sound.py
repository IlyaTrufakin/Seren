"""Regression coverage for API clarifications, source-loss sound and configuration migration."""
from dataclasses import asdict
import json
from pathlib import Path
import queue
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from src.config import AppConfig
from src.modbus_worker import ModbusWorker
from src.threat_evaluator import ThreatEvaluator
from src.threat_models import NO_LINK_SOUND_CODE, ThreatSystemConfig


class APISoundTests(unittest.TestCase):
    def setUp(self):
        self.background_patch=patch('src.background_common.enabled',return_value=False)
        self.background_patch.start();self.addCleanup(self.background_patch.stop)
        self.audit = patch('src.threat_evaluator.ThreatAuditLogger', return_value=MagicMock())
        self.audit.start()
        self.addCleanup(self.audit.stop)
        self.config = ThreatSystemConfig(telegram_enabled=False, alarmmap_enabled=True)
        self.config.schedule.enabled = False
        self.evaluator = ThreatEvaluator(self.config)
        self.addCleanup(self.evaluator.stop)

    def api(self, events):
        self.evaluator._alarmmap_online = True
        self.evaluator._api_last_success = time.time()
        self.evaluator._alarmmap_active_alarms = events
        self.evaluator._refresh()
        return self.evaluator.status

    def test_unqualified_air_uses_level_three_only_for_rocket(self):
        for level, expected in ((1, 'low_drone'), (2, 'high_drone'), (3, 'critical_rocket')):
            with self.subTest(level=level):
                status = self.api([dict(type='air', level=level)])
                self.assertEqual(status.active_rule_id, expected)
                self.assertEqual(status.has_rocket, level == 3)
                self.assertEqual(status.sound_code, next(r.sound.code for r in self.config.alarm_rules if r.id == expected))
                self.assertIn('Без уточнения', status.reason)

    def test_clarifications_override_air_in_either_order_and_parent_territory(self):
        for kind, expected_type in (('fight-drones', 'drone'), ('fpv-drones', 'drone'),
                                    ('fpv', 'drone'), ('kab-bombs', 'kab')):
            for explicit_level, severity in ((1, 'high'), (2, 'critical')):
                for reverse in (False, True):
                    with self.subTest(kind=kind, level=explicit_level, reverse=reverse):
                        events = [dict(type='air', level=3, katottg='parent'),
                                  dict(type=kind, level=explicit_level, katottg='city')]
                        status = self.api(events[::-1] if reverse else events)
                        self.assertEqual(status.active_rule_id, severity + '_' + expected_type)
                        self.assertFalse(status.has_rocket)
                        self.assertEqual(status.alarmmap_active_count, 2)
                        self.assertIn('тип определяют уточнения', status.alarmmap_full_text)
                        self.assertNotIn('API air/3', status.reason)

    def test_multiple_clarifications_keep_severity_priority(self):
        status = self.api([dict(type='air', level=3), dict(type='kab-bombs', level=1),
                           dict(type='fight-drones', level=2)])
        self.assertEqual(status.active_rule_id, 'critical_drone')
        status = self.api([dict(type='air', level=3), dict(type='kab-bombs', level=2),
                           dict(type='fpv-drones', level=2)])
        self.assertEqual(status.active_rule_id, 'critical_kab')

    def test_filtered_explicit_type_never_falls_back_to_general_rocket(self):
        for rule in self.config.alarm_rules:
            if rule.threat_type == 'drone':
                rule.enabled = False
        status = self.api([dict(type='air', level=3), dict(type='fight-drones', level=2)])
        self.assertEqual(status.active_rule_id, '')
        self.assertFalse(status.has_rocket)

    def test_api_type_filter_cannot_relabel_a_drone_as_rocket(self):
        rule = next(r for r in self.config.alarm_rules if r.id == 'critical_rocket')
        rule.api_types = ['fight-drones', 'air']
        rule.api_levels = [2, 3]
        status = self.api([dict(type='fight-drones', level=2)])
        self.assertEqual(status.active_rule_id, 'critical_drone')
        status = self.api([dict(type='air', level=2)])
        self.assertEqual(status.active_rule_id, 'high_drone')

    def test_telegram_rocket_remains_independent_of_api_clarification(self):
        self.config.telegram_enabled = True
        self.config.telegram_channels = ['alpha']
        self.evaluator._on_tg_health('alpha', True)
        self.api([dict(type='air', level=3), dict(type='fight-drones', level=1)])
        self.evaluator._handle_telegram_message(dict(id='alpha/1', channel='alpha',
            text='ракета над основа', timestamp=time.time()))
        self.assertEqual(self.evaluator.status.active_rule_id, 'critical_rocket')
        self.assertEqual(self.evaluator.status.matched_sources, ['alarmmap', 'telegram:alpha'])
        self.assertTrue(self.evaluator.status.has_drone)
        self.assertTrue(self.evaluator.status.has_rocket)

    def test_fpv_catalog_title_and_unrecognised_levels(self):
        self.evaluator._api_catalog = {('tactical-uav', 2): dict(title='Загроза FPV-дронів')}
        rule = next(r for r in self.config.alarm_rules if r.id == 'critical_drone')
        rule.api_types.append('tactical-uav')
        status = self.api([dict(type='air', level=3), dict(type='tactical-uav', level=2)])
        self.assertEqual(status.active_rule_id, 'critical_drone')
        status = self.api([dict(type='air', level=3), dict(type='fight-drones', level=99)])
        self.assertEqual(status.active_rule_id, '')
        self.assertFalse(status.has_rocket)
        self.evaluator._api_catalog = {('other', 1): dict(title=None)}
        self.api([dict(type='other', level=1)])

    def test_source_loss_is_shown_in_main_window(self):
        from src.app import ModbusApp
        from src.main_config import MainSystemConfig
        with patch('src.main_evaluator.MainAPIDebugLogger', return_value=MagicMock()), \
             patch('src.app.MainSystemConfig.load', return_value=MainSystemConfig.from_legacy(self.config)), \
             patch('src.app.AppConfig.load', return_value=AppConfig()), \
             patch.object(ThreatEvaluator, 'start'), \
             patch.object(ModbusApp, '_auto_connect_plc'):
            app = ModbusApp()
            app.withdraw()
            try:
                self.evaluator._refresh()
                app._apply_threat_status_ui(self.evaluator.status)
                self.assertIn('Нет связи', app.var_threat_title.get())
                self.assertIn('Нет связи', app.var_sound_title.get())
                self.assertEqual(app.lbl_threat_badge.cget('bg'), '#78350f')
                app._apply_threat_status_ui(self.api([]))
                self.assertIn('Отсутствие тревог', app.var_threat_title.get())
                self.assertEqual(app.lbl_threat_badge.cget('bg'), '#065f46')
            finally:
                app._on_close()

    def test_api_air_two_and_explicit_drone_ignore_telegram_group_filter(self):
        rule = next(r for r in self.config.alarm_rules if r.id == 'high_drone')
        for groups in ([3], [1], []):
            rule.drone_groups = groups
            for events in ([dict(type='air', level=2)],
                           [dict(type='air', level=2), dict(type='fight-drones', level=1)]):
                with self.subTest(groups=groups, events=events):
                    status = self.api(events)
                    self.assertEqual(status.active_rule_id, 'high_drone')
                    self.assertEqual(status.level_code, 2)
                    self.assertEqual(status.sound_code, 7)
                    self.assertTrue(status.has_drone)
                    self.assertFalse(status.has_rocket)

    def test_api_only_drone_rule_can_have_no_telegram_groups(self):
        rule = next(r for r in self.config.alarm_rules if r.id == 'critical_drone')
        rule.sources = ['alarmmap']
        rule.drone_groups = []
        self.config.validate()
        self.assertEqual(self.api([dict(type='fight-drones', level=2)]).active_rule_id, 'critical_drone')
        rule.sources.append('telegram:*')
        with self.assertRaises(ValueError):
            self.config.validate()

    def test_source_loss_sound_and_recovery(self):
        self.evaluator._refresh()
        status = self.evaluator.status
        self.assertTrue(status.no_data_link)
        self.assertEqual(status.sound_code, NO_LINK_SOUND_CODE)
        self.assertEqual(status.level_title, 'Нет связи с онлайн-источниками')
        self.assertTrue(status.modbus_word & (1 << self.config.bit_mapping.bit_no_link))
        status = self.api([])
        self.assertFalse(status.no_data_link)
        self.assertEqual(status.sound_code, 0)
        self.assertEqual(status.level_title, 'Отсутствие тревог')
        self.evaluator._api_last_success -= self.config.api_stale_seconds + 1
        self.evaluator._refresh()
        self.assertEqual(self.evaluator.status.sound_code, NO_LINK_SOUND_CODE)

    def test_partial_loss_and_disabled_sources(self):
        self.config.telegram_enabled = True
        self.config.telegram_channels = ['alpha', 'beta']
        self.evaluator._on_tg_health('alpha', True)
        self.evaluator._on_tg_health('beta', False, 'offline')
        status = self.api([])
        self.assertEqual(status.sound_code, NO_LINK_SOUND_CODE)
        self.assertIn('telegram:beta', status.reason)
        self.evaluator._on_tg_health('beta', True)
        self.evaluator._refresh()
        self.assertEqual(self.evaluator.status.sound_code, 0)
        self.config.telegram_enabled = self.config.alarmmap_enabled = False
        self.evaluator._refresh()
        self.assertFalse(self.evaluator.status.no_data_link)
        self.assertEqual(self.evaluator.status.sound_code, 0)

    def test_fresh_alarm_has_priority_over_source_loss_and_stale_alarm_does_not(self):
        self.api([dict(type='air', level=3)])
        self.evaluator._alarmmap_online = False
        self.evaluator._refresh()
        self.assertTrue(self.evaluator.status.no_data_link)
        self.assertEqual(self.evaluator.status.sound_code, 1)
        self.evaluator._api_last_success -= self.config.api_stale_seconds + 1
        self.evaluator._refresh()
        self.assertEqual(self.evaluator.status.sound_code, NO_LINK_SOUND_CODE)
        self.assertEqual(self.evaluator.status.active_rule_id, '')
        self.assertIn('УСТАРЕВШИЕ', self.evaluator.status.alarmmap_full_text)

    def test_source_loss_sound_respects_mute_switch_and_custom_parameters(self):
        self.config.no_link_sound.beep_count = 4
        self.evaluator._refresh()
        self.assertEqual(self.evaluator.status.sound_beep_count, 4)
        with patch.object(type(self.config.schedule), 'is_in_schedule', return_value=True):
            self.evaluator._refresh()
            self.assertEqual(self.evaluator.status.sound_beep_count, 0)
        self.evaluator.set_plc_analysis_switch(False)
        self.assertEqual(self.evaluator.status.sound_beep_count, 0)
        self.evaluator.set_plc_analysis_switch(True)
        self.assertEqual(self.evaluator.status.sound_code, NO_LINK_SOUND_CODE)
        self.config.no_link_sound.beep_count = 0
        self.evaluator._refresh()
        self.assertEqual(self.evaluator.status.sound_beep_count, 0)

    def test_no_link_profile_is_delivered_with_mw1_preserved(self):
        self.evaluator._refresh()
        status = self.evaluator.status
        worker = ModbusWorker(AppConfig(), queue.Queue())
        values = [status.sound_code, status.sound_beep_count, status.sound_duration_ms,
                  status.sound_pause_ms, status.sound_interval_ms]
        worker.set_control_snapshot(status.modbus_word, values)
        client = MagicMock()
        client.write_registers.return_value.isError.return_value = False
        client.write_register.return_value.isError.return_value = False
        ok, _, _ = worker._control_cycle(client, None, None)
        self.assertTrue(ok)
        self.assertEqual(client.write_registers.call_args.kwargs, dict(address=2, values=values, device_id=255))
        self.assertEqual(client.write_register.call_args.kwargs['address'], 0)


class ConfigurationMigrationTests(unittest.TestCase):
    def test_legacy_config_migrates_only_new_api_paths(self):
        cfg = ThreatSystemConfig()
        legacy = asdict(cfg)
        legacy.pop('api_classification_version')
        legacy.pop('no_link_sound')
        for row in legacy['alarm_rules']:
            row.pop('api_levels_by_type')
            if row['threat_type'] == 'drone':
                row['api_types'] = ['fight-drones']
        legacy['alarm_rules'][0]['sound']['beep_duration_ms'] = 510
        legacy['alarm_rules'][0]['sources'] = ['telegram:*']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(legacy), encoding='utf-8')
            loaded = ThreatSystemConfig.load(path)
            self.assertEqual(loaded.alarm_rules[0].sound.beep_duration_ms, 510)
            self.assertEqual(loaded.alarm_rules[0].sources, ['telegram:*'])
            for rule in loaded.alarm_rules:
                if rule.threat_type == 'drone':
                    self.assertIn('air', rule.api_types)
                    self.assertIn('fpv-drones', rule.api_types)
                    self.assertEqual(rule.api_levels_by_type['air'],
                                     {'critical': [], 'high': [2], 'low': [1]}[rule.severity])
            loaded.no_link_sound.beep_count = 4
            loaded.save(path)
            again = ThreatSystemConfig.load(path)
            self.assertEqual(asdict(loaded), asdict(again))
            self.assertEqual(len(again.alarm_rules), 12)
            self.assertEqual(again.no_link_sound.code, 13)

    def test_new_config_keeps_custom_api_filters_and_validates_new_sound(self):
        cfg = ThreatSystemConfig()
        rule = next(r for r in cfg.alarm_rules if r.id == 'high_drone')
        rule.api_types = ['air']
        rule.api_levels_by_type['air'] = [1, 2]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            cfg.save(path)
            loaded = ThreatSystemConfig.load(path)
            selected = next(r for r in loaded.alarm_rules if r.id == 'high_drone')
            self.assertEqual(selected.api_types, ['air'])
            self.assertEqual(selected.api_levels_by_type['air'], [1, 2])
            before = path.read_text(encoding='utf-8')
            loaded.no_link_sound.beep_duration_ms = 11
            with self.assertRaises(ValueError):
                loaded.save(path)
            self.assertEqual(path.read_text(encoding='utf-8'), before)

    def test_no_link_profile_can_be_edited_and_saved_in_dialog(self):
        import tkinter as tk
        from src.threat_config_dialog import ThreatConfigDialog
        root = tk.Tk()
        root.withdraw()
        cfg = ThreatSystemConfig()
        callback = MagicMock()
        try:
            dialog = ThreatConfigDialog(root, cfg, callback)
            dialog.withdraw()
            self.assertIn('air_levels', dialog.rule_inputs['high_drone'])
            entry = dialog.sound_profile_entries['no_link'][0]
            entry.delete(0, 'end')
            entry.insert(0, '4')
            with patch.object(dialog, '_save_to_json') as save, patch('src.threat_config_dialog.messagebox.showinfo'):
                dialog._save_and_close()
            save.assert_called_once()
            self.assertEqual(callback.call_args.args[0].no_link_sound.beep_count, 4)
            self.assertEqual(cfg.no_link_sound.beep_count, 2)
        finally:
            root.destroy()
