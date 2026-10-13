from copy import deepcopy
import unittest
from unittest.mock import MagicMock, patch
from src.archive_replay import ArchiveReplay
from src.threat_evaluator import ThreatEvaluator
from src.threat_models import ThreatSystemConfig


class LiveCompositionTests(unittest.TestCase):
    def setUp(self):
        self.background_patch=patch('src.background_common.enabled',return_value=False)
        self.background_patch.start();self.addCleanup(self.background_patch.stop)
        self.clock = [1791370800.0]
        self.time_patch = patch('src.threat_evaluator.time.time', side_effect=lambda: self.clock[0])
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        self.audit_patch = patch('src.threat_evaluator.ThreatAuditLogger', return_value=MagicMock())
        self.audit_patch.start()
        self.addCleanup(self.audit_patch.stop)
        self.config = ThreatSystemConfig(telegram_channels=['alpha', 'beta'])
        self.config.schedule.enabled = False
        self.e = ThreatEvaluator(self.config)
        self.addCleanup(self.e.stop)
        for channel in self.config.telegram_channels:
            self.e._on_tg_health(channel, True)
        self.api([dict(type='air', level=2)])
        self.counter = 0

    def api(self, alarms):
        self.e._alarmmap_online = True
        self.e._api_last_success = self.clock[0]
        self.e._alarmmap_active_alarms = alarms
        self.e._refresh()

    def message(self, text, channel='alpha'):
        self.counter += 1
        self.clock[0] += 1
        payload = dict(id=f'{channel}/{self.counter}', channel=channel, text=text, timestamp=self.clock[0])
        self.e._handle_telegram_message(payload)
        return payload

    def test_baseline_types_raise_and_independent_channel_cancel_reach_control_word(self):
        self.message('ракета над основа')
        self.message('каб над харьков', 'beta')
        state = self.e.status
        self.assertEqual(state.api_baseline['types'], ['drone'])
        self.assertEqual(state.level_code, 5)
        self.assertEqual(state.active_threat_types, ['rocket', 'kab', 'drone'])
        self.assertEqual(state.sound_code, 1)
        self.assertEqual(state.modbus_word & ((1 << 6) | (1 << 7) | (1 << 8)), (1 << 6) | (1 << 7) | (1 << 8))
        self.message('отбой ракеты харьков')
        self.assertEqual(self.e.status.channel_states['alpha']['level_code'], 0)
        self.assertEqual(self.e.status.channel_states['beta']['level_code'], 2)
        self.assertEqual(self.e.status.active_threat_types, ['kab', 'drone'])
        self.assertEqual(self.e.status.level_code, 2)
        self.assertTrue(any('Отбой' in change['summary'] for change in self.e.status.channel_states['alpha']['changes']))

    def test_same_severity_uses_maximum_proximity_and_one_sound_profile(self):
        self.api([dict(type='air', level=3)])
        self.message('шахед над основа')
        self.assertEqual(self.e.status.level_code, 5)
        self.assertEqual(self.e.status.sound_code, 1)
        self.assertEqual(self.e.status.active_rule_id, 'critical_rocket')
        self.assertTrue(self.e.status.has_drone)
        self.assertTrue(self.e.status.has_rocket)

    def test_expiry_returns_to_api_and_explains_source(self):
        self.message('ракета над основа')
        self.clock[0] += self.config.district.ttl_seconds + 1
        self.e._api_last_success = self.clock[0]
        for channel in self.config.telegram_channels:
            self.e._on_tg_health(channel, True)
        self.e._refresh()
        self.assertEqual(self.e.status.level_code, 2)
        self.assertEqual(self.e.status.active_threat_types, ['drone'])
        self.assertIn('@alpha', self.e.status.reason)
        self.assertIn('TTL', self.e.status.reason)

    def test_no_api_baseline_still_allows_telegram_and_channel_context_never_crosses(self):
        self.api([])
        self.message('пуск ракеты')
        self.message('на основа', 'beta')
        self.assertEqual(self.e.status.api_baseline['level_code'], 0)
        self.assertEqual(self.e.status.channel_states['alpha']['level_code'], 1)
        self.assertEqual(self.e.status.channel_states['beta']['level_code'], 0)

    def test_movement_away_obeys_existing_hold_and_keeps_api_floor(self):
        self.message('ракета над харьков')
        self.message('уходит от города')
        latest = self.e.status.channel_states['alpha']['tracks'][0]
        self.assertEqual(latest['direction'], 'От города')
        self.assertEqual(latest['proximity'], 'Вне города')
        self.assertTrue(any(o.resolution for o in self.e._observations.values()))
        self.clock[0] += self.config.tracking.movement_hold_seconds + 1
        self.e._api_last_success = self.clock[0]
        self.e._refresh()
        self.assertEqual(self.e.status.active_threat_types, ['drone'])
        self.assertEqual(self.e.status.level_code, 2)

    def test_mute_and_switch_keep_all_aggregate_bits_suppressed(self):
        self.message('ракета над основа')
        with patch.object(type(self.config.schedule), 'is_in_schedule', return_value=True):
            self.e._refresh()
            self.assertEqual(self.e.status.modbus_word & ((1 << 6) | (1 << 8)), 0)
            self.assertEqual(self.e.status.sound_beep_count, 0)
        self.e.set_plc_analysis_switch(False)
        self.assertEqual(self.e.status.level_code, 0)
        self.assertEqual(self.e.status.modbus_word & ((1 << 6) | (1 << 8)), 0)
        self.assertEqual(self.e.status.sound_beep_count, 0)

    def test_main_window_uses_api_without_internal_channel_chats(self):
        from src.app import ModbusApp
        from src.main_config import MainSystemConfig
        with patch('src.main_evaluator.MainAPIDebugLogger', return_value=MagicMock()), \
             patch('src.app.MainSystemConfig.load', return_value=MainSystemConfig.from_legacy(self.config)), \
             patch.object(ThreatEvaluator, 'start'), patch.object(ModbusApp, '_auto_connect_plc'):
            window = ModbusApp()
            window.withdraw()
            try:
                self.assertIsNone(window.threat_evaluator.tg_reader)
                self.assertFalse(window.threat_evaluator.config.telegram_enabled)
                self.assertFalse(hasattr(window, 'channel_panels'))
                window.threat_evaluator._alarmmap_online = True
                window.threat_evaluator._api_last_success = self.clock[0]
                window.threat_evaluator._alarmmap_active_alarms = [dict(type='air', level=2)]
                window.threat_evaluator._refresh()
                window._apply_threat_status_ui(window.threat_evaluator.status)
                self.assertIn('База API', window.txt_threat_reason.get('1.0', 'end'))
                self.assertIn('без ограничения', window.var_sound_timer.get())
            finally:
                window._on_close()

    def test_archive_and_live_share_the_same_parser_and_result(self):
        messages = [self.message('пуск ракеты'), self.message('на харьков'),
                    self.message('каб над основа', 'beta'), self.message('уходит от города')]
        live = deepcopy(self.e.status)
        replay = ArchiveReplay(messages, self.config, [dict(type='air', level=2)])
        for _ in messages:
            archive = replay.step()
        for field in ('level_code', 'active_threat_types', 'sound_code', 'active_rule_id'):
            self.assertEqual(getattr(live, field), getattr(archive, field), field)
        self.assertEqual(live.channel_states['alpha']['tracks'][0]['direction'], archive.channel_states['alpha']['tracks'][0]['direction'])

    def test_general_air_levels_in_parent_territories_do_not_invent_a_second_type(self):
        self.api([dict(type='air', level=2), dict(type='air', level=3)])
        self.assertEqual(self.e.status.api_baseline['types'], ['rocket'])
        self.assertEqual(self.e.status.active_threat_types, ['rocket'])
        self.assertFalse(self.e.status.has_drone)
        self.assertEqual(self.e.status.level_code, 4)

    def test_explicit_shelter_call_is_not_hidden_by_outside_motion_label(self):
        self.message('за городом, в укрытие харьков')
        self.assertGreater(self.e.status.channel_states['alpha']['level_code'], 0)
        self.assertTrue(self.e.status.has_unknown)
