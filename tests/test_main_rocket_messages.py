from copy import deepcopy
from datetime import datetime, timezone
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from src.main_config import MainSystemConfig
from src.main_evaluator import ApiMainEvaluator
from src.threat_models import ThreatSystemConfig
from src.app import format_api_brief


class RocketMessageTests(unittest.TestCase):
    def setUp(self):
        self.now = 1800000000.0
        self.config = MainSystemConfig.from_legacy(ThreatSystemConfig())
        self.config.schedule.enabled = False
        self.config.rocket_message_ttl_s = 600
        self.city = self.config.alarmmap_katottg
        self.region = 'UA63000000000041885'
        self.clock = patch('src.main_evaluator.time.time', side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.audit = patch('src.threat_evaluator.ThreatAuditLogger', return_value=MagicMock())
        self.audit.start()
        self.addCleanup(self.audit.stop)
        self.ev = ApiMainEvaluator(self.config, debug_logger=MagicMock())
        self.ev._message_territories = {self.city, self.region}
        self.addCleanup(self.ev.stop)

    def message(self, kind='rocket', codes=None, age=0):
        return dict(type=kind, title='Ракетная опасность', text='Сообщение API',
                    date=datetime.fromtimestamp(self.now-age, timezone.utc).isoformat(),
                    katottgs=codes if codes is not None else [self.city])

    def sample(self, messages, alarms=None):
        self.ev._alarmmap_active_alarms = alarms if alarms is not None else [dict(type='air', level=3, katottg=self.city)]
        self.ev._alarmmap_online = True
        self.ev._api_last_success = self.now
        self.ev._api_messages = messages
        self.ev._api_messages_last_success = self.now
        self.ev._refresh()
        return self.ev.status

    def test_explicit_types_select_rocket_sound_and_actual_message_in_card(self):
        for kind in ('rocket', 'ballistics'):
            state = self.sample([self.message(kind)])
            self.assertTrue(state.has_rocket)
            self.assertFalse(state.has_unknown)
            self.assertEqual(state.level_code, 4)
            self.assertEqual(state.active_rule_id, 'critical_rocket')
            self.assertEqual(state.sound_code, next(r.sound.code for r in self.config.alarm_rules if r.id=='critical_rocket'))
            self.assertIn('отдельного уровня нет', format_api_brief(state))
            self.assertIn('event/'+kind, state.reason)

    def test_territory_global_age_and_future_filters(self):
        cases = [self.message(codes=['global']), self.message(codes=['other']),
                 self.message(age=600), self.message(age=900), self.message(age=-1),
                 dict(type='rocket', date='broken', katottgs=[self.city]),
                 dict(type='rocket', date='2026-10-10T12:00:00', katottgs=[self.city])]
        for message in cases:
            with self.subTest(message=message):
                state = self.sample([message])
                self.assertFalse(state.has_rocket)
                self.assertTrue(state.has_unknown)
                self.assertEqual(state.level_code,4)
        self.assertTrue(self.sample([self.message(codes=[self.region])]).has_rocket)

    def test_ttl_is_from_event_time_not_repeated_poll_time_and_clear_removes_type(self):
        message = self.message()
        self.assertTrue(self.sample([message]).has_rocket)
        self.now += 599
        self.assertTrue(self.sample([message]).has_rocket)
        self.now += 1
        self.assertTrue(self.sample([message]).has_unknown)
        self.assertFalse(self.sample([self.message()], alarms=[]).has_rocket)
        self.assertEqual(self.ev.status.level_code, 0)

    def test_rocket_can_coexist_with_explicit_drone(self):
        state = self.sample([self.message()], alarms=[dict(type='air',level=3),dict(type='fight-drones',level=2)])
        self.assertTrue(state.has_drone)
        self.assertTrue(state.has_rocket)
        self.assertFalse(state.has_unknown)

    def test_invalid_or_missing_message_feed_never_discards_air_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            key=Path(folder)/'key.txt';key.write_text('test-secret',encoding='utf-8')
            self.ev.config.alarmmap_key_file=str(key)
            self.ev._territories_loaded=self.now
            self.ev._catalog_last_success=self.now
            response=MagicMock()
            response.__enter__.return_value.read.return_value=json.dumps({'data':[{'type':'air','level':3}]}).encode()
            with patch('urllib.request.urlopen',side_effect=[response,OSError('feed unavailable')]):
                self.ev._poll_alarmmap()
            self.assertTrue(self.ev.status.alarmmap_online)
            self.assertTrue(self.ev.status.has_unknown)
            self.assertEqual(self.ev.status.level_code,4)
            self.assertIn('feed unavailable',self.ev._api_messages_error)

    def test_migration_preserves_general_levels_and_timings_without_rocket_inference(self):
        old=deepcopy(self.config)
        old.air_classification_version=3
        general=next(r for r in old.alarm_rules if r.id=='critical_unknown')
        general.enabled=False;general.api_types=[]
        rocket=next(r for r in old.alarm_rules if r.id=='critical_rocket')
        rocket.sound.total_duration_s=123
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'config.json';old.save(path)
            migrated=MainSystemConfig.load(path)
        migrated_general=next(r for r in migrated.alarm_rules if r.id=='critical_unknown')
        self.assertEqual(migrated.air_classification_version,4)
        self.assertEqual(migrated_general.api_levels_by_type['air'],rocket.api_levels_by_type.get('air',rocket.api_levels))
        self.assertEqual(migrated_general.sound.total_duration_s,123)
        self.assertEqual(rocket.sound.code,next(r.sound.code for r in migrated.alarm_rules if r.id=='critical_rocket'))

    def test_history_window_disappearance_is_not_cancellation(self):
        message=self.message()
        self.sample([message])
        self.now+=10
        merged=self.ev._merge_message_history([self.message(codes=['other'])])
        self.assertIn(message,merged)
        self.assertTrue(self.sample(merged).has_rocket)
        self.now+=600
        self.assertNotIn(message,self.ev._merge_message_history([]))

    def test_parent_lookup_uses_provider_hierarchy(self):
        self.ev._message_territories=set()
        values={self.city:dict(katottg=self.city,parent_katottg=self.region),
                self.region:dict(katottg=self.region,parent_katottg=None)}
        with patch.object(self.ev,'_request_api',side_effect=lambda suffix,key:values[suffix.rsplit('/',1)[-1]]):
            self.ev._load_message_territories('test')
        self.assertEqual(self.ev._message_territories,{self.city,self.region})
