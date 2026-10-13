import unittest
from src.threat_composition import ThreatComposition
from src.threat_evaluator import Observation
from src.threat_models import ThreatSystemConfig


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.config = ThreatSystemConfig(telegram_channels=['alpha', 'beta'])
        self.rules = {r.id: r for r in self.config.alarm_rules}
        self.composer = ThreatComposition()

    def observe(self, source, kind, approach, event='1', expiry=1000):
        return Observation(source, kind, approach, 100, expiry, 'test evidence', event_id=event)

    def calculate(self, entries, now=100):
        matches = [(self.rules[rule], [observation]) for rule, observation in entries]
        observations = {(o.source, o.threat_type, o.event_id): o for _, o in entries if o.source != 'alarmmap'}
        return self.composer.calculate(matches, observations, ['alpha', 'beta'], {}, {}, True, now)

    def test_baseline_and_all_channel_types_survive_sound_priority(self):
        api = self.observe('alarmmap', 'drone', '')
        rocket = self.observe('telegram:alpha', 'rocket', 'district')
        bomb = self.observe('telegram:beta', 'kab', 'city')
        result = self.calculate([('high_drone', api), ('critical_rocket', rocket), ('high_kab', bomb)])
        self.assertEqual(result['api_baseline']['level_code'], 2)
        self.assertEqual(result['final_level'], 5)
        self.assertEqual(result['active_threat_types'], ['rocket', 'kab', 'drone'])
        self.assertTrue(result['channel_states']['alpha']['raises_level'])
        self.assertFalse(result['channel_states']['beta']['raises_level'])
        self.assertEqual(result['channel_states']['beta']['adds_types'], ['kab'])

    def test_one_channel_cancel_does_not_remove_other_channel_or_api(self):
        api = self.observe('alarmmap', 'drone', '')
        alpha = self.observe('telegram:alpha', 'rocket', 'district')
        beta = self.observe('telegram:beta', 'rocket', 'district')
        self.calculate([('high_drone', api), ('critical_rocket', alpha), ('critical_rocket', beta)])
        result = self.calculate([('high_drone', api), ('critical_rocket', beta)], 110)
        self.assertEqual(result['final_level'], 5)
        self.assertEqual(result['api_baseline']['types'], ['drone'])
        self.assertEqual(result['channel_states']['alpha']['level_code'], 0)
        self.assertEqual(result['channel_states']['beta']['level_code'], 5)
        self.assertEqual(result['new_changes'][0]['source'], 'telegram:alpha')

    def test_expiry_returns_to_base_with_explicit_cause_and_no_duplicate_ticks(self):
        api = self.observe('alarmmap', 'drone', '')
        alpha = self.observe('telegram:alpha', 'rocket', 'district', expiry=120)
        self.calculate([('high_drone', api), ('critical_rocket', alpha)])
        result = self.calculate([('high_drone', api)], 121)
        self.assertEqual(result['final_level'], 2)
        self.assertEqual(result['new_changes'][0]['action'], 'expired')
        self.assertIn('TTL', result['formation_text'])
        self.assertEqual(self.calculate([('high_drone', api)], 122)['new_changes'], [])

    def test_telegram_without_base_and_lower_telegram_cannot_reduce_base(self):
        alpha = self.observe('telegram:alpha', 'rocket', 'launch')
        result = self.calculate([('low_rocket', alpha)])
        self.assertEqual(result['final_level'], 1)
        api = self.observe('alarmmap', 'drone', '')
        result = self.calculate([('low_rocket', alpha), ('critical_drone', api)])
        self.assertEqual(result['final_level'], 4)
        self.assertEqual(result['active_threat_types'], ['rocket', 'drone'])
