import unittest
from src.archive_replay import ArchiveReplay
from src.threat_models import ThreatSystemConfig


class MovementRetentionTests(unittest.TestCase):
    def config(self):
        config = ThreatSystemConfig(telegram_channels=['alpha', 'beta'])
        config.schedule.enabled = False
        return config

    def message(self, ident, offset, text, channel='alpha'):
        return dict(id=f'{channel}/{ident}', channel=channel, timestamp=1000+offset, text=text)

    def test_unknown_destination_preserves_original_ttl_for_shorten_and_replace(self):
        for action in ('shorten', 'replace'):
            with self.subTest(action=action):
                cfg = self.config()
                cfg.tracking.movement_action = action
                replay = ArchiveReplay([
                    self.message(1, 0, 'пуск КАБ'),
                    self.message(2, 85, 'КАБ змінює курс на Тернову'),
                    self.message(3, 160, 'КАБ перетинає кордон на Веселе'),
                ], cfg)
                for _ in range(3):
                    replay.step()
                original = next(o for o in replay.evaluator._observations.values() if o.event_id == 'alpha/1')
                self.assertEqual(original.expires_at, 1600)
                self.assertEqual(replay.evaluator._channel_context['telegram:alpha']['event_id'], 'alpha/1')
                self.assertIn('прежняя тревога сохранена', replay.evaluator.status.reason)
                replay.advance(1599)
                self.assertEqual(replay.evaluator.status.level_code, 1)
                replay.advance(1600)
                self.assertEqual(replay.evaluator.status.level_code, 0)

    def test_recognized_location_without_enabled_rule_preserves_prior_alarm(self):
        cfg = self.config()
        for rule in cfg.alarm_rules:
            if rule.threat_type == 'kab' and rule.severity != 'low':
                rule.enabled = False
        replay = ArchiveReplay([self.message(1, 0, 'пуск КАБ'),
                                self.message(2, 85, 'КАБ над харьков')], cfg)
        replay.step()
        replay.step()
        replay.advance(1146)
        self.assertEqual(replay.evaluator.status.level_code, 1)
        original = next(o for o in replay.evaluator._observations.values() if o.event_id == 'alpha/1')
        self.assertEqual(original.expires_at, 1600)

    def test_known_transition_after_unknown_update_still_shortens_original_zone(self):
        replay = ArchiveReplay([self.message(1, 0, 'КАБ над основа'),
                                self.message(2, 30, 'КАБ змінює курс на Тернову'),
                                self.message(3, 60, 'КАБ над харьков')], self.config())
        for _ in range(3):
            replay.step()
        original = next(o for o in replay.evaluator._observations.values() if o.event_id == 'alpha/1')
        self.assertEqual(original.expires_at, 1120)
        self.assertEqual(replay.evaluator.status.level_code, 5)
        replay.advance(1120)
        self.assertEqual(replay.evaluator.status.level_code, 2)

    def test_confirmed_departure_after_unknown_update_does_not_clear_other_channel(self):
        replay = ArchiveReplay([self.message(1, 0, 'КАБ над харьков'),
                                self.message(2, 5, 'КАБ над основа', 'beta'),
                                self.message(3, 30, 'КАБ змінює курс на Тернову'),
                                self.message(4, 60, 'КАБ уходит от города')], self.config())
        for _ in range(4):
            replay.step()
        replay.advance(1120)
        self.assertEqual(replay.evaluator.status.channel_states['alpha']['level_code'], 0)
        self.assertEqual(replay.evaluator.status.channel_states['beta']['level_code'], 5)

    def test_explicit_cancel_after_unknown_destination_clears_preserved_alarm(self):
        replay = ArchiveReplay([self.message(1, 0, 'пуск КАБ'),
                                self.message(2, 30, 'КАБ змінює курс на Тернову'),
                                self.message(3, 60, 'отбой КАБ харьков')], self.config())
        for _ in range(3):
            replay.step()
        self.assertEqual(replay.evaluator.status.level_code, 0)
