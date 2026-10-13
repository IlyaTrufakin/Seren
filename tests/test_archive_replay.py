from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from src.archive_replay import ArchiveReplay, KYIV_ARCHIVE, load_archives
from src.threat_models import ThreatSystemConfig


class ArchiveReplayTests(unittest.TestCase):
    def config(self):
        config = ThreatSystemConfig(telegram_channels=['alpha', 'beta'])
        config.schedule.enabled = False
        return config

    def messages(self):
        base = datetime(2026, 10, 7, 12, 0, tzinfo=KYIV_ARCHIVE).timestamp()
        return [dict(id='alpha/1', channel='alpha', timestamp=base, text='ракета над основа'),
                dict(id='beta/1', channel='beta', timestamp=base+10, text='каб над основа'),
                dict(id='alpha/2', channel='alpha', timestamp=base+20, text='отбой ракеты харьков')]

    def test_independent_channels_combined_types_and_cancel(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            replay = ArchiveReplay(self.messages(), self.config(), [dict(type='air', level=2)])
            first = replay.step()
            self.assertEqual(first.api_baseline['level_code'], 2)
            self.assertEqual(first.active_threat_types, ['rocket', 'drone'])
            second = replay.step()
            self.assertEqual(second.active_threat_types, ['rocket', 'kab', 'drone'])
            final = replay.step()
            self.assertEqual(final.active_threat_types, ['kab', 'drone'])
            self.assertEqual(final.channel_states['alpha']['level_code'], 0)
            self.assertEqual(final.channel_states['beta']['level_code'], 5)
            self.assertIn('отбой', final.channel_states['alpha']['messages'][0]['text'])
            self.assertTrue(any(c['action'] == 'removed' for c in final.channel_states['alpha']['changes']))
            with self.assertRaises(RuntimeError):
                replay.evaluator.start()
            with self.assertRaises(RuntimeError):
                replay.evaluator._request_api('anything', 'unused')

    def test_expiry_without_new_posts_returns_to_baseline(self):
        replay = ArchiveReplay(self.messages()[:1], self.config(), [dict(type='air', level=2)])
        replay.step()
        state = replay.advance(replay.now+601)
        self.assertEqual(state.level_code, 2)
        self.assertEqual(state.active_threat_types, ['drone'])
        self.assertTrue(any(change['action'] == 'expired' for change in state.formation_changes))
        self.assertIn('TTL', state.reason)

    def test_launch_movement_and_proximity_are_per_channel(self):
        messages = self.messages()
        messages[0]['text'] = 'пуск ракеты'
        messages[1].update(channel='alpha', id='alpha/2', text='на харьков')
        messages[2].update(channel='alpha', id='alpha/3', text='ракета уходит от города')
        replay = ArchiveReplay(messages, self.config())
        state = replay.step()
        self.assertTrue(state.channel_states['alpha']['tracks'][0]['launch_detected'])
        state = replay.step()
        self.assertEqual(state.channel_states['alpha']['tracks'][0]['direction'], 'На город')
        state = replay.step()
        self.assertEqual(state.channel_states['alpha']['tracks'][0]['direction'], 'От города')
        self.assertEqual(state.channel_states['alpha']['tracks'][0]['proximity'], 'Вне города')
        self.assertEqual(len(state.channel_states['alpha']['messages']), 3)

    def test_reset_replays_same_result_and_export_does_not_change_config(self):
        config = self.config()
        config.auto_transfer_to_plc = True
        replay = ArchiveReplay(self.messages(), config)
        for _ in self.messages():
            state = replay.step()
        expected = (state.level_code, state.active_threat_types)
        replay.reset()
        for _ in self.messages():
            state = replay.step()
        self.assertEqual((state.level_code, state.active_threat_types), expected)
        self.assertTrue(config.auto_transfer_to_plc)
        self.assertFalse(replay.evaluator.config.auto_transfer_to_plc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.csv'
            replay.export_csv(path)
            self.assertIn('channel_levels', path.read_text(encoding='utf-8-sig'))

    def test_jsonl_and_telegram_export_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.jsonl'
            path.write_text('\n'.join(json.dumps(m) for m in self.messages()), encoding='utf-8')
            self.assertEqual(len(load_archives([path])), 3)
            path = Path(directory) / 'export.json'
            path.write_text(json.dumps(dict(username='alpha', messages=[dict(id=1, type='message',
                date_unixtime='1791363600', text=['пуск ', dict(text='ракеты')])])), encoding='utf-8')
            messages = load_archives([path])
            self.assertEqual(messages[0]['channel'], 'alpha')
            self.assertEqual(messages[0]['text'], 'пуск ракеты')

    def test_archive_viewer_shows_each_channel_chat_without_starting_readers(self):
        from src.archive_viewer import ArchiveViewer
        with patch('src.archive_viewer.ThreatSystemConfig.load', return_value=self.config()), \
             patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            window = ArchiveViewer()
            window.withdraw()
            try:
                window.messages = self.messages()
                window.restart()
                window.step()
                window.step()
                self.assertEqual(set(window.channels.panels), {'alpha', 'beta'})
                alpha_chat = window.channels.panels['alpha'][2].get('1.0', 'end')
                beta_chat = window.channels.panels['beta'][2].get('1.0', 'end')
                self.assertIn('ракета', alpha_chat)
                self.assertNotIn('каб над', alpha_chat)
                self.assertIn('каб над', beta_chat)
                self.assertIn('База API', window.formation.get('1.0', 'end'))
            finally:
                window.close()

    def test_archive_config_dialog_does_not_save_working_settings(self):
        import tkinter as tk
        from src.threat_config_dialog import ThreatConfigDialog
        root = tk.Tk()
        root.withdraw()
        try:
            dialog = ThreatConfigDialog(root, self.config(), MagicMock(), persist=False)
            dialog.withdraw()
            with patch.object(dialog.config, 'save') as save:
                dialog._save_to_json()
                save.assert_not_called()
            dialog.destroy()
        finally:
            root.destroy()
