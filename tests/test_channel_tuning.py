from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from src.channel_debug_model import analyze_messages, date_window
from src.channel_tuning import ChannelProfile, evaluate_criteria, export_report, main, write_json
from src.threat_models import ThreatSystemConfig


class ChannelTuningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = ThreatSystemConfig(telegram_channels=['alpha', 'beta'])
        self.cfg.schedule.enabled = False
        self.cfg.telegram_api_hash = 'secret-not-for-report'
        self.profile = ChannelProfile.create(self.root/'alpha', 'alpha', self.cfg)
        self.start, self.end = date_window('2026-10-05', '2026-10-05')
        self.messages = [dict(id='alpha/1', channel='alpha', timestamp=self.start+10, text='пуск КАБ'),
                         dict(id='alpha/2', channel='alpha', timestamp=self.start+90, text='КАБ змінює курс на Тернову')]
        self.result = analyze_messages(self.messages, 'alpha', self.start, self.end,
                                       self.profile.load_config(), threading.Event(), lambda s:None)

    def test_profiles_are_independent_and_save_retains_revision_without_working_mutation(self):
        before = asdict(self.cfg)
        beta = ChannelProfile.create(self.root/'beta', 'beta', self.cfg)
        config = self.profile.load_config()
        config.approach_keywords['toward_city'].append('в напрямку')
        self.profile.save_config(config)
        self.assertNotIn('в напрямку', beta.load_config().approach_keywords['toward_city'])
        self.assertEqual(asdict(self.cfg), before)
        self.assertTrue(list((self.profile.directory/'revisions').glob('*.json')))
        self.assertFalse(self.profile.load_config().auto_transfer_to_plc)
        self.assertIsNone(self.profile.load_config().telegram_api_hash)
        with self.assertRaises(ValueError):
            ChannelProfile.create(self.root/'alpha', 'alpha', self.cfg)

    def test_message_and_between_message_ttl_criteria(self):
        self.profile.set_message_case(self.messages[1], 1, {'kab':1}, 'Сохранить прежнюю тревогу')
        cases = self.profile.cases()+[
            dict(at='2026-10-05T00:10:09+03:00', expected_level=1),
            dict(at='2026-10-05T00:10:10+03:00', expected_level=0, expected_levels={'kab':0}, split='validation')]
        result = evaluate_criteria(self.result, cases)
        self.assertEqual((result['checked'], result['failed']), (3, 0))
        self.assertEqual(evaluate_criteria(self.result, cases, 'validation')['checked'], 1)

    def test_mismatches_missing_messages_and_changed_text_are_failures(self):
        self.profile.set_message_case(self.messages[1], 4, {'kab':4})
        cases = self.profile.cases()+[dict(message_id='alpha/999', expected_level=0)]
        self.assertEqual(evaluate_criteria(self.result, cases)['failed'], 2)
        cases[0]['expected_level'] = 1
        cases[0]['expected_levels'] = {'kab':1}
        cases[0]['reference_text'] = 'Устаревшая цитата'
        self.assertTrue(evaluate_criteria(self.result, cases)['details'][0]['problems'])

    def test_invalid_empty_criteria_and_wrong_channel_are_rejected(self):
        with self.assertRaises(ValueError):
            self.profile.set_message_case(self.messages[0])
        with self.assertRaises(ValueError):
            self.profile.set_message_case(self.messages[0], True)
        wrong = dict(self.messages[0], channel='beta')
        with self.assertRaises(ValueError):
            self.profile.set_message_case(wrong, 1)
        write_json(self.profile.criteria_path, {'schema_version':1, 'channel':'beta', 'cases':[]})
        with self.assertRaises(ValueError):
            self.profile.cases()

    def test_report_has_reproducibility_hashes_and_no_credentials(self):
        archive = self.root/'history.jsonl'
        archive.write_text('\n'.join(json.dumps(m) for m in self.messages), encoding='utf-8')
        summary = export_report(self.result, self.profile, [archive], self.root/'report')
        self.assertEqual(summary['evaluation']['checked'], 0)
        self.assertEqual(len(summary['config_sha256']), 64)
        for path in (self.root/'report').iterdir():
            self.assertNotIn('secret-not-for-report', path.read_text(encoding='utf-8-sig'))
        self.assertTrue((self.root/'report'/'timeline.csv').exists())

    def test_cli_exit_codes_distinguish_unlabelled_pass_and_fail_without_network(self):
        archive = self.root/'history.jsonl'
        archive.write_text('\n'.join(json.dumps(m) for m in self.messages), encoding='utf-8')
        args = ['check', '--profile', str(self.profile.directory), '--archives', str(archive),
                '--start', '2026-10-05', '--end', '2026-10-05', '--output', str(self.root/'report')]
        with patch('urllib.request.urlopen', side_effect=AssertionError('Network forbidden')):
            self.assertEqual(main(args), 2)
            self.profile.set_message_case(self.messages[1], 1)
            self.assertEqual(main(args), 0)
            self.profile.set_message_case(self.messages[1], 4)
            self.assertEqual(main(args), 1)

    def test_old_criteria_are_collapsed_to_four_states_and_backed_up(self):
        write_json(self.profile.criteria_path, {'schema_version':1,'channel':'alpha','cases':[
            dict(message_id='alpha/1',expected_level=3,expected_levels={'kab':5})]})
        cases=self.profile.cases()
        self.assertEqual(cases[0]['expected_level'],2)
        self.assertEqual(cases[0]['expected_levels']['kab'],4)
        self.assertTrue(list((self.profile.directory/'revisions').glob('criteria_legacy_*.json')))
        self.assertEqual(self.profile.cases(),cases)
        with self.assertRaises(ValueError):
            self.profile.set_message_case(self.messages[0],5)

    def test_gui_criteria_offer_four_named_states(self):
        from tkinter import ttk
        from src.channel_debugger import ChannelDebugger
        window=ChannelDebugger();window.withdraw()
        try:
            window._use_profile(self.profile.directory)
            window.show_result(self.result)
            window.annotate_message()
            def descendants(widget):
                for child in widget.winfo_children():
                    yield child
                    yield from descendants(child)
            combos=[c for c in descendants(window) if isinstance(c,ttk.Combobox)
                    and 'Критическая' in c.cget('values')]
            self.assertEqual(len(combos),5)
            for combo in combos:
                self.assertEqual(tuple(combo.cget('values')),('', 'Нет тревоги','Низкая','Высокая','Критическая'))
        finally:
            window.close()

    def test_gui_opens_same_profile_and_loads_external_edits(self):
        from src.channel_debugger import ChannelDebugger
        window = ChannelDebugger()
        window.withdraw()
        try:
            window._use_profile(self.profile.directory)
            self.assertEqual(window.channel.get(), 'alpha')
            self.assertEqual(asdict(window.config_data), asdict(self.profile.load_config()))
            window.show_result(self.result)
            self.profile.set_message_case(self.messages[1], 1)
            window.check_criteria()
            self.assertIn('ошибок: 0', window.status.get())
            config = self.profile.load_config()
            config.approach_keywords['toward_city'].append('в напрямку')
            self.profile.save_config(config)
            window.reload_profile()
            self.assertIn('в напрямку', window.config_data.approach_keywords['toward_city'])
            self.assertIsNone(window.result)
        finally:
            window.close()
