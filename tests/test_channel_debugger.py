from datetime import datetime
import threading
import unittest
from unittest.mock import MagicMock, patch
from src.archive_replay import KYIV_ARCHIVE
from src.channel_debug_model import analyze_messages, channel_name, date_window, fetch_public_history
from src.threat_models import ThreatSystemConfig


class ChannelDebugTests(unittest.TestCase):
    def setUp(self):
        self.config = ThreatSystemConfig(telegram_channels=['alpha', 'beta'])
        self.config.schedule.enabled = False
        self.start, self.end = date_window('2026-10-07', '2026-10-07')
        self.cancel = threading.Event()

    def message(self, ident, offset, text, channel='alpha'):
        return dict(id=channel+'/'+str(ident), channel=channel, timestamp=self.start+offset, text=text)

    def analyze(self, messages):
        return analyze_messages(messages, 'alpha', self.start, self.end, self.config, self.cancel, lambda text: None)

    def test_types_have_independent_levels_and_ttl_falls_between_messages(self):
        result = self.analyze([self.message(1, 100, 'ракета над основа'),
                               self.message(2, 120, 'шахед над харьков'),
                               self.message(3, 140, 'отбой ракеты харьков')])
        self.assertEqual(result.rows[0]['levels']['rocket'], 4)
        self.assertEqual(result.rows[1]['levels']['rocket'], 4)
        self.assertEqual(result.rows[1]['levels']['drone'], 2)
        self.assertEqual(result.rows[2]['levels']['rocket'], 0)
        self.assertEqual(result.rows[2]['levels']['drone'], 2)
        self.assertTrue(any(point['timestamp'] == self.start+720 and point['levels']['drone'] == 0 for point in result.points))
        self.assertEqual(result.points[-1]['timestamp'], self.end)
        self.assertTrue(all(value == 0 for value in result.points[-1]['levels'].values()))

    def test_warmup_restores_initial_threat_and_channel_filter_is_independent(self):
        result = self.analyze([self.message(1, -60, 'ракета над основа'),
                               self.message(2, 10, 'обычное сообщение'),
                               self.message(3, 20, 'каб над основа', 'beta')])
        self.assertEqual(result.warmup_messages, 1)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.points[0]['levels']['rocket'], 4)
        self.assertEqual(result.rows[0]['levels']['kab'], 0)
        self.assertIsNone(result.rows[0]['event'])

    def test_end_date_is_inclusive_and_next_day_is_excluded(self):
        result = self.analyze([self.message(1, 86399, 'пуск ракеты'),
                               self.message(2, 86400, 'каб над основа')])
        self.assertEqual(len(result.rows), 1)
        with self.assertRaises(ValueError):
            date_window('2026-10-08', '2026-10-07')
        self.assertEqual(channel_name('https://t.me/s/Alpha'), 'alpha')

    def test_dates_follow_kyiv_winter_time_and_daylight_saving_changes(self):
        begin, end = date_window('2026-01-10', '2026-01-10')
        self.assertEqual(datetime.fromtimestamp(begin, KYIV_ARCHIVE).utcoffset().total_seconds(), 7200)
        begin, end = date_window('2026-03-29', '2026-03-29')
        self.assertEqual(end-begin, 23*3600)
        begin, end = date_window('2026-10-25', '2026-10-25')
        self.assertEqual(end-begin, 25*3600)

    def test_coincident_timestamps_follow_numeric_message_order(self):
        result = self.analyze([self.message(10, 100, 'отбой ракеты харьков'),
                               self.message(2, 100, 'ракета над основа')])
        self.assertEqual([r['message']['id'] for r in result.rows], ['alpha/2', 'alpha/10'])
        self.assertEqual(result.rows[0]['levels']['rocket'], 4)
        self.assertEqual(result.rows[1]['levels']['rocket'], 0)

    def test_cancellation_and_dictionary_diagnostics_do_not_change_working_config(self):
        before = self.config.alarm_rules[0].sound.beep_count
        result = self.analyze([self.message(1, 1, 'пуск ракеты')])
        self.assertIn('Ракеты', result.rows[0]['dictionary_matches'])
        self.assertEqual(self.config.alarm_rules[0].sound.beep_count, before)
        self.cancel.set()
        with self.assertRaises(InterruptedError):
            self.analyze([self.message(1, 1, 'пуск ракеты')])

    def test_public_page_loader_paginates_with_mocked_network(self):
        def page(ident, day, text):
            return ('<div class="tgme_widget_message_wrap"><div data-post="alpha/'+str(ident)+'">'
                    '<div class="tgme_widget_message_text">'+text+'</div>'
                    '<time datetime="2026-10-'+day+'T12:00:00Z"></time></div></div>')
        responses = []
        for raw in (page(100, '08', 'new'), page(80, '07', 'пуск ракеты')+page(60, '06', 'old')):
            response = MagicMock()
            response.__enter__.return_value.read.return_value = raw.encode()
            responses.append(response)
        with patch('urllib.request.urlopen', side_effect=responses) as network, patch.object(self.cancel, 'wait', return_value=False):
            messages, complete = fetch_public_history('alpha', self.start, self.end, self.cancel, lambda text: None)
        self.assertTrue(complete)
        self.assertEqual(len(messages), 1)
        self.assertIn('?before=100', network.call_args_list[1].args[0].full_url)

    def test_window_message_selection_moves_plot_marker_and_click_selects_message(self):
        from src.channel_debugger import ChannelDebugger
        result = self.analyze([self.message(1, 100, 'пуск ракеты'), self.message(2, 200, 'на харьков')])
        with patch('src.channel_debugger.ThreatSystemConfig.load', return_value=self.config):
            window = ChannelDebugger()
            window.withdraw()
            try:
                window.show_result(result)
                window.select_index(1)
                self.assertEqual(window.plot.marker['message']['id'], 'alpha/2')
                self.assertIn('на харьков', window.details.get('1.0', 'end'))
                self.assertEqual(len(window.table.get_children()), 2)
                left, _, right, _ = window.plot.geometry()
                event = MagicMock(x=left+(100/(self.end-self.start))*(right-left))
                window.plot.click(event)
                self.assertEqual(window.table.selection(), ('0',))
            finally:
                window.close()
