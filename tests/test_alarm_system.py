import json
from pathlib import Path
import queue
import socketserver
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from src.config import AppConfig
from src.modbus_worker import ModbusWorker
from src.telegram_reader import TelegramWebReader
from src.threat_evaluator import ThreatEvaluator
from src.threat_models import ThreatSystemConfig


class AlarmTests(unittest.TestCase):
    def setUp(self):
        self.log_patch = patch('src.threat_evaluator.ThreatAuditLogger', return_value=MagicMock())
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)
        self.cfg = ThreatSystemConfig(telegram_enabled=True, alarmmap_enabled=False,
                                     telegram_channels=['alpha', 'beta'])
        self.cfg.district.district_keywords = ['основа']
        self.cfg.district.city_keywords = ['харьков']
        self.e = ThreatEvaluator(self.cfg)
        self.addCleanup(self.e.stop)

    def msg(self, text, channel='alpha', age=0):
        self.e._handle_telegram_message(dict(text=text, channel=channel, timestamp=time.time()-age))

    def test_all_nine_variants_have_independent_profiles(self):
        # Exercise nine distinct user-configured conditions, independently of the early-warning preset.
        for rule in self.cfg.alarm_rules:
            rule.approaches = {'critical': ['district'], 'high': ['city'], 'low': ['launch']}[rule.severity]
        texts = {'rocket': 'ракета', 'kab': 'каб', 'drone': 'шахед'}
        for degree, location in [('critical', 'над основа'), ('high', 'над харьков'), ('low', 'пуск')]:
            for kind, text in texts.items():
                with self.subTest(degree=degree, kind=kind):
                    self.e._observations.clear()
                    self.msg(text + ' ' + location)
                    self.assertEqual(self.e.status.active_rule_id, degree + '_' + kind)
                    rule = next(r for r in self.cfg.alarm_rules if r.id == degree + '_' + kind)
                    self.assertEqual(self.e.status.sound_code, rule.sound.code)
                    self.assertIn('@alpha', self.e.status.reason)
        self.assertEqual(len({r.sound.code for r in self.cfg.alarm_rules}), 9)

    def test_degree_precedes_type_and_same_degree_type_priority(self):
        self.msg('пуск ракеты')
        self.msg('шахед над основа')
        self.assertEqual(self.e.status.active_rule_id, 'critical_drone')
        self.msg('каб над основа')
        self.assertEqual(self.e.status.active_rule_id, 'critical_kab')
        self.msg('ракета над основа')
        self.assertEqual(self.e.status.active_rule_id, 'critical_rocket')

    def test_sources_and_drone_groups_are_filters(self):
        rule = next(r for r in self.cfg.alarm_rules if r.id == 'critical_drone')
        rule.sources = ['telegram:beta']
        self.msg('шахед над основа')
        self.assertEqual(self.e.status.active_rule_id, '')
        self.msg('шахед над основа', 'beta')
        self.assertEqual(self.e.status.active_rule_id, rule.id)
        rule.drone_groups = [2]
        self.e._refresh()
        self.assertEqual(self.e.status.active_rule_id, '')
        self.msg('молния над основа', 'beta')
        self.assertEqual(self.e.status.active_rule_id, rule.id)

    def test_old_future_undated_messages_and_original_ttl(self):
        self.msg('ракета над основа', age=86400)
        self.assertEqual(self.e.status.level_code, 0)
        self.msg('ракета над основа', age=-300)
        self.e._handle_telegram_message(dict(channel='alpha', text='ракета над основа'))
        self.assertEqual(self.e.status.level_code, 0)
        self.msg('ракета над основа', age=590)
        remaining = next(iter(self.e._observations.values())).expires_at - time.time()
        self.assertTrue(8 < remaining < 11)

    def test_location_without_approach_does_not_claim_overflight(self):
        self.msg('шахед основа')
        self.assertEqual(self.e.status.level_code, 0)
        self.msg('шахед курс на основа')
        self.assertEqual(self.e.status.active_rule_id, 'critical_drone')
        self.e._observations.clear()
        self.msg('ракета над киев')
        self.assertEqual(self.e.status.level_code, 0)

    def test_clear_only_its_source_and_false_target_is_not_all_clear(self):
        self.msg('ракета над основа', 'alpha')
        self.msg('каб над основа', 'beta')
        self.msg('отбой ракеты харьков', 'alpha')
        self.assertEqual(self.e.status.active_rule_id, 'critical_kab')
        self.msg('ложная цель над основа', 'beta')
        self.assertTrue(any(o.threat_type == 'drone' for o in self.e._observations.values()))
        self.assertEqual(self.e.status.active_rule_id, 'critical_kab')

    def test_health_comes_from_successful_fetch_not_message_count(self):
        self.e._on_tg_health('alpha', True)
        self.e._on_tg_health('beta', True)
        self.e._refresh()
        self.assertTrue(self.e.status.tg_online)
        self.assertFalse(self.e.status.no_data_link)
        self.e._tg_health['alpha']['last_success'] -= 86400
        self.e._refresh()
        self.assertFalse(self.e.status.tg_online)
        self.assertTrue(self.e.status.no_data_link)
        self.e._on_tg_health('alpha', False, 'network down')
        self.e._refresh()
        self.assertIn('telegram:alpha', self.e.status.reason)

    def test_api_catalog_is_type_specific_and_api_mapping_explicit(self):
        self.cfg.alarmmap_enabled = True
        for rule in self.cfg.alarm_rules:
            rule.api_types = []
        self.e._alarmmap_online = True
        self.e._api_last_success = time.time()
        self.e._alarmmap_active_alarms = [dict(type='air', level=2, start='2026-01-01T00:00:00Z')]
        self.e._api_catalog = {('air', 2): dict(type='air', level=2, title='Официальное название', description='Пояснение API')}
        self.e._refresh()
        self.assertEqual(self.e.status.active_rule_id, '')
        self.assertIn('Официальное название', self.e.status.alarmmap_full_text)
        rule = next(r for r in self.cfg.alarm_rules if r.id == 'high_rocket')
        rule.api_types, rule.api_levels = ['air'], [2]
        self.e._refresh()
        self.assertEqual(self.e.status.active_rule_id, 'high_rocket')
        self.assertIn('AlarmMap API', self.e.status.reason)
        self.assertIn('air/2', self.e.status.reason)
        self.e._api_last_success -= 86400
        self.e._refresh()
        self.assertEqual(self.e.status.active_rule_id, '')
        self.assertIn('УСТАРЕВШИЕ', self.e.status.alarmmap_full_text)

    def test_unknown_api_level_not_fabricated_and_drone_group_unknown(self):
        self.cfg.alarmmap_enabled = True
        self.e._api_last_success = time.time()
        self.e._alarmmap_online = True
        self.e._alarmmap_active_alarms = [dict(type='fight-drones', level=12)]
        rule = next(r for r in self.cfg.alarm_rules if r.id == 'critical_drone')
        rule.api_levels = [12]
        rule.drone_groups = [1]
        self.e._refresh()
        self.assertEqual(self.e.status.active_rule_id, '')
        rule.drone_groups.append(0)
        self.e._refresh()
        self.assertEqual(self.e.status.active_rule_id, 'critical_drone')
        self.assertIn('справочник ещё не получен', self.e.status.alarmmap_full_text)

    def test_mute_and_plc_switch(self):
        self.msg('ракета над основа')
        with patch.object(type(self.cfg.schedule), 'is_in_schedule', return_value=True):
            self.e._refresh()
            self.assertEqual(self.e.status.active_rule_id, 'critical_rocket')
            self.assertEqual(self.e.status.sound_beep_count, 0)
            self.assertTrue(self.e.status.modbus_word & (1 << 10))
            self.assertFalse(self.e.status.modbus_word & (1 << 6))
        self.e.set_plc_analysis_switch(False)
        self.assertEqual(self.e.status.level_code, 0)
        self.assertEqual(self.e.status.sound_beep_count, 0)

    def test_slow_api_does_not_block_evaluation(self):
        self.cfg.alarmmap_enabled = True
        entered, release = threading.Event(), threading.Event()
        snapshots = []
        self.e.on_status_change = lambda s: snapshots.append(s)
        def blocked():
            entered.set()
            release.wait(2)
        with patch.object(self.e, '_poll_alarmmap', side_effect=blocked):
            self.e.start()
            self.assertTrue(entered.wait(1))
            time.sleep(0.65)
            self.assertGreaterEqual(len(snapshots), 2)
            self.e.stop()
            release.set()

    def test_snapshot_is_detached(self):
        seen = []
        self.e.on_status_change = seen.append
        self.msg('ракета над основа')
        snapshot = seen[-1]
        self.msg('отбой ракеты харьков')
        self.assertEqual(snapshot.active_rule_id, 'critical_rocket')
        self.assertEqual(self.e.status.active_rule_id, '')

    def test_short_followup_inherits_only_fresh_single_channel_context(self):
        self.msg('шахед над харьков')
        self.msg('на основа')
        self.assertEqual(self.e.status.active_rule_id, 'critical_drone')
        self.assertIn('тип из контекста', self.e.status.reason)
        self.e._observations.clear()
        self.e._channel_context.clear()
        self.msg('шахед над харьков', 'alpha')
        self.msg('на основа', 'beta')
        self.assertFalse(self.e.status.is_district_threat)
        self.e._channel_context['telegram:alpha']['timestamp'] -= 500
        self.msg('на основа')
        self.assertFalse(self.e.status.is_district_threat)

    def test_mixed_types_do_not_supply_ambiguous_context(self):
        self.msg('каб и ракета над харьков')
        self.msg('на основа')
        self.assertFalse(self.e.status.is_district_threat)

    def test_launch_and_movement_are_explainable(self):
        self.msg('Взлет Ту-95 с Оленьи')
        self.assertEqual(self.e.status.active_rule_id, 'low_rocket')
        self.msg('Ракета над основа')
        previous = [o for o in self.e._observations.values() if o.district]
        self.msg('На Харьков')
        self.assertTrue(all(o.expires_at-time.time() <= 61 for o in previous))
        self.assertIn('Продвижение', self.e.status.reason)

    def test_impact_shortens_with_hold_but_cannot_clear_other_channel(self):
        self.msg('каб над основа', 'alpha')
        self.msg('ракета над основа', 'beta')
        self.msg('Впав', 'alpha')
        bomb = [o for o in self.e._observations.values() if o.source == 'telegram:alpha']
        rocket = [o for o in self.e._observations.values() if o.source == 'telegram:beta']
        self.assertLessEqual(bomb[0].expires_at-time.time(), 60)
        self.assertGreater(rocket[0].expires_at-time.time(), 500)
        self.assertIn('выдержка', self.e.status.reason)

    def test_uncertain_impact_and_repeat_launch_do_not_end_attack(self):
        self.msg('каб над основа')
        expire = next(iter(self.e._observations.values())).expires_at
        self.msg('Предварительно упал')
        self.assertEqual(next(iter(self.e._observations.values())).expires_at, expire)
        self.msg('Впав. Заходять на повторні пуски')
        self.assertEqual(next(iter(self.e._observations.values())).expires_at, expire)
        self.assertIn('продолжающуюся угрозу', self.e.status.reason)
        self.msg('КАБ не упал, работа ПВО')
        self.assertEqual(next(iter(self.e._observations.values())).expires_at, expire)
        self.assertIn('отрицание', self.e.status.reason)

    def test_group_of_targets_not_cancelled_by_single_impact(self):
        self.msg('2 шахеда над основа')
        expire = next(iter(self.e._observations.values())).expires_at
        self.msg('Взрыв основа')
        self.assertEqual(next(iter(self.e._observations.values())).expires_at, expire)
        self.assertIn('несколько целей', self.e.status.reason)

    def test_loss_of_contact_not_all_clear_and_custom_end_condition(self):
        self.msg('шахед над основа')
        expire = next(iter(self.e._observations.values())).expires_at
        self.msg('Локаційно не фіксується')
        self.assertEqual(next(iter(self.e._observations.values())).expires_at, expire)
        from src.threat_models import EndCondition
        self.cfg.end_conditions.insert(0, EndCondition(name='Подтверждённое завершение', keywords=['цель завершена'],
                                        action='clear', allow_without_location=True))
        self.msg('Цель завершена')
        self.assertEqual(self.e.status.active_rule_id, '')

    def test_clear_for_city_and_replay_cannot_restore_ended_target(self):
        published = time.time()-1
        self.e._handle_telegram_message(dict(id='alpha/1', text='ракета над основа', channel='alpha', timestamp=published))
        self.msg('Відбій для міста')
        self.assertEqual(self.e.status.active_rule_id, '')
        self.e._handle_telegram_message(dict(id='alpha/1', text='ракета над основа', channel='alpha', timestamp=published))
        self.assertEqual(self.e.status.active_rule_id, '')

    def test_config_roundtrip_migration_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            self.cfg.alarm_rules[0].sources = ['telegram:beta']
            self.cfg.save(path)
            loaded = ThreatSystemConfig.load(path)
            self.assertEqual(loaded.alarm_rules[0].sources, ['telegram:beta'])
            before = path.read_text(encoding='utf-8')
            loaded.alarm_rules[0].sound.interval_series_ms = 99999
            with self.assertRaises(ValueError):
                loaded.save(path)
            self.assertEqual(path.read_text(encoding='utf-8'), before)
            path.write_text(json.dumps({'sound_profiles': {'rocket_critical': {'beep_count': 7}}}), encoding='utf-8')
            migrated = ThreatSystemConfig.load(path)
            self.assertEqual(migrated.alarm_rules[0].sound.beep_count, 7)
            self.assertEqual(len(migrated.alarm_rules), 9)


class ModbusTests(unittest.TestCase):
    def setUp(self):
        self.events = queue.Queue()
        self.worker = ModbusWorker(AppConfig(), self.events)
        self.client = MagicMock()
        response = MagicMock()
        response.isError.return_value = False
        self.client.write_register.return_value = response
        self.client.write_registers.return_value = response

    def test_sound_enqueue_does_not_replace_mw0(self):
        self.worker.queue_write(32769, 0)
        self.worker.queue_write_registers([0, 1, 200, 0, 30000], 2)
        self.assertEqual(self.worker.current_write_val, 32769)

    def test_latest_snapshot_heartbeat_and_both_writes_ack(self):
        with patch('src.modbus_worker.time.monotonic', return_value=100):
            self.worker.set_control_snapshot(1, [0, 1, 200, 0, 30000])
            self.worker.set_control_snapshot(80, [1, 3, 1000, 400, 4000])
            ok, revision, hb = self.worker._control_cycle(self.client, None, None)
        self.assertTrue(ok)
        self.assertEqual(self.client.write_register.call_args.kwargs['value'], 80)
        self.assertEqual(self.client.write_registers.call_args.kwargs['address'], 2)
        with patch('src.modbus_worker.time.monotonic', return_value=101):
            ok, _, _ = self.worker._control_cycle(self.client, revision, hb)
        self.assertEqual(self.client.write_register.call_args.kwargs['value'], 80 | 32768)
        self.assertEqual(sum(self.events.get()['type'] == 'control_ack' for _ in range(self.events.qsize())), 2)

    def test_failed_profile_never_acknowledges_pair_or_commits_word(self):
        self.worker.set_control_snapshot(80, [1, 3, 1000, 400, 4000])
        self.client.write_registers.return_value.isError.return_value = True
        ok, _, _ = self.worker._control_cycle(self.client, None, None)
        self.assertFalse(ok)
        self.client.write_register.assert_not_called()
        self.assertFalse(any(self.events.get()['type'] == 'control_ack' for _ in range(self.events.qsize())))

    def test_stalled_evaluator_stops_heartbeat(self):
        with patch('src.modbus_worker.time.monotonic', return_value=100):
            self.worker.set_control_snapshot(1, [0, 1, 200, 0, 30000])
        with patch('src.modbus_worker.time.monotonic', return_value=104):
            self.worker._control_cycle(self.client, None, None)
        self.client.write_register.assert_not_called()

    def test_auto_reconnect_false_after_io_failure(self):
        self.worker.config.auto_reconnect = False
        self.client.connect.return_value = True
        self.client.read_holding_registers.side_effect = IOError('offline')
        with patch('src.modbus_worker.ModbusTcpClient', return_value=self.client) as factory:
            self.worker.start()
            self.worker._thread.join(1)
            self.assertFalse(self.worker._thread.is_alive())
            self.assertEqual(factory.call_count, 1)


class ReaderTests(unittest.TestCase):
    def test_message_id_date_and_text_are_from_same_block(self):
        html = '''<div class="tgme_widget_message_wrap"><div data-post="alpha/1"><time datetime="2026-01-01T00:00:00Z"></time></div></div>
        <div class="tgme_widget_message_wrap"><div data-post="alpha/2"><div class="tgme_widget_message_text">same text</div><time datetime="2026-01-02T00:00:00Z"></time></div></div>
        <div class="tgme_widget_message_wrap"><div data-post="alpha/3"><div class="tgme_widget_message_text">same text</div><time datetime="2026-01-03T00:00:00Z"></time></div></div>'''
        messages = TelegramWebReader.parse_messages(html, 'alpha')
        self.assertEqual([m['id'] for m in messages], ['alpha/2', 'alpha/3'])
        self.assertNotEqual(messages[0]['timestamp'], messages[1]['timestamp'])

    def test_repeated_text_with_new_id_is_not_lost(self):
        seen = []
        reader = TelegramWebReader(['alpha'], seen.append, poll_interval=0.01)
        messages = [dict(id=str(i), text='same', timestamp=time.time(), channel='alpha') for i in (1, 2)]
        # Stop only after both callback deliveries, then let the reader exit normally.
        def receive(msg):
            seen.append(msg)
            if len(seen) == 2:
                reader._stop_event.set()
        reader.on_message = receive
        with patch.object(reader, '_fetch_channel_messages', return_value=messages):
            reader._run_loop()
        self.assertEqual([m['id'] for m in seen], ['1', '2'])


class WireProtocolTests(unittest.TestCase):
    def test_installed_pymodbus_with_local_tcp_plc_simulator(self):
        memory = {1: 0x8004}
        writes = []
        class Handler(socketserver.BaseRequestHandler):
            def exact(self, count):
                result = b''
                while len(result) < count:
                    try:
                        piece = self.request.recv(count-len(result))
                    except (ConnectionError, OSError):
                        return None
                    if not piece:
                        return None
                    result += piece
                return result
            def handle(self):
                while True:
                    header = self.exact(7)
                    if header is None:
                        return
                    transaction, protocol, length, device = struct.unpack('>HHHB', header)
                    pdu = self.exact(length-1)
                    if pdu is None:
                        return
                    function = pdu[0]
                    address, count_or_value = struct.unpack('>HH', pdu[1:5])
                    if function == 3:
                        response = bytes([3, 2*count_or_value]) + struct.pack('>'+'H'*count_or_value,
                            *(memory.get(address+i, 0) for i in range(count_or_value)))
                    elif function == 6:
                        memory[address] = count_or_value
                        writes.append((address, [count_or_value]))
                        response = pdu
                    elif function == 16:
                        values = list(struct.unpack('>'+'H'*count_or_value, pdu[6:]))
                        memory.update({address+i: value for i, value in enumerate(values)})
                        writes.append((address, values))
                        response = pdu[:5]
                    else:
                        response = bytes([function|0x80, 1])
                    self.request.sendall(struct.pack('>HHHB', transaction, protocol, len(response)+1, device)+response)
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
        server = Server(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        events = queue.Queue()
        worker = ModbusWorker(AppConfig(host='127.0.0.1', port=server.server_address[1],
                                      poll_interval_ms=50, auto_reconnect=False), events)
        try:
            worker.set_control_snapshot(80, [1, 3, 1000, 400, 4000])
            worker.start()
            deadline = time.time()+3
            ack = None
            while time.time() < deadline:
                event = events.get(timeout=2)
                if event['type'] == 'control_ack':
                    ack = event['data']
                    break
            self.assertIsNotNone(ack)
            self.assertEqual(ack['word'] & 0x7fff, 80)
            self.assertEqual([memory[i] for i in range(2, 7)], [1, 3, 1000, 400, 4000])
            self.assertEqual(memory[1], 0x8004)
            self.assertEqual(writes[0][0], 2)
            self.assertEqual(writes[1][0], 0)
        finally:
            worker.stop()
            server.shutdown()
            server.server_close()


class DialogTests(unittest.TestCase):
    def test_cancel_and_invalid_save_leave_original_config_unchanged(self):
        import tkinter as tk
        from src.threat_config_dialog import ThreatConfigDialog
        root = tk.Tk()
        root.withdraw()
        cfg = ThreatSystemConfig()
        try:
            dialog = ThreatConfigDialog(root, cfg, MagicMock())
            dialog.withdraw()
            self.assertEqual(dialog.rule_inputs['critical_rocket']['groups'], {})
            self.assertEqual(dialog.rule_inputs['critical_kab']['groups'], {})
            self.assertEqual(len(dialog.rule_inputs['critical_drone']['groups']), 4)
            dialog.rule_inputs['critical_rocket']['enabled'].set(False)
            dialog.sound_profile_entries['critical_rocket'][0].delete(0, 'end')
            dialog.sound_profile_entries['critical_rocket'][0].insert(0, '-1')
            with patch.object(dialog, '_save_to_json') as save, patch('src.threat_config_dialog.messagebox.showerror') as error:
                dialog._save_and_close()
                self.assertTrue(error.called)
                save.assert_not_called()
            self.assertTrue(cfg.alarm_rules[0].enabled)
            self.assertEqual(cfg.alarm_rules[0].sound.beep_count, 3)
            dialog.destroy()
        finally:
            root.destroy()


class LeadTimeTests(unittest.TestCase):
    def test_90_and_120_seconds_missed_and_muted_commands(self):
        from scripts.evaluate_lead_time import score_cases
        messages = [dict(id='alpha/1', timestamp=100), dict(id='alpha/2', timestamp=220)]
        cases = [dict(case_id='example', impact_message_id='alpha/2', threat_type='kab',
                      signal_message_ids='alpha/1', review_status='provisional')]
        decision = dict(timestamp=100, severity='critical', audible=True, rule='critical_kab',
                        selected_event_ids='alpha/1', time='100', message_id='alpha/1')
        row = score_cases(messages, [decision], cases)[0]
        self.assertEqual(row['lead_seconds'], 120)
        self.assertTrue(row['meets_90_seconds'])
        self.assertTrue(row['meets_120_seconds'])
        decision['timestamp'] = 125
        row = score_cases(messages, [decision], cases)[0]
        self.assertTrue(row['meets_90_seconds'])
        self.assertFalse(row['meets_120_seconds'])
        decision['audible'] = False
        self.assertEqual(score_cases(messages, [decision], cases)[0]['result'], 'NO_CRITICAL_COMMAND')

    def test_historical_clock_expires_hold_before_next_post(self):
        from scripts.replay_telegram import replay
        cfg = ThreatSystemConfig(telegram_channels=['alpha'], alarmmap_enabled=False)
        cfg.district.district_keywords = ['основа']
        cfg.district.ttl_seconds = 600
        messages = [dict(id='alpha/1', channel='alpha', text='каб над основа', timestamp=1000),
                    dict(id='alpha/2', channel='alpha', text='Впав', timestamp=1010),
                    dict(id='alpha/3', channel='alpha', text='обычное сообщение', timestamp=1200)]
        decisions, transitions = replay(messages, cfg)
        self.assertEqual(decisions[0]['rule'], 'critical_kab')
        self.assertTrue(any(r['rule'] == 'safe' and 1069 < r['timestamp'] < 1071 for r in transitions))

    def test_critical_command_from_other_threat_is_separate_metric(self):
        from scripts.evaluate_lead_time import score_cases
        messages = [dict(id='alpha/1', timestamp=100), dict(id='alpha/2', timestamp=220)]
        cases = [dict(case_id='example', impact_message_id='alpha/2', threat_type='kab', signal_message_ids='alpha/1')]
        other = dict(timestamp=90, severity='critical', audible=True, rule='critical_rocket',
                     selected_event_ids='alpha/other', time='90', message_id='alpha/other')
        row = score_cases(messages, [other], cases)[0]
        self.assertEqual(row['lead_seconds'], '')
        self.assertEqual(row['any_critical_lead_seconds'], 130)

    def test_independent_impact_time_can_reveal_late_command(self):
        from scripts.evaluate_lead_time import score_cases
        from datetime import datetime, timezone
        messages = [dict(id='alpha/1', timestamp=100), dict(id='alpha/2', timestamp=220)]
        cases = [dict(case_id='example', impact_message_id='alpha/2', threat_type='kab', signal_message_ids='alpha/1',
                      physical_impact_time=datetime.fromtimestamp(200, timezone.utc).isoformat(), review_status='reviewed')]
        late = dict(timestamp=210, severity='critical', audible=True, rule='critical_kab',
                    selected_event_ids='alpha/1', time='210', message_id='alpha/1')
        row = score_cases(messages, [late], cases)[0]
        self.assertEqual(row['lead_seconds'], -10)
        self.assertEqual(row['result'], 'AFTER_IMPACT')


if __name__ == '__main__':
    unittest.main()
