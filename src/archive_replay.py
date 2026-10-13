"""Deterministic archive simulation. No readers, network requests or PLC transport."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import csv
import json
import re
from pathlib import Path
from unittest.mock import patch
from src.threat_evaluator import ThreatEvaluator
from src.telegram_reader import normalize_channel

try:
    KYIV_ARCHIVE = ZoneInfo('Europe/Kyiv')
except ZoneInfoNotFoundError:
    KYIV_ARCHIVE = timezone(timedelta(hours=3))  # Compatibility for old environments; debugger requires tzdata.


class NullAudit:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def load_archives(paths):
    messages = []
    for path in map(Path, paths):
        raw = path.read_text(encoding='utf-8-sig')
        if path.suffix.lower() == '.csv':
            entries = list(csv.DictReader(raw.splitlines()))
            metadata = {}
        elif path.suffix.lower() == '.json':
            payload = json.loads(raw)
            metadata = payload if isinstance(payload, dict) else {}
            entries = metadata.get('messages', []) if metadata else payload
        else:
            entries = [json.loads(line) for line in raw.splitlines() if line.strip()]
            metadata = {}
        for item in entries:
            if item.get('type', 'message') != 'message':
                continue
            channel = item.get('channel') or metadata.get('username')
            if not channel:
                match = re.search(r'telegram_(.+)_\d{4}-\d{2}-\d{2}', path.stem)
                channel = match[1] if match else metadata.get('name', path.stem)
                channel = re.sub(r'[^a-zA-Z0-9_]', '_', channel)
            channel = normalize_channel(channel)
            text = item.get('text', '')
            if isinstance(text, list):
                text = ''.join(part if isinstance(part, str) else part.get('text', '') for part in text)
            if not text:
                continue
            stamp = item.get('timestamp', item.get('date_unixtime'))
            if stamp is None:
                dt = datetime.fromisoformat(item['date'].replace('Z', '+00:00'))
                stamp = (dt if dt.tzinfo else dt.replace(tzinfo=KYIV_ARCHIVE)).timestamp()
            ident = str(item.get('id', len(messages) + 1))
            if '/' not in ident:
                ident = channel + '/' + ident
            reply_to = item.get('reply_to') or item.get('reply_to_message_id')
            if reply_to and '/' not in str(reply_to):reply_to = channel+'/'+str(reply_to)
            messages.append(dict(id=ident, channel=channel, text=text, timestamp=float(stamp),
                                 reply_to=reply_to, reply_text=item.get('reply_text','')))

    seen = set()
    unique = []
    for message in sorted(messages, key=lambda m: (m['timestamp'], m['channel'], m['id'])):
        key = (message['id'], message['text'], message['timestamp'])
        if key not in seen:
            unique.append(message)
            seen.add(key)
    if not unique:
        raise ValueError('В выбранных архивах нет текстовых сообщений')
    return unique


class OfflineEvaluator(ThreatEvaluator):
    def _init_tg_reader(self):
        self.tg_reader = None

    def start(self):
        raise RuntimeError('Архивный анализатор не запускает онлайн-потоки')

    def _request_api(self, *args):
        raise RuntimeError('Сетевые запросы запрещены в архивном режиме')



class ArchiveReplay:
    def __init__(self, messages, config, baseline=None):
        self.messages = list(messages)
        self.original_config = deepcopy(config)
        self.baseline = baseline
        self.reset()

    def reset(self):
        config = deepcopy(self.original_config)
        config.telegram_enabled = True
        config.telegram_mode = 'web'
        config.telegram_channels = sorted({m['channel'] for m in self.messages})
        config.alarmmap_enabled = self.baseline is not None
        config.auto_transfer_to_plc = False
        self.now = self.messages[0]['timestamp']
        self.index = 0
        self.decisions = []
        with patch('src.threat_evaluator.ThreatAuditLogger', return_value=NullAudit()):
            self.evaluator = OfflineEvaluator(config)
        self._tick()

    def _tick(self, message=None):
        e = self.evaluator
        historical = datetime.fromtimestamp(self.now, KYIV_ARCHIVE)
        with patch('src.threat_evaluator.time.time', return_value=self.now), \
             patch.object(type(e.config.schedule), 'is_in_schedule',
                          lambda schedule, dt=None: self._scheduled(schedule, dt or historical)):
            for channel in e.config.telegram_channels:
                e._on_tg_health(channel, True)
            e._alarmmap_online = self.baseline is not None
            e._api_last_success = self.now
            e._alarmmap_active_alarms = deepcopy(self.baseline or [])
            if message:
                e._handle_telegram_message(message)
            else:
                e._refresh()
            state = deepcopy(e.status)
        self.decisions.append(dict(timestamp=self.now, channel=message['channel'] if message else 'timer',
            message_id=message['id'] if message else '', message=message['text'] if message else 'TTL / выдержка / расписание',
            api_level=state.api_baseline['level_code'], final_level=state.level_code,
            types=', '.join(state.active_threat_types), sound_code=state.sound_code,
            channel_levels=json.dumps({channel: item['level_code'] for channel, item in state.channel_states.items()}),
            reason=state.reason))
        return state

    @staticmethod
    def _scheduled(schedule, dt):
        if not schedule.enabled:
            return False
        current = dt.strftime('%H:%M')
        start, end = schedule.start_time, schedule.end_time
        return start <= current < end if start < end else current >= start or current < end

    def advance(self, target):
        if target < self.now:
            raise ValueError('Для перехода назад сбросьте воспроизведение')
        while True:
            expiries = [o.expires_at for o in self.evaluator._observations.values() if self.now < o.expires_at <= target]
            boundaries = []
            if self.evaluator.config.schedule.enabled:
                dt = datetime.fromtimestamp(self.now, KYIV_ARCHIVE)
                for days in (0, 1):
                    for value in (self.evaluator.config.schedule.start_time, self.evaluator.config.schedule.end_time):
                        hour, minute = map(int, value.split(':'))
                        stamp = (dt + timedelta(days=days)).replace(hour=hour, minute=minute, second=0, microsecond=0).timestamp()
                        if self.now < stamp <= target:
                            boundaries.append(stamp)
            if not expiries and not boundaries:
                break
            self.now = min(expiries + boundaries)
            self._tick()
        self.now = target
        return self._tick()

    def step(self):
        if self.index >= len(self.messages):
            return None
        message = self.messages[self.index]
        self.advance(message['timestamp'])
        result = self._tick(message)
        self.index += 1
        return result

    def export_csv(self, path):
        with Path(path).open('w', encoding='utf-8-sig', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(self.decisions[0]))
            writer.writeheader()
            writer.writerows(self.decisions)
