"""Read-only history analysis using the application's real Telegram evaluator."""
from bisect import bisect_right
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re
import urllib.request
from src.archive_replay import ArchiveReplay, KYIV_ARCHIVE, load_archives
from src.telegram_reader import TelegramWebReader, normalize_channel
from src.threat_models import THREAT_TYPES
from src.channel_levels import collapse_level

COLORS = {'rocket': '#ef4444', 'kab': '#f59e0b', 'drone': '#a855f7', 'unknown': '#64748b'}


def channel_name(value):
    value = value.strip().split('?')[0].rstrip('/')
    value = re.sub(r'^https?://(?:t\.me|telegram\.me)/(?:s/)?', '', value).lstrip('@')
    if not re.fullmatch(r'[A-Za-z0-9_]+', value):
        raise ValueError('Укажите @имя публичного канала или ссылку t.me/канал')
    return normalize_channel(value)


def date_window(start, end):
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        zone = ZoneInfo('Europe/Kyiv')
    except ZoneInfoNotFoundError as error:
        raise ValueError('Для дат Киева нужен tzdata. Запустите run_channel_debugger.bat или установите requirements.txt.') from error
    first = datetime.strptime(start.strip(), '%Y-%m-%d').replace(tzinfo=zone)
    last = datetime.strptime(end.strip(), '%Y-%m-%d').replace(tzinfo=zone) + timedelta(days=1)
    if last <= first:
        raise ValueError('Дата конца должна быть не раньше даты начала')
    return first.timestamp(), last.timestamp()


def fetch_public_history(channel, start, end, cancel, progress, max_pages=2000):
    """Fetch public t.me pages backwards; report access/coverage limitations explicitly."""
    channel = channel_name(channel)
    before = None
    messages = {}
    oldest = None
    for page in range(max_pages):
        if cancel.is_set():
            raise InterruptedError('Загрузка отменена')
        url = f'https://t.me/s/{channel}' + (f'?before={before}' if before is not None else '')
        request = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode('utf-8', errors='replace')
        ids = [int(value) for value in re.findall(r'data-post="' + re.escape(channel) + r'/(\d+)"', raw, flags=re.I)]
        if not ids:
            raise ValueError('Публичная история недоступна. Загрузите JSON/JSONL-архив или экспорт Telegram.')
        dates = re.findall(r'<time datetime="([^" ]+)"', raw)
        stamps = []
        for value in dates:
            try:
                stamps.append(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())
            except ValueError:
                continue
        if stamps:
            oldest = min(stamps)
        for message in TelegramWebReader.parse_messages(raw, channel):
            if start <= message['timestamp'] < end:
                messages[message['id']] = message
        progress(f'Загрузка @{channel}: {page+1} страниц, {len(messages)} сообщений')
        if oldest is not None and oldest <= start:
            return sorted(messages.values(), key=lambda item: (item['timestamp'], item['id'])), True
        next_before = min(ids)
        if before is not None and next_before >= before:
            return sorted(messages.values(), key=lambda item: (item['timestamp'], item['id'])), False
        if next_before <= 1:
            return sorted(messages.values(), key=lambda item: (item['timestamp'], item['id'])), True
        before = next_before
        if cancel.wait(0.2):
            raise InterruptedError('Загрузка отменена')
    raise ValueError('Достигнут предел загрузки. Сузьте даты или используйте локальный архив.')


def dictionary_matches(text, config):
    groups = {'Ракеты': config.tracking.rocket_keywords, 'КАБ': config.tracking.bomb_keywords,
              'Носители / пуски': config.tracking.rocket_launch_keywords,
              'Движение': config.tracking.movement_keywords,
              'Город': config.district.city_keywords, 'Районы': config.district.district_keywords,
              'Укрытие': config.district.critical_alert_keywords,
              'Неуверенность': config.tracking.uncertain_keywords,
              'Продолжение атаки': config.tracking.continuing_keywords}
    groups.update({f'Дроны: группа {i}': getattr(config.drone_dict, f'group{i}_keywords') for i in range(4)})
    groups.update({'Приближение ' + key: value for key, value in config.approach_keywords.items()})
    for condition in config.end_conditions:
        groups['Окончание: ' + condition.name] = condition.keywords
    lower = text.lower()
    return {name: [word for word in words if word and word.lower() in lower]
            for name, words in groups.items() if any(word and word.lower() in lower for word in words)}


@dataclass
class DebugResult:
    channel: str
    start: float
    end: float
    rows: list
    points: list
    config: object
    warmup_messages: int


class CapturedReplay(ArchiveReplay):
    def reset(self):
        self.points = []
        self.rows = []
        super().reset()

    def _tick(self, message=None):
        state = super()._tick(message)
        levels = dict.fromkeys(THREAT_TYPES, 0)
        for contribution in state.telegram_contributions:
            kind = contribution['threat_type']
            levels[kind] = max(levels[kind], collapse_level(contribution['level_code']))
        point = dict(timestamp=self.now, levels=levels, level=collapse_level(state.level_code))
        self.points.append(point)
        if message:
            channel_state = state.channel_states.get(message['channel'], {})
            event = next((item for item in channel_state.get('messages', []) if item['event_id'] == message['id']), None)
            self.rows.append(dict(message=deepcopy(message), point_index=len(self.points)-1,
                level=collapse_level(state.level_code), levels=levels, reason=state.reason,
                event=event, tracks=deepcopy(channel_state.get('tracks', []))))
        return state


def context_lookback(config):
    return max(config.district.ttl_seconds, config.tracking.context_seconds,
               config.tracking.movement_hold_seconds,
               max((item.hold_seconds for item in config.end_conditions), default=0))


def analyze_messages(messages, channel, start, end, config, cancel, progress):
    channel = channel_name(channel)
    cfg = deepcopy(config)
    lookback = context_lookback(cfg)
    selected = [item for item in messages if channel_name(item['channel']) == channel
                and start-lookback <= float(item['timestamp']) < end]
    selected.sort(key=lambda item: (item['timestamp'],
        0 if str(item['id']).rsplit('/', 1)[-1].isdigit() else 1,
        int(str(item['id']).rsplit('/', 1)[-1]) if str(item['id']).rsplit('/', 1)[-1].isdigit() else str(item['id'])))
    if not any(item['timestamp'] >= start for item in selected):
        raise ValueError('Для этого канала в указанном диапазоне нет сообщений')
    replay = CapturedReplay(selected, cfg)
    for index, _ in enumerate(selected):
        if cancel.is_set():
            raise InterruptedError('Анализ отменён')
        replay.step()
        if index % 50 == 0:
            progress(f'Анализ @{channel}: {index+1}/{len(selected)} сообщений')
    replay.advance(end)
    rows = [item for item in replay.rows if start <= item['message']['timestamp'] < end]
    points = replay.points
    prior = [item for item in points if item['timestamp'] <= start]
    initial = dict(prior[-1]) if prior else dict(timestamp=start, levels=dict.fromkeys(THREAT_TYPES, 0), level=0)
    initial['timestamp'] = start
    clipped = [initial] + [item for item in points if start < item['timestamp'] <= end]
    # Preserve a direct association with the post-message state, including coincident timestamps.
    for row in rows:
        row['dictionary_matches'] = dictionary_matches(row['message']['text'], cfg)
    return DebugResult(channel, start, end, rows, clipped, cfg,
                       sum(item['timestamp'] < start for item in selected))
