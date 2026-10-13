"""Pure composition of an API baseline and independent Telegram observations.

This module performs no I/O and cannot connect to a PLC or online source.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from src.threat_models import SEVERITIES, THREAT_TYPES
from src.telegram_reader import normalize_channel


def level_name(value):
    return {0: 'Нет тревоги', 1: 'Низкая', 2: 'Высокая (город)', 3: 'Высокая (район)',
            4: 'Критическая (город)', 5: 'Критическая (район)'}[value]


def ordered_types(rows):
    return [kind for kind in THREAT_TYPES if any(row['threat_type'] == kind for row in rows)]


def match_rows(matches):
    rows = {}
    for rule, evidence in matches:
        for observation in evidence:
            district = observation.approach in ('district', 'toward_district')
            level = {'low': 1, 'high': 3 if district else 2, 'critical': 5 if district else 4}[rule.severity]
            if observation.source == 'alarmmap' and getattr(rule, 'api_level_code', None) is not None:
                level = rule.api_level_code
            if observation.external_level is not None:
                level=observation.external_level
            key = (observation.source, observation.threat_type, observation.event_id or observation.api_type)
            row = asdict(observation)
            row.update(level_code=level, severity=rule.severity, rule_id=rule.id)
            if key not in rows or level > rows[key]['level_code']:
                rows[key] = row
    return list(rows.values())


class ThreatComposition:
    def __init__(self):
        self.previous_tracks = {}
        self.previous_base = None
        self.history = []

    def calculate(self, matches, observations, channels, channel_events, health, api_available, now,
                  removals=None):
        removals = removals or {}
        rows = match_rows(matches)
        api = [row for row in rows if row['source'] == 'alarmmap']
        tg = [row for row in rows if row['source'].startswith('telegram:')]
        base_level = max((row['level_code'] for row in api), default=0)
        base_types = ordered_types(api)
        final_level = max((row['level_code'] for row in rows), default=0)
        all_types = ordered_types(rows)
        changes = []
        def record(source, action, summary, event_id=''):
            entry = dict(source=source, action=action, summary=summary, event_id=event_id, timestamp=now)
            changes.append(entry)
            self.history.insert(0, entry)
        base_signature = (api_available, base_level, tuple(base_types))
        if self.previous_base is not None and base_signature != self.previous_base:
            record('alarmmap', 'baseline', 'База API изменена: ' + level_name(base_level))
        self.previous_base = base_signature
        contribution = {(row['source'], row['threat_type'], row['event_id']): row for row in tg}
        tracks = {}
        for key, observation in observations.items():
            row = asdict(observation)
            matched = contribution.get(key)
            row.update(level_code=matched['level_code'] if matched else 0,
                       rule_id=matched['rule_id'] if matched else '',
                       remaining_seconds=max(0, int(observation.expires_at - now)))
            row['raises_level'] = row['level_code'] > base_level
            row['adds_type'] = bool(matched and observation.threat_type not in base_types)
            row['reaction'] = ('Устанавливает ' + level_name(row['level_code']) if matched else
                               'Наблюдается; не соответствует включённым правилам')
            tracks[key] = row
        for key, row in self.previous_tracks.items():
            if key not in tracks:
                expired = row['expires_at'] <= now
                reason = ('истекла выдержка' if row.get('resolution') else 'истёк срок сообщения (TTL)') if expired else removals.get(key, 'снято или изменены условия правила')
                record(row['source'], 'expired' if expired else 'removed',
                       '@' + row['source'].split(':', 1)[1] + ': снято дополнение '
                       + THREAT_TYPES[row['threat_type']] + ' — ' + reason, row['event_id'])
        for key, row in tracks.items():
            previous = self.previous_tracks.get(key)
            signature_fields = ('text', 'approach', 'level_code', 'resolution', 'expires_at')
            if previous is None or any(previous.get(field) != row.get(field) for field in signature_fields):
                text = '@' + row['source'].split(':', 1)[1] + ': ' + THREAT_TYPES[row['threat_type']] + ' · ' + row['reaction']
                if row['raises_level']:
                    text += '; повышает уровень относительно API'
                if row['adds_type']:
                    text += '; добавлен тип угрозы'
                if row.get('resolution'):
                    text += '; ' + row['resolution']
                record(row['source'], 'added' if previous is None else 'changed', text, row['event_id'])
        self.previous_tracks = deepcopy(tracks)
        del self.history[40:]
        states = {}
        for raw_channel in channels:
            channel = normalize_channel(raw_channel)
            source = 'telegram:' + channel
            local = [row for row in tg if row['source'] == source]
            states[channel] = dict(level_code=max((row['level_code'] for row in local), default=0),
                types=ordered_types(local), raises_level=any(row['level_code'] > base_level for row in local),
                adds_types=[kind for kind in ordered_types(local) if kind not in base_types],
                health=deepcopy(health.get(source, {})),
                tracks=sorted((row for row in tracks.values() if row['source'] == source), key=lambda row: row['timestamp'], reverse=True),
                messages=[asdict(event) for event in channel_events.get(channel, [])],
                changes=[deepcopy(change) for change in self.history if change['source'] == source])
        base_text = level_name(base_level) if api_available else 'нет актуальной базы API'
        if base_types:
            base_text += ' · ' + ', '.join(THREAT_TYPES[kind] for kind in base_types)
        lines = ['База API (AlarmMap API): ' + base_text]
        if api:
            lines.append('API: ' + '; '.join(sorted({f"{row['api_type']}/{row['api_level']}" for row in api})))
            if any('Без уточнения' in row['text'] for row in api):
                lines[-1] += ' · Без уточнения типа'
        lines.append('Дополнения Telegram:')
        for channel, state in states.items():
            if state['level_code']:
                effects = ['повышает уровень'] if state['raises_level'] else []
                if state['adds_types']:
                    effects.append('добавляет ' + ', '.join(THREAT_TYPES[kind] for kind in state['adds_types']))
                lines.append('@' + channel + ': ' + level_name(state['level_code']) + ' · '
                             + ', '.join(THREAT_TYPES[kind] for kind in state['types']) + ' — '
                             + ('; '.join(effects) or 'подтверждает базу'))
        if not tg:
            lines.append('Нет действующих дополнений')
        lines.append('Итог: ' + level_name(final_level) + (' · ' + ', '.join(THREAT_TYPES[kind] for kind in all_types) if all_types else ''))
        if self.history:
            lines.append('Последние изменения:')
            lines.extend(datetime.fromtimestamp(change['timestamp']).strftime('%H:%M:%S') + ' '
                         + change['summary'] for change in self.history[:3])
        return dict(api_baseline=dict(available=api_available, level_code=base_level, types=base_types, contributions=api),
                    telegram_contributions=tg, active_threat_types=all_types, channel_states=states,
                    formation_changes=deepcopy(self.history), formation_text='\n'.join(lines),
                    final_level=final_level, rows=rows, new_changes=changes)
