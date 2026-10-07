"""Offline replay of public text history. Never starts readers or a Modbus worker."""
import argparse
from collections import Counter
from copy import deepcopy
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.threat_models import ThreatSystemConfig, ScheduleConfig
from src.threat_evaluator import ThreatEvaluator

KYIV = timezone(timedelta(hours=3))  # Corpus: Sep 7–Oct 7, 2026, entirely UTC+03.


class NullAudit:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def load_history(paths):
    messages = {}
    for path in paths:
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            if not line.strip():
                continue
            message = json.loads(line)
            for key in ('id', 'channel', 'text', 'timestamp'):
                if key not in message:
                    raise ValueError(f'{path}: нет поля {key}')
            messages[message['id']] = message
    return sorted(messages.values(), key=lambda m: (float(m['timestamp']), m['channel'], int(m['id'].rsplit('/', 1)[-1])))


def replay(messages, config, preserve_schedule=True):
    config = deepcopy(config)
    config.alarmmap_enabled = False
    config.telegram_enabled = True
    config.telegram_mode = 'web'
    config.schedule.enabled = config.schedule.enabled and preserve_schedule
    if not messages:
        raise ValueError('История пуста')
    clock = [float(messages[0]['timestamp'])]
    schedule_original = ScheduleConfig.is_in_schedule
    def historical_schedule(self, dt=None):
        return schedule_original(self, dt or datetime.fromtimestamp(clock[0], KYIV))
    with patch('src.threat_evaluator.ThreatAuditLogger', return_value=NullAudit()), \
         patch('src.threat_evaluator.time.time', side_effect=lambda: clock[0]), \
         patch('src.threat_evaluator.time.monotonic', side_effect=lambda: clock[0]), \
         patch.object(ScheduleConfig, 'is_in_schedule', historical_schedule):
        evaluator = ThreatEvaluator(config)
        previous = None
        transitions, decisions = [], []
        def healthy():
            for channel in config.telegram_channels:
                evaluator._on_tg_health(channel, True)
        def record_transition(cause, message_id=''):
            nonlocal previous
            s = evaluator.status
            state = (s.active_rule_id, s.is_muted, s.sound_code, s.sound_beep_count)
            if state != previous:
                transitions.append(dict(timestamp=clock[0], time=datetime.fromtimestamp(clock[0], KYIV).isoformat(),
                    message_id=message_id, cause=cause, rule=s.active_rule_id or 'safe',
                    severity=s.severity, muted=s.is_muted, sound_code=s.sound_code,
                    selected_event_ids='|'.join(s.selected_event_ids), audible=s.sound_beep_count > 0 and not s.is_muted,
                    mw0=s.modbus_word & ~(1 << config.bit_mapping.bit_heartbeat), reason=s.reason))
                previous = state
        def advance(target):
            while True:
                future = [o.expires_at + 0.0001 for o in evaluator._observations.values()
                          if clock[0] < o.expires_at + 0.0001 < target]
                if config.schedule.enabled:
                    day = datetime.fromtimestamp(clock[0], KYIV)
                    for delta in (0, 1):
                        for text in (config.schedule.start_time, config.schedule.end_time):
                            hour, minute = map(int, text.split(':'))
                            boundary = (day + timedelta(days=delta)).replace(hour=hour, minute=minute, second=0, microsecond=0).timestamp()
                            if clock[0] < boundary < target:
                                future.append(boundary)
                if not future:
                    break
                clock[0] = min(future)
                healthy()
                evaluator._refresh()
                record_transition('TTL / выдержка / расписание')
            clock[0] = target
            healthy()
        for message in messages:
            advance(float(message['timestamp']))
            resolution_before = evaluator._last_resolution
            evaluator._handle_telegram_message(message)
            evaluator._refresh()
            s = evaluator.status
            significant = (s.last_event_time == float(message['timestamp']) and
                           s.last_event_source == '@' + message['channel'] and s.last_event_text == message['text'])
            last = s.significant_events[0] if significant and s.significant_events else None
            decisions.append(dict(message_id=message['id'], timestamp=float(message['timestamp']),
                time=datetime.fromtimestamp(float(message['timestamp']), KYIV).isoformat(), channel=message['channel'],
                text=message['text'], significant=significant, inferred=bool(last and 'контекст канала' in last.badge_target),
                category=last.category if last else '', rule=s.active_rule_id or 'safe', severity=s.severity,
                muted=s.is_muted, sound_code=s.sound_code, resolution=(s.last_resolution if evaluator._last_resolution != resolution_before else ''),
                selected_event_ids='|'.join(s.selected_event_ids), audible=s.sound_beep_count > 0 and not s.is_muted,
                reason=s.reason))
            record_transition('сообщение', message['id'])
        advance(clock[0]+config.district.ttl_seconds+1)
        evaluator._refresh()
        record_transition('завершение записи')
    return decisions, transitions


def write_csv(path, rows):
    if not rows:
        return
    with path.open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def evaluate_labels(decisions, labels):
    lookup = {row['message_id']: row for row in decisions}
    checked, failures = 0, []
    if not labels:
        return dict(checked=0, failures=[], note='Нет ручной разметки: точность не оценивалась')
    with Path(labels).open(encoding='utf-8-sig', newline='') as stream:
        for label in csv.DictReader(stream):
            expected = label.get('expected_rule', '').strip()
            phrase = label.get('expected_reason_contains', '').strip()
            if not expected and not phrase:
                continue
            checked += 1
            actual = lookup.get(label['message_id'])
            if actual is None or (expected and actual['rule'] != expected) or (phrase and phrase.lower() not in actual['reason'].lower()):
                failures.append(dict(message_id=label['message_id'], expected_rule=expected,
                                     actual_rule=actual['rule'] if actual else 'MESSAGE_MISSING', expected_reason_contains=phrase))
    return dict(checked=checked, failures=failures, note='Ручная разметка сопоставлена с результатом после каждого сообщения')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--history', nargs='+', type=Path)
    parser.add_argument('--config', type=Path, default=ROOT/'config_threats.json')
    parser.add_argument('--output', type=Path, default=ROOT/'test_results'/'telegram_replay')
    parser.add_argument('--labels', type=Path)
    parser.add_argument('--ignore-schedule', action='store_true')
    args = parser.parse_args()
    paths = args.history or sorted((ROOT/'logs').glob('telegram_*_2026-09-07_2026-10-07.jsonl'))
    if not paths:
        parser.error('Нет истории. Укажите --history файл.jsonl')
    messages = load_history(paths)
    config = ThreatSystemConfig.load(args.config)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output/'config_used.json').write_text(json.dumps({
        'alarm_rules': [vars(r) | {'sound': vars(r.sound)} for r in config.alarm_rules],
        'tracking': vars(config.tracking), 'end_conditions': [vars(c) for c in config.end_conditions],
        'district': vars(config.district), 'approach_keywords': config.approach_keywords,
        'bit_mapping': vars(config.bit_mapping), 'plc_feedback': vars(config.plc_feedback),
        'schedule': vars(config.schedule), 'telegram_channels': config.telegram_channels,
        'ignore_schedule': args.ignore_schedule}, ensure_ascii=False, indent=2), encoding='utf-8')
    decisions, transitions = replay(messages, config, preserve_schedule=not args.ignore_schedule)
    write_csv(output/'decisions.csv', decisions)
    write_csv(output/'transitions.csv', transitions)
    labels = output/'labels_template.csv'
    if not labels.exists():
        write_csv(labels, [dict(message_id=d['message_id'], time=d['time'], channel=d['channel'], text=d['text'],
                               expected_rule='', expected_reason_contains='', notes='') for d in decisions])
    evaluation = evaluate_labels(decisions, args.labels)
    stats = dict(messages=len(messages), channels=dict(Counter(m['channel'] for m in messages)),
                 significant=sum(d['significant'] for d in decisions), inferred=sum(d['inferred'] for d in decisions),
                 resolution_events=sum(bool(d['resolution']) for d in decisions), transitions=len(transitions),
                 rule_counts=dict(Counter(d['rule'] for d in decisions)), evaluation=evaluation,
                 input_hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (output/'summary.json').write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding='utf-8')
    write_csv(output/'label_failures.csv', evaluation['failures'])
    report = f'''# Офлайн-воспроизведение Telegram

Сообщений: {len(messages)}. Переходов состояния: {len(transitions)}.
Значимых сообщений: {stats['significant']}; наследований контекста: {stats['inferred']}; событий окончания/движения: {stats['resolution_events']}.

- `decisions.csv` — решение после каждого сообщения, текст, признаки, причина, звук.
- `transitions.csv` — изменения тревоги и тишины, включая точные истечения TTL/выдержки между сообщениями.
- `config_used.json` — параметры прогона без ключей Telegram/API.
- `labels_template.csv` — заполните `expected_rule` (safe либо ID правила) и/или `expected_reason_contains`.
- `summary.json` — статистика, контрольные суммы входов, результаты сверки разметки.

Размеченных строк проверено: {evaluation['checked']}. Несовпадений: {len(evaluation['failures'])}.
Без ручной разметки статистика не является оценкой точности. Частоты посчитаны по сообщениям, а не по длительности тревог.

Прогон использует историческое время UTC+03 (период 7 сентября — 7 октября 2026), исходное расписание и только Telegram. Связь с каналами предполагается исправной. Состояния API в этой истории отсутствуют. Сетевые читатели и Modbus не запускаются. История содержит публичные текстовые посты; удалённые и недоступные сообщения не восстановлены.

Для проверки разметки:
```powershell
.venv\\Scripts\\python.exe scripts\\replay_telegram.py --labels test_results\\telegram_replay\\labels_template.csv
```
'''
    (output/'REPORT.md').write_text(report, encoding='utf-8')
    print(json.dumps({k: stats[k] for k in ('messages', 'significant', 'inferred', 'resolution_events', 'transitions')}, ensure_ascii=False))
    print(f'Report: {output / "REPORT.md"}')
    return 1 if evaluation['failures'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
