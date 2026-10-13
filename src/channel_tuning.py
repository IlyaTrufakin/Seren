"""Offline channel tuning shared by the GUI and command line; no live transport."""
import argparse
from bisect import bisect_right
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import threading
from src.archive_replay import load_archives
from src.channel_debug_model import analyze_messages, channel_name, date_window
from src.threat_models import ThreatSystemConfig, THREAT_TYPES
from src.channel_levels import LEVEL_NAMES, LEVEL_SCALE, collapse_level


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.tmp')
    pending.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    pending.replace(path)


def channel_config(config, channel):
    channel = channel_name(channel)
    config = deepcopy(config)
    config.telegram_channels = [channel_name(channel)]
    config.telegram_enabled = True
    config.telegram_mode = 'web'
    config.telegram_api_id = config.telegram_api_hash = config.telegram_phone = None
    config.alarmmap_enabled = False
    config.auto_transfer_to_plc = False
    for rule in config.alarm_rules:
        rule.sources = [s for s in rule.sources if s in ('telegram:*', 'telegram:' + channel)]
        rule.api_types=[]
        rule.api_levels=[]
        rule.api_levels_by_type={}
        if not rule.sources:
            rule.enabled = False
    for condition in config.end_conditions:
        condition.sources = [s for s in condition.sources if s in ('telegram:*', 'telegram:' + channel)]
        if not condition.sources:
            condition.enabled = False
    config.validate()
    return config


class ChannelProfile:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        manifest = read_json(self.directory / 'profile.json')
        if manifest.get('schema_version') != 1:
            raise ValueError('Неизвестная версия профиля')
        self.channel = channel_name(manifest['channel'])
        self.config_path = self.directory / 'config.json'
        self.criteria_path = self.directory / 'criteria.json'
        if not self.config_path.exists():
            raise ValueError('В профиле отсутствует config.json')

    @classmethod
    def create(cls, directory, channel, config):
        directory = Path(directory).resolve()
        if directory.exists() and any(directory.iterdir()):
            raise ValueError('Папка профиля не пуста; существующие настройки не перезаписываются')
        channel = channel_name(channel)
        prepared = channel_config(config, channel)
        directory.mkdir(parents=True, exist_ok=True)
        prepared.save(str(directory / 'config.json'))
        write_json(directory / 'criteria.json', {'schema_version': 1, 'level_scale': LEVEL_SCALE, 'channel': channel, 'cases': []})
        write_json(directory / 'profile.json', {'schema_version': 1, 'channel': channel})
        return cls(directory)

    def load_config(self):
        return channel_config(ThreatSystemConfig.load(str(self.config_path)), self.channel)

    def save_config(self, config):
        prepared = channel_config(config, self.channel)
        previous = self.config_path.read_bytes()
        digest = hashlib.sha256(previous).hexdigest()[:12]
        revision = self.directory / 'revisions' / ('config_' + digest + '.json')
        revision.parent.mkdir(exist_ok=True)
        if not revision.exists():
            revision.write_bytes(previous)
        prepared.save(str(self.config_path))

    def cases(self):
        payload = read_json(self.criteria_path)
        if payload.get('schema_version') != 1 or payload.get('channel') != self.channel:
            raise ValueError('Версия или канал критериев не соответствуют профилю')
        cases = payload.get('cases')
        if not isinstance(cases, list):
            raise ValueError('cases должен быть списком')
        if payload.get('level_scale') != LEVEL_SCALE:
            if payload.get('level_scale') is not None:
                raise ValueError('Неизвестная шкала критериев')
            for case in cases:
                if 'expected_level' in case:
                    case['expected_level']=collapse_level(case['expected_level'])
                for kind,value in case.get('expected_levels',{}).items():
                    case['expected_levels'][kind]=collapse_level(value)
            for case in cases:
                validate_case(case,self.channel)
            revision=self.directory/'revisions'/('criteria_legacy_'+hashlib.sha256(self.criteria_path.read_bytes()).hexdigest()[:12]+'.json')
            revision.parent.mkdir(exist_ok=True)
            if not revision.exists():
                revision.write_bytes(self.criteria_path.read_bytes())
            payload['level_scale']=LEVEL_SCALE
            write_json(self.criteria_path,payload)
        for case in cases:
            validate_case(case, self.channel)
        selectors = [('message', c['message_id']) if 'message_id' in c else ('time', c['at']) for c in cases]
        if len(selectors) != len(set(selectors)):
            raise ValueError('Повторяющиеся критерии для одного сообщения или момента')
        return cases

    def set_message_case(self, message, expected_level=None, expected_levels=None, note='', split='tuning'):
        if channel_name(message['channel']) != self.channel:
            raise ValueError('Сообщение относится к другому каналу')
        case = dict(message_id=message['id'], expected_levels=expected_levels or {}, note=note,
                    split=split, reference_text=message['text'])
        if expected_level is not None:
            case['expected_level'] = expected_level
        validate_case(case, self.channel)
        cases = [c for c in self.cases() if c.get('message_id') != message['id']]
        cases.append(case)
        write_json(self.criteria_path, {'schema_version': 1, 'level_scale': LEVEL_SCALE, 'channel': self.channel, 'cases': cases})


def validate_case(case, channel):
    if not isinstance(case, dict):
        raise ValueError('Критерий должен быть объектом')
    if ('message_id' in case) == ('at' in case):
        raise ValueError('Критерию нужен ровно один селектор: message_id или at')
    if 'message_id' in case and not str(case['message_id']).startswith(channel + '/'):
        raise ValueError('message_id должен содержать имя канала и номер сообщения')
    if 'at' in case:
        parse_time(case['at'])
    if case.get('split', 'tuning') not in ('tuning', 'validation'):
        raise ValueError('split: tuning или validation')
    levels = case.get('expected_levels', {})
    if not isinstance(levels, dict) or not set(levels) <= set(THREAT_TYPES):
        raise ValueError('Неизвестный тип в expected_levels')
    values = list(levels.values()) + ([case['expected_level']] if 'expected_level' in case else [])
    if not values or any(type(v) is not int or v not in LEVEL_NAMES for v in values):
        raise ValueError('Нужен хотя бы один ожидаемый уровень: нет тревоги, низкая, высокая или критическая (внутренние коды 0, 1, 2, 4)')
    if 'reason_contains' in case and (not isinstance(case['reason_contains'], str) or not case['reason_contains'].strip()):
        raise ValueError('reason_contains должен быть непустым текстом')


def parse_time(value):
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('В at нужен часовой пояс, например +03:00')
        return dt.timestamp()
    raise ValueError('at: время в формате ISO с часовым поясом')


def evaluate_criteria(result, cases, split='all'):
    selected = [c for c in cases if split == 'all' or c.get('split', 'tuning') == split]
    rows = {r['message']['id']: r for r in result.rows}
    stamps = [p['timestamp'] for p in result.points]
    details = []
    for case in selected:
        validate_case(case, result.channel)
        actual = None
        problems = []
        if 'message_id' in case:
            actual = rows.get(case['message_id'])
            if actual and 'reference_text' in case and actual['message']['text'] != case['reference_text']:
                problems.append('Изменился исходный текст сообщения: требуется пересмотр критерия')
        else:
            stamp = parse_time(case['at'])
            if result.start <= stamp < result.end:
                index = bisect_right(stamps, stamp) - 1
                if index >= 0:
                    actual = result.points[index]
        if actual is None:
            problems.append('Сообщение или момент отсутствует в анализируемом диапазоне')
        else:
            if 'expected_level' in case and actual['level'] != case['expected_level']:
                problems.append(f"Итог: ожидалось {case['expected_level']}, получено {actual['level']}")
            for kind, expected in case.get('expected_levels', {}).items():
                if actual['levels'][kind] != expected:
                    problems.append(f"{kind}: ожидалось {expected}, получено {actual['levels'][kind]}")
            if case.get('reason_contains'):
                if 'message_id' not in case:
                    problems.append('Проверка reason_contains поддерживается только для сообщения')
                elif case['reason_contains'].lower() not in actual['reason'].lower():
                    problems.append('Не найдено ожидаемое пояснение')
        details.append(dict(case=case, passed=not problems, problems=problems,
                            actual_level=actual['level'] if actual else None,
                            actual_levels=actual['levels'] if actual else None))
    return dict(checked=len(details), passed=sum(d['passed'] for d in details),
                failed=sum(not d['passed'] for d in details), details=details,
                note='Без размеченных критериев точность не оценена' if not details else
                'Результат относится только к размеченным примерам и выбранному архиву')


def export_report(result, profile, archives, directory, split='all'):
    output = Path(directory).resolve()
    if output == profile.directory or output in profile.directory.parents:
        raise ValueError('Для отчёта нужна отдельная папка')
    output.mkdir(parents=True, exist_ok=True)
    from dataclasses import asdict
    if asdict(result.config) != asdict(profile.load_config()):
        raise ValueError('Настройки профиля изменились во время анализа. Повторите прогон.')
    evaluation = evaluate_criteria(result, profile.cases(), split)
    def digest(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    summary = dict(level_scale=LEVEL_SCALE, channel=result.channel, start=result.start, end=result.end, messages=len(result.rows),
                   warmup_messages=result.warmup_messages, split=split, evaluation=evaluation,
                   config_sha256=digest(profile.config_path), criteria_sha256=digest(profile.criteria_path),
                   archive_sha256={str(Path(p).resolve()): digest(p) for p in archives})
    write_json(output / 'summary.json', summary)
    channel_config(result.config, profile.channel).save(str(output / 'config_used.json'))
    write_json(output / 'criteria_used.json', {'schema_version': 1, 'level_scale': LEVEL_SCALE, 'channel': profile.channel,
                                             'cases': [d['case'] for d in evaluation['details']]})
    with (output / 'decisions.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['message_id', 'timestamp', 'text', 'level', *THREAT_TYPES, 'reaction', 'reason'])
        writer.writeheader()
        for row in result.rows:
            writer.writerow(dict(message_id=row['message']['id'], timestamp=row['message']['timestamp'],
                                 text=row['message']['text'], level=row['level'], **row['levels'],
                                 reaction=(row['event'] or {}).get('outcome', ''), reason=row['reason']))
    with (output / 'timeline.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['timestamp', 'level', *THREAT_TYPES])
        writer.writeheader()
        for point in result.points:
            writer.writerow(dict(timestamp=point['timestamp'], level=point['level'], **point['levels']))
    if not (output / 'review_template.json').exists():
        write_json(output / 'review_template.json', {'schema_version': 1, 'channel': result.channel,
            'note': 'Заполните expected_level или expected_levels только после выбора ожидаемого поведения. Не копируйте actual_level автоматически в критерии.',
            'messages': [dict(message_id=r['message']['id'], text=r['message']['text'], actual_level=r['level'],
                              actual_levels=r['levels'], expected_level=None, expected_levels={}, split='tuning') for r in result.rows]})
    (output / 'REPORT.md').write_text(
        f"# Проверка профиля @{result.channel}\n\nСообщений: {len(result.rows)}. "
        f"Критериев: {evaluation['checked']}. Несовпадений: {evaluation['failed']}.\n\n"
        + evaluation['note'] + '.\n\nРезультаты: decisions.csv, timeline.csv, summary.json. '
        'review_template.json — список для ручной разметки, он не является готовым набором критериев. '
        'Ключи API и Telegram в отчёт не включаются.\n', encoding='utf-8')
    return summary


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init', help='Создать отдельный профиль канала')
    init.add_argument('--profile', required=True, type=Path)
    init.add_argument('--channel', required=True)
    init.add_argument('--config', type=Path, default=Path('config_threats.json'))
    check = commands.add_parser('check', help='Проверить профиль на архиве без сети и ПЛК')
    check.add_argument('--profile', required=True, type=Path)
    check.add_argument('--archives', required=True, nargs='+', type=Path)
    check.add_argument('--start', required=True)
    check.add_argument('--end', required=True)
    check.add_argument('--output', required=True, type=Path)
    check.add_argument('--split', choices=['all', 'tuning', 'validation'], default='all')
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            profile = ChannelProfile.create(args.profile, args.channel, ThreatSystemConfig.load(str(args.config)))
            print(str(profile.directory))
            return 0
        profile = ChannelProfile(args.profile)
        config = profile.load_config()
        start, end = date_window(args.start, args.end)
        result = analyze_messages(load_archives(args.archives), profile.channel, start, end,
                                  config, threading.Event(), lambda s: print(s, file=sys.stderr))
        summary = export_report(result, profile, args.archives, args.output, args.split)
        print(json.dumps({k: summary['evaluation'][k] for k in ('checked', 'passed', 'failed')}, ensure_ascii=False))
        return 1 if summary['evaluation']['failed'] else (0 if summary['evaluation']['checked'] else 2)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
