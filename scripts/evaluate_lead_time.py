"""Evaluate 90/120-second critical-command lead time on explicitly paired cases."""
import argparse
import csv
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.replay_telegram import load_history, replay, write_csv, KYIV
from src.threat_models import ThreatSystemConfig


def prepare_impact_candidates(messages, output):
    """Generate an unlabelled review list; never overwrite manually edited labels."""
    import re
    if output.exists():
        return
    rows = []
    channels = {}
    for message in messages:
        channel = message['channel']
        previous = channels.setdefault(channel, [])
        lower = message['text'].lower()
        if re.search(r'вибух|взрыв|прил[еёі]т|упал|упали|впав|впали', lower):
            context = [m for m in previous[-25:] if 0 < float(message['timestamp'])-float(m['timestamp']) <= 600]
            typed = []
            for item in context:
                text = item['text'].lower()
                kind = 'kab' if re.search(r'каб|авіабомб|авиабомб|фаб', text) else 'rocket' if re.search(r'ракет|балист|баліст|баллист', text) else 'drone' if re.search(r'бпла|дрон|шахед|бандерол', text) else ''
                if kind:
                    typed.append((item, kind))
            inferred = typed[-1][1] if typed else ''
            flags = []
            for expression, flag in [
                (r'не упал|не впав|работа пво|робота ппо', 'NEGATED_OR_AIR_DEFENCE'),
                (r'повторн|повторні|ще |еще |ещё |продовж|продолжа', 'CONTINUING_ATTACK'),
                (r'попередньо|предварительно|можливо|возможно', 'UNCONFIRMED'),
                (r'на |над |курс|upd|апд', 'MIXED_OR_EDITED_POST_TIME_UNKNOWN')]:
                if re.search(expression, lower):
                    flags.append(flag)
            if len({kind for _, kind in typed}) > 1:
                flags.append('MULTIPLE_TYPES_IN_CONTEXT')
            if not typed:
                flags.append('NO_TYPED_CONTEXT')
            rows.append(dict(case_id=message['id'].replace('/', '_'), impact_message_id=message['id'],
                threat_type=inferred, signal_message_ids='|'.join(item['id'] for item, kind in typed if kind == inferred),
                review_status='unreviewed', physical_impact_time='', flags='|'.join(flags), impact_text=message['text'],
                context=' || '.join(item['id']+': '+item['text'].replace('\n', ' ') for item in context), notes=''))
        previous.append(message)
    write_csv(output, rows)


def score_cases(messages, decisions, cases):
    lookup = {m['id']: m for m in messages}
    result = []
    truth = lambda value: value is True or str(value).lower() == 'true'
    episodes = []
    opened = None
    for decision in sorted(decisions, key=lambda d: float(d['timestamp'])):
        active = decision['severity'] == 'critical' and truth(decision['audible'])
        if active and opened is None:
            opened = float(decision['timestamp'])
        elif not active and opened is not None:
            episodes.append((opened, float(decision['timestamp'])))
            opened = None
    if opened is not None:
        episodes.append((opened, float('inf')))
    for case in cases:
        impact = lookup.get(case['impact_message_id'])
        signal_ids = set(case['signal_message_ids'].split('|'))
        signals = [lookup[ident] for ident in signal_ids if ident in lookup]
        if impact is None or len(signals) != len(signal_ids):
            raise ValueError(f"Неполные входные данные кейса {case['case_id']}")
        physical = case.get('physical_impact_time', '').strip()
        if physical:
            physical_dt = datetime.fromisoformat(physical.replace('Z', '+00:00'))
            if physical_dt.tzinfo is None:
                raise ValueError('physical_impact_time должен содержать часовой пояс')
            impact_time = physical_dt.timestamp()
        else:
            impact_time = float(impact['timestamp'])
        first_signal = min(float(m['timestamp']) for m in signals)
        candidates = [d for d in decisions if first_signal <= float(d['timestamp']) < float(impact['timestamp'])
            and d['severity'] == 'critical' and truth(d['audible']) and d['rule'].endswith('_'+case['threat_type'])
            and set(d['selected_event_ids'].split('|')) & signal_ids]
        alarm = min(candidates, key=lambda d: float(d['timestamp'])) if candidates else None
        lead = impact_time-float(alarm['timestamp']) if alarm else None
        global_episode = next((start for start, end in episodes if start < impact_time and end > first_signal), None)
        global_lead = impact_time-global_episode if global_episode is not None else None
        result.append(dict(case_id=case['case_id'], threat_type=case['threat_type'],
            review_status=case.get('review_status', 'provisional'),
            timing_basis='physical' if physical else 'telegram_publication_proxy',
            first_signal_time=datetime.fromtimestamp(first_signal, KYIV).isoformat(),
            critical_command_time=alarm['time'] if alarm else '',
            critical_message_id=alarm['message_id'] if alarm else '',
            impact_time=datetime.fromtimestamp(impact_time, KYIV).isoformat(),
            impact_message_id=case['impact_message_id'], lead_seconds=round(lead, 3) if lead is not None else '',
            meets_90_seconds=lead is not None and lead >= 90,
            meets_120_seconds=lead is not None and lead >= 120,
            result='NO_CRITICAL_COMMAND' if lead is None else 'AFTER_IMPACT' if lead < 0 else 'UNDER_90' if lead < 90 else '90_TO_119' if lead < 120 else 'AT_LEAST_120',
            any_critical_command_time=datetime.fromtimestamp(global_episode, KYIV).isoformat() if global_episode is not None else '',
            any_critical_lead_seconds=round(global_lead, 3) if global_lead is not None else '',
            any_critical_meets_90=global_lead is not None and global_lead >= 90,
            any_critical_meets_120=global_lead is not None and global_lead >= 120,
            notes=case.get('notes', '')))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT/'config_threats.json')
    parser.add_argument('--cases', type=Path, default=ROOT/'tests'/'evacuation_cases.csv')
    parser.add_argument('--output', type=Path, default=ROOT/'test_results'/'evacuation')
    parser.add_argument('--decisions', type=Path)
    parser.add_argument('--compare', action='store_true', help='Compare city-critical and launch-critical experimental policies')
    parser.add_argument('--require-seconds', type=int, choices=[90, 120], help='Fail if a reviewed case with independent impact time does not meet the threshold')
    args = parser.parse_args()
    messages = load_history(sorted((ROOT/'logs').glob('telegram_*_2026-09-07_2026-10-07.jsonl')))
    with args.cases.open(encoding='utf-8-sig', newline='') as stream:
        cases = list(csv.DictReader(stream))
    args.output.mkdir(parents=True, exist_ok=True)
    prepare_impact_candidates(messages, args.output/'impact_candidates.csv')
    cases = [case for case in cases if case.get('review_status') in ('provisional', 'reviewed')]
    config = ThreatSystemConfig.load(args.config)
    scenarios = [('current', config)]
    if args.compare:
        early = deepcopy(config)
        for rule in early.alarm_rules:
            if rule.severity == 'critical' and rule.threat_type in ('rocket', 'kab'):
                rule.approaches = list(dict.fromkeys(rule.approaches+['city', 'toward_city']))
        scenarios.append(('city_critical', early))
        launch = deepcopy(early)
        for rule in launch.alarm_rules:
            if rule.severity == 'critical' and rule.threat_type == 'kab':
                rule.approaches = list(dict.fromkeys(rule.approaches+['launch']))
        scenarios.append(('kab_launch_critical', launch))
    all_rows = []
    for name, scenario in scenarios:
        folder = args.output/name
        folder.mkdir(parents=True, exist_ok=True)
        shareable = deepcopy(scenario)
        shareable.telegram_mode = 'web'
        shareable.telegram_api_hash = None
        shareable.telegram_phone = None
        shareable.alarmmap_enabled = False
        shareable.save(folder/'config.json')
        if name == 'current' and args.decisions:
            with args.decisions.open(encoding='utf-8-sig', newline='') as stream:
                decisions = list(csv.DictReader(stream))
            transitions_file = args.decisions.with_name('transitions.csv')
            if transitions_file.exists():
                with transitions_file.open(encoding='utf-8-sig', newline='') as stream:
                    decisions += list(csv.DictReader(stream))
        else:
            decisions, transitions = replay(messages, scenario)
            decisions += transitions
        scores = score_cases(messages, decisions, cases)
        write_csv(folder/'lead_times.csv', scores)
        for score in scores:
            all_rows.append(dict(scenario=name, **score))
        print(name, json.dumps({row['case_id']: row['lead_seconds'] for row in scores}))
    write_csv(args.output/'comparison.csv', all_rows)
    lines = ['# Запас времени для эвакуации', '',
        'Основная проверка: от первого включения **озвучиваемой команды критической тревоги, связанной с данным кейсом**, до падения. Пороги — не меньше 90 с и не меньше 120 с; более ранняя тревога не является нарушением этой метрики.', '',
        '| Сценарий | Кейс | Связанная тревога, с | ≥90 с | ≥120 с | Любая критическая команда, с |',
        '|---|---|---:|---|---|---:|']
    for row in all_rows:
        lines.append(f"| {row['scenario']} | {row['case_id']} | {row['lead_seconds'] if row['lead_seconds'] != '' else 'нет команды'} | {row['meets_90_seconds']} | {row['meets_120_seconds']} | {row['any_critical_lead_seconds'] if row['any_critical_lead_seconds'] != '' else 'нет команды'} |")
    lines += ['', 'Дополнительно проверяется любая озвучиваемая критическая команда, активная во время рассматриваемой цепочки, с обоих каналов. Она могла возникнуть из-за другой угрозы; этот столбец показывает фактическое состояние команды приложения, а не подтверждает распознавание именно данного падения.']
    lines += ['', 'Все исходные кейсы имеют статус **provisional** и требуют ручного подтверждения связи сообщений с конкретным падением. `physical_impact_time` пока пуст: время поста — приближение времени падения, а задержка публикации неизвестна. Посты, в которые позже дописали падение, не подходят для измерения: публичная HTML-история не даёт времени редактирования.', '',
        'Прогоны не измеряют сетевую задержку до ПЛК, фактическое начало звука или длительность эвакуации. Присутствие команд проверяется с учётом тихого часа. Состояния API отсутствуют в датасете.', '',
        'city_critical и kab_launch_critical — отдельные экспериментальные конфигурации. Рабочий config_threats.json не меняется. Более ранние критерии могут создавать дополнительные тревоги; их точность без разметки всех атак/отбоев не оценена.', '',
        'Для принятия результата подтвердите case pairing (review_status=reviewed), внесите независимое время падения с часовым поясом, добавьте пропущенные атаки и повторите прогон. Таблица comparisons показывает только размеченные кейсы, не всю статистику падений за месяц.', '',
        'Коды результатов: NO_CRITICAL_COMMAND — критическая команда не сформирована; AFTER_IMPACT — команда после независимого времени падения; UNDER_90 — менее 90 с; 90_TO_119 — выполнен только порог 90 с; AT_LEAST_120 — выполнены оба порога.', '',
        'До изменения рабочих условий исходный отчёт сохранён отдельно: [исходные правила](../evacuation_before_city_critical/REPORT.md).', '',
        'Запуск сравнения: `.venv\\Scripts\\python.exe -X utf8 scripts\\evaluate_lead_time.py --compare`.']
    (args.output/'REPORT.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(f"Report: {args.output/'REPORT.md'}")
    if args.require_seconds:
        validated = [r for r in all_rows if r['scenario'] == 'current' and r['review_status'] == 'reviewed' and r['timing_basis'] == 'physical']
        if not validated:
            print('No reviewed cases with independent physical impact time; threshold cannot be certified.')
            return 2
        if any(r['lead_seconds'] == '' or r['lead_seconds'] < args.require_seconds for r in validated):
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
