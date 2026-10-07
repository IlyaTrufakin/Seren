"""Configurable alarm rules; network I/O never blocks evaluation or PLC heartbeat."""
from copy import deepcopy
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import os
import re
import threading
import time
import urllib.request

from src.threat_models import (ThreatSystemConfig, ThreatStatus, SignificantEvent,
                               SEVERITIES, THREAT_TYPES, APPROACHES)
from src.telegram_reader import TelegramWebReader, TelegramTelethonReader, normalize_channel
from src.audit_logger import ThreatAuditLogger


@dataclass
class Observation:
    source: str
    threat_type: str
    approach: str
    timestamp: float
    expires_at: float
    text: str
    drone_group: int = 0
    drone_name: str = ''
    district: str = ''
    api_type: str = ''
    api_level: int = 0
    event_id: str = ''
    quantity: int = 1
    resolution: str = ''


class ThreatEvaluator:
    def __init__(self, config: ThreatSystemConfig, on_status_change=None):
        self.config = config
        self.on_status_change = on_status_change
        self.status = ThreatStatus()
        self.audit_logger = ThreatAuditLogger()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread = self._api_thread = None
        self._observations = {}
        self._channel_context = {}
        self._end_watermarks = {}
        self._last_resolution = ''
        self._last_resolution_time = 0.0
        self._alarmmap_active_alarms = []
        self._api_catalog = {}
        self._catalog_last_success = 0.0
        self._catalog_last_attempt = 0.0
        self._alarmmap_online = False
        self._alarmmap_last_poll = 0.0
        self._api_last_success = 0.0
        self._api_error = ''
        self._tg_health = {}
        self._tg_last_msg_time = 0.0
        self._heartbeat_state = 0
        self._plc_analysis_enabled = True
        self.recent_events_log = []
        self.tg_reader = None
        self._prev_alarmmap_sig = None
        self._init_tg_reader()

    def _init_tg_reader(self):
        if not self.config.telegram_enabled:
            return
        if self.config.telegram_mode == 'telethon':
            if not self.config.telegram_api_id or not self.config.telegram_api_hash:
                self._api_error = 'Не настроены реквизиты Telethon'
                return
            self.tg_reader = TelegramTelethonReader(
                self.config.telegram_api_id, self.config.telegram_api_hash,
                self.config.telegram_channels, self._handle_telegram_message,
                on_health=self._on_tg_health)
        else:
            self.tg_reader = TelegramWebReader(self.config.telegram_channels,
                self._handle_telegram_message, self.config.telegram_poll_interval_s,
                on_health=self._on_tg_health)

    def _on_tg_health(self, channel, ok, error=''):
        if self._stop_event.is_set():
            return
        with self._lock:
            previous = self._tg_health.get(normalize_channel(channel), {})
            self._tg_health[normalize_channel(channel)] = {
                'ok': ok, 'last_success': time.time() if ok else previous.get('last_success', 0),
                'error': error}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        if self.tg_reader:
            self.tg_reader.start()
        if self.config.alarmmap_enabled:
            self._api_thread = threading.Thread(target=self._api_loop, name='AlarmMapReader', daemon=True)
            self._api_thread.start()
        self._thread = threading.Thread(target=self._run_loop, name='ThreatEvaluator', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self.tg_reader:
            self.tg_reader.stop()
        for thread in (self._thread, self._api_thread):
            if thread and thread is not threading.current_thread():
                thread.join(timeout=0.2)

    def _publish(self):
        with self._lock:
            if self._stop_event.is_set():
                return
            snapshot = deepcopy(self.status)
        if self.on_status_change:
            self.on_status_change(snapshot)

    def _refresh(self):
        self._evaluate_current_threat_state()
        self._heartbeat_state = int(time.monotonic()) % 2
        self._build_modbus_word()
        self._determine_sound_profile()

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                with self._lock:
                    self._refresh()
                self._publish()
            except Exception as exc:
                self.audit_logger.log_diagnostic('Ошибка анализатора', str(exc))
            self._stop_event.wait(0.5)

    def _api_loop(self):
        while not self._stop_event.is_set():
            self._poll_alarmmap()
            self._stop_event.wait(self.config.alarmmap_poll_interval_s)

    def _request_api(self, suffix, key):
        request = urllib.request.Request('https://alarmmap.online/api/v1/' + suffix,
            headers={'Authorization': f'Bearer {key}', 'User-Agent': 'Seren/2.0'})
        with urllib.request.urlopen(request, timeout=10.0) as response:
            payload = json.loads(response.read().decode('utf-8'))
        data = payload.get('data') if isinstance(payload, dict) else payload
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError('Некорректный ответ AlarmMap: требуется список data')
        return data

    def _poll_alarmmap(self):
        with self._lock:
            self._alarmmap_last_poll = time.time()
        try:
            with open(self.config.alarmmap_key_file, encoding='utf-8-sig') as f:
                key = f.read().strip()
            if not key:
                raise ValueError('Пустой файл ключа API')
            alarms = self._request_api('emergencies/ua/' + self.config.alarmmap_katottg, key)
            # Validate before replacing the last successful snapshot.
            for alarm in alarms:
                if not isinstance(alarm.get('type'), str) or not isinstance(alarm.get('level'), int):
                    raise ValueError('Некорректные type/level в ответе API')
            if self._stop_event.is_set():
                return
            with self._lock:
                self._alarmmap_active_alarms = alarms
                self._api_last_success = time.time()
                self._alarmmap_online = True
                self._api_error = ''
                self._refresh()
                signature = tuple(sorted((a['type'], a['level'], str(a.get('katottg', '')),
                                          str(a.get('start', ''))) for a in alarms))
                changed = signature != self._prev_alarmmap_sig
                self._prev_alarmmap_sig = signature
                reaction = self._get_current_reaction_dict()
                details = deepcopy(self.status.alarmmap_decoded_details)
                summary = self.status.alarmmap_status_text
            if changed:
                self.audit_logger.log_api_event(summary, details, reaction)
            self._publish()
            now = time.time()
            # Catalog is separate from the health of the current-emergencies endpoint.
            if now - self._catalog_last_success > 86400 and now - self._catalog_last_attempt > 300:
                self._catalog_last_attempt = now
                try:
                    catalog = self._request_api('emergencies/levels', key)
                    parsed = {(str(a['type']), int(a['level'])): a for a in catalog}
                    if self._stop_event.is_set():
                        return
                    with self._lock:
                        self._api_catalog = parsed
                        self._catalog_last_success = time.time()
                except Exception as exc:
                    self.audit_logger.log_diagnostic('Справочник уровней API недоступен', str(exc))
        except Exception as exc:
            if self._stop_event.is_set():
                return
            with self._lock:
                self._alarmmap_online = False
                self._api_error = str(exc)
                self._refresh()
            self._publish()

    def _parse_api_time(self, iso):
        try:
            dt = datetime.fromisoformat(iso.replace('Z', '+00:00'))
            elapsed = max(0, int(time.time() - dt.timestamp()))
            return dt.astimezone().strftime('%H:%M:%S'), f'{elapsed // 60} мин {elapsed % 60} с'
        except (ValueError, TypeError, AttributeError):
            return '-', '-'

    def _match_drone_dictionary(self, text):
        for group in (1, 2, 3):
            for keyword in getattr(self.config.drone_dict, f'group{group}_keywords'):
                if keyword and keyword.lower() in text:
                    return group, keyword
        return (0, 'тип не определён') if any(k in text for k in ['дрон', 'бпла', 'бплa', 'бпл', 'мопед', 'бандерол']) else (0, '')

    def _message_timestamp(self, msg):
        try:
            if msg.get('datetime_iso'):
                dt = datetime.fromisoformat(msg['datetime_iso'].replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    return None
                return dt.timestamp()
            return float(msg['timestamp'])
        except (ValueError, TypeError, KeyError):
            return None

    def _detect_approach(self, text, district, city=False):
        keywords = self.config.approach_keywords
        def matches(key):
            return any(k.strip() and re.search(r'(?<!\w)' + re.escape(k.strip().lower()) +
                       (r'\w*(?!\w)' if key == 'launch' else r'(?!\w)'), text)
                       for k in keywords.get(key, []))
        if district and matches('toward_district'):
            return 'toward_district'
        if district and matches('district'):
            return 'district'
        if city and matches('city'):
            return 'city'
        if city and matches('toward_city'):
            return 'toward_city'
        if matches('launch'):
            return 'launch'
        return ''  # A place name by itself does not prove proximity.

    @staticmethod
    def _has_keywords(text, keywords):
        return any(k.strip() and re.search(r'(?<!\w)' + re.escape(k.strip().lower()) +
                   (r'(?!\w)' if len(k.strip()) < 4 else ''), text) for k in keywords)

    def _ending_condition(self, text, source, kinds):
        for condition in self.config.end_conditions:
            if (condition.enabled and self._source_matches(condition, source)
                    and self._has_keywords(text, condition.keywords)
                    and (not kinds or set(kinds) & set(condition.threat_types))):
                return condition
        return None

    def _end_observations(self, condition, source, kinds, district, city, published, text, event_id):
        """Never dismiss independent confirmations, ambiguous tracks or a continuing attack."""
        tracking = self.config.tracking
        matching = [(key, o) for key, o in self._observations.items()
                    if o.source == source and o.threat_type in condition.threat_types
                    and (not kinds or o.threat_type in kinds) and o.timestamp <= published
                    and o.expires_at > published]
        note = f'{condition.name}: '
        if self._has_keywords(text, condition.reject_keywords):
            return note + 'отрицание падения/уничтожения или работа ПВО; снятие не выполнено.'
        if condition.action == 'ignore':
            return note + 'срок тревоги не изменён (настроено наблюдение без снятия).'
        if condition.require_confirmed and self._has_keywords(text, tracking.uncertain_keywords):
            return note + 'предварительное сообщение — автоматическое снятие не выполнено.'
        if self._has_keywords(text, tracking.continuing_keywords):
            return note + 'сообщение содержит продолжающуюся угрозу; общий сброс запрещён.'
        if district:
            landmarks = set(district.split(', '))
            matching = [(key, o) for key, o in matching if landmarks & set(o.district.split(', '))]
        elif not city:
            same_post = [(key, o) for key, o in matching if o.event_id == event_id]
            if not condition.allow_without_location:
                return note + 'нет привязки к наблюдаемому городу/району.'
            context = self._channel_context.get(source)
            if not context or not 0 <= published-context['timestamp'] <= condition.context_seconds:
                return note + 'нет свежего контекста этого канала.'
            if len(context['kinds']) != 1:
                return note + 'контекст неоднозначен: несколько типов целей.'
            matching = same_post or [(key, o) for key, o in matching if o.event_id == context['event_id']]
        # Regional/city all-clear is explicit. Other endings require a single target event.
        explicit_clear = condition.regional_clear and condition.action == 'clear' and bool(city)
        events = {o.event_id for _, o in matching}
        if not explicit_clear and len(events) != 1:
            return note + 'цель не определена однозначно; срок тревоги сохранён.'
        if not matching:
            return note + 'подходящих активных наблюдений нет.'
        if not explicit_clear and any(o.quantity > 1 for _, o in matching):
            return note + 'наблюдаются несколько целей; единичный прилёт не завершает всю группу.'
        for key, observation in matching:
            if condition.action == 'clear':
                del self._observations[key]
            else:
                observation.expires_at = min(observation.expires_at, published + condition.hold_seconds)
                observation.resolution = f'{condition.name} @{source.split(":",1)[1]}: {text}; выдержка {condition.hold_seconds} с'
            # An older replay cannot restore an ended observation.
            marker = (source, observation.threat_type, observation.district)
            self._end_watermarks[marker] = max(published, self._end_watermarks.get(marker, 0))
        return note + (f'сняты {len(matching)} наблюдения своего канала.' if condition.action == 'clear'
                       else f'оставлена выдержка {condition.hold_seconds} с для {len(matching)} наблюдения.')

    def _handle_telegram_message(self, msg):
        if self._stop_event.is_set():
            return
        published = self._message_timestamp(msg)
        now = time.time()
        ttl = self.config.district.ttl_seconds
        # Show recent operational channel messages in UI (up to 2 hours history), but active alarms require fresh TTL
        history_window = 7200
        if published is None or published > now + 30 or published + history_window <= now:
            return
        channel = normalize_channel(msg.get('channel', ''))
        if channel not in [normalize_channel(c) for c in self.config.telegram_channels]:
            return
        text = msg.get('text', '').strip()
        lower = text.lower()
        if not lower:
            return
        # Ignore ads, donation cards, administrative messages
        if any(w in lower for w in ['monobank', 'монобанк', 'карта:', 'картку', 'фінансова підтримка',
                                    'финансовая поддержка', 'збір на', 'сбор на', 'підтримати канал', 'поддержать канал']):
            return
        with self._lock:
            if self._stop_event.is_set():
                return
            self._tg_last_msg_time = max(self._tg_last_msg_time, published)
            source = 'telegram:' + channel
            district = ', '.join(k for k in self.config.district.district_keywords if k and k.lower() in lower)
            city = district or any(k and k.lower() in lower for k in self.config.district.city_keywords)
            group, name = self._match_drone_dictionary(lower)
            tracking = self.config.tracking
            approach = self._detect_approach(lower, district, city)
            kinds = []
            if self._has_keywords(lower, tracking.rocket_keywords) or (approach == 'launch' and self._has_keywords(lower, tracking.rocket_launch_keywords)):
                kinds.append('rocket')
            if self._has_keywords(lower, tracking.bomb_keywords):
                kinds.append('kab')
            if name:
                kinds.append('drone')

            # 100% guarantee trigger phrases: Call to shelter & Attack heading to city/district
            shelter_keywords = getattr(self.config.district, 'critical_alert_keywords', []) or [
                'в укриття', 'в укрытие', 'всі в укриття', 'все в укрытие',
                'негайно в укриття', 'терміново в укриття', 'срочно в укрытие', 'немедленно в укрытие',
                'перебувайте в укриттях', 'перебувати в укриттях', 'находитесь в укрытиях', 'находиться в укрытиях',
                'в безпечні місця', 'в безопасные места', 'в безпечне місце', 'в безопасное место', 'укриття'
            ]
            has_shelter = any(k.strip() and k.strip().lower() in lower for k in shelter_keywords)

            city_approach_phrases = [
                'на місто', 'на город', 'курс на місто', 'курс на город', 'напрямок на місто', 'направление на город',
                'в бік міста', 'у бік міста', 'в сторону города', 'до міста', 'к городу',
                'на харків', 'на харьков', 'курс на харків', 'курс на харьков',
                'в бік харкова', 'у бік харкова', 'в сторону харькова',
                'заходить на місто', 'заходит на город', 'заходить на харків', 'заходит на харьков',
                'рухається на місто', 'движется на город', 'летить на місто', 'летит на город',
                'прямує на місто', 'захід на місто', 'захід на харків'
            ]
            has_city_approach = any(p in lower for p in city_approach_phrases)

            if has_shelter:
                city = True
                if not approach:
                    approach = 'district' if district else 'city'

            if has_city_approach:
                city = True
                if not approach:
                    approach = 'city' if any(w in lower for w in ['над', 'в черте', 'в межах']) else 'toward_city'

            context = self._channel_context.get(source)
            if not context or published - context['timestamp'] > tracking.context_seconds:
                for other_src, other_ctx in self._channel_context.items():
                    if 0 <= published - other_ctx['timestamp'] <= tracking.context_seconds:
                        context = other_ctx
                        break
            context_fresh = (tracking.enabled and context and len(context['kinds']) == 1
                and 0 <= published-context['timestamp'] <= tracking.context_seconds)
            if context_fresh:
                recent_kinds = {o.threat_type for o in self._observations.values()
                                if o.source == source and 0 <= published-o.timestamp <= tracking.context_seconds}
                context_fresh = len(recent_kinds) <= 1
            movement = self._has_keywords(lower, tracking.movement_keywords)
            event_id = str(msg.get('id') or f"{source}:{published}")
            inferred = False
            if not kinds:
                if context_fresh and ((movement and (district or city)) or approach == 'launch' or has_shelter or has_city_approach):
                    kinds = list(context['kinds'])
                    group, name = context['group'], context['name']
                    inferred = True
                elif has_shelter:
                    # An urgent call to shelter with no prior context: treat as high-priority alert (rocket)
                    kinds = ['rocket']
                    inferred = True
                elif has_city_approach or (movement and (district or city)):
                    # Explicit movement towards city/district with no prior context: treat as incoming drone
                    kinds = ['drone']
                    group = 0
                    name = 'тип не определён'
                    inferred = True
            condition = self._ending_condition(lower, source, kinds)
            if condition and condition.regional_clear and self._has_keywords(lower,
                    ['для міста', 'для города', 'город', 'місто', 'область', 'области', 'повітряний', 'воздушный']):
                city = True
            if not kinds and not condition:
                return
            count_match = re.search(r'(?<!\w)(\d{1,2})\s+(?:ракет|каб|шахед|бпла|бандерол|на\s)', lower)
            quantity = max(1, int(count_match[1])) if count_match else (context['quantity'] if (inferred and context) else 1)
            if self._has_keywords(lower, ['два', 'дві', 'две', 'декілька', 'несколько']):
                quantity = max(2, quantity)
            has_explicit_threat = (self._has_keywords(lower, tracking.rocket_keywords) or
                                   self._has_keywords(lower, tracking.bomb_keywords) or bool(name))
            category = 'clear' if condition else ('shelter' if has_shelter and not has_explicit_threat else kinds[0])
            badge_threat_str = condition.name if condition else ('В укрытие!' if has_shelter and not has_explicit_threat else '/'.join(THREAT_TYPES[k] for k in kinds))
            event = SignificantEvent(
                time_str=datetime.fromtimestamp(published).strftime('%H:%M:%S'), timestamp=published,
                channel=channel, category=category,
                badge_threat=badge_threat_str,
                badge_target=APPROACHES.get(approach, 'Приближение не определено') + (' / контекст канала' if inferred else ''),
                sector_name=district or 'Город / область', drone_name=name, drone_group=group,
                text=text, is_critical=approach in ('district', 'toward_district') or has_shelter)
            self.status.significant_events.insert(0, event)
            del self.status.significant_events[40:]
            self.recent_events_log.insert(0, dict(channel=channel, text=text, time_str=event.time_str))
            del self.recent_events_log[50:]
            if condition:
                note = self._end_observations(condition, source, kinds, district, city, published, lower, event_id)
                self._last_resolution = f"@{channel} [{event.time_str}]: {note} «{text}»"
                self._last_resolution_time = published
                if condition.action == 'ignore' and kinds and approach:
                    for kind in kinds:
                        key = (source, kind, event_id)
                        if key not in self._observations and published > self._end_watermarks.get((source, kind, district), 0):
                            if published + ttl > now:
                                self._observations[key] = Observation(source, kind, approach, published, published+ttl,
                                    text, group if kind == 'drone' else 0, name if kind == 'drone' else '', district,
                                    event_id=event_id, quantity=quantity, resolution='Потеря фиксации не подтверждает завершение угрозы')
                # Do not re-activate a target from the threat words in an ending message.
            else:
                movement_note = ''
                if movement and context_fresh and context['kinds'] == kinds and context['quantity'] == 1 and quantity == 1:
                    previous = [(key, o) for key, o in self._observations.items()
                                if o.source == source and o.event_id == context['event_id'] and o.timestamp <= published]
                    if previous and all(o.district != district or o.approach != approach for _, o in previous):
                        for key, o in previous:
                            if tracking.movement_action == 'replace':
                                del self._observations[key]
                            elif tracking.movement_action == 'shorten':
                                o.expires_at = min(o.expires_at, published + tracking.movement_hold_seconds)
                                o.resolution = f'Продвижение цели: {text}; прежняя зона удерживается {tracking.movement_hold_seconds} с'
                        movement_note = f"Продвижение цели ({tracking.movement_action}); предыдущий сектор не снимает подтверждения других каналов."
                for kind in kinds:
                    # Keep several target events independently; ending one cannot discard another.
                    key = (source, kind, event_id)
                    marker = (source, kind, district)
                    if published <= self._end_watermarks.get(marker, 0):
                        continue
                    if published + ttl <= now:
                        continue  # Expired observation: kept in operational event history, but does not trigger live alarm
                    observation_text = text
                    if inferred and context:
                        observation_text += f" [тип из контекста @{channel}: {context['text']}]"
                    self._observations[key] = Observation(source, kind, approach, published, published + ttl,
                        observation_text, group if kind == 'drone' else 0, name if kind == 'drone' else '', district,
                        event_id=event_id, quantity=quantity)
                if not context or published >= context['timestamp']:
                    self._channel_context[source] = dict(kinds=kinds, timestamp=published, event_id=event_id,
                        group=group, name=name, quantity=quantity, text=text)
                if movement_note:
                    self._last_resolution = f'@{channel} [{event.time_str}]: {movement_note}'
                    self._last_resolution_time = published
            self.status.last_event_time = published
            self.status.last_event_source = '@' + channel
            self.status.last_event_text = text
            self._refresh()
            reaction = self._get_current_reaction_dict()
        self.audit_logger.log_telegram_event(asdict(event), reaction)
        self._publish()

    @staticmethod
    def _source_matches(rule, source):
        sources = [s.lower() for s in rule.sources]
        return source in sources or (source.startswith('telegram:') and 'telegram:*' in sources)

    def _rule_matches(self, rule, observation):
        if not rule.enabled or not self._source_matches(rule, observation.source):
            return False
        if observation.source == 'alarmmap':
            # Do not invent a drone group or physical approach from an API level.
            return (observation.api_type in rule.api_types and observation.api_level in rule.api_levels
                    and (rule.threat_type != 'drone' or 0 in rule.drone_groups))
        return (rule.threat_type == observation.threat_type and observation.approach in rule.approaches
                and (rule.threat_type != 'drone' or observation.drone_group in rule.drone_groups))

    def _evaluate_current_threat_state(self):
        now = time.time()
        if now-self._last_resolution_time > self.config.district.ttl_seconds:
            self._last_resolution = ''
        st = self.status
        st.last_resolution = self._last_resolution
        self._end_watermarks = {key: stamp for key, stamp in self._end_watermarks.items()
                                if now - stamp <= self.config.district.ttl_seconds}
        st.alarmmap_catalog = [dict(value) for value in self._api_catalog.values()]
        self._observations = {k: v for k, v in self._observations.items() if v.expires_at > now}
        observations = list(self._observations.values()) if self.config.telegram_enabled else []
        api_fresh = self._api_last_success > 0 and now - self._api_last_success <= self.config.api_stale_seconds
        st.alarmmap_online = self.config.alarmmap_enabled and self._alarmmap_online and api_fresh
        st.alarmmap_last_poll_time = self._alarmmap_last_poll
        st.alarmmap_decoded_details = []
        type_names = {'air': 'Воздушная тревога (тип цели не указан)', 'kab-bombs': 'Бомбовая угроза / КАБ',
                      'fight-drones': 'Ударные БпЛА', 'artillery': 'Артиллерийский обстрел',
                      'rockets': 'Ракетная угроза', 'chemical': 'Химическая опасность', 'radiation': 'Радиационная опасность'}
        st.alarmmap_has_air = st.alarmmap_has_kab = st.alarmmap_has_drone = st.alarmmap_has_artillery = False
        st.alarmmap_level = 0
        for alarm in self._alarmmap_active_alarms if self.config.alarmmap_enabled else []:
            kind, level = alarm['type'], alarm['level']
            entry = self._api_catalog.get((kind, level), {})
            title = entry.get('title') or f'Уровень {level}: справочник ещё не получен'
            description = entry.get('description') or 'Смысл уровня не подтверждён справочником API'
            start, duration = self._parse_api_time(alarm.get('start', ''))
            target = 'г. Харьков' if alarm.get('katottg') == 'UA63120270010096107' else str(alarm.get('katottg', 'Не указана'))
            detail = dict(type=kind, type_title=type_names.get(kind, kind), icon='•', level=level,
                          level_title=title, description=description, start_local=start, duration_str=duration,
                          katottg=alarm.get('katottg', ''), target_name=target, stale=not api_fresh)
            st.alarmmap_decoded_details.append(detail)
            st.alarmmap_level = max(st.alarmmap_level, level)
            for expected, attr in [('air', 'alarmmap_has_air'), ('kab-bombs', 'alarmmap_has_kab'),
                                   ('fight-drones', 'alarmmap_has_drone'), ('artillery', 'alarmmap_has_artillery')]:
                if kind == expected:
                    setattr(st, attr, True)
            if api_fresh:
                observations.append(Observation('alarmmap', '', '', self._api_last_success,
                    self._api_last_success + self.config.api_stale_seconds,
                    f'{type_names.get(kind, kind)}; API {kind}/{level}: {title}. {description}; территория: {target}',
                    api_type=kind, api_level=level))
        st.alarmmap_active_count = len(st.alarmmap_decoded_details)
        st.alarmmap_types_summary = ', '.join(f"{d['type_title']} — {d['level_title']}" for d in st.alarmmap_decoded_details)
        st.alarmmap_duration_summary = ', '.join(d['duration_str'] for d in st.alarmmap_decoded_details)
        st.alarmmap_full_text = '\n'.join(
            f"{d['type_title']} | {d['type']}/{d['level']}: {d['level_title']}\n{d['description']} | {d['target_name']} | с {d['start_local']} ({d['duration_str']})"
            for d in st.alarmmap_decoded_details) or ('Активных записей нет' if st.alarmmap_online else 'Актуальные данные API недоступны')
        if not api_fresh and st.alarmmap_decoded_details:
            st.alarmmap_full_text = 'УСТАРЕВШИЕ ДАННЫЕ (не участвуют в выборе тревоги)\n' + st.alarmmap_full_text
        st.alarmmap_status_text = ('Отключено' if not self.config.alarmmap_enabled else
            ('Онлайн: есть активные записи' if st.alarmmap_active_count else 'Онлайн: активных записей нет')
            if st.alarmmap_online else 'Нет связи / ' + (self._api_error or 'нет актуальных данных'))
        health = {}
        if self.config.alarmmap_enabled:
            health['alarmmap'] = dict(ok=st.alarmmap_online, error=self._api_error)
        for channel in self.config.telegram_channels if self.config.telegram_enabled else []:
            channel = normalize_channel(channel)
            info = self._tg_health.get(channel, {})
            ok = info.get('ok', False) and now - info.get('last_success', 0) <= self.config.source_stale_seconds
            health['telegram:' + channel] = dict(ok=ok, error=info.get('error', '') if not ok else '')
        st.source_health = health
        st.tg_online = self.config.telegram_enabled and bool(self.config.telegram_channels) and all(
            health.get('telegram:' + normalize_channel(c), {}).get('ok', False) for c in self.config.telegram_channels)
        st.no_data_link = any(not v['ok'] for v in health.values())
        st.tg_mode, st.tg_channels, st.tg_last_msg_time = self.config.telegram_mode, list(self.config.telegram_channels), self._tg_last_msg_time
        matches = []
        for rule in self.config.alarm_rules:
            evidence = [o for o in observations if self._rule_matches(rule, o)]
            if evidence:
                matches.append((rule, evidence))
        matches.sort(key=lambda pair: ({'critical': 3, 'high': 2, 'low': 1}[pair[0].severity],
                                       {'rocket': 3, 'kab': 2, 'drone': 1}[pair[0].threat_type]), reverse=True)
        st.analysis_disabled_by_plc = not self._plc_analysis_enabled or not self.config.enabled
        st.is_muted = self.config.schedule.is_in_schedule()
        st.active_rule_id = st.active_threat_type = ''
        st.severity, st.level_code, st.level_title = 'safe', 0, 'Отсутствие тревог'
        st.has_rocket = st.has_kab = st.has_drone = False
        st.is_city_threat = st.is_district_threat = False
        st.drone_group, st.matched_drone_name = 0, ''
        st.matched_sources = []
        st.selected_event_ids = []
        if matches and not st.analysis_disabled_by_plc:
            rule, evidence = matches[0]
            leading = max(evidence, key=lambda o: o.timestamp)
            st.active_rule_id, st.active_threat_type, st.severity = rule.id, rule.threat_type, rule.severity
            st.is_district_threat = any(o.approach in ('district', 'toward_district') for o in evidence)
            st.is_city_threat = True
            st.level_code = {'low': 1, 'high': 3 if st.is_district_threat else 2,
                             'critical': 5 if st.is_district_threat else 4}[rule.severity]
            st.level_title = f'{SEVERITIES[rule.severity]} опасность — {THREAT_TYPES[rule.threat_type].lower()}'
            # Flags represent the selected alarm; simultaneous alternatives are explained below.
            st.has_rocket, st.has_kab, st.has_drone = (rule.threat_type == k for k in ('rocket', 'kab', 'drone'))
            st.drone_group, st.matched_drone_name = leading.drone_group, leading.drone_name
            st.matched_sources = sorted({o.source for o in evidence})
            st.selected_event_ids = sorted({o.event_id for o in evidence if o.event_id})
            reasons = []
            for o in evidence:
                source = 'AlarmMap API' if o.source == 'alarmmap' else '@' + o.source.split(':', 1)[1]
                timestamp = datetime.fromtimestamp(o.timestamp).strftime('%H:%M:%S')
                details = o.text if o.source == 'alarmmap' else (
                    f"{APPROACHES.get(o.approach, 'не определено')}; {o.district or 'город/область'}; "
                    + (f'группа дрона {o.drone_group or "неизвестна"}; ' if rule.threat_type == 'drone' else '')
                    + f'«{o.text}» (осталось {max(0, int(o.expires_at-now))} с)'
                    + (f'; {o.resolution}' if o.resolution else ''))
                reasons.append(f'{source} [{timestamp}]: {details}')
            st.reason = f'Сработало правило «{rule.sound.name}».\n' + '\n'.join(reasons)
            if len(matches) > 1:
                st.reason += '\nДругие совпадения: ' + ', '.join(r.sound.name for r, _ in matches[1:]) + '. Выбор: степень → ракета → бомба → дрон.'
        else:
            st.reason = 'Нет совпадений с включёнными правилами.'
            if observations:
                st.reason += '\nДанные есть, но не подходят выбранным источникам, приближению, группе или уровням API.'
            if st.analysis_disabled_by_plc:
                st.level_title = 'Анализ приостановлен'
                st.reason += '\nТумблер ПЛК или общий анализ выключен.'
        if st.no_data_link:
            st.reason += '\nНедоступные источники: ' + ', '.join(src for src, info in health.items() if not info['ok']) + '. Отсутствие совпадений не подтверждает отсутствие угроз.'
        if st.is_muted:
            st.reason += '\nТихий час: тревога отображается, выдача сигналов в ПЛК подавлена.'
        if self._last_resolution:
            st.reason += '\nПоследнее условие завершения/движения: ' + self._last_resolution
        st.description = st.level_title if st.active_rule_id else 'Нет активного правила; состояние источников указано в причине'
        tg = [o for o in observations if o.source.startswith('telegram:')]
        for scope in ('city', 'district'):
            selected = [o for o in tg if bool(o.district) == (scope == 'district')]
            scope_matches = [(r, o) for r in self.config.alarm_rules for o in selected if self._rule_matches(r, o)]
            scope_matches.sort(key=lambda pair: ({'critical': 3, 'high': 2, 'low': 1}[pair[0].severity],
                                                 {'rocket': 3, 'kab': 2, 'drone': 1}[pair[0].threat_type]), reverse=True)
            scope_rule, chosen = scope_matches[0] if scope_matches else (None, None)
            setattr(st, f'tg_{scope}_threat', chosen.threat_type if chosen else '')
            scope_level = ({'low': 1, 'high': 3 if scope == 'district' else 2,
                            'critical': 5 if scope == 'district' else 4}[scope_rule.severity] if scope_rule else 0)
            setattr(st, f'tg_{scope}_level', scope_level)
            setattr(st, f'tg_{scope}_ttl_remain_s', max(0, int(chosen.expires_at-now)) if chosen else 0)
        st.tg_district_landmarks = ', '.join(sorted({o.district for o in tg if o.district}))
        st.tg_drone_name, st.tg_drone_group = st.matched_drone_name, st.drone_group

    def _determine_sound_profile(self):
        st = self.status
        profile = next((r.sound for r in self.config.alarm_rules if r.id == st.active_rule_id), self.config.safe_sound)
        if st.analysis_disabled_by_plc or st.is_muted:
            st.sound_code = st.sound_beep_count = st.sound_duration_ms = st.sound_pause_ms = st.sound_interval_ms = 0
            st.sound_profile_name = 'Блокировка / Тишина'
        else:
            st.sound_code, st.sound_beep_count = profile.code, profile.beep_count
            st.sound_duration_ms, st.sound_pause_ms, st.sound_interval_ms = profile.beep_duration_ms, profile.pause_between_ms, profile.interval_series_ms
            st.sound_profile_name = profile.name

    def _build_modbus_word(self):
        st, bm = self.status, self.config.bit_mapping
        val = 0
        if st.is_muted:
            val = (1 << bm.bit_safe) | (1 << bm.bit_muted_by_schedule)
        else:
            level_bits = [bm.bit_safe, bm.bit_threat_minimal, bm.bit_threat_city_potential,
                          bm.bit_threat_district_potential, bm.bit_threat_city_critical, bm.bit_threat_district_critical]
            val = 1 << level_bits[st.level_code]
            for active, bit in [(st.has_rocket, bm.bit_type_rocket), (st.has_kab, bm.bit_type_kab), (st.has_drone, bm.bit_type_drone)]:
                if active:
                    val |= 1 << bit
        if st.no_data_link:
            val |= 1 << bm.bit_no_link
        if self._heartbeat_state:
            val |= 1 << bm.bit_heartbeat
        st.modbus_word = val & 0xffff

    def _get_current_reaction_dict(self):
        return asdict(self.status)

    def set_plc_analysis_switch(self, enabled):
        with self._lock:
            if self._plc_analysis_enabled == enabled:
                return
            self._plc_analysis_enabled = enabled
            self._refresh()
            reaction = self._get_current_reaction_dict()
        self.audit_logger.log_plc_switch_event(enabled, reaction)
        self._publish()

    def reset_threat_state(self, source='ПЛК (Кнопка сброса)'):
        with self._lock:
            self._observations.clear()
            self._channel_context.clear()
            self._last_resolution = "Наблюдения Telegram сброшены оператором"
            # API is a live state: an operator reset cannot dismiss an ongoing API event.
            self._refresh()
            reaction = self._get_current_reaction_dict()
        self.audit_logger.log_reset_event(source, reaction)
        self._publish()
