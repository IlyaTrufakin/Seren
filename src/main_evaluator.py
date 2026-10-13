"""API baseline, external channel snapshots and sound lifetime; no Telegram readers."""
import math
from datetime import datetime
from copy import deepcopy
import threading
import time
import json
import urllib.request
from src.analyzer_transport import ExternalStateStore, AnalyzerServer, DailyLog, transport_settings, shared_token
from src.main_api_debug import MainAPIDebugLogger
from src.threat_evaluator import ThreatEvaluator, Observation


class ProfileDurationTimer:
    def __init__(self):
        self.code = None
        self.started = None
        self._lock = threading.Lock()

    def sample(self, code, total_seconds, active, now):
        with self._lock:
            if self.code != code:
                self.code, self.started = code, None
            if active and self.started is None:
                self.started = now
            elapsed = max(0, now-self.started) if self.started is not None else 0
            expired = bool(total_seconds and self.started is not None and elapsed >= total_seconds)
            remaining = max(0, math.ceil(total_seconds-elapsed)) if total_seconds else 0
            return int(elapsed), remaining, expired


class ApiMainEvaluator(ThreatEvaluator):
    def __init__(self, config, on_status_change=None, sound_timer=None, debug_logger=None, on_debug=None):
        self.api_requests_paused=False;self._api_request_generation=0;self._api_next_poll=0
        self.transport=transport_settings()
        self.external_store=ExternalStateStore(self.transport["channels"],self.transport["timeout_s"])
        self.external_server=None
        self.external_server_error=""
        self.main_config = config
        self.debug_logger = debug_logger if debug_logger is not None else MainAPIDebugLogger()
        self.on_debug = on_debug
        self._debug_signature = None
        self._poll_thread_id = None
        self._poll_payload = None
        self._poll_logged = False
        self._api_messages = []
        self._api_messages_error = ''
        self._api_messages_last_success = 0
        self._message_territories = set()
        self._territories_loaded = 0
        self.sound_timer = sound_timer or ProfileDurationTimer()
        self._last_sound_expiry = None
        super().__init__(config.to_engine(), on_status_change)
        self.config.telegram_channels=list(self.transport["channels"])

    def start(self):
        if self.external_server is None:
            try:
                server=AnalyzerServer(self.external_store,self.transport['port'],shared_token(),DailyLog('external_receiver'))
                server.start();self.external_server=server;self.external_server_error=''
            except OSError as error:
                self.external_server_error=str(error)
                self.audit_logger.log_diagnostic('Приём анализаторов недоступен',str(error))
        super().start()

    def stop(self):
        super().stop()
        if self.external_server:self.external_server.stop();self.external_server=None

    def set_api_requests_paused(self,value):
        with self._lock:
            self.api_requests_paused=bool(value);self._api_request_generation+=1;self._api_next_poll=0
            self._alarmmap_online=False
            self._api_error='Запросы API приостановлены' if value else 'Ожидание нового ответа API'
            self._refresh()
        self.audit_logger.log_diagnostic('Опрос API',self._api_error)
        self._publish()

    def _api_loop(self):
        while not self._stop_event.is_set():
            if not self.api_requests_paused and time.monotonic()>=self._api_next_poll:
                self._api_next_poll=time.monotonic()+self.config.alarmmap_poll_interval_s
                generation=self._api_request_generation
                self._poll_alarmmap()
                if generation==self._api_request_generation:self._api_next_poll=time.monotonic()+self.config.alarmmap_poll_interval_s
            self._stop_event.wait(.2)

    def _api_data_is_current(self,now):
        return bool(not self.api_requests_paused and self.config.alarmmap_enabled and self._alarmmap_online and super()._api_data_is_current(now))

    def _extra_observations(self):
        result=[]
        for channel,packet in self.external_store.snapshots().items():
            for kind,level in packet['levels'].items():
                if not level:continue
                evidence=packet.get('evidence',{}).get(kind,{})
                result.append(Observation('telegram:'+channel,kind,'',packet['sent_at'],packet['expires'][kind],
                    evidence.get('text') or packet.get('reason',''),event_id=evidence.get('message_id') or channel+'/'+kind,
                    external_level=level))
        return result

    def _eligible_rocket_messages(self):
        now = time.time()
        ttl = self.main_config.rocket_message_ttl_s
        if not ttl or not self._alarmmap_online or not self.config.alarmmap_enabled or not self._general_api_level() or now - self._api_last_success > self.config.api_stale_seconds or now - self._api_messages_last_success > self.config.api_stale_seconds:
            return []
        territories = {self.config.alarmmap_katottg} | self._message_territories
        result = []
        for message in self._api_messages:
            if message.get('type') not in ('rocket', 'ballistics'):
                continue
            codes = message.get('katottgs')
            if not isinstance(codes, list) or any(not isinstance(c, str) for c in codes) or not (territories.intersection(codes) or self.main_config.rocket_messages_global and 'global' in codes):
                continue
            try:
                date = datetime.fromisoformat(message['date'].replace('Z', '+00:00'))
                if date.tzinfo is None:
                    continue
                age = now - date.timestamp()
            except (KeyError, ValueError, TypeError, AttributeError):
                continue
            if 0 <= age < ttl:
                result.append(message)
        return result

    def _unqualified_air_type(self, level):
        return '' if self._eligible_rocket_messages() else 'unknown'

    def _api_extra_observations(self):
        level = self._general_api_level()
        return [Observation('alarmmap', 'rocket', '', self._api_last_success,
                    self._api_last_success + self.config.api_stale_seconds,
                    f"Ракетное уточнение API event/{m['type']}: {m.get('title','')}; {m['date']}; территории: {m['katottgs']}; уровень взят из air/{level}",
                    api_type='air', api_level=level) for m in self._eligible_rocket_messages()]

    def _evaluate_current_threat_state(self):
        super()._evaluate_current_threat_state()
        state=self.status
        state.external_analyzers=self.external_store.snapshots()
        state.external_server_error=self.external_server_error
        online_analyzers=[channel for channel,packet in state.external_analyzers.items()
                          if packet['connected'] and packet.get('source_online') and not packet.get('paused')]
        state.no_data_link=bool(self.config.alarmmap_enabled and not state.alarmmap_online and not online_analyzers)
        if not state.alarmmap_online and online_analyzers:
            fallback='API недоступен; расчёт по анализаторам: '+', '.join('@'+c for c in online_analyzers)
            state.formation_text=fallback+'\n'+state.formation_text
            state.reason=fallback+'\n'+state.reason
            if not state.active_rule_id and not state.analysis_disabled_by_plc:
                state.level_title='Нет активных угроз по анализаторам'
                state.description=state.level_title+'; API недоступен'
        for channel,packet in state.external_analyzers.items():
            if channel in state.channel_states:
                state.channel_states[channel]['health']=dict(ok=packet['connected'],error='' if packet['connected'] else 'нет связи')
        state.api_rocket_messages = deepcopy(self._eligible_rocket_messages())
        state.api_rocket_messages_error = self._api_messages_error
        if state.api_rocket_messages:
            for detail in state.alarmmap_decoded_details:
                if detail['type']=='air':
                    detail['classification']='Общий уровень air; ракетный тип подтверждён сообщением API event ' + f'(срок {self.main_config.rocket_message_ttl_s} с)'
        if 'unknown' in state.active_threat_types:
            state.level_title=state.level_title.replace('неопознанная','общая воздушная тревога')
            state.description=state.description.replace('неопознанная','общая воздушная тревога')
            state.reason=state.reason.replace('Неопознанная','Общая воздушная тревога (тип не уточнён)')
            state.formation_text=state.formation_text.replace('Неопознанная','Общая воздушная тревога (тип не уточнён)')

    def _general_api_level(self):
        return max((a['level'] for a in self._alarmmap_active_alarms
                    if a.get('type')=='air' and type(a.get('level')) is int), default=None)

    def _rule_matches(self, rule, observation):
        if observation.external_level is not None:
            return rule.threat_type==observation.threat_type and getattr(rule,'api_level_code',None)==observation.external_level
        if observation.source=='alarmmap' and observation.threat_type in ('kab','drone'):
            general=getattr(rule,'general_api_levels',None)
            if general is not None and self._general_api_level() not in general:
                return False
        return super()._rule_matches(rule,observation)

    def _debug_output(self):
        state=self.status
        return dict(general_api_level=self._general_api_level(), level={0:'нет угрозы',1:'низкая',2:'высокая',4:'критическая'}.get(state.level_code,state.level_title),
                    internal_level_code=state.level_code, threat_types=list(state.active_threat_types),
                    rule_id=state.active_rule_id, reason=state.reason,
                    sound_code=state.sound_code, sound_name=state.sound_profile_name,
                    sound_beep_count=state.sound_beep_count, sound_timer_expired=state.sound_timer_expired,
                    sound_remaining_s=state.sound_remaining_s,
                    external_analyzers=state.external_analyzers,
                    api_online=state.alarmmap_online, api_requests_paused=self.api_requests_paused, no_data_link=state.no_data_link, muted=state.is_muted,
                    disabled_by_plc=state.analysis_disabled_by_plc)

    def _write_debug(self, kind, payload=None):
        output=self._debug_output()
        record=dict(event=kind, territory=self.config.alarmmap_katottg, input=deepcopy(payload),
                    accepted_alarms=deepcopy(self._alarmmap_active_alarms),
                    api_error=self._api_error, output=output,
                    messages=deepcopy(self._api_messages), messages_error=self._api_messages_error,
                    accepted_rocket_messages=deepcopy(self._eligible_rocket_messages()),
                    rocket_message_ttl_s=self.main_config.rocket_message_ttl_s,
                    message_territories=sorted(self._message_territories),
                    bomb_conditions=[dict(rule_id=r.id, enabled=r.enabled,
                        general_levels=getattr(r,'general_api_levels',None),
                        general_matches=(getattr(r,'general_api_levels',None) is None
                            or self._general_api_level() in r.general_api_levels),
                        kab_levels=r.api_levels_by_type.get('kab-bombs',r.api_levels))
                        for r in self.config.alarm_rules if r.threat_type=='kab'])
        try:
            path=self.debug_logger.write(record)
            if self.on_debug:
                data=payload.get('data',[]) if isinstance(payload,dict) else (payload or [])
                inputs=', '.join(f"{a.get('type')}={a.get('level')}" for a in data if isinstance(a,dict)) if isinstance(data,list) else 'некорректный ответ'
                message=f"{kind}: API [{inputs or 'нет активных записей'}] → {output['level']}; правило {output['rule_id'] or 'нет'}"
                if self._api_error:
                    message+='; '+self._api_error
                selected=self._eligible_rocket_messages()
                if selected:
                    message+='; уточнение API: '+', '.join(sorted({m['type'] for m in selected}))
                if self._api_messages_error:
                    message+='; сообщения API недоступны: '+self._api_messages_error
                self.on_debug(message,path)
        except Exception as error:
            self.audit_logger.log_diagnostic('Ошибка журнала API',str(error))

    def _request_api(self, suffix, key):
        generation=self._api_request_generation
        if self.api_requests_paused or self._stop_event.is_set():raise InterruptedError('Запросы API приостановлены')
        request=urllib.request.Request('https://alarmmap.online/api/v1/'+suffix,
            headers={'Authorization':f'Bearer {key}','User-Agent':'Seren/2.0'})
        with urllib.request.urlopen(request,timeout=10.0) as response:
            payload=json.loads(response.read().decode('utf-8'))
        if self.api_requests_paused or generation!=self._api_request_generation or self._stop_event.is_set():
            raise InterruptedError('Ответ предыдущего запроса API отменён')
        if suffix.startswith('emergencies/ua/'):
            self._poll_payload=deepcopy(payload)
            # Messages are a historical feed, not an active-emergency snapshot.
            # Collect separately; its failure must not discard current emergencies.
            try:
                self._load_message_territories(key)
                messages=self._request_api('event/type/rocket', key) + self._request_api('event/type/ballistics', key)
                with self._lock:
                    self._api_messages=self._merge_message_history(messages)
                    self._api_messages_error=''
                    self._api_messages_last_success=time.time()
            except Exception as error:
                with self._lock:
                    self._api_messages_error=str(error)
        if self.api_requests_paused or generation!=self._api_request_generation:raise InterruptedError('Ответ предыдущего запроса API отменён')
        data=payload.get('data') if isinstance(payload,dict) else payload
        if suffix.startswith('atu/') and isinstance(data,dict):
            return data
        if not isinstance(data,list) or any(not isinstance(item,dict) for item in data):
            raise ValueError('Некорректный ответ AlarmMap: требуется список data')
        return data

    def _merge_message_history(self, messages):
        # The last-ten feed is history, so disappearance from its window is not an all-clear.
        retained = []
        for message in self._api_messages:
            try:
                date = datetime.fromisoformat(message['date'].replace('Z', '+00:00'))
                if date.tzinfo is not None and 0 <= time.time() - date.timestamp() < self.main_config.rocket_message_ttl_s:
                    retained.append(message)
            except (KeyError, ValueError, TypeError, AttributeError):
                pass
        unique = {json.dumps(m, sort_keys=True, ensure_ascii=False): m for m in retained + messages}
        return deepcopy(list(unique.values()))

    def _load_message_territories(self, key):
        if time.time() - self._territories_loaded < 86400 and self._message_territories:
            return
        code = self.config.alarmmap_katottg
        chain = set()
        for _ in range(6):
            if not code or code in chain:
                break
            territory = self._request_api('atu/ua/' + code, key)
            if not isinstance(territory, dict) or territory.get('katottg') != code:
                raise ValueError('Некорректный справочник территорий API')
            chain.add(code)
            code = territory.get('parent_katottg')
        with self._lock:
            self._message_territories = chain
            self._territories_loaded = time.time()

    def _poll_alarmmap(self):
        if self.api_requests_paused:return
        self._poll_thread_id=threading.get_ident()
        self._poll_payload=None
        self._poll_logged=False
        try:
            super()._poll_alarmmap()
        finally:
            if not self._poll_logged and not self._stop_event.is_set():
                with self._lock:
                    self._write_debug('api_poll',self._poll_payload)
            self._poll_thread_id=None

    def _get_current_reaction_dict(self):
        reaction=super()._get_current_reaction_dict()
        if threading.get_ident()==self._poll_thread_id and not self._poll_logged:
            self._write_debug('api_poll',self._poll_payload)
            self._poll_logged=True
        return reaction

    def _refresh(self):
        super()._refresh()
        state=self.status
        signature=(state.level_code,tuple(state.active_threat_types),state.active_rule_id,
                   state.sound_code,state.sound_beep_count,state.sound_timer_expired,
                   state.alarmmap_online,state.no_data_link,state.is_muted,state.analysis_disabled_by_plc)
        if signature!=self._debug_signature:
            self._write_debug('decision',self._alarmmap_active_alarms)
            self._debug_signature=signature

    def inherit_api_state(self, previous):
        self.api_requests_paused=previous.api_requests_paused
        # A sound/rule edit must not invent a brief API outage and restart its timer.
        if self.external_store.channels==previous.external_store.channels:
            self.external_store=previous.external_store
            self.external_store.timeout=self.transport['timeout_s']
        same_target = (self.main_config.alarmmap_katottg == previous.main_config.alarmmap_katottg
                       and self.main_config.alarmmap_key_file == previous.main_config.alarmmap_key_file)
        if not same_target:
            return
        with previous._lock:
            for attr in ('_alarmmap_active_alarms', '_api_catalog', '_catalog_last_success',
                         '_catalog_last_attempt', '_alarmmap_online', '_alarmmap_last_poll',
                         '_api_last_success', '_api_error', '_prev_alarmmap_sig',
                         '_api_messages', '_api_messages_error', '_api_messages_last_success', '_message_territories', '_territories_loaded'):
                setattr(self, attr, deepcopy(getattr(previous, attr)))

    def _handle_telegram_message(self, msg):
        # Telegram is evaluated exclusively by independent external analyzers.
        return

    def reset_threat_state(self, source='ПЛК (Кнопка сброса)'):
        # Acknowledgement cannot cancel an ongoing API event or restart its sound budget.
        with self._lock:
            self._refresh()
            reaction = self._get_current_reaction_dict()
        self.audit_logger.log_reset_event(source, reaction)
        self._publish()

    def _determine_sound_profile(self):
        super()._determine_sound_profile()
        state = self.status
        profile = next((r.sound for r in self.config.alarm_rules if r.id == state.active_rule_id), self.config.safe_sound)
        if state.no_data_link and not state.active_rule_id:
            profile = self.config.no_link_sound
        elapsed, remaining, expired = self.sound_timer.sample(
            profile.code, profile.total_duration_s,
            bool(state.sound_beep_count), time.monotonic())
        state.sound_total_duration_s = profile.total_duration_s
        state.sound_elapsed_s = elapsed
        state.sound_remaining_s = remaining
        state.sound_timer_expired = expired
        if expired:
            state.sound_beep_count = 0
            if self._last_sound_expiry != profile.code:
                self.audit_logger.log_diagnostic('Общий таймер звука истёк',
                    f'{profile.name}: {profile.total_duration_s} с; звук отключён, тревога сохраняется')
            self._last_sound_expiry = profile.code
        else:
            self._last_sound_expiry = None
        # Level/type bits remain active when the audible lifetime has elapsed.
