"""API-only main application configuration; no Telegram dictionaries or credentials."""
from copy import deepcopy
from dataclasses import dataclass, field, asdict, fields
import json
import os
from pathlib import Path
import tempfile
from src.threat_models import (ThreatSystemConfig, SoundProfile, AlarmRule, BitMappingConfig,
                               PlcFeedbackConfig, ScheduleConfig)


@dataclass
class MainAlarmRule:
    id: str
    severity: str
    threat_type: str
    enabled: bool
    api_types: list
    api_levels: list
    api_levels_by_type: dict
    sound: SoundProfile
    level_code: int
    general_api_levels: list | None = None  # КАБ/дрон: дополнительное условие по air; None — старые настройки


@dataclass
class MainSystemConfig:
    schema_version: int = 1
    air_classification_version: int = 4
    enabled: bool = True
    city_name: str = 'Харьков'
    alarmmap_enabled: bool = True
    alarmmap_key_file: str = 'API/alarmmap.online.txt'
    alarmmap_katottg: str = 'UA63120270010096107'
    alarmmap_poll_interval_s: int = 15
    api_stale_seconds: int = 60
    rocket_message_ttl_s: int = 600  # 0 disables message classification
    rocket_messages_global: bool = False
    auto_transfer_to_plc: bool = True
    alarm_rules: list = field(default_factory=list)
    safe_sound: SoundProfile = field(default_factory=SoundProfile)
    no_link_sound: SoundProfile = field(default_factory=SoundProfile)
    bit_mapping: BitMappingConfig = field(default_factory=BitMappingConfig)
    plc_feedback: PlcFeedbackConfig = field(default_factory=PlcFeedbackConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)

    @classmethod
    def from_legacy(cls, legacy):
        cfg = cls()
        for key in ('enabled', 'alarmmap_enabled', 'alarmmap_key_file', 'alarmmap_katottg',
                    'alarmmap_poll_interval_s', 'api_stale_seconds', 'auto_transfer_to_plc',
                    'safe_sound', 'no_link_sound', 'bit_mapping', 'plc_feedback', 'schedule'):
            setattr(cfg, key, deepcopy(getattr(legacy, key)))
        for rule in legacy.alarm_rules:
            cfg.alarm_rules.append(MainAlarmRule(rule.id, rule.severity, rule.threat_type,
                rule.enabled and 'alarmmap' in rule.sources, deepcopy(rule.api_types),
                deepcopy(rule.api_levels), deepcopy(rule.api_levels_by_type), deepcopy(rule.sound),
                {'critical':4, 'high':2, 'low':1}[rule.severity]))
        for rule in cfg.alarm_rules:
            if rule.threat_type in ('kab','drone'):
                rule.general_api_levels = [1,2,3]
        cfg.migrate_all_air_to_rocket()
        cfg.migrate_unqualified_air()
        cfg.validate()
        return cfg

    def migrate_general_air(self):
        # Retain the user's severity selections, but stop tagging unqualified air as drones.
        for rule in self.alarm_rules:
            if rule.threat_type != 'drone' or 'air' not in rule.api_types:
                continue
            levels=[n for n in rule.api_levels_by_type.get('air',rule.api_levels) if n in (1,2)]
            general=next(r for r in self.alarm_rules if r.id==rule.severity+'_unknown')
            general.enabled=rule.enabled and bool(levels)
            general.api_types=['air']
            general.api_levels=[]
            general.api_levels_by_type={'air':levels}
            for attr in ('beep_count','beep_duration_ms','pause_between_ms','interval_series_ms','total_duration_s'):
                setattr(general.sound,attr,getattr(rule.sound,attr))
            rule.api_types=[kind for kind in rule.api_types if kind!='air']
            rule.api_levels_by_type.pop('air',None)
        self.air_classification_version=2

    def migrate_all_air_to_rocket(self):
        for rule in self.alarm_rules:
            if rule.threat_type not in ('unknown','drone') or 'air' not in rule.api_types:
                continue
            if rule.enabled:
                levels=rule.api_levels_by_type.get('air',rule.api_levels)
                rocket=next(r for r in self.alarm_rules if r.id==rule.severity+'_rocket')
                previous=rocket.api_levels_by_type.get('air',rocket.api_levels) if 'air' in rocket.api_types else []
                selected=sorted(set(previous)|set(levels))
                if selected:
                    rocket.enabled=True
                    if 'air' not in rocket.api_types:
                        rocket.api_types.append('air')
                    rocket.api_levels_by_type['air']=selected
            rule.api_types=[kind for kind in rule.api_types if kind!='air']
            rule.api_levels_by_type.pop('air',None)
            if not rule.api_types:
                rule.enabled=False
        self.air_classification_version=3

    def migrate_unqualified_air(self):
        # Preserve configured severity and pulse timings without inventing a rocket type.
        for rocket in self.alarm_rules:
            if rocket.threat_type != 'rocket' or 'air' not in rocket.api_types:
                continue
            general = next(r for r in self.alarm_rules if r.id == rocket.severity + '_unknown')
            if not general.enabled or not general.api_types:
                general.enabled = rocket.enabled
                general.api_types = ['air']
                general.api_levels = deepcopy(rocket.api_levels)
                general.api_levels_by_type = {'air': deepcopy(rocket.api_levels_by_type.get('air', rocket.api_levels))}
                for attr in ('beep_count', 'beep_duration_ms', 'pause_between_ms', 'interval_series_ms', 'total_duration_s'):
                    setattr(general.sound, attr, getattr(rocket.sound, attr))
        self.air_classification_version = 4

    @classmethod
    def load(cls, path='config_main.json'):
        path = Path(path)
        if not path.exists():
            legacy = path.parent/'config_threats.json'
            cfg = cls.from_legacy(ThreatSystemConfig.load(str(legacy)))
            cfg.save(path)
            return cfg
        data = json.loads(path.read_text(encoding='utf-8-sig'))
        if data.get('schema_version') != 1:
            raise ValueError('Неизвестная версия настроек основного приложения')
        allowed = {f.name for f in fields(cls)}
        if set(data) - allowed:
            raise ValueError('Неизвестные поля в config_main.json')
        simple = {key:value for key,value in data.items() if key not in (
            'alarm_rules', 'safe_sound', 'no_link_sound', 'bit_mapping', 'plc_feedback', 'schedule')}
        cfg = cls(**simple)
        cfg.alarm_rules = [MainAlarmRule(**dict(r, sound=SoundProfile(**r['sound']))) for r in data['alarm_rules']]
        for key, kind in [('safe_sound',SoundProfile), ('no_link_sound',SoundProfile),
                          ('bit_mapping',BitMappingConfig), ('plc_feedback',PlcFeedbackConfig),
                          ('schedule',ScheduleConfig)]:
            setattr(cfg,key,kind(**data[key]))
        for rule in cfg.alarm_rules:
            rule.level_code={'critical':4,'high':2,'low':1}[rule.severity]
            if rule.threat_type in ('kab','drone') and rule.general_api_levels is None:
                rule.general_api_levels = [1,2,3]
        if data.get('air_classification_version',1)<3:
            cfg.migrate_all_air_to_rocket()
        if data.get('air_classification_version',1)<4:
            cfg.migrate_unqualified_air()
        cfg.validate()
        return cfg

    def to_engine(self):
        engine = ThreatSystemConfig()
        for key in ('enabled', 'alarmmap_enabled', 'alarmmap_key_file', 'alarmmap_katottg',
                    'alarmmap_poll_interval_s', 'api_stale_seconds', 'auto_transfer_to_plc',
                    'safe_sound', 'no_link_sound', 'bit_mapping', 'plc_feedback', 'schedule'):
            setattr(engine,key,deepcopy(getattr(self,key)))
        engine.telegram_enabled = False
        engine.telegram_channels = []
        engine.telegram_api_id = engine.telegram_api_hash = engine.telegram_phone = None
        engine.tracking.enabled = False
        for attr in vars(engine.tracking):
            if attr.endswith('_keywords'):
                setattr(engine.tracking,attr,[])
        engine.district.name = self.city_name
        engine.district.city_keywords = engine.district.district_keywords = engine.district.critical_alert_keywords = []
        for attr in vars(engine.drone_dict):
            setattr(engine.drone_dict,attr,[])
        engine.approach_keywords = {key:[] for key in engine.approach_keywords}
        engine.end_conditions = []
        engine.alarm_rules = []
        for rule in self.alarm_rules:
            converted = AlarmRule(id=rule.id, severity=rule.severity, threat_type=rule.threat_type,
                enabled=rule.enabled, sources=['alarmmap'], api_types=deepcopy(rule.api_types),
                api_levels=deepcopy(rule.api_levels), api_levels_by_type=deepcopy(rule.api_levels_by_type),
                sound=deepcopy(rule.sound))
            converted.api_level_code = rule.level_code
            converted.general_api_levels = deepcopy(rule.general_api_levels)
            engine.alarm_rules.append(converted)
        return engine

    def validate(self):
        if type(self.rocket_message_ttl_s) is not int or not 0 <= self.rocket_message_ttl_s <= 86400:
            raise ValueError('Срок ракетного уточнения: 0 (отключено) или 1–86400 секунд')
        if type(self.rocket_messages_global) is not bool:
            raise ValueError('Учитывать global: требуется логическое значение')
        if not self.city_name.strip():
            raise ValueError('Укажите название города')
        for rule in self.alarm_rules:
            if rule.general_api_levels is not None and (not isinstance(rule.general_api_levels, list)
                    or any(type(n) is not int or n not in (1,2,3) for n in rule.general_api_levels)):
                raise ValueError('Общий уровень API: выбираются только 1, 2, 3')
            allowed = {'critical':(4,), 'high':(2,), 'low':(1,)}.get(rule.severity,())
            if type(rule.level_code) is not int or rule.level_code not in allowed:
                raise ValueError('Уровень правила должен соответствовать его степени опасности')
        self.to_engine().validate()

    def save(self, path='config_main.json'):
        self.validate()
        path = Path(path).resolve()
        fd, temporary = tempfile.mkstemp(dir=path.parent, suffix='.tmp')
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                json.dump(asdict(self),stream,ensure_ascii=False,indent=2)
            os.replace(temporary,path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
