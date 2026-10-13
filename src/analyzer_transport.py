"""Authenticated loopback snapshots; no PLC access."""
import json
import secrets
import threading
import time
import math
import re
from copy import deepcopy
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
from src.archive_replay import KYIV_ARCHIVE

ROOT = Path(__file__).resolve().parents[1]
KINDS = ('rocket','kab','drone','unknown')

class DailyLog:
    def __init__(self, name, directory=None):
        self.name=name; self.directory=Path(directory or ROOT/'logs'); self.lock=threading.Lock()
    def write(self, event, **data):
        now=datetime.now(KYIV_ARCHIVE)
        with self.lock:
            self.directory.mkdir(parents=True,exist_ok=True)
            with (self.directory/f'{self.name}_{now:%Y-%m-%d}.jsonl').open('a',encoding='utf-8') as stream:
                record=dict(timestamp=now.isoformat(),event=event)
                if 'timestamp' in data:
                    data=dict(data);data['observed_at']=data.pop('timestamp')
                record.update(data)
                stream.write(json.dumps(record,ensure_ascii=False)+'\n')

def transport_settings(path=None):
    path=Path(path or ROOT/'config_analyzers.json')
    defaults=dict(port=8765,timeout_s=15,channels=['monitor1654'],publish_interval_s=2)
    if path.exists():defaults.update(json.loads(path.read_text(encoding='utf-8-sig')))
    if not 1024<=defaults['port']<=65535 or not 5<=defaults['timeout_s']<=120:
        raise ValueError('Invalid analyzer port/timeout')
    channels=defaults['channels']
    if not isinstance(channels,list) or not 1<=len(channels)<=3 or len(set(channels))!=len(channels) or any(not re.fullmatch('[a-z0-9_]+',c) for c in channels):
        raise ValueError('Configure one to three distinct analyzer channels')
    if not 1<=defaults['publish_interval_s']<=defaults['timeout_s']/2:raise ValueError('Invalid publish interval')
    return defaults

def shared_token():
    path=ROOT/'runtime'/'analyzer.key';path.parent.mkdir(exist_ok=True)
    try:
        with path.open('x',encoding='ascii') as stream:stream.write(secrets.token_hex(32))
    except FileExistsError:pass
    # Another freshly launched process may still be completing its exclusive write.
    for attempt in range(10):
        value=path.read_text(encoding='ascii').strip()
        if len(value)>=32:return value
        time.sleep(.02)
    raise ValueError('Invalid analyzer token file')

class ExternalStateStore:
    def __init__(self, channels, timeout=15, clock=time.time):
        self.channels=list(channels);self.timeout=timeout;self.clock=clock;self.lock=threading.Lock();self.data={}
    def accept(self, packet):
        if not isinstance(packet,dict) or packet.get('version')!=1:raise ValueError('Unknown protocol version')
        channel=packet.get('channel')
        if channel not in self.channels:raise ValueError('Unregistered channel')
        if not isinstance(packet.get('session'),str) or not 1<=len(packet['session'])<=80:raise ValueError('Invalid session')
        if type(packet.get('sequence')) is not int or packet['sequence']<0:raise ValueError('Invalid sequence')
        stamp=packet.get('sent_at');now=self.clock()
        if type(stamp) not in (float,int) or not math.isfinite(stamp) or not -5<=now-stamp<=self.timeout:raise ValueError('Stale/future packet')
        levels=packet.get('levels')
        if not isinstance(levels,dict) or set(levels)!=set(KINDS) or any(type(v) is not int or v not in (0,1,2,4) for v in levels.values()):raise ValueError('Invalid levels')
        for key in ('source_online','paused'):
            if type(packet.get(key)) is not bool:raise ValueError('Invalid health')
        expires=packet.get('expires',{})
        if not isinstance(expires,dict):raise ValueError('Invalid deadlines')
        for kind,value in levels.items():
            expiry=expires.get(kind,0)
            if value and (type(expiry) not in (float,int) or not math.isfinite(expiry) or expiry<=now or expiry>now+86400):raise ValueError('Invalid threat deadline')
        if packet['paused'] and any(levels.values()):raise ValueError('Paused analyzer must withdraw levels')
        evidence=packet.get('evidence',{})
        if not isinstance(evidence,dict) or any(k not in KINDS or not isinstance(v,dict) for k,v in evidence.items()):raise ValueError('Invalid evidence')
        for value in evidence.values():
            if not isinstance(value.get('text',''),str) or len(value.get('text',''))>8000 or not isinstance(value.get('message_id',''),str) or len(value.get('message_id',''))>200:raise ValueError('Invalid evidence fields')
        reason=packet.get('reason','')
        if not isinstance(reason,str) or len(reason)>12000:raise ValueError('Invalid reason')
        clean={k:deepcopy(packet.get(k)) for k in ('version','channel','session','sequence','sent_at','levels','expires','evidence','reason','source_online','paused')}
        with self.lock:
            old=self.data.get(channel)
            if old and (stamp<old['sent_at'] or packet['session']==old['session'] and packet['sequence']<=old['sequence']):raise ValueError('Out-of-order packet')
            clean['received_at']=now;self.data[channel]=clean
    def snapshots(self):
        now=self.clock()
        with self.lock:
            result={}
            for channel in self.channels:
                packet=deepcopy(self.data.get(channel,{}))
                age=now-packet.get('received_at',0)
                connected=bool(packet) and age<=self.timeout
                levels={k:(packet.get('levels',{}).get(k,0) if connected and not packet.get('paused') and packet.get('expires',{}).get(k,0)>now else 0) for k in KINDS}
                packet.update(connected=connected,age_s=round(age,1) if packet else None,levels=levels)
                result[channel]=packet
            return result

class AnalyzerServer:
    def __init__(self, store, port, token, log=None):
        self.store=store;self.port=port;self.token=token;self.log=log;self.server=None;self.thread=None
    def start(self):
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                if self.path!='/v1/state':self.send_error(404);return
                if not secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+outer.token):self.send_error(401);return
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if not 0<length<=65536:raise ValueError('Payload too large/empty')
                    self.connection.settimeout(3)
                    packet=json.loads(self.rfile.read(length));outer.store.accept(packet)
                    if outer.log:
                        try:outer.log.write('snapshot',packet=packet)
                        except OSError:pass
                    body=b'{"ok":true}';self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                except (ValueError,TypeError,KeyError,UnicodeError):self.send_error(400)
        self.server=ThreadingHTTPServer(('127.0.0.1',self.port),Handler);self.server.daemon_threads=True
        self.port=self.server.server_port
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True,name='AnalyzerReceiver');self.thread.start()
    def stop(self):
        if self.server:self.server.shutdown();self.server.server_close();self.server=None
        if self.thread:self.thread.join(timeout=2)
