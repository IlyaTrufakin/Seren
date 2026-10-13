"""Local authenticated commands and state for background engines and GUI viewers."""
import json,time,os,uuid,hmac,hashlib
from pathlib import Path
from src.analyzer_transport import ROOT,shared_token

def enabled():
    try:return json.loads((ROOT/'config_background.json').read_text(encoding='utf-8-sig')).get('enabled') is True
    except (OSError,ValueError):return False

def write_state(role,value):
    directory=ROOT/'runtime';directory.mkdir(exist_ok=True)
    path=directory/('background_'+role+'.json');temp=directory/(path.name+f'.{os.getpid()}.tmp')
    temp.write_text(json.dumps(dict(at=time.time(),pid=os.getpid(),data=value),ensure_ascii=False),encoding='utf-8')
    # Windows readers and sync software can briefly lock the destination.
    for attempt in range(4):
        try:
            os.replace(temp,path)
            return True
        except PermissionError:
            if attempt < 3:
                time.sleep(.05)
    # Keep the last atomic snapshot; the next tick retries with new data.
    try:temp.unlink()
    except OSError:pass
    return False

def read_state(role):
    try:
        value=json.loads((ROOT/'runtime'/('background_'+role+'.json')).read_text(encoding='utf-8'))
        return value['data'] if 0<=time.time()-value['at']<=15 else None
    except (OSError,ValueError,KeyError,TypeError):return None

def send_command(role,action,value=None):
    payload=dict(role=role,action=action,value=value,at=time.time(),id=str(uuid.uuid4()))
    raw=json.dumps(payload,sort_keys=True).encode()
    packet=dict(payload=payload,signature=hmac.new(shared_token().encode(),raw,hashlib.sha256).hexdigest())
    directory=ROOT/'runtime'/'commands';directory.mkdir(parents=True,exist_ok=True)
    temporary=directory/(payload['id']+'.tmp');path=directory/(role+'_'+payload['id']+'.json')
    temporary.write_text(json.dumps(packet),encoding='utf-8');os.replace(temporary,path)

def take_commands(role):
    result=[];directory=ROOT/'runtime'/'commands';directory.mkdir(parents=True,exist_ok=True)
    for path in sorted(directory.glob(role+'_*.json'))[:100]:
        try:
            if path.stat().st_size>65536:continue
            packet=json.loads(path.read_text(encoding='utf-8'));payload=packet['payload']
            signature=hmac.new(shared_token().encode(),json.dumps(payload,sort_keys=True).encode(),hashlib.sha256).hexdigest()
            if payload['role']==role and 0<=time.time()-payload['at']<=30 and hmac.compare_digest(signature,packet['signature']):result.append(payload)
        except (OSError,ValueError,KeyError,TypeError):pass
        finally:
            try:path.unlink()
            except OSError:pass
    return sorted(result,key=lambda c:c['at'])
