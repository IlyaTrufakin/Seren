"""Per-user single instances and desktop liveness for the supervisor."""
import os
import sys
import json
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
_HANDLES=[]
def single_instance(name,global_scope=False):
    if os.name!='nt':return True
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.restype=ctypes.c_void_p
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_bool,ctypes.c_wchar_p]
    handle=kernel.CreateMutexW(None,False,('Global\\' if global_scope else 'Local\\')+'Seren_'+name)
    if not handle:raise OSError(ctypes.get_last_error())
    _HANDLES.append(handle)
    return ctypes.get_last_error()!=183

def heartbeat(role):
    directory=ROOT/'runtime';directory.mkdir(exist_ok=True)
    path=directory/(role+'.json');temporary=directory/(role+f'.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(dict(pid=os.getpid(),launcher_pid=os.getppid(),role=role,root=str(ROOT),instance=os.environ.get('SEREN_INSTANCE_ID',''),at=time.time())),encoding='utf-8')
    for attempt in range(4):
        try:
            os.replace(temporary,path)
            return
        except PermissionError:
            if attempt == 3:raise
            time.sleep(.05)


def request_launch(role):
    import uuid
    directory=ROOT/'runtime';directory.mkdir(exist_ok=True)
    path=directory/(role+'.launch.json');temporary=directory/(role+f'.launch.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(dict(id=str(uuid.uuid4()),at=time.time())),encoding='utf-8')
    os.replace(temporary,path)

def launch_request_id(role):
    try:return json.loads((ROOT/'runtime'/(role+'.launch.json')).read_text(encoding='utf-8')).get('id','')
    except (OSError,ValueError,AttributeError):return ''
