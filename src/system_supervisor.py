"""Desktop process supervisor: deliberate closes stop, crashes/hangs restart."""
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from src.runtime_support import single_instance,request_launch,launch_request_id
from src.analyzer_transport import DailyLog,ROOT

def terminate_process_tree(process):
    if os.name=='nt':
        result=subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode and process.poll() is None:raise OSError('Cannot terminate hung process tree')
    else:process.kill()
    process.wait(timeout=5)

class ExistingProcess:
    """Watch an already running GUI while replacing only the supervisor."""
    def __init__(self,pid):
        import ctypes
        self.pid=pid;self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.kernel.OpenProcess.restype=ctypes.c_void_p
        self.kernel.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_bool,ctypes.c_uint32]
        self.kernel.GetExitCodeProcess.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32)]
        self.handle=self.kernel.OpenProcess(0x1000,False,pid)
        if not self.handle:raise OSError(ctypes.get_last_error())
    def executable(self):
        import ctypes
        value=ctypes.create_unicode_buffer(32768);size=ctypes.c_uint32(len(value))
        self.kernel.QueryFullProcessImageNameW.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_uint32)]
        if not self.kernel.QueryFullProcessImageNameW(self.handle,0,value,ctypes.byref(size)):raise OSError(ctypes.get_last_error())
        return Path(value.value)
    def poll(self):
        import ctypes
        code=ctypes.c_uint32()
        if not self.kernel.GetExitCodeProcess(self.handle,ctypes.byref(code)):raise OSError(ctypes.get_last_error())
        return None if code.value==259 else code.value
    def wait(self,timeout=5):
        end=time.monotonic()+timeout
        while self.poll() is None:
            if time.monotonic()>end:raise subprocess.TimeoutExpired('existing process',timeout)
            time.sleep(.05)
        return self.poll()

class ManagedApplication:
    def __init__(self,role,args,log,clock=time.time,popen=subprocess.Popen):
        self.role=role;self.args=args;self.log=log;self.clock=clock;self.popen=popen
        self.instance=str(uuid.uuid4());self.process=None;self.started=0;self.next_start=0;self.failures=0;self.closed=False;self.stream=None;self.last_check=None;self.resume_grace=0
    def tick(self):
        now=self.clock()
        if self.closed:return
        if self.last_check is not None and now-self.last_check>10:
            self.resume_grace=now+45
            self.log.write('watchdog_resume_grace',application=self.role,gap_s=round(now-self.last_check,1))
        self.last_check=now
        if self.process is None:
            if now<self.next_start:return
            try:
                directory=ROOT/'logs';directory.mkdir(exist_ok=True)
                self.stream=(directory/(self.role+'_process.log')).open('a',encoding='utf-8')
                self.instance=str(uuid.uuid4())
                self.process=self.popen(self.args,cwd=ROOT,stdout=self.stream,stderr=subprocess.STDOUT,
                    env=dict(os.environ,SEREN_INSTANCE_ID=self.instance),
                    creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                self.started=now;self.log.write('started',application=self.role,pid=self.process.pid)
            except OSError as error:
                self.failed(str(error))
            return
        code=self.process.poll()
        if code is not None:
            if code==0:
                self.closed=True;self.log.write('closed_by_user',application=self.role)
                if self.stream:self.stream.close()
                return
            self.failed('exit code '+str(code));return
        alive=self.started
        try:
            data=json.loads((ROOT/'runtime'/(self.role+'.json')).read_text(encoding='utf-8'))
            if data.get('instance')==self.instance or data.get('launcher_pid')==self.process.pid or data.get('pid')==self.process.pid:
                alive=max(alive,data['at'])
        except (OSError,ValueError,KeyError,TypeError):pass
        if now-self.started>90 and now-alive>45 and now>self.resume_grace:
            terminate_process_tree(self.process);self.failed('GUI heartbeat lost; last age '+str(round(now-alive,1))+' s')
        elif now-self.started>300:self.failures=0
    def reopen(self):
        if not self.closed:return
        self.closed=False;self.process=None;self.stream=None;self.next_start=0;self.failures=0
        self.log.write('reopen_requested',application=self.role)
    def failed(self,reason):
        if self.stream:self.stream.close();self.stream=None
        self.process=None;self.failures+=1;delay=min(60,3*2**min(self.failures-1,5))
        self.next_start=self.clock()+delay
        self.log.write('restart_scheduled',application=self.role,reason=reason,delay_s=delay)

def adopt_recent_process(app):
    if os.name!='nt':return False
    try:
        data=json.loads((ROOT/'runtime'/(app.role+'.json')).read_text(encoding='utf-8'))
        if type(data.get('pid')) is not int or not 0<=app.clock()-data['at']<=10:return False
        if data.get('role',app.role)!=app.role or data.get('root',str(ROOT))!=str(ROOT):return False
        existing=ExistingProcess(data['pid'])
        if existing.poll() is not None or existing.executable().name.lower() not in ('python.exe','pythonw.exe'):return False
        app.process=existing;app.started=app.clock()
        app.log.write('adopted',application=app.role,pid=existing.pid,source='fresh_gui_heartbeat')
        return True
    except (OSError,ValueError,TypeError,KeyError):return False

def main():
    import argparse
    parser=argparse.ArgumentParser(description='Seren process supervisor')
    parser.add_argument('--analyzer-only',type=Path)
    parser.add_argument('--no-publish',action='store_true')
    parser.add_argument('--adopt',action='store_true')
    parser.add_argument('--background',action='store_true')
    args=parser.parse_args()
    role=None
    if args.analyzer_only:
        from src.channel_tuning import ChannelProfile
        role=ChannelProfile(args.analyzer_only).channel
    identity='background_supervisor' if args.background else 'supervisor_'+role if role else 'supervisor'
    if not single_instance(identity,global_scope=args.background):
        if role:request_launch(role)
        return
    python=Path(sys.executable).with_name('pythonw.exe')
    if not python.exists():python=Path(sys.executable)
    log=DailyLog('background_supervisor' if args.background else 'supervisor_'+role if role else 'supervisor')
    applications=[ManagedApplication('main',[str(python),str(ROOT/'main.py')],log),
                  ManagedApplication('monitor1654',[str(python),'-m','src.live_analyzer'],log),
                  ManagedApplication('radar_kharkov',[str(python),'-m','src.live_analyzer','--profile',str(ROOT/'profiles/radar_kharkov')],log)]
    if role:
        command=[str(python),'-m','src.live_analyzer','--profile',str(args.analyzer_only.resolve())]
        if args.no_publish:command.append('--no-publish')
        applications=[ManagedApplication(role,command,log)]
    if args.background:
        applications=[ManagedApplication('service_'+name,[str(python),'-m','src.background_runner','--role',name],log) for name in ('main','monitor1654','radar_kharkov')]
    if args.adopt:
        handoff_path=ROOT/'runtime'/(role+'_handoff.json' if role else 'supervisor_handoff.json')
        handoff=json.loads(handoff_path.read_text(encoding='utf-8-sig'))
        for app in applications:
            pid=handoff.get(app.role)
            if pid:
                app.process=ExistingProcess(pid);app.started=time.time()
                log.write('adopted',application=app.role,pid=pid)
    for app in applications:
        if app.process is None:adopt_recent_process(app)
    log.write('supervisor_started',pid=os.getpid())
    seen_request=launch_request_id(role) if role else ''
    while True:
        if role:
            request=launch_request_id(role)
            if request and request!=seen_request:
                seen_request=request
                for app in applications:app.reopen()
        for app in applications:app.tick()
        time.sleep(2)
if __name__=='__main__':main()
