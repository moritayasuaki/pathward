#!/usr/bin/env python3
"""Disposable VM guest: real PID 1, real persistent ext4, no network adapter."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path('/opt/pathward-reboot-test')
spec = importlib.util.spec_from_file_location('recovery', ROOT/'pathward_recovery.py')
r = importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
PLAN = ROOT/'plan.json'
JOURNAL = ROOT/'journal.json'
COUNTER = ROOT/'counter'
STATE = ROOT/'case.json'


def emit(message):
    with open('/dev/ttyS0','w') as serial:
        serial.write(message+'\n');serial.flush()


def command(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=60).stdout.strip()


def file(path, data, mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True)
    r.replace_bytes(path,data.encode() if isinstance(data,str) else data,mode)


def initialize(start_case=True):
    # There is deliberately no NIC. Do not spend each cold boot waiting for
    # a network device that this fixture cannot have; recovery uses loopback.
    command('systemctl','mask','systemd-networkd-wait-online.service')
    old = {'phase':'cutover_pending','transaction':'a'*32}
    r.write_record(JOURNAL,old)
    service=ROOT/'service.py'
    code='''import http.server,os,sys
from pathlib import Path
side=sys.argv[1];root=Path('/opt/pathward-reboot-test')
if side=='NEW' and (root/'fail-new').exists():sys.exit(9)
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(side.encode())
 def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',18080),Handler)
print('PW_FIXTURE_BOUND_'+side,flush=True)
server.serve_forever()
'''
    file(service,code)
    plan={'schema':1,'transaction':'a'*32,'journal':str(JOURNAL),
          'permit':'/run/pathward-recovery/permit.json','kernel':str(ROOT/'pathward-recovery'),
          'kernel_sha256':r.digest_file(ROOT/'pathward-recovery'),'state_seed':old}
    for side in ['old','new']:
        plan[side]={'units':['test-'+side+'.service'],'files':{str(service):r.digest_file(service)},'check':['/usr/bin/true']}
        file(Path('/etc/systemd/system/test-'+side+'.service'),f'''[Unit]
Description=Isolated {side} fixture
[Service]
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 {service} {side.upper()}
[Install]
WantedBy=multi-user.target
''')
    r.write_record(PLAN,plan)
    sha=r.digest_file(PLAN)
    boot,drops,fallback=r.unit_text(ROOT/'pathward_recovery.py',PLAN,sha,'test-old.service','test-new.service')
    file(Path('/etc/systemd/system/pathward-recovery.service'),boot)
    file(Path('/etc/systemd/system/pathward-recovery-fallback.service'),fallback)
    for name,text in drops.items():file(Path('/etc/systemd/system')/(name+'.d')/'90-pathward-recovery.conf',text)
    file(Path('/etc/systemd/system/test-case.service'),f'''[Unit]
Description=Isolated boot assertion and power-cut driver
After=pathward-recovery.service
Wants=pathward-recovery.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {ROOT}/reboot_guest.py
TimeoutStartSec=infinity
[Install]
WantedBy=multi-user.target
''')
    file(COUNTER,'0',0o600)
    file(STATE,json.dumps({'boots':[],'plan_sha256':sha,'results':[]}),0o600)
    command('systemd-analyze','verify','/etc/systemd/system/pathward-recovery.service',
            '/etc/systemd/system/test-old.service','/etc/systemd/system/test-new.service')
    command('systemctl','daemon-reload')
    # Deliberately enable both: enablement must not override the decision.
    command('systemctl','enable','test-old.service','test-new.service','pathward-recovery.service','test-case.service')
    command('systemd-run','--unit=lost-transient-guard','--on-active=3600s','/bin/true')
    if start_case: command('systemctl','start','--no-block','test-case.service')


def selected_body(expected):
    until=time.monotonic()+90
    last=''
    while time.monotonic()<until:
        try:
            with urllib.request.urlopen('http://127.0.0.1:18080/',timeout=1) as response:last=response.read().decode()
            if last in expected:return last
        except Exception:pass
        time.sleep(.2)
    raise RuntimeError('No selected fixture response: '+last)


def advance(number):
    file(COUNTER,str(number),0o600)


def cut_at(stage,case):
    def checkpoint(point):
        if point==stage:
            emit(f'PW_CUT_POWER {case} {point}')
            while True:time.sleep(1)
    r.write_record(JOURNAL,{'phase':'committed','transaction':'a'*32},checkpoint)
    raise RuntimeError('Power cut did not happen')


def run():
    case=int(COUNTER.read_text());report=json.loads(STATE.read_text())
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    assert boot not in report['boots'];report['boots'].append(boot)
    if case==7:
        time.sleep(2)
        for side in ['old','new']:
            assert subprocess.run(['systemctl','is-active','--quiet','test-'+side+'.service']).returncode!=0
            assert 'PW_FIXTURE_BOUND_' not in command('journalctl','-b','-u','test-'+side+'.service','--no-pager')
        assert subprocess.run(['systemctl','is-failed','--quiet','pathward-recovery.service']).returncode==0
        report['results'].append({'case':case,'selected':'HOLD'})
        report['versions']={'systemd':command('systemd','--version').splitlines()[0],
                            'python':sys.version.split()[0],'kernel':command('uname','-r')}
        report['kernel_sha256']=r.digest_file(ROOT/'pathward-recovery')
        emit('PW_VM_RECOVERY_PASS '+json.dumps(report,sort_keys=True))
        command('systemctl','poweroff');return
    expected={'NEW'} if case==4 else ({'OLD','NEW'} if case==3 else {'OLD'})
    body=selected_body(expected)
    wrong='OLD' if body=='NEW' else 'NEW'
    assert 'PW_FIXTURE_BOUND_'+wrong not in command('journalctl','-b','-u','test-'+wrong.lower()+'.service','--no-pager'), 'Unselected service ran'
    if case>0:
        assert subprocess.run(['systemctl','is-active','--quiet','lost-transient-guard.timer']).returncode!=0
    if case==6:
        assert r.read_record(JOURNAL)['phase']=='rolled_back'
    report['results'].append({'case':case,'selected':body})
    file(STATE,json.dumps(report),0o600)
    emit(f'PW_BOOT_CHECKED {case} {body} {boot}')
    if case in [0,1,2,3]:
        r.write_record(JOURNAL,{'phase':'cutover_pending','transaction':'a'*32})
        advance(case+1)
        cut_at(['partial','file_synced','renamed','directory_synced'][case],case)
    elif case==4:
        advance(5)
        file(JOURNAL,b'{"format":1,"payload":',0o600)
        emit('PW_COLD_REBOOT 4');command('systemctl','reboot')
    elif case==5:
        advance(6)
        r.write_record(JOURNAL,{'phase':'committed','transaction':'a'*32})
        file(ROOT/'fail-new','1',0o600)
        emit('PW_COLD_REBOOT 5');command('systemctl','reboot')
    elif case==6:
        advance(7)
        file(PLAN,b'corrupt plan',0o600)
        emit('PW_COLD_REBOOT 6');command('systemctl','reboot')


if __name__=='__main__':
    try:
        initialize() if '--initialize' in sys.argv else run()
    except BaseException as error:
        emit('PW_VM_FAILURE '+repr(error))
        for unit in ['pathward-recovery.service','test-old.service','test-new.service','pathward-recovery-fallback.service']:
            result=subprocess.run(['journalctl','-b','-u',unit,'--no-pager','-n','30'],capture_output=True,text=True)
            emit(result.stdout)
        raise
