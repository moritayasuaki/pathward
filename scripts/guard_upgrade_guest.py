"""Actual systemd guard adoption, power-cut recovery, retry and stale rejection."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path('/opt/pathward-reboot-test')
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
b=module('reboot_guest');u=module('pathward_guard_upgrade');r=u.r
STORE=ROOT/'guards';UNITS=Path('/etc/systemd/system')


def initialize():
    b.initialize(start_case=False)
    r.write_record(b.JOURNAL,{'phase':'prepared','transaction':'a'*32})
    b.file(UNITS/'test-case.service',f'''[Unit]
Description=Isolated guard upgrade power-cut test
After=pathward-recovery.service
Wants=pathward-recovery.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {ROOT}/guard_upgrade_guest.py
TimeoutStartSec=infinity
[Install]
WantedBy=multi-user.target
''')
    b.command('systemctl','daemon-reload');b.command('systemctl','start','--no-block','test-case.service')


def request(number):return ROOT/f'upgrade-{number}.json'


def prepare(number):
    candidate=ROOT/f'helper-{number}.py'
    b.file(candidate,(ROOT/'pathward_recovery.py').read_bytes()+f'\n# Reviewed fixture guard {number}\n'.encode(),0o600)
    return u.prepare(STORE,UNITS,b.PLAN,r.digest_file(b.PLAN),ROOT/'pathward_recovery.py',
                     r.digest_file(ROOT/'pathward_recovery.py'),candidate,r.digest_file(candidate),
                     ROOT/'pathward-recovery',r.digest_file(ROOT/'pathward-recovery'),request(number))


def apply(number,checkpoint=lambda _:None):return u.apply(request(number),r.digest_file(request(number)),checkpoint)


def cut(number,stage):
    def checkpoint(point):
        if point==stage:
            b.emit(f'PW_CUT_POWER {number} {point}')
            while True:time.sleep(1)
    apply(number,checkpoint)
    raise RuntimeError('Missing power checkpoint')


def run():
    case=int(b.COUNTER.read_text());report=json.loads(b.STATE.read_text())
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    assert boot not in report['boots'];report['boots'].append(boot)
    assert b.selected_body({'OLD'})=='OLD'
    assert 'PW_FIXTURE_BOUND_NEW' not in b.command('journalctl','-b','-u','test-new.service','--no-pager')
    pid=b.command('systemctl','show','test-old.service','--property=MainPID','--value')
    before={str(p):r.digest_file(p) for p in [b.PLAN,b.JOURNAL,Path('/run/pathward-recovery/permit.json')]}
    with r.LOCK.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if case>0:
            receipt=apply(case)
            assert receipt['epoch']==case
            assert b.command('systemctl','show','test-old.service','--property=MainPID','--value')==pid
        report['results'].append({'case':case,'epoch':case,'selected':'OLD','retry':case>0})
        if case<5:
            prepare(case+1)
            for path,digest in before.items():assert r.digest_file(path)==digest
            b.file(b.STATE,json.dumps(report),0o600);b.advance(case+1)
            b.emit(f'PW_BOOT_CHECKED {case} OLD epoch={case}')
            cut(case+1,['adopt:pathward-recovery.service:renamed','activate:created',
                        'activate:renamed','activate:synced','receipt:partial'][case])
        else:
            latest=u.identity(u.current(STORE))
            try:apply(1)
            except RuntimeError:pass
            else:raise AssertionError('Stale retry accepted')
            assert u.identity(u.current(STORE))==latest
            prepare(6)
            value=r.read_record(request(6));member=STORE/'generations'/u.identity(value['target'])/'pathward-recovery.service'
            b.file(member,b'corrupt staged unit',0o644)
            try:apply(6)
            except RuntimeError:pass
            else:raise AssertionError('Corrupt target accepted')
            assert u.identity(u.current(STORE))==latest
            # A different reviewed request from the same base can succeed.
            prepare(7)
            real=r.command
            def reload_failure(args,**kwargs):
                if list(args)==['systemctl','daemon-reload']:raise subprocess.CalledProcessError(1,args)
                return real(args,**kwargs)
            r.command=reload_failure
            try:
                try:apply(7)
                except subprocess.CalledProcessError:pass
                else:raise AssertionError('Injected reload did not fail')
            finally:r.command=real
            assert apply(7)['epoch']==6
            assert apply(7)['epoch']==6
            assert b.command('systemctl','show','test-old.service','--property=MainPID','--value')==pid
            for path,digest in before.items():assert r.digest_file(path)==digest
            report.update(final_epoch=6,stale_retry_rejected=True,corrupt_candidate_rejected=True,
                          reload_failure_retry_passed=True,application_files_unchanged=True,
                          live_service_pid_unchanged=True,kernel_sha256=r.digest_file(ROOT/'pathward-recovery'),
                          versions={'systemd':b.command('systemd','--version').splitlines()[0],
                                    'kernel':b.command('uname','-r'),'python':sys.version.split()[0]})
            b.emit('PW_VM_RECOVERY_PASS '+json.dumps(report,sort_keys=True))
    b.command('systemctl','poweroff')


if __name__=='__main__':
    try:initialize() if '--initialize' in sys.argv else run()
    except BaseException as error:
        b.emit('PW_VM_FAILURE '+repr(error))
        for unit in ['test-case.service','pathward-recovery.service','test-old.service','test-new.service']:
            result=subprocess.run(['journalctl','-b','-u',unit,'--no-pager','-n','25'],capture_output=True,text=True)
            b.emit(result.stdout)
        raise
