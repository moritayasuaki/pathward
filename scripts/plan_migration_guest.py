"""Real systemd: disjoint-plan handoff, cold boots and interrupted collection."""
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path('/opt/pathward-reboot-test');UNITS=Path('/etc/systemd/system');STORE=ROOT/'guards'
def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
b=module('reboot_guest');m=module('pathward_plan_migration');u=m.u;r=m.r


def initialize():
    b.initialize(start_case=False)
    plan=r.load_plan(b.PLAN,r.digest_file(b.PLAN))
    if (ROOT/'initial-recovery').exists():
        plan.update(kernel=str(ROOT/'initial-recovery'),kernel_sha256=r.digest_file(ROOT/'initial-recovery'))
        r.write_record(b.PLAN,plan)
        for name,text in u.unit_files(ROOT/'pathward_recovery.py',b.PLAN,r.digest_file(b.PLAN),'test-old.service','test-new.service').items():
            b.file(UNITS/name,text)
    r.write_record(b.JOURNAL,{'phase':'prepared','transaction':'a'*32})
    b.file(UNITS/'test-case.service',f'''[Unit]
Description=Isolated recovery-plan migration and GC
After=pathward-recovery.service
Wants=pathward-recovery.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {ROOT}/plan_migration_guest.py
TimeoutStartSec=infinity
[Install]
WantedBy=multi-user.target
''')
    b.command('systemctl','daemon-reload');b.command('systemctl','start','--no-block','test-case.service')


def request(n):return ROOT/f'migration-{n}.json'
def prepare(n):
    current=u.current(STORE);old=u.validate_generation(current)
    plan=dict(old,transaction=f'{n:032x}',journal=str(ROOT/f'journal-{n}.json'),
              permit=f'/run/pathward-plan-{n}/permit.json',state_seed=r.journal(old),
              kernel=str(ROOT/'pathward-recovery'),kernel_sha256=r.digest_file(ROOT/'pathward-recovery'))
    path=ROOT/f'plan-{n}.json';r.write_record(path,plan)
    candidate=ROOT/f'helper-{n}.py'
    b.file(candidate,(ROOT/'pathward_recovery.py').read_bytes()+f'\n# Reviewed migration {n}\n'.encode(),0o600)
    return m.prepare_migration(STORE,UNITS,path,r.digest_file(path),candidate,r.digest_file(candidate),
                               ROOT/'pathward-recovery',r.digest_file(ROOT/'pathward-recovery'),request(n))
def apply(n,checkpoint=lambda _:None):return m.apply_migration(request(n),r.digest_file(request(n)),checkpoint)
def gc(checkpoint=lambda _:None):return m.apply_gc(ROOT/'collect.json',r.digest_file(ROOT/'collect.json'),checkpoint)
def cut(stage):
    def checkpoint(point):
        if point==stage:
            b.emit('PW_CUT_POWER '+point)
            while True:time.sleep(1)
    return checkpoint
def save(report,next_case):b.file(b.STATE,json.dumps(report),0o600);b.advance(next_case)


def run():
    case=int(b.COUNTER.read_text());report=json.loads(b.STATE.read_text())
    boot=r.BOOT_ID.read_text().strip();assert boot not in report['boots'];report['boots'].append(boot)
    for name,digest in report.get('previous_source',{}).items():assert r.digest_file(name)==digest
    side='OLD' if case<5 else 'NEW';assert b.selected_body({side})==side
    wrong='NEW' if side=='OLD' else 'OLD'
    assert 'PW_FIXTURE_BOUND_'+wrong not in b.command('journalctl','-b','-u','test-'+wrong.lower()+'.service','--no-pager')
    pid=b.command('systemctl','show','test-'+side.lower()+'.service','--property=MainPID','--value')
    with r.LOCK.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if case==0:
            candidate=ROOT/'adopt.py';b.file(candidate,(ROOT/'pathward_recovery.py').read_bytes()+b'\n# adoption\n',0o600)
            req=ROOT/'adopt.json'
            sha=u.prepare(STORE,UNITS,b.PLAN,r.digest_file(b.PLAN),ROOT/'pathward_recovery.py',r.digest_file(ROOT/'pathward_recovery.py'),
                          candidate,r.digest_file(candidate),ROOT/'pathward-recovery',r.digest_file(ROOT/'pathward-recovery'),req)
            assert u.apply(req,sha)['epoch']==1
        elif case<=4:assert apply(case+1)['epoch']==case+1
        report['results'].append({'case':case,'selected':side,'epoch':u.current(STORE)['epoch']})
        if case<4:
            n=case+2;prepare(n);current=u.current(STORE);plan=u.validate_generation(current)
            report['previous_source']={str(p):r.digest_file(p) for p in [current['plan'],plan['journal']]}
            save(report,case+1)
            apply(n,cut(['journal:partial','migrate:renamed','migrate:synced','receipt:partial'][case]))
            raise RuntimeError('Missing cut boundary')
        if case==4:
            prepare(6);real=r.command
            def fail_reload(args,**kw):
                if list(args)==['systemctl','daemon-reload']:raise subprocess.CalledProcessError(1,args)
                return real(args,**kw)
            r.command=fail_reload
            try:
                try:apply(6)
                except subprocess.CalledProcessError:pass
                else:raise AssertionError('Reload failure not injected')
            finally:r.command=real
            assert apply(6)['epoch']==6
            assert b.command('systemctl','show','test-old.service','--property=MainPID','--value')==pid
            # The fixture performs the application transition separately.
            current=u.current(STORE);plan=u.validate_generation(current)
            report.pop('previous_source',None)
            b.command('systemctl','stop','test-old.service')
            r.write_record(plan['journal'],dict(r.journal(plan),phase='committed'))
            r.publish(plan,current['plan_sha256'],'NEW')
            b.command('systemctl','reset-failed','test-new.service');b.command('systemctl','start','test-new.service')
            assert b.selected_body({'NEW'})=='NEW'
            pid=b.command('systemctl','show','test-new.service','--property=MainPID','--value')
            source_sha=r.digest_file(plan['journal']);prepare(7);assert apply(7)['epoch']==7
            assert r.digest_file(plan['journal'])==source_sha
            assert b.command('systemctl','show','test-new.service','--property=MainPID','--value')==pid
            try:m.prepare_gc(STORE,UNITS,ROOT/'pathward-recovery',r.digest_file(ROOT/'pathward-recovery'),ROOT/'too-soon.json')
            except RuntimeError as error:assert 'later boot' in str(error)
            else:raise AssertionError('Same-boot collection allowed')
            prepare(8) # A prepared future plan must remain available across GC.
            report.update(live_service_pid_unchanged=True,source_journal_unchanged=True,
                          reload_failure_retry_passed=True,same_boot_gc_rejected=True)
            save(report,5);b.emit('PW_COLD_REBOOT plan handoff complete')
        elif case==5:
            assert apply(7)['epoch']==7
            m.prepare_gc(STORE,UNITS,ROOT/'pathward-recovery',r.digest_file(ROOT/'pathward-recovery'),ROOT/'collect.json')
            save(report,6);gc(cut('gc:moved:generations'));raise RuntimeError('Missing GC rename cut')
        elif case==6:
            save(report,7);gc(cut('gc:unlink:pathward-recovery.service'));raise RuntimeError('Missing GC unlink cut')
        else:
            current=u.current(STORE);result=gc();assert gc()==result
            assert u.current(STORE)==current
            assert b.command('systemctl','show','test-new.service','--property=MainPID','--value')==pid
            assert apply(7)['epoch']==7 # The retained parent also supports final retry.
            future=r.read_record(request(8))['target'];u.verify_generation(STORE,future)
            u.verify_generation(STORE,r.read_record(STORE/'generations'/current['parent']/'manifest.json'))
            assert (ROOT/'pathward_recovery.py').exists() and b.PLAN.exists() and b.JOURNAL.exists()
            report.update(final_epoch=7,collected=result,retained_epochs=sorted(r.read_record(p/'manifest.json')['epoch'] for p in (STORE/'generations').iterdir()),
                          protected_objects_preserved=True,completed_retry_after_gc=True,
                          initial_kernel_sha256=r.digest_file(ROOT/'initial-recovery') if (ROOT/'initial-recovery').exists() else None,
                          kernel_sha256=r.digest_file(ROOT/'pathward-recovery'),
                          versions={'systemd':b.command('systemd','--version').splitlines()[0],'kernel':b.command('uname','-r'),'python':sys.version.split()[0]})
            b.emit('PW_VM_RECOVERY_PASS '+json.dumps(report,sort_keys=True));b.command('systemctl','poweroff');return
    b.command('systemctl','reboot')


if __name__=='__main__':
    try:initialize() if '--initialize' in sys.argv else run()
    except BaseException as error:
        b.emit('PW_VM_FAILURE '+repr(error))
        for unit in ['test-case.service','pathward-recovery.service','test-old.service','test-new.service']:
            out=subprocess.run(['journalctl','-b','-u',unit,'--no-pager','-n','25'],capture_output=True,text=True);b.emit(out.stdout)
        raise
