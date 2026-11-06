"""Real files, Rust decisions and killed writers; systemd calls are mocked here."""
import importlib.util
import itertools
import os
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
b=module('fixtures',ROOT/'scripts/test_guard_upgrade.py')
m=module('migration',ROOT/'deploy/pathward_plan_migration.py')
m.u=b.u;m.r=b.r
r=m.r;u=m.u


class Fixture(b.Fixture):
    def __init__(self,root):
        super().__init__(root)
        self.boot.write_text('11111111-1111-1111-1111-111111111111')
        boot,command=self.contexts()
        with boot,command:r.publish(self.plan_data,self.plan_sha,'OLD');self.resume()

    def command(self,args,**kw):
        if list(map(str,args))[:2]==['systemctl','list-jobs']:return SimpleNamespace(stdout='',returncode=0)
        return super().command(args,**kw)

    def next_plan(self,n,edit=lambda _:None):
        plan=dict(self.plan_data,transaction=f'{n:032x}',journal=str(self.root/f'journal{n}'),permit=str(self.root/f'run{n}/permit'),
                  state_seed={'phase':'prepared'},kernel=str(b.KERNEL),kernel_sha256=r.digest_file(b.KERNEL))
        plan['old']=dict(plan['old'],files=dict(plan['old']['files']))
        plan['new']=dict(plan['new'],files=dict(plan['new']['files']))
        edit(plan);path=self.root/f'plan{n}';r.write_record(path,plan)
        return path

    def migration(self,n,edit=lambda _:None):
        path=self.next_plan(n,edit)
        self.candidate.write_bytes(self.candidate.read_bytes()+f'# Reviewed plan {n}\n'.encode())
        request=self.root/f'migrate{n}'
        digest=m.prepare_migration(self.store,self.units,path,r.digest_file(path),self.candidate,r.digest_file(self.candidate),
                                   b.KERNEL,r.digest_file(b.KERNEL),request)
        return request,digest

    def reboot(self,n=2):
        self.boot.write_text(f'{n:08x}-1111-1111-1111-111111111111')
        for path in self.root.glob('run*'):
            if path.is_dir():shutil.rmtree(path)
        active=u.current(self.store);r.publish(u.validate_generation(active),active['plan_sha256'],'OLD')

    def chain(self):
        for n in range(2,5):m.apply_migration(*self.migration(n))
        self.reboot()

    def gc(self,name='gc',keep=()):
        request=self.root/name
        return request,m.prepare_gc(self.store,self.units,b.KERNEL,r.digest_file(b.KERNEL),request,keep)


class PlanMigrationTests(unittest.TestCase):
    def test_migration_every_interruption_can_retry_after_a_new_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));boot,command=f.contexts();points=[]
            with boot,command:m.apply_migration(*f.migration(2),points.append)
        self.assertGreater(len(points),12)
        for index,point in enumerate(points):
            with self.subTest(point=point),tempfile.TemporaryDirectory() as tmp:
                f=Fixture(Path(tmp));boot,command=f.contexts()
                with boot,command:
                    request,digest=f.migration(2);old=(f.root/'journal').read_bytes()
                    child=os.fork()
                    if child==0:
                        count=[0]
                        def kill(_):
                            n=count[0];count[0]+=1
                            if n==index:os.kill(os.getpid(),signal.SIGKILL)
                        try:m.apply_migration(request,digest,kill)
                        except BaseException:os._exit(2)
                        os._exit(3)
                    _,status=os.waitpid(child,0);self.assertTrue(os.WIFSIGNALED(status))
                    f.reboot();result=m.apply_migration(request,digest)
                    self.assertEqual(result['epoch'],2);self.assertEqual(m.apply_migration(request,digest),result)
                    self.assertEqual((f.root/'journal').read_bytes(),old)
                    self.assertEqual(r.select(u.validate_generation(u.current(f.store))),'OLD')
                    self.assertFalse(any(c[:2] in [['systemctl','start'],['systemctl','stop'],['systemctl','enable'],['systemctl','disable']] for c in f.calls))

    def test_incompatible_plans_and_changed_application_are_rejected(self):
        for kind in ['journal','permit','units','changed','stale']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                f=Fixture(Path(tmp));boot,command=f.contexts()
                with boot,command:
                    base=u.identity(u.current(f.store))
                    def edit(p):
                        if kind=='journal':p['journal']=f.plan_data['journal']
                        if kind=='permit':p['permit']=f.plan_data['permit']
                        if kind=='units':p['old']['units']=['another.service']
                    if kind in ['journal','permit','units']:
                        with self.assertRaises(RuntimeError):f.migration(2,edit)
                    else:
                        req,digest=f.migration(2)
                        if kind=='changed':r.write_record(f.root/'journal',dict(f.plan_data['state_seed'],phase='cutover_pending'))
                        else:m.apply_migration(*f.migration(3));base=u.identity(u.current(f.store))
                        with self.assertRaises(RuntimeError):m.apply_migration(req,digest)
                    self.assertEqual(u.identity(u.current(f.store)),base)

    def test_gc_requires_later_boot_and_preserves_current_parent_and_prepared(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));boot,command=f.contexts()
            with boot,command:
                with self.assertRaisesRegex(RuntimeError,'later boot'):f.gc()
                f.chain();current=u.current(f.store);f.migration(5)
                future={p.name for p in (f.store/'generations').iterdir() if p.is_dir()}
                request,digest=f.gc();value=r.read_record(request)
                result=m.apply_gc(request,digest)
                self.assertGreater(result['generations'],0);self.assertGreater(result['blobs'],0)
                self.assertEqual(m.apply_gc(request,digest),result)
                remaining={p.name for p in (f.store/'generations').iterdir() if p.is_dir()}
                self.assertEqual(remaining,future-set(value['generations']))
                self.assertIn(current['parent'],remaining);self.assertIn(u.identity(current),remaining)
                self.assertTrue(f.legacy.exists());self.assertTrue((f.root/'journal').exists())

    def test_gc_every_interruption_retries_partial_trash(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));boot,command=f.contexts();points=[]
            with boot,command:f.chain();m.apply_gc(*f.gc(),points.append)
        self.assertGreater(len(points),20)
        for index,point in enumerate(points):
            with self.subTest(point=point),tempfile.TemporaryDirectory() as tmp:
                f=Fixture(Path(tmp));boot,command=f.contexts()
                with boot,command:
                    f.chain();request,digest=f.gc();current=u.current(f.store)
                    child=os.fork()
                    if child==0:
                        count=[0]
                        def kill(_):
                            n=count[0];count[0]+=1
                            if n==index:os.kill(os.getpid(),signal.SIGKILL)
                        try:m.apply_gc(request,digest,kill)
                        except BaseException:os._exit(2)
                        os._exit(3)
                    _,status=os.waitpid(child,0);self.assertTrue(os.WIFSIGNALED(status))
                    f.reboot(3);result=m.apply_gc(request,digest)
                    self.assertEqual(m.apply_gc(request,digest),result)
                    self.assertEqual(u.current(f.store),current)
                    u.verify_generation(f.store,r.read_record(f.store/'generations'/current['parent']/'manifest.json'))

    def test_new_references_pin_helpers_and_a_new_generation_invalidates_gc(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));boot,command=f.contexts()
            with boot,command:
                f.chain();req,digest=f.gc()
                value=r.read_record(req);blob=next(iter(value['blobs']));path=f.store/'blobs'/blob
                def pin(p):p['old']['files'][str(path)]=r.digest_file(path)
                f.migration(5,pin)
                with self.assertRaisesRegex(RuntimeError,'referenced'):m.apply_gc(req,digest)
                self.assertTrue(path.exists())
                req2,digest2=f.gc('gc2');m.apply_gc(req2,digest2);self.assertTrue(path.exists())
                m.apply_migration(*f.migration(6))
                with self.assertRaisesRegex(RuntimeError,'stale'):m.apply_gc(req2,digest2)

    def test_rust_migration_and_collection_gates(self):
        for bits in itertools.product([False,True],repeat=6):
            for operation,want in [('migrate',all(bits)),('collect',all(bits[:3]) and not bits[3] and all(bits[4:]))]:
                out=subprocess.run([str(b.KERNEL),operation,*map(lambda x:str(int(x)),bits)],check=True,capture_output=True,text=True).stdout
                self.assertEqual(out,'ALLOW\n' if want else 'DENY\n')

    def test_busy_units_linked_generations_and_foreign_trash_refuse_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));boot,command=f.contexts()
            with boot,command:
                f.chain();request,digest=f.gc();value=r.read_record(request)
                real=r.command
                def busy(args,**kw):
                    if list(args)[:2]==['systemctl','list-jobs']:
                        return SimpleNamespace(stdout='42 old.service start running\n')
                    return real(args,**kw)
                with patch.object(r,'command',side_effect=busy):
                    with self.assertRaisesRegex(RuntimeError,'quiescent'):m.apply_gc(request,digest)
                key=next(iter(value['generations']));path=f.store/'generations'/key
                backup=f.root/'outside-store';path.rename(backup);path.symlink_to(backup)
                with self.assertRaisesRegex(RuntimeError,'Unexpected generation'):m.apply_gc(request,digest)
                self.assertTrue((backup/'manifest.json').exists());path.unlink();backup.rename(path)
                def stop(point):
                    if point=='gc:moved:generations':raise InterruptedError('simulated interruption')
                with self.assertRaises(InterruptedError):m.apply_gc(request,digest,stop)
                retired=next((f.store/'trash'/digest).glob('generations-*'))
                foreign=retired/'unexpected';foreign.write_text('retain unknown data')
                with self.assertRaisesRegex(RuntimeError,'Foreign trash'):m.apply_gc(request,digest)
                self.assertEqual(foreign.read_text(),'retain unknown data')
                self.assertEqual(u.identity(u.current(f.store)),value['current'])


if __name__=='__main__':unittest.main()
