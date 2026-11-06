"""Real files, real killed writers and real Rust decisions; service API mocked."""
import hashlib
import importlib.util
import itertools
import os
from pathlib import Path
import py_compile
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrade', ROOT/'deploy/pathward_guard_upgrade.py')
u = importlib.util.module_from_spec(spec); spec.loader.exec_module(u)
r = u.r
KERNEL = Path(os.environ.get('PATHWARD_RECOVERY_BINARY', Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'release/pathward-recovery')).resolve()
LEGACY_KERNEL = Path(os.environ.get('PATHWARD_LEGACY_RECOVERY_BINARY', KERNEL)).resolve()


class Fixture:
    def __init__(self, root):
        self.root = root; self.store = root/'store'; self.units = root/'units'; self.units.mkdir()
        self.plan = root/'plan'; self.request = root/'request'; self.calls = []
        self.legacy = root/'legacy.py'; self.legacy.write_bytes((ROOT/'deploy/pathward_recovery.py').read_bytes())
        self.candidate = root/'candidate.py'; self.candidate.write_bytes(self.legacy.read_bytes()+b'\n# Reviewed fixture revision 2\n')
        self.boot = root/'boot'; self.boot.write_text('test-boot')
        self.plan_data = {'schema':1,'transaction':'a'*32,'journal':str(root/'journal'),
                         'permit':str(root/'run/permit'),'kernel':str(LEGACY_KERNEL),
                         'kernel_sha256':r.digest_file(LEGACY_KERNEL),'state_seed':{'phase':'prepared','transaction':'a'*32}}
        for side in ['old','new']:
            self.plan_data[side] = {'units':[side+'.service'],'files':{str(self.legacy):r.digest_file(self.legacy)},'check':['/usr/bin/true']}
        r.write_record(self.plan,self.plan_data); self.plan_sha = r.digest_file(self.plan)
        r.write_record(root/'journal',self.plan_data['state_seed'])
        with patch.object(r,'BOOT_ID',self.boot):r.publish(self.plan_data,self.plan_sha,'OLD')
        for name,text in u.unit_files(self.legacy,self.plan,self.plan_sha,'old.service','new.service').items():
            (self.units/name).parent.mkdir(exist_ok=True)
            (self.units/name).write_text(text)
        (self.units/'multi-user.target.wants').mkdir()
        (self.units/'multi-user.target.wants/pathward-recovery.service').symlink_to(self.units/'pathward-recovery.service')
        self.real_command = r.command

    def command(self, args, **kwargs):
        args = list(map(str,args)); self.calls.append(args)
        if args[0] == 'systemd-analyze':return SimpleNamespace(stdout='',returncode=0)
        if args[:2] == ['systemctl','daemon-reload']:return SimpleNamespace(stdout='',returncode=0)
        if args[:2] == ['systemctl','show']:
            if '--property=ActiveState' in args:
                return SimpleNamespace(stdout='active' if args[2]=='old.service' else 'inactive')
            name = args[2] if args[2].startswith('pathward-') else args[2]+'.d/90-pathward-recovery.conf'
            return SimpleNamespace(stdout=(self.units/name).read_text())
        return self.real_command(args,**kwargs)

    def prepare(self, checkpoint=lambda _:None):
        return u.prepare(self.store,self.units,self.plan,self.plan_sha,self.legacy,r.digest_file(self.legacy),
                         self.candidate,r.digest_file(self.candidate),KERNEL,r.digest_file(KERNEL),self.request,checkpoint)

    def resume(self, checkpoint=lambda _:None):
        digest = r.digest_file(self.request) if self.request.exists() else self.prepare(checkpoint)
        return u.apply(self.request,digest,checkpoint)

    def contexts(self):
        return patch.object(r,'BOOT_ID',self.boot),patch.object(r,'command',side_effect=self.command)


class GuardUpgradeTests(unittest.TestCase):
    def test_privileged_helper_uses_trusted_source_and_ancestors(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp).resolve()/'untrusted';parent.mkdir();parent.chmod(0o777)
            helper=parent/'helper.py';helper.write_text('raise Exception("must not execute")')
            with patch.object(u.sys,'platform','linux'):
                with self.assertRaisesRegex(RuntimeError,'Untrusted guard ancestor'):
                    u.checked_module(helper,r.digest_file(helper))
                with self.assertRaisesRegex(RuntimeError,'Untrusted guard ancestor'):
                    u.apply(parent/'request','0'*64)
        with tempfile.TemporaryDirectory() as temp, patch.object(u.sys,'pycache_prefix',None):
            helper=Path(temp).resolve()/'candidate.py'
            helper.write_text("value = 'unreviewed'\n")
            stamp=helper.stat();py_compile.compile(str(helper),doraise=True)
            helper.write_text("value = 'reviewed__'\n")
            os.utime(helper,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
            self.assertEqual(u.checked_module(helper,r.digest_file(helper)).value,'reviewed__')

    def test_separate_and_bind_mounts_cannot_hold_boot_units(self):
        with patch.object(u.sys,'platform','linux'),patch.object(Path,'resolve',lambda p:p),patch.object(u,'trusted_path'):
            for entry in ['1 0 1:1 / / rw - ext4 root rw\n2 1 1:1 /bind /opt/guards rw - ext4 root rw\n',
                          '1 0 1:1 / / rw - ext4 root rw\n2 1 2:2 / /opt rw - ext4 other rw\n']:
                with patch.object(Path,'read_text',return_value=entry):
                    with self.assertRaisesRegex(RuntimeError,'root mount'):u.boot_storage(Path('/opt/guards/store'))

    def test_killed_at_every_persistence_boundary_can_retry_without_changing_application(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Fixture(Path(temp));boot,command=f.contexts();points=[]
            with boot,command:f.resume(points.append)
        self.assertGreater(len(points),35)
        for index,point in enumerate(points):
            with self.subTest(index=index,point=point),tempfile.TemporaryDirectory() as temp:
                f=Fixture(Path(temp));boot,command=f.contexts()
                original={name:(f.root/name).read_bytes() for name in ['journal','plan','run/permit']}
                with boot,command:
                    child=os.fork()
                    if child==0:
                        count=[0]
                        def kill(stage):
                            n=count[0];count[0]+=1
                            if n==index:os.kill(os.getpid(),signal.SIGKILL)
                        try:f.resume(kill)
                        except BaseException:os._exit(2)
                        os._exit(3)
                    _,status=os.waitpid(child,0)
                    self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
                    receipt=f.resume()
                    self.assertEqual(receipt['epoch'],1)
                    self.assertEqual(u.current(f.store),r.read_record(f.request)['target'])
                    self.assertEqual(f.resume(),receipt)
                for name,data in original.items():self.assertEqual((f.root/name).read_bytes(),data)
                self.assertFalse(any(c[:2] in [['systemctl','start'],['systemctl','stop'],['systemctl','enable'],['systemctl','disable']] for c in f.calls))

    def test_later_generation_rejects_old_retry_and_retains_old_bundles(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Fixture(Path(temp));boot,command=f.contexts()
            with boot,command:
                first=f.resume();old_request=f.request;old_digest=r.digest_file(old_request)
                f.request=f.root/'request2';f.candidate.write_bytes(f.candidate.read_bytes()+b'# Reviewed revision 3\n')
                second=f.resume();self.assertEqual(second['epoch'],2)
                with self.assertRaisesRegex(RuntimeError,'Stale'):u.apply(old_request,old_digest)
                self.assertEqual(u.identity(u.current(f.store)),second['target'])
                for key in [first['base'],first['target'],second['target']]:
                    self.assertTrue((f.store/'generations'/key/'manifest.json').is_file())

    def test_corruption_changed_units_and_pending_application_refuse_activation(self):
        for case in ['generation','foreign_link','pending','wrong_hash']:
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temp:
                f=Fixture(Path(temp));boot,command=f.contexts()
                with boot,command:
                    digest=f.prepare();req=r.read_record(f.request)
                    if case=='generation':(f.store/'generations'/u.identity(req['target'])/'pathward-recovery.service').write_text('bad')
                    if case=='foreign_link':
                        p=f.units/'pathward-recovery.service';p.unlink();p.symlink_to(f.legacy)
                    if case=='pending':r.write_record(f.root/'journal',{'phase':'cutover_pending','transaction':'a'*32})
                    if case=='wrong_hash':digest='0'*64
                    with self.assertRaises((RuntimeError,OSError)):u.apply(f.request,digest)
                    self.assertFalse((f.store/'current').exists())
        # A replacement after the private read cannot change the bytes which
        # are hash-checked and decoded, even if the replacement is well formed.
        with tempfile.TemporaryDirectory() as temp:
            f=Fixture(Path(temp));boot,command=f.contexts()
            with boot,command:
                digest=f.prepare();read=r.private_bytes;request_reads=[]
                def replace_after_read(path):
                    raw=read(path)
                    if Path(path)==f.request:
                        request_reads.append(path)
                        r.write_record(f.request,{'schema':2})
                    return raw
                with patch.object(r,'private_bytes',side_effect=replace_after_read):
                    self.assertEqual(u.apply(f.request,digest)['epoch'],1)
                self.assertEqual(len(request_reads),1)

    def test_competing_target_is_rejected_and_missing_receipt_does_not_rewind(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Fixture(Path(temp));boot,command=f.contexts()
            with boot,command:
                first=f.prepare();original=f.request
                f.request=f.root/'other-request';f.candidate.write_bytes(f.candidate.read_bytes()+b'# other candidate\n')
                other=f.prepare()
                result=u.apply(original,first)
                with self.assertRaisesRegex(RuntimeError,'Stale'):u.apply(f.request,other)
                (f.store/'last-applied.json').write_bytes(b'torn receipt')
                self.assertEqual(u.apply(original,first),result)
                self.assertEqual(u.identity(u.current(f.store)),result['target'])

    def test_rust_protocol_rejects_stale_overflow_ambiguous_and_unready_updates(self):
        for base,target in [(0,1),(5,6),(5,5),(5,7),((1<<64)-1,0)]:
            for bits in itertools.product([False,True],repeat=5):
                at_base,at_target,ready,compatible,stable=bits
                expected='REJECT'
                if base<(1<<64)-1 and target==base+1 and ready and compatible and stable and not(at_base and at_target):
                    expected='FINISH' if at_target else ('INSTALL' if at_base else 'REJECT')
                result=subprocess.run([str(KERNEL),'upgrade',str(base),str(target),*[str(int(b)) for b in bits]],capture_output=True,text=True,check=True)
                self.assertEqual(result.stdout,expected+'\n')


if __name__=='__main__':unittest.main()
