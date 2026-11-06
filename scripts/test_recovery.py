"""Fault injection against the real stdlib journal and extracted decision CLI."""
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'deploy/pathward_recovery.py'
spec = importlib.util.spec_from_file_location('recovery', SOURCE)
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
KERNEL = Path(os.environ.get('PATHWARD_RECOVERY_BINARY', Path(os.environ.get('CARGO_TARGET_DIR', ROOT/'target'))/'release/pathward-recovery'))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root/'journal'
        self.old = {'phase': 'cutover_pending', 'transaction': 'a'*32}
        self.new = dict(self.old, phase='committed')

    def tearDown(self):
        self.temp.cleanup()

    def test_partial_and_orphan_files_cannot_be_promoted_or_block_writes(self):
        recovery.write_record(self.path, self.old)
        expected = self.path.read_bytes()
        for phase in ['created', 'partial', 'written', 'file_synced']:
            def fail(stage):
                if stage == phase: raise OSError('injected write interruption')
            with self.assertRaises(OSError): recovery.write_record(self.path, self.new, fail)
            self.assertEqual(self.path.read_bytes(), expected)
        self.path.with_name('journal.next').write_bytes(b'{"phase":"committed"')
        self.path.with_name('.journal.tmp-stale').write_bytes(b'partial')
        recovery.write_record(self.path, self.new)
        self.assertEqual(recovery.read_record(self.path), self.new)

    def test_actual_killed_writer_at_every_persistence_boundary(self):
        code = '''import importlib.util,json,os,signal,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('r',sys.argv[1]);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def kill(stage):
 if stage==sys.argv[3]:os.kill(os.getpid(),signal.SIGKILL)
r.write_record(Path(sys.argv[2]),json.loads(sys.argv[4]),kill)
'''
        for phase in ['created','partial','written','file_synced','renamed','directory_synced']:
            recovery.write_record(self.path, self.old)
            result = subprocess.run([sys.executable,'-c',code,str(SOURCE),str(self.path),phase,json.dumps(self.new)], timeout=10)
            self.assertLess(result.returncode, 0)
            value = recovery.read_record(self.path)
            self.assertEqual(value, self.new if phase in ['renamed','directory_synced'] else self.old)
            recovery.write_record(self.path, self.new)
            self.assertEqual(recovery.read_record(self.path), self.new)

    def test_truncation_corruption_duplicate_keys_and_wrong_inodes_are_invalid(self):
        recovery.write_record(self.path, self.new)
        raw = self.path.read_bytes()
        for end in range(len(raw)-1):
            self.path.write_bytes(raw[:end])
            self.assertIsNone(recovery.read_record(self.path))
        for value in [raw.replace(b'committed',b'prepared!'),b'{"format":1,"format":1}',b'NaN']:
            self.path.write_bytes(value);self.assertIsNone(recovery.read_record(self.path))
        recovery.write_record(self.path, self.new)
        self.path.chmod(0o644);self.assertIsNone(recovery.read_record(self.path))
        self.path.chmod(0o600)
        os.link(self.path,self.root/'linked');self.assertIsNone(recovery.read_record(self.path))
        (self.root/'linked').unlink()
        link=self.root/'symbolic';link.symlink_to(self.path);self.assertIsNone(recovery.read_record(link))

    def test_actual_policy_exhaustively_checks_boot_inputs(self):
        for bits in itertools.product([False, True], repeat=6):
            p,r,c,t,n,o=bits
            expected='HOLD' if not p else ('NEW' if r and c and t and n else ('OLD' if o else 'HOLD'))
            result=subprocess.run([str(KERNEL),'select',*map(lambda b:str(int(b)),bits)],capture_output=True,text=True,check=True,timeout=5)
            self.assertEqual(result.stdout,expected+'\n')
        for chosen,request,boot,plan in itertools.product(['HOLD','OLD','NEW'],['OLD','NEW'],[0,1],[0,1]):
            result=subprocess.run([str(KERNEL),'start',chosen,request,str(boot),str(plan)],capture_output=True,text=True,check=True,timeout=5)
            self.assertEqual(result.stdout,'ALLOW\n' if boot and plan and chosen==request else 'DENY\n')
        for bad in ['-1','+1','01','18446744073709551616','1\n']:
            result=subprocess.run([str(KERNEL),'trial','1','1','1',bad],capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0);self.assertFalse(result.stdout)

    def test_boot_selection_ignores_mixed_enablement_and_stale_commit(self):
        plan={'kernel':str(KERNEL),'journal':str(self.path),'transaction':'a'*32,
              'old':{},'new':{}}
        with patch.object(recovery,'verified',return_value=True):
            self.assertEqual(recovery.select(plan),'OLD')
            for invalid_phase in [None,[],{},17,'unknown']:
                recovery.write_record(self.path,dict(self.old,phase=invalid_phase))
                self.assertEqual(recovery.select(plan),'OLD')
            for phase in ['prepared','cutover_pending','awaiting_external_verification','rollback_pending','rolled_back']:
                recovery.write_record(self.path,dict(self.old,phase=phase))
                self.assertEqual(recovery.select(plan),'OLD')
            recovery.write_record(self.path,dict(self.new,transaction='b'*32))
            self.assertEqual(recovery.select(plan),'OLD')
            recovery.write_record(self.path,self.new)
            self.assertEqual(recovery.select(plan),'NEW')
        with patch.object(recovery,'verified',return_value=False):
            self.assertEqual(recovery.select(plan),'HOLD')

    def test_permit_from_previous_boot_or_plan_never_starts_either_side(self):
        plan={'kernel':str(KERNEL),'permit':str(self.root/'run/permit')}
        boot=self.root/'boot-id';boot.write_text('first-boot')
        with patch.object(recovery,'BOOT_ID',boot):
            recovery.publish(plan,'digest','NEW')
            self.assertTrue(recovery.allow(plan,'digest','NEW'))
            self.assertFalse(recovery.allow(plan,'digest','OLD'))
            boot.write_text('second-boot')
            self.assertFalse(recovery.allow(plan,'digest','NEW'))
            boot.write_text('first-boot')
            self.assertFalse(recovery.allow(plan,'changed','NEW'))

    def test_recovery_waits_for_ordered_stop_and_never_starts_old_after_timeout(self):
        recovery.write_record(self.path,self.old)
        plan={'journal':str(self.path),'transaction':'a'*32,'state_seed':self.old,
              'new':{'units':['new.service','bridge.service']},'old':{'units':['old.service']}}
        calls=[]
        def stalled(args,check=True,timeout=45):
            calls.append((args,timeout))
            raise subprocess.TimeoutExpired(args,timeout)
        with patch.object(recovery,'verified',return_value=True),patch.object(recovery,'command',side_effect=stalled), \
             patch.object(recovery,'publish') as publish:
            with self.assertRaises(subprocess.TimeoutExpired):recovery.recover(plan,'sealed')
            publish.assert_not_called()
        self.assertEqual(calls,[(['systemctl','stop','bridge.service','new.service'],300)])
        self.assertEqual(recovery.read_record(self.path),self.old)


if __name__ == '__main__': unittest.main()
