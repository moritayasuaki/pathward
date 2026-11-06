#!/usr/bin/env python3
"""Boot a disposable, NIC-free Ubuntu VM and kill only our own QEMU process.

Requires preinstalled QEMU and an ISO creator. Never installs host packages.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
BASE_SHA='406630c08b5e545fcc7209854b129d47e3af822db128c9f19336593b5a2d3fe0'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image',type=Path,required=True)
    parser.add_argument('--kernel-binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--guard-upgrade',action='store_true')
    mode.add_argument('--plan-migration',action='store_true')
    mode.add_argument('--role-contract',action='store_true')
    parser.add_argument('--admin-binary',type=Path)
    parser.add_argument('--role-guest',type=Path)
    parser.add_argument('--role-fixture',type=Path)
    parser.add_argument('--initial-kernel-binary',type=Path)
    args=parser.parse_args()
    assert hashlib.sha256(args.base_image.read_bytes()).hexdigest()==BASE_SHA
    assert args.kernel_binary.read_bytes()[:4]==b'\x7fELF','Use the CI Linux decision binary'
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    seed=args.output/'seed';seed.mkdir()
    files={'pathward_recovery.py':ROOT/'deploy/pathward_recovery.py',
           'reboot_guest.py':ROOT/'scripts/reboot_guest.py','pathward-recovery':args.kernel_binary}
    if args.guard_upgrade or args.plan_migration:
        files.update({'pathward_guard_upgrade.py':ROOT/'deploy/pathward_guard_upgrade.py',
                      'guard_upgrade_guest.py':ROOT/'scripts/guard_upgrade_guest.py'})
    if args.plan_migration:
        files.update({'pathward_plan_migration.py':ROOT/'deploy/pathward_plan_migration.py',
                      'plan_migration_guest.py':ROOT/'scripts/plan_migration_guest.py'})
    if args.initial_kernel_binary:
        assert args.plan_migration and args.initial_kernel_binary.read_bytes()[:4]==b'\x7fELF'
        files['initial-recovery']=args.initial_kernel_binary
    if args.role_contract:
        for name,path in [('pathward-admin',args.admin_binary),('role_vm_guest',args.role_guest),('role_fixture',args.role_fixture)]:
            assert path is not None and path.read_bytes()[:4]==b'\x7fELF','Reviewed Linux native test binaries required'
            files[name]=path
    entries=[]
    for name,path in files.items():
        entries.append({'path':'/opt/pathward-reboot-test/'+name,'permissions':'0755' if name in ['pathward-recovery','initial-recovery','pathward-admin','role_vm_guest','role_fixture'] else '0600',
                        'encoding':'b64','content':base64.b64encode(path.read_bytes()).decode()})
    user={'package_update':False,'package_upgrade':False,'ssh_deletekeys':False,
          'write_files':entries,'runcmd':[['/usr/bin/python3','/opt/pathward-reboot-test/'+
                       ('plan_migration_guest.py' if args.plan_migration else 'guard_upgrade_guest.py' if args.guard_upgrade else 'reboot_guest.py'),'--initialize']]}
    if args.role_contract:user['runcmd']=[['/opt/pathward-reboot-test/role_vm_guest','--initialize']]
    (seed/'user-data').write_text('#cloud-config\n'+json.dumps(user))
    (seed/'meta-data').write_text('instance-id: pathward-recovery-isolated\nlocal-hostname: recovery-test\n')
    (seed/'network-config').write_text('version: 2\nethernets: {}\n')
    iso=args.output/'seed.iso'
    if shutil.which('hdiutil'):
        command=['hdiutil','makehybrid','-iso','-joliet','-default-volume-name','cidata','-o',str(iso),str(seed)]
    else:
        command=['genisoimage','-output',str(iso),'-volid','cidata','-joliet','-rock',str(seed/'user-data'),str(seed/'meta-data'),str(seed/'network-config')]
    subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
    disk=args.output/'disk.qcow2'
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(args.base_image.resolve()),str(disk),'4G'],check=True)
    results=[]
    for attempt in range(14 if args.role_contract else 12 if args.plan_migration else 8):
        log=args.output/f'boot-{attempt}.log'
        command=['qemu-system-x86_64','-accel','tcg,thread=multi','-m','1024','-smp','2',
                 '-display','none','-monitor','none','-serial','file:'+str(log),'-nic','none','-no-reboot',
                 '-drive',f'file={disk},format=qcow2,if=virtio,cache=none',
                 '-drive',f'file={iso},format=raw,media=cdrom,readonly=on']
        with (args.output/f'qemu-{attempt}.log').open('w') as stderr:
            process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=stderr)
            try:
                # Initial native fixture provisioning under CPU emulation can
                # exceed a normal boot. Service/health deadlines remain intact.
                deadline=time.monotonic()+(900 if args.role_contract and attempt==0 else 420)
                while time.monotonic()<deadline:
                    text=log.read_text(errors='replace') if log.exists() else ''
                    if 'PW_VM_FAILURE ' in text:raise RuntimeError(f'Guest assertion failed: {log}')
                    if 'PW_VM_RECOVERY_PASS ' in text:
                        line=text.split('PW_VM_RECOVERY_PASS ',1)[1].splitlines()[0]
                        report=json.loads(line);report.update(base_image_sha256=BASE_SHA,external_network=False,host_services_changed=False)
                        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
                        process.wait(timeout=90)
                        print('PASS real cold boots and hard power cuts:',args.output/'result.json',flush=True);return
                    if 'PW_CUT_POWER ' in text:
                        print(text.split('PW_CUT_POWER ',1)[1].splitlines()[0],flush=True)
                        process.kill();process.wait(timeout=30);break
                    if process.poll() is not None:
                        if 'PW_COLD_REBOOT ' not in text:raise RuntimeError(f'Unexpected VM exit: {log}')
                        print('Cold reboot',attempt,flush=True);break
                    time.sleep(.2)
                else:raise RuntimeError(f'VM deadline exceeded: {log}')
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=30)
    raise RuntimeError('VM did not reach final verification')


if __name__=='__main__':main()
