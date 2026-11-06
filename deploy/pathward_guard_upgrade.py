#!/usr/bin/env python3
"""Replace recovery implementations without replacing their plan or listeners.

Root retains the prepare request hash and retries the same apply request. The
application journal, permit, plan and service enablement are never written here.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

spec = importlib.util.spec_from_file_location('recovery', Path(__file__).with_name('pathward_recovery.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
MAX = (1 << 64) - 1


def trusted_path(path):
    """Root (or the test uid) controls every component used by executable paths."""
    if sys.platform != 'linux': return
    path = Path(path)
    r.require(path.resolve() == path, 'Symlink ancestor in guard path')
    for parent in path.parents:
        meta = parent.lstat()
        r.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid in {0,os.geteuid()}
                  and (not meta.st_mode & 0o022 or meta.st_mode & stat.S_ISVTX),
                  'Untrusted guard ancestor')


def boot_storage(path):
    # Linked unit definitions must exist before systemd can construct boot jobs.
    # A separate or bind-mounted store may be unavailable then, even on the
    # same st_dev. Native deployment is Linux; other platforms run file tests.
    if sys.platform != 'linux': return
    trusted_path(path)
    r.require(path.resolve() == path, 'Guard store has a symlink ancestor')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1],8)), line.split()[4])
        if point != '/':
            r.require(not path.is_relative_to(Path(point)), 'Guard store must be on the root mount')


def identity(value):
    return hashlib.sha256(r.canonical(value)).hexdigest()


def directory(path):
    path = Path(path)
    try: path.mkdir(mode=0o700)
    except FileExistsError: pass
    meta = path.lstat()
    r.require(path.is_dir() and not path.is_symlink() and meta.st_uid == os.geteuid()
              and not meta.st_mode & 0o022, 'Untrusted upgrade directory')
    r.sync_directory(path); r.sync_directory(path.parent)


def checked_module(path, digest):
    trusted_path(path)
    r.require(r.digest_file(path) == digest, 'Helper digest mismatch')
    source = Path(path).read_bytes()
    r.require(hashlib.sha256(source).hexdigest() == digest, 'Helper changed before import')
    spec = importlib.util.spec_from_file_location('checked_helper', path)
    module = importlib.util.module_from_spec(spec)
    # A timestamp/size-matching .pyc can hold code other than the pinned source.
    # Compile exactly the bytes hashed above; never consult candidate bytecode.
    exec(compile(source, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def unit_files(helper, plan_path, plan_sha, old, new, module=r):
    boot, drops, fallback = module.unit_text(helper, plan_path, plan_sha, old, new)
    return {'pathward-recovery.service': boot,
            'pathward-recovery-fallback.service': fallback,
            **{name+'.d/90-pathward-recovery.conf': text for name,text in drops.items()}}


def generation(epoch, parent, helper, helper_sha, plan_path, plan_sha, old, new):
    return {'schema': 1, 'epoch': epoch, 'parent': parent, 'helper': str(helper),
            'helper_sha256': helper_sha, 'plan': str(plan_path), 'plan_sha256': plan_sha,
            'old_unit': old, 'new_unit': new,
            'units': unit_files(helper, plan_path, plan_sha, old, new)}


def validate_generation(value):
    r.require(type(value) is dict and type(value.get('epoch')) is int
              and 0 <= value['epoch'] <= MAX and type(value.get('schema')) is int and value['schema'] == 1,
              'Invalid guard generation')
    r.require(value == generation(value['epoch'], value['parent'], value['helper'],
              value['helper_sha256'], value['plan'], value['plan_sha256'],
              value['old_unit'], value['new_unit']), 'Unsupported guard contract')
    r.require(value['parent'] == '' if value['epoch'] == 0 else
              bool(re.fullmatch('[0-9a-f]{64}', value['parent'])), 'Invalid parent generation')
    trusted_path(value['helper']); trusted_path(value['plan'])
    r.require(r.digest_file(value['helper']) == value['helper_sha256'], 'Guard helper changed')
    plan = r.load_plan(Path(value['plan']), value['plan_sha256'])
    trusted_path(plan['kernel'])
    r.require(plan['old']['units'][0] == value['old_unit'] and
              plan['new']['units'][0] == value['new_unit'], 'Guard unit/plan mismatch')
    return plan


def compatible(base, target):
    return all(base[k] == target[k] for k in ['plan','plan_sha256','old_unit','new_unit'])


def verify_generation(store, value):
    validate_generation(value)
    root = store/'generations'/identity(value)
    r.require(not root.is_symlink(), 'Linked generation')
    r.require(r.read_record(root/'manifest.json') == value, 'Guard manifest mismatch')
    wanted = {'manifest.json', *value['units']}
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if not p.is_dir()}
    r.require(actual == wanted and not any(p.is_symlink() for p in root.rglob('*')), 'Unexpected guard members')
    for name, text in value['units'].items():
        r.require(r.digest_file(root/name) == hashlib.sha256(text.encode()).hexdigest(), 'Guard unit changed')
    # A previous writer may have died after rename but before directory fsync.
    r.sync_directory(root.parent)


def stage(store, value, checkpoint):
    validate_generation(value)
    final = store/'generations'/identity(value)
    if final.exists() or final.is_symlink():
        verify_generation(store, value); return
    temporary = Path(tempfile.mkdtemp(prefix='.stage-', dir=final.parent))
    try:
        for name, text in value['units'].items():
            if (temporary/name).parent != temporary: directory((temporary/name).parent)
            r.replace_bytes(temporary/name, text.encode(), 0o644)
            checkpoint('stage:'+name)
        r.write_record(temporary/'manifest.json', value)
        r.sync_directory(temporary)
        os.rename(temporary, final); checkpoint('generation_renamed')
        r.sync_directory(final.parent); checkpoint('generation_synced')
    finally:
        if temporary.exists(): shutil.rmtree(temporary)
    verify_generation(store, value)


def current(store):
    path = store/'current'
    if not path.exists() and not path.is_symlink(): return None
    r.require(path.is_symlink(), 'Guard pointer must be a symlink')
    target = os.readlink(path)
    r.require(re.fullmatch(r'generations/[0-9a-f]{64}', target), 'Invalid guard pointer')
    value = r.read_record(store/target/'manifest.json')
    r.require(value is not None and identity(value) == target.split('/')[1], 'Invalid current generation')
    verify_generation(store, value)
    return value


def link(path, target, checkpoint, label):
    if path.is_symlink() and os.readlink(path) == target:
        r.sync_directory(path.parent); return
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'.link-', dir=path.parent)
    os.close(fd); os.unlink(temporary)
    try:
        os.symlink(target, temporary); checkpoint(label+':created')
        os.replace(temporary, path); checkpoint(label+':renamed')
        r.sync_directory(path.parent); checkpoint(label+':synced')
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)


def stable(plan, plan_sha):
    record = r.journal(plan)
    if not record or record.get('transaction') != plan['transaction']: return False
    side = {'prepared': 'OLD', 'rolled_back': 'OLD', 'committed': 'NEW'}.get(record['phase'])
    if not side or not r.allow(plan, plan_sha, side) or not r.verified(plan[side.lower()]): return False
    # Test actual stable states; "not active" alone also includes deactivating.
    for kind, item in [('OLD', plan['old']), ('NEW', plan['new'])]:
        for unit in item['units']:
            state = r.command(['systemctl','show',unit,'--property=ActiveState','--value']).stdout.strip()
            allowed = state == 'active' if kind == side else state in ['inactive','failed']
            if not allowed: return False
    return True


def installed(units, store, base, managed_only=False):
    for name, text in base['units'].items():
        path = units/name
        expected = str(store/'current'/name)
        if path.is_symlink():
            r.require(os.readlink(path) == expected, 'Foreign guard link')
        else:
            r.require(not managed_only and base['epoch'] == 0 and
                      r.digest_file(path) == hashlib.sha256(text.encode()).hexdigest(), 'Installed guard changed')
    wants = units/'multi-user.target.wants/pathward-recovery.service'
    r.require(wants.is_symlink() and os.readlink(wants) == str(units/'pathward-recovery.service'), 'Persistent boot guard missing')


def prepare(store, units, plan_path, plan_sha, legacy_helper, legacy_sha,
            candidate, candidate_sha, kernel, kernel_sha, request, checkpoint=lambda _: None):
    """Stage only; caller owns the administrator lock. No service changes."""
    r.require(all(r.absolute(str(p)) for p in [store,units,plan_path,legacy_helper,candidate,kernel,request]),
              'Unsafe directory/path spelling')
    for path in [units,plan_path,legacy_helper,candidate,kernel,request]: trusted_path(path)
    boot_storage(store)
    directory(units)
    for path in [store, store/'blobs', store/'generations']: directory(path)
    r.require(r.digest_file(kernel) == kernel_sha, 'Upgrade decision binary changed')
    plan = r.load_plan(plan_path, plan_sha)
    base = current(store)
    if base is None:
        module = checked_module(legacy_helper, legacy_sha)
        base = generation(0, '', legacy_helper, legacy_sha, plan_path, plan_sha,
                          plan['old']['units'][0], plan['new']['units'][0])
        r.require(base['units'] == unit_files(legacy_helper, plan_path, plan_sha,
                  base['old_unit'], base['new_unit'], module), 'Unsupported legacy guard')
    validate_generation(base)
    r.require(base['plan'] == str(plan_path) and base['plan_sha256'] == plan_sha, 'Cannot change recovery plan')
    installed(units, store, base, managed_only=base['epoch'] > 0)
    r.require(stable(plan, plan_sha), 'Upgrade requires a stable terminal transaction')
    r.require(base['epoch'] < MAX, 'Guard epoch exhausted')
    module = checked_module(candidate, candidate_sha)
    blob = store/'blobs'/(candidate_sha+'.py')
    if blob.exists() or blob.is_symlink():
        r.require(r.digest_file(blob) == candidate_sha, 'Conflicting helper blob')
        r.sync_directory(blob.parent)
    else:
        r.replace_bytes(blob, Path(candidate).read_bytes(), 0o600,
                        lambda point: checkpoint('blob:'+point))
    target = generation(base['epoch']+1, identity(base), blob, candidate_sha,
                        plan_path, plan_sha, base['old_unit'], base['new_unit'])
    r.require(target['units'] == unit_files(blob, plan_path, plan_sha,
              base['old_unit'], base['new_unit'], module), 'Unsupported candidate guard contract')
    stage(store, base, checkpoint); stage(store, target, checkpoint)
    value = {'schema': 1, 'store': str(store), 'units': str(units), 'base': base, 'target': target,
             'kernel': str(kernel), 'kernel_sha256': kernel_sha}
    if request.exists() or request.is_symlink():
        r.require(r.read_record(request) == value, 'Request already exists; retry its original apply')
    else: r.write_record(request, value)
    return r.digest_file(request)


def action(value, active, ready, is_stable):
    base, target = value['base'], value['target']
    at_base = (active == base) or (active is None and base['epoch'] == 0)
    at_target = active == target
    result = r.command([value['kernel'], 'upgrade', str(base['epoch']), str(target['epoch']),
                        str(int(at_base)), str(int(at_target)), str(int(ready)),
                        str(int(compatible(base,target))), str(int(is_stable))]).stdout
    r.require(result in ['INSTALL\n','FINISH\n','REJECT\n'], 'Invalid upgrade policy reply')
    r.require(result != 'REJECT\n', 'Stale, incompatible or unstable guard upgrade')
    return result.strip()


def apply(request, expected, checkpoint=lambda _: None):
    """Retry this exact sealed request, including after a cold boot."""
    trusted_path(request)
    # Hash and decode the same private inode bytes, not two separate opens.
    raw = r.private_bytes(request)
    r.require(hashlib.sha256(raw).hexdigest() == expected, 'Upgrade request digest mismatch')
    value = r.decode(raw)
    r.require(value is not None and set(value) == {'schema','store','units','base','target','kernel','kernel_sha256'}
              and value['schema'] == 1, 'Invalid upgrade request')
    store, units = Path(value['store']), Path(value['units'])
    trusted_path(units); trusted_path(value['kernel'])
    boot_storage(store)
    directory(units)
    directory(store)
    base, target = value['base'], value['target']
    r.require(r.digest_file(value['kernel']) == value['kernel_sha256'], 'Upgrade decision binary changed')
    r.require(target['parent'] == identity(base), 'Target belongs to another base')
    for entry in [base, target]: verify_generation(store, entry)
    plan = validate_generation(target)
    active = current(store)
    choice = action(value, active, True, stable(plan,target['plan_sha256']))
    installed(units, store, base, managed_only=base['epoch'] > 0 or active == target)
    # Check the staged definitions before changing even one installed path.
    r.command(['systemd-analyze','verify',store/'generations'/identity(target)/'pathward-recovery.service',
               store/'generations'/identity(target)/'pathward-recovery-fallback.service'])
    if active is None:
        link(store/'current', 'generations/'+identity(base), checkpoint, 'bootstrap')
    for name in base['units']:
        directory((units/name).parent)
        link(units/name, str(store/'current'/name), checkpoint, 'adopt:'+name)
    # Observe again after potentially slow verification; all writers share LOCK.
    choice = action(value, current(store), True, stable(plan,target['plan_sha256']))
    if choice == 'INSTALL':
        link(store/'current', 'generations/'+identity(target), checkpoint, 'activate')
    else: r.sync_directory(store)
    r.require(current(store) == target, 'Guard activation readback failed')
    checkpoint('before_reload')
    r.command(['systemctl','daemon-reload']); checkpoint('after_reload')
    for unit, property_name in [('pathward-recovery.service','ExecStart'),
                                ('pathward-recovery-fallback.service','ExecStart'),
                                (target['old_unit'],'ExecStartPre'),(target['new_unit'],'ExecStartPre')]:
        loaded = r.command(['systemctl','show',unit,'--property='+property_name,'--value']).stdout
        r.require(target['helper'] in loaded and target['plan_sha256'] in loaded, 'Loaded guard differs; retry apply')
    receipt = {'base': identity(base), 'target': identity(target), 'epoch': target['epoch'],
               'plan_sha256': target['plan_sha256']}
    r.write_record(store/'last-applied.json', receipt, lambda p: checkpoint('receipt:'+p))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    prep = sub.add_parser('prepare')
    for name in ['store','units','plan','legacy-helper','candidate','kernel','request']:
        prep.add_argument('--'+name, type=Path, required=True)
    for name in ['plan-sha','legacy-sha','candidate-sha','kernel-sha']:
        prep.add_argument('--'+name, required=True)
    use = sub.add_parser('apply'); use.add_argument('--request',type=Path,required=True); use.add_argument('--sha256',required=True)
    args = parser.parse_args(); r.require(sys.platform == 'linux' and os.geteuid() == 0,'Linux administrator required'); os.umask(0o077)
    with r.LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.mode == 'prepare':
            digest = prepare(args.store,args.units,args.plan,args.plan_sha,args.legacy_helper,args.legacy_sha,
                             args.candidate,args.candidate_sha,args.kernel,args.kernel_sha,args.request)
            print('PREPARED_GUARD_UPGRADE '+digest)
        else: print('APPLIED_GUARD_UPGRADE '+r.canonical(apply(args.request,args.sha256)).decode())


if __name__ == '__main__': main()
