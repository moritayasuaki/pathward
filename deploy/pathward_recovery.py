#!/usr/bin/env python3
"""Persistent boot arbitration. Standard library only; deployment owns the plan.

The sealed plan is independent of the mutable journal. Invalid/torn journals
never authorize the candidate. Temporary files are never recovery candidates.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

LIMIT = 65536
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
LOCK = Path('/run/pathward-migration.lock')
PHASES = {'prepared', 'cutover_pending', 'awaiting_external_verification',
          'committed', 'rollback_pending', 'rolled_back'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'Duplicate JSON key')
        out[key] = value
    return out


def decode(raw):
    require(len(raw) <= LIMIT, 'Record too large')
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    require(type(value) is dict and set(value) == {'format', 'payload', 'sha256'}
            and type(value['format']) is int and value['format'] == 1
            and type(value['payload']) is dict, 'Invalid record envelope')
    require(hashlib.sha256(canonical(value['payload'])).hexdigest() == value['sha256'],
            'Record checksum mismatch')
    return value['payload']


def private_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1
                and stat.S_IMODE(s.st_mode) in [0o600, 0o400] and s.st_size <= LIMIT,
                'Untrusted record inode')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            return stream.read(LIMIT + 1)
    finally:
        os.close(fd)


def read_record(path):
    try:
        return decode(private_bytes(path))
    except (OSError, ValueError, RuntimeError, TypeError):
        return None


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_record(path, payload, checkpoint=lambda _: None):
    """Atomic envelope replacement; caller holds the transaction lock.

    checkpoint is an explicit test argument, never an environment-variable hook.
    Orphans from killed writers are ignored, never promoted or overwritten.
    """
    raw = canonical({'format': 1, 'payload': payload,
                     'sha256': hashlib.sha256(canonical(payload)).hexdigest()}) + b'\n'
    require(len(raw) <= LIMIT, 'Record too large')
    replace_bytes(path, raw, 0o600, checkpoint)


def replace_bytes(path, raw, mode=0o600, checkpoint=lambda _: None):
    path = Path(path)
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and not parent.st_mode & 0o022, 'Untrusted record directory')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.tmp-', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            checkpoint('created')
            half = len(raw) // 2
            stream.write(raw[:half]); stream.flush(); checkpoint('partial')
            stream.write(raw[half:]); stream.flush(); checkpoint('written')
            os.fsync(stream.fileno()); checkpoint('file_synced')
        os.replace(temporary, path); checkpoint('renamed')
        sync_directory(path.parent); checkpoint('directory_synced')
    finally:
        temporary.unlink(missing_ok=True)


def digest_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid()
                and not s.st_mode & 0o022 and s.st_size <= 256 << 20, 'Untrusted program/configuration')
        h = hashlib.sha256()
        with os.fdopen(os.dup(fd), 'rb') as stream:
            for block in iter(lambda: stream.read(1 << 20), b''):
                h.update(block)
        return h.hexdigest()
    finally:
        os.close(fd)


def command(args, check=True):
    return subprocess.run(list(map(str, args)), check=check, timeout=45,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})


def absolute(value):
    return type(value) is str and value.startswith('/') and re.fullmatch(r'[A-Za-z0-9_./-]+', value) and '..' not in Path(value).parts


def load_plan(path, expected):
    raw = private_bytes(path)
    require(hashlib.sha256(raw).hexdigest() == expected, 'Sealed recovery plan mismatch')
    plan = decode(raw)
    require(type(plan.get('schema')) is int and plan['schema'] == 1 and re.fullmatch('[0-9a-f]{32}', plan.get('transaction', '')),
            'Invalid recovery plan')
    for key in ['journal', 'permit', 'kernel']:
        require(absolute(plan.get(key)), 'Invalid recovery path')
    require(digest_file(plan['kernel']) == plan['kernel_sha256'], 'Recovery executable mismatch')
    for side in ['old', 'new']:
        item = plan[side]
        require(1 <= len(item['units']) <= 3 and all(re.fullmatch(r'[A-Za-z0-9_-]+\.service', u) for u in item['units']), 'Invalid service list')
        require(type(item['check']) is list and 0 < len(item['check']) <= 24
                and absolute(item['check'][0]) and all(type(v) is str and '\x00' not in v for v in item['check']), 'Invalid validator')
        require(item['files'] and all(absolute(p) and re.fullmatch('[0-9a-f]{64}', h) for p, h in item['files'].items()), 'Invalid sealed files')
    require(set(plan['old']['units']).isdisjoint(plan['new']['units']), 'Overlapping services')
    return plan


def policy(plan, operation, *values):
    args = [str(int(v)) if type(v) is bool else str(v) for v in values]
    output = command([plan['kernel'], operation, *args]).stdout
    allowed = {'HOLD\n', 'OLD\n', 'NEW\n'} if operation == 'select' else {'ALLOW\n', 'DENY\n'}
    require(output in allowed, 'Invalid recovery policy reply')
    return output.strip()


def verified(item):
    try:
        return (all(digest_file(p) == h for p, h in item['files'].items())
                and command(item['check'], check=False).returncode == 0)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


def journal(plan):
    value = read_record(plan['journal'])
    if value is None or type(value.get('phase')) is not str or value['phase'] not in PHASES:
        return None
    return value


def select(plan):
    value = journal(plan)
    valid = value is not None
    bound = valid and value.get('transaction') == plan['transaction']
    committed = valid and value['phase'] == 'committed'
    return policy(plan, 'select', True, valid, committed, bound,
                  verified(plan['new']) if committed and bound else False, verified(plan['old']))


def publish(plan, expected, selection):
    require(selection in ['OLD', 'NEW'], 'No verified service to start')
    directory = Path(plan['permit']).parent
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    write_record(plan['permit'], {'boot_id': BOOT_ID.read_text().strip(),
                 'plan_sha256': expected, 'selection': selection})


def allow(plan, expected, requested):
    permit = read_record(plan['permit']) or {}
    chosen = permit.get('selection', 'HOLD')
    if chosen not in ['OLD', 'NEW']:
        chosen = 'HOLD'
    return policy(plan, 'start', chosen, requested,
                  permit.get('boot_id') == BOOT_ID.read_text().strip(),
                  permit.get('plan_sha256') == expected) == 'ALLOW'


def boot(plan, expected):
    selected = select(plan)
    publish(plan, expected, selected)
    # Nonblocking start avoids a dependency cycle: these units wait for us.
    command(['systemctl', 'start', '--no-block', *plan[selected.lower()]['units']])
    print('RECOVERY_BOOT_' + selected, flush=True)


def recover(plan, expected):
    value = journal(plan)
    if value and value.get('transaction') == plan['transaction'] and value['phase'] in ['committed', 'prepared', 'rolled_back']:
        return
    require(verified(plan['old']), 'Old service validation failed; hold')
    command(['systemctl', 'stop', *reversed(plan['new']['units'])])
    require(all(command(['systemctl', 'is-active', '--quiet', u], check=False).returncode != 0 for u in plan['new']['units']), 'Candidate still active')
    publish(plan, expected, 'OLD')
    command(['systemctl', 'start', *plan['old']['units']])
    require(all(command(['systemctl', 'is-active', '--quiet', u], check=False).returncode == 0 for u in plan['old']['units']), 'Old service not active')
    value = dict(value or plan['state_seed'], phase='rolled_back', transaction=plan['transaction'],
                 recovery_plan_sha256=expected)
    write_record(plan['journal'], value)
    print('RECOVERY_RESTORED_OLD', flush=True)


def trial(plan, expected, timer):
    value = journal(plan) or {}
    now = time.monotonic_ns(); start = value.get('cutover_monotonic_ns')
    require(type(start) is int and 0 <= start <= now, 'Invalid trial clock')
    require(value.get('phase') == 'cutover_pending' and policy(plan, 'trial',
            value.get('boot_id') == BOOT_ID.read_text().strip(),
            value.get('transaction') == plan['transaction'],
            command(['systemctl', 'is-active', '--quiet', timer], check=False).returncode == 0,
            now - start) == 'ALLOW', 'Trial not authorized')
    require(all(command(['systemctl', 'is-active', '--quiet', u], check=False).returncode != 0 for u in plan['old']['units']), 'Old service still active')
    require(verified(plan['new']), 'Candidate validation failed')
    publish(plan, expected, 'NEW')


def boot_failure(plan, expected):
    permit = read_record(plan['permit']) or {}
    failed = command(['systemctl', 'show', plan['new']['units'][0], '--property=ActiveState', '--value']).stdout.strip() == 'failed'
    require(policy(plan, 'fallback', permit.get('selection') == 'NEW',
                   permit.get('boot_id') == BOOT_ID.read_text().strip(),
                   permit.get('plan_sha256') == expected, failed, verified(plan['old'])) == 'ALLOW',
            'Failure recovery not authorized')
    value = dict(journal(plan) or plan['state_seed'], phase='rollback_pending', transaction=plan['transaction'])
    write_record(plan['journal'], value)
    recover(plan, expected)


def unit_text(helper, plan_path, expected, old_unit, new_unit):
    require(absolute(str(helper)) and absolute(str(plan_path)) and re.fullmatch('[0-9a-f]{64}', expected), 'Invalid unit argument')
    require(all(re.fullmatch(r'[A-Za-z0-9_-]+\.service', u) for u in [old_unit, new_unit]), 'Invalid unit name')
    invocation = f'/usr/bin/python3 -I {helper} --plan {plan_path} --sha256 {expected}'
    boot_unit = f'''[Unit]
Description=PathWard durable boot recovery
After=local-fs.target
Before={old_unit} {new_unit}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={invocation} boot
TimeoutStartSec=180
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
'''
    dropins = {}
    for unit, side in [(old_unit, 'OLD'), (new_unit, 'NEW')]:
        other = new_unit if side == 'OLD' else old_unit
        ordering = f'Before={old_unit}\n' if side == 'NEW' else ''
        failure = 'OnFailure=pathward-recovery-fallback.service\n' if side == 'NEW' else ''
        dropins[unit] = f'''[Unit]
Requires=pathward-recovery.service
After=pathward-recovery.service
Conflicts={other}
{ordering}{failure}
[Service]
ExecStartPre=+{invocation} allow-{side.lower()}
'''
    fallback = f'''[Unit]
Description=PathWard verified fallback after candidate failure
After=pathward-recovery.service

[Service]
Type=oneshot
ExecStart={invocation} boot-failure
TimeoutStartSec=180
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
'''
    return boot_unit, dropins, fallback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('mode', choices=['boot', 'recover', 'boot-failure', 'allow-old', 'allow-new'])
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Administrator required')
    os.umask(0o077)
    plan = load_plan(args.plan, args.sha256)
    if args.mode.startswith('allow-'):
        raise SystemExit(0 if allow(plan, args.sha256, args.mode[6:].upper()) else 1)
    # Preparation can start this unit while holding the administrator lock.
    # A checked permit is private, atomic and scoped to this boot and plan.
    # Cold boot has no permit and must run the full locked recovery below.
    if args.mode == 'boot' and any(allow(plan, args.sha256, side) for side in ['OLD', 'NEW']):
        return
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        {'boot': boot, 'recover': recover, 'boot-failure': boot_failure}[args.mode](plan, args.sha256)


if __name__ == '__main__':
    main()
