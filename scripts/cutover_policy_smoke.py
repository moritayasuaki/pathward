#!/usr/bin/env python3
"""Exercise the actual policy CLI without service, file, or network mutations."""
import itertools
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('PATHWARD_TEST_BINARY', ROOT/'server/target/release/pathward-server'))

def call(name, args, expected):
    result = subprocess.run([str(BINARY), 'cutover-policy', name, *map(str, args)],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and result.stdout == ('ALLOW\n' if expected else 'DENY\n'), (name, args, result)

for values in itertools.product([0, 1], repeat=4):
    for gate in ['stop-old', 'commit']: call(gate, values, all(values))
for values in itertools.product([0, 1], repeat=3):
    call('watchdog', values, not any(values))
for boot in [0, 1]:
    for start in [0, 1, 2**64-1]:
        for now in [0, 1, 899999999999, 900000000000, 900000000001, 2**64-1]:
            call('window', [boot, start, now], boot == 1 and 0 <= now-start < 900000000000)
for committed in [0, 1]:
    for persisted, current in itertools.product([0, 1, 2**64-1], repeat=2):
        call('disarm', [committed, persisted, current], committed == 1 and current > 0 and persisted == current)
for bad in ['-1', '+1', '01', '1\n', str(2**64), '']:
    p = subprocess.run([str(BINARY),'cutover-policy','window','1','0',bad],capture_output=True,timeout=5)
    assert p.returncode != 0 and not p.stdout
print('PASS cutover policy CLI: missing prerequisites, deadline, reboot, stale epoch, malformed numbers')
