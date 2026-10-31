#!/usr/bin/env python3
"""Wait for a continuous soak checkpoint without restarting the tested process."""
import argparse
import json
import os
from pathlib import Path
import time
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("elapsed", type=int)
p.add_argument("--report", type=Path, required=True)
p.add_argument("--pid", type=Path, required=True)
p.add_argument("--final", action="store_true")
a = p.parse_args()
pid = int(a.pid.read_text())
deadline = time.monotonic()+720
while time.monotonic() < deadline:
    data = json.loads(a.report.read_text()) if a.report.exists() else None
    if data:
        assert data["state"] != "failed", data["failures"]
        if (data["state"] == "passed" if a.final else data["elapsed_seconds"] >= a.elapsed):
            assert not data["failures"]
            print(json.dumps(data, sort_keys=True))
            break
    os.kill(pid, 0)
    time.sleep(2)
else:
    raise SystemExit("soak checkpoint timed out")
