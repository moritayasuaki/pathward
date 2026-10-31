#!/usr/bin/env python3
"""Linux managed release CLI, conflict/rollback/permissions/restart tests."""
from pathlib import Path
import concurrent.futures
import json
import os
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time
ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'server/target/release/pathward-server'
def run(*args,ok=True):
    result=subprocess.run([str(BIN),*map(str,args)],capture_output=True,text=True,timeout=10)
    assert (result.returncode==0)==ok,(args,result.stdout,result.stderr)
    return result.stdout.strip()
def get(port,path='/'):
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n'.encode())
        out=b''
        while chunk:=s.recv(8192):out+=chunk
        return out
with tempfile.TemporaryDirectory(prefix='pathward-release-') as tmp:
    root=Path(tmp)
    for name in ['v1','v2']:
        (root/name).mkdir();(root/name/'index.html').write_text(name);(root/name/'secret.txt').write_text('NEVER DISCOVER')
    base=root/'base.kdl'
    base.write_text(f'site "example.com" {{\nroot "{root/"v1"}"\npublish "/" "index.html"\ntls "auto"\nheader "*" "referrer-policy" "no-referrer"\n}}\n')
    manifest=root/'public-files.txt';manifest.write_text('index.html\n')
    candidate=root/'candidate.kdl';candidate.write_text(run('generate',base,'example.com',root/'v2',manifest,'--index','index.html'))
    run('check',candidate)
    assert 'secret.txt' not in candidate.read_text()
    bad=root/'bad.kdl';bad.write_text(candidate.read_text().replace('index.html','missing.html'))
    run('check',bad,ok=False)
    control=root/'control';run('init',control,base)
    assert os.stat(control).st_mode&0o777==0o700
    assert os.stat(control/'.config').st_mode&0o777==0o600
    def start():
        p=subprocess.Popen([str(BIN),'serve-http',str(control/'.config'),'127.0.0.1:0','--control-dir',str(control)],stderr=subprocess.PIPE)
        first=queue.Queue()
        def drain():
            for line in p.stderr:
                data=json.loads(line)
                if data['event']=='listening':first.put(data)
        threading.Thread(target=drain,daemon=True).start()
        event=first.get(timeout=10)
        return p,event['port']
    process,port=start()
    try:
        assert get(port).endswith(b'v1')
        old=run('status','--control-dir',control)
        assert os.stat(control/'control.sock').st_mode&0o777==0o600
        # An old expected revision cannot overwrite a concurrent successful commit.
        def activate():
            return subprocess.run([str(BIN),'activate','--control-dir',str(control),'--expect',old,str(candidate)],capture_output=True,text=True,timeout=10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:activate(),range(2)))
        assert sorted(r.returncode for r in results)==[0,1],results
        current=run('status','--control-dir',control)
        assert current!=old and get(port).endswith(b'v2')
        assert get(port,'/secret.txt').startswith(b'HTTP/1.1 404')
        run('activate','--control-dir',control,'--expect',current,bad,ok=False)
        assert run('status','--control-dir',control)==current
        # Managed storage is excluded on SIGHUP as well as activation.
        stored=(control/'.config').read_bytes()
        invalid=stored.replace(str(root/'v2').encode(),str(control).encode())
        (control/'.config').write_bytes(invalid);process.send_signal(signal.SIGHUP);time.sleep(.15)
        assert run('status','--control-dir',control)==current
        (control/'.config').write_bytes(stored)
        restored=run('rollback','--control-dir',control,'--expect',current)
        assert restored!=current and get(port).endswith(b'v1')
        # Candidate symlink/FIFO/hardlink files are rejected before activation.
        os.unlink(root/'v2'/'index.html');os.symlink(root/'v2'/'secret.txt',root/'v2'/'index.html')
        run('activate','--control-dir',control,'--expect',restored,candidate,ok=False)
        os.unlink(root/'v2'/'index.html');os.mkfifo(root/'v2'/'index.html')
        run('activate','--control-dir',control,'--expect',restored,candidate,ok=False)
        os.unlink(root/'v2'/'index.html');os.link(root/'v2'/'secret.txt',root/'v2'/'index.html')
        run('activate','--control-dir',control,'--expect',restored,candidate,ok=False)
        assert run('status','--control-dir',control)==restored
        # No automatic deletion of either release, even after rollback.
        assert (root/'v1'/'index.html').exists() and (root/'v2'/'secret.txt').exists()
        process.kill();assert process.wait(timeout=5)==-signal.SIGKILL
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
    process,port=start()
    try:
        assert get(port).endswith(b'v1')
        process.terminate();assert process.wait(timeout=5)==0
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
print('Deployment CLI passed: explicit grants, preflight, concurrent CAS, private storage, SIGHUP isolation, rollback, unsafe files, durable restart.')
