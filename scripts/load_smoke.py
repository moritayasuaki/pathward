#!/usr/bin/env python3
"""Bounded adversarial connections plus healthy-peer progress; Linux loopback."""
from pathlib import Path
import json,queue,re,signal,socket,subprocess,tempfile,threading,time
ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'server/target/release/pathward-server'
def receive(s):
    out=b''
    try:
        while chunk:=s.recv(8192):out+=chunk
    except (ConnectionResetError,BrokenPipeError):pass
    return out
with tempfile.TemporaryDirectory(prefix='pathward-load-') as tmp:
    root=Path(tmp);(root/'a').write_text('OK')
    config=root/'config.kdl';config.write_text(f'site "example.com" {{\nroot "{root}"\npublish "/" "a"\ntls "auto"\n}}')
    p=subprocess.Popen([str(BIN),'serve-http',str(config),'127.0.0.1:0','--monitor','127.0.0.1:0'],stderr=subprocess.PIPE)
    startup=queue.Queue()
    def logs():
        for line in p.stderr:
            e=json.loads(line)
            if e['event']=='listening':startup.put(e)
    threading.Thread(target=logs,daemon=True).start();e=startup.get(timeout=10);port=e['port'];monitor=e['monitor_port']
    def connect(ip='127.0.0.2'):
        return socket.create_connection(('127.0.0.1',port),timeout=2,source_address=(ip,0))
    def get(ip='127.0.0.2'):
        with connect(ip) as s:
            try:s.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
            except (BrokenPipeError,ConnectionResetError):return b''
            return receive(s)
    held=[]
    try:
        held=[connect(),connect()]
        for s in held:s.sendall(b'GET / HTTP/1.1\r\n')
        time.sleep(.05)
        assert get('127.0.0.3').endswith(b'OK'), 'another peer made no progress'
        held.extend(connect() for _ in range(4))
        time.sleep(.05)
        assert get()==b'', 'seventh concurrent connection from one peer was admitted'
        for s in held:s.close()
        held=[];time.sleep(.05)
        denied=0
        for _ in range(50):
            if not get('127.0.0.4'):denied+=1
        assert denied>0
        time.sleep(1)
        assert get('127.0.0.4').endswith(b'OK'), 'bucket did not refill'
        # Repeated short bursts from distinct peers: accepted work remains bounded.
        for round in range(20):
            held=[connect(f'127.0.{round+1}.{i+1}') for i in range(24)]
            time.sleep(.02)
            for s in held:s.close()
            held=[]
            time.sleep(.02)
        with socket.create_connection(('127.0.0.1',monitor),timeout=2) as s:
            s.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n');data=receive(s)
        assert b'pathward_admission_rejected_total 0\n' not in data
        assert b'pathward_admission_rejected_total ' in data
        for reason in ('peer_active', 'peer_rate'):
            count = re.search(rb'pathward_admission_rejections_total\{reason="' + reason.encode() + rb'"\} (\d+)\n', data)
            assert count and int(count[1]) > 0, ('missing rejection reason', reason)
        p.send_signal(signal.SIGTERM);assert p.wait(timeout=7)==0
    finally:
        for s in held:s.close()
        if p.poll() is None:p.kill();p.wait(timeout=5)
print('Load test passed: per-peer concurrency, healthy-peer progress, rate refill, bounded bursts, telemetry and shutdown.')
