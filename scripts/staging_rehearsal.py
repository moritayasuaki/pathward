#!/usr/bin/env python3
"""Isolated, bounded Caddy -> PathWard -> Caddy rehearsal; Python standard library.

Invoked by acme_integration.py --rehearsal under a resource-limited user service.
Never loads the system Caddy configuration, calls its admin API, or binds public IPs.
This is a test controller, not a production deployment/automatic failover service.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'server/target/release/pathward-server'
DRIVER = ROOT / 'server/target/release/examples/soak_server'
GATE = ROOT / 'server/target/release/examples/migration_gate'
HOST = 'stage.pathward.test'
SECURITY = {'strict-transport-security': 'max-age=2592000',
            'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
            'referrer-policy': 'strict-origin-when-cross-origin',
            'x-frame-options': 'DENY', 'permissions-policy': 'camera=(), microphone=(), geolocation=()'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def available_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def read_manifest(source, manifest):
    # Deliberately no directory discovery, symlink following or hard-link reuse.
    names = manifest.read_text().splitlines()
    require(0 < len(names) <= 240 and len(set(names)) == len(names), 'manifest count/duplicates')
    require('index.html' in names, 'explicit index.html required')
    data = {}
    for name in names:
        require(re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*', name)
                and all(not p.endswith('.') for p in name.split('/')), 'unsafe manifest entry')
        require(name not in ('release-a.txt', 'release-b.txt', 'private.txt', 'legacy'), 'reserved fixture entry')
        p = source
        for component in name.split('/'):
            p = p / component
            require(not p.is_symlink(), 'manifest symlink')
        info = p.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 64*1024*1024,
                'unsafe manifest file')
        data[name] = p.read_bytes()
        require(sum(map(len, data.values())) <= 128*1024*1024, 'fixture exceeds 128 MiB')
    return data


class Rehearsal:
    def __init__(self, work, content, seconds, headers):
        self.work, self.content, self.seconds = work, content, seconds
        self.security = dict(headers, **{'x-content-type-options': 'nosniff'})
        self.ports = {'tls': int(os.environ['PATHWARD_TEST_PORT']), 'http': available_port(), 'monitor': available_port()}
        require(len(set(self.ports.values())) == 3 and all(p > 1024 for p in self.ports.values()), 'isolated ports')
        self.context = ssl.create_default_context(cafile=os.environ['PATHWARD_TEST_ISSUER'])
        self.context.load_verify_locations(cafile=os.environ['PATHWARD_TEST_CA'])
        self.context.set_alpn_protocols(['http/1.1'])
        self.process = None
        self.reader = None
        self.kind = None
        self.logs = []
        self.events = collections.Counter()
        self.counts = collections.Counter(steady_errors=0, transition_errors=0)
        self.certificates = set()
        self.overlap = 0
        self.order_active = False
        self.stop_load = threading.Event()
        self.transition = threading.Event()
        self.lock = threading.Lock()
        self.peer = 0
        self.failures = []
        self.handoffs = []
        self.resources = []
        self.caddy = shutil.which('caddy')
        require(self.caddy, 'existing Caddy binary required; never installed automatically')
        self.control, self.cache = work/'control', work/'cache'
        self.configs = {}
        for release in ('a', 'b'):
            root = work/release
            root.mkdir()
            for name, data in content.items():
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (root/f'release-{release}.txt').write_text(release)
            (root/'private.txt').write_text('UNPUBLISHED_CANARY')
            (root/'.private').write_text('HIDDEN_CANARY')
            base = work/f'base-{release}.kdl'
            policy = ''.join(f'header "*" {json.dumps(k)} {json.dumps(v)}\n' for k,v in headers.items())
            base.write_text(f'site "{HOST}" {{\nroot {json.dumps(str(root))}\ntls "auto"\n'
                            f'publish "/" "index.html"\nredirect "/legacy" "{HOST}" "/index.html" "308"\n'
                            + policy + f'header "*" "x-robots-tag" "release-{release}"\n}}\n')
            manifest = work/f'manifest-{release}.txt'
            manifest.write_text('\n'.join(content)+f'\nrelease-{release}.txt\n')
            generated = self.cli('generate', base, HOST, root, manifest, '--index', 'index.html').stdout
            path = work/f'{release}.kdl'
            path.write_text(generated)
            self.cli('check', path)
            self.configs[release] = path
        self.cli('init', self.control, self.configs['a'])
        self.caddyfile = work/'Caddyfile'
        header_lines = '\n'.join('    '+k+' '+json.dumps(v) for k,v in self.security.items())
        public_paths = ' '.join(json.dumps('/'+n) for n in content)
        cert, key = os.environ['PATHWARD_TEST_FALLBACK_CERT'], os.environ['PATHWARD_TEST_FALLBACK_KEY']
        self.caddyfile.write_text('''{
    admin off
    auto_https off
    servers {
        protocols h1
    }
    storage file_system {
        root %s
    }
}
https://%s:%d {
    bind 127.0.0.1
    tls %s %s
    header {
        -Server
%s
        x-robots-tag release-a
    }
    @legacy path /legacy
    redir @legacy https://%s/index.html?{http.request.uri.query} 308
    @public path / %s /release-a.txt
    handle @public {
        root * %s
        file_server
    }
    respond "" 404
}
http://%s:%d {
    bind 127.0.0.1
    redir https://%s{uri} 308
}
''' % (json.dumps(str(work/'caddy-storage')), HOST, self.ports['tls'], json.dumps(cert), json.dumps(key),
       header_lines, HOST, public_paths, json.dumps(str(work/'a')), HOST, self.ports['http'], HOST))
        subprocess.run([self.caddy,'validate','--config',str(self.caddyfile),'--adapter','caddyfile'],
                       env=self.caddy_env(), capture_output=True, check=True, timeout=15)
        self.inspected = self.snapshot()

    def caddy_env(self):
        return dict(os.environ, XDG_DATA_HOME=str(self.work/'caddy-data'), XDG_CONFIG_HOME=str(self.work/'caddy-config'))

    def cli(self, *args, ok=True):
        result = subprocess.run([str(BIN), *map(str,args)], capture_output=True, text=True, timeout=15)
        require((result.returncode == 0) == ok, 'CLI '+str(args[0])+' unexpected outcome: '+result.stderr[:200])
        return result

    def snapshot(self):
        paths = [BIN, DRIVER, GATE, Path(self.caddy), self.caddyfile, self.control/'.config', *self.configs.values()]
        paths += [self.work/r/n for r in ('a','b') for n in self.content]
        paths += [self.work/r/f'release-{r}.txt' for r in ('a','b')]
        return sha(json.dumps([self.ports, [(str(p),sha(p.read_bytes())) for p in paths]],sort_keys=True).encode())

    def gate(self, current=None, flags=(True,True,True,True), ok=True):
        result = subprocess.run([str(GATE),current or self.snapshot(),self.inspected,
                                 *(str(x).lower() for x in flags)],capture_output=True,timeout=5)
        require((result.returncode == 0) == ok, 'migration gate outcome')

    def response(self, target='/', method='GET', plain=False, authority=HOST, monitor=False):
        with self.lock:
            self.peer = (self.peer+1) % 200
            peer = f'127.0.1.{self.peer+1}'
        port = self.ports['monitor'] if monitor else self.ports['http'] if plain else self.ports['tls']
        stream = socket.create_connection(('127.0.0.1',port),timeout=2,source_address=(peer,0))
        try:
            if not (plain or monitor):
                stream = self.context.wrap_socket(stream,server_hostname=HOST)
                with self.lock:
                    self.certificates.add(sha(stream.getpeercert(binary_form=True)))
            stream.sendall(f'{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n'.encode())
            out=b''
            while chunk:=stream.recv(65536):
                out+=chunk
                require(len(out) <= 65*1024*1024, 'response bound')
            head,body=out.split(b'\r\n\r\n',1)
            lines=head.decode('ascii').split('\r\n')
            headers={}
            for line in lines[1:]:
                k,v=line.split(':',1)
                require(k.lower() not in headers,'duplicate header')
                headers[k.lower()]=v.strip()
            return int(lines[0].split()[1]),headers,body
        finally:
            stream.close()

    def check_file(self, name, method='GET'):
        result=self.response('/'+name,method)
        code,headers,body=result
        expected=self.content[name]
        require(code==200 and body==(expected if method=='GET' else b''), 'file body/status '+name)
        require(int(headers['content-length'])==len(expected), 'file length '+name)
        for k,v in self.security.items():
            require(headers.get(k)==v, 'security header '+k)
        require('server' not in headers, 'server banner')
        if name.endswith('.xml'):
            require(headers['content-type'].split(';')[0] in ('application/xml','text/xml'), 'XML MIME type')
        self.counts['file_checks']+=1
        return headers['content-type']

    def contract(self, release='a'):
        types={}
        for name in self.content:
            types[name]=self.check_file(name)
            self.check_file(name,'HEAD')
            time.sleep(.04)
        require(self.response()[2]==self.content['index.html'],'root alias')
        for target in ('/private.txt','/.private','/missing','/release-'+('b' if release=='a' else 'a')+'.txt'):
            code,_,body=self.response(target)
            require(code==404 and body==b'','unpublished URL')
        code,headers,body=self.response('/legacy?q=raw%20bytes')
        require(code==308 and headers.get('location')==f'https://{HOST}/index.html?q=raw%20bytes' and not body,
                'redirect contract')
        code,headers,body=self.response('/index.html?q=raw%20bytes',plain=True)
        require(code==308 and headers.get('location')==f'https://{HOST}/index.html?q=raw%20bytes','HTTP redirect')
        require('strict-transport-security' not in headers,'HSTS over plaintext')
        return types

    def launch(self, kind, broken=False):
        require(self.process is None,'process ownership')
        self.kind=kind
        log=(self.work/f'{kind}-{len(self.logs)}.log').open('w')
        self.logs.append(log)
        if kind=='caddy':
            cmd=[self.caddy,'run','--config',str(self.caddyfile),'--adapter','caddyfile']
        else:
            cmd=[str(DRIVER),str(self.control),str(self.cache),os.environ['PATHWARD_TEST_DIRECTORY'],
                 os.environ['PATHWARD_TEST_CA'],*(str(self.ports[p]) for p in ('tls','http','monitor'))]
            if broken: cmd.append('injected-invalid-argument')
        self.process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.PIPE,text=True,
                                      env=self.caddy_env() if kind=='caddy' else None)
        process=self.process
        def drain():
            for line in process.stderr:
                log.write(line);log.flush()
                if kind=='pathward':
                    try: event=json.loads(line)['event']
                    except (ValueError,KeyError): continue
                    with self.lock:
                        self.events[event]+=1
                        if event=='acme_order_started':self.order_active=True
                        if event=='reload_committed' and self.order_active:self.overlap+=1
                        if event in ('acme_activated','acme_failed'):self.order_active=False
        self.reader=threading.Thread(target=drain,daemon=True)
        self.reader.start()

    def ready(self, timeout=20):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            require(self.process.poll() is None, 'candidate exited during startup')
            try:
                code,_,body=self.response()
                if code==200 and body==self.content['index.html']:
                    if self.kind=='pathward':
                        require(self.response('/readyz',authority='localhost',monitor=True)[0]==200,'monitor readiness')
                    return
            except (OSError,ValueError):pass
            time.sleep(.1)
        raise RuntimeError('readiness deadline')

    def stop(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
                try:self.process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    self.process.kill();self.process.wait(timeout=5)
                    raise RuntimeError('graceful shutdown exceeded 12 seconds')
            self.process=None
            if self.reader:
                self.reader.join(timeout=2)
                require(not self.reader.is_alive(),'log reader did not stop')
                self.reader=None

    def handoff(self, kind, broken=False):
        if kind=='pathward':self.gate()
        self.transition.set()
        before=self.counts['transition_errors']
        began=time.monotonic()
        try:
            self.stop()
            self.launch(kind,broken)
            self.ready()
        except Exception:
            self.stop()
            self.launch('caddy')
            self.ready()
            self.counts['automatic_rollbacks']+=1
            if not broken:raise
        else:
            require(not broken,'injected failure unexpectedly passed')
        finally:
            elapsed=time.monotonic()-began
            self.handoffs.append({'target':kind,'injected_start_failure':broken,'seconds':round(elapsed,3),
                                  'failed_probes':self.counts['transition_errors']-before})
            self.transition.clear()
        self.contract()

    def background(self):
        while not self.stop_load.is_set():
            transition=self.transition.is_set()
            try:
                code,headers,body=self.response()
                require(code==200 and body==self.content['index.html'],'background body')
                for k,v in self.security.items():require(headers.get(k)==v,'background security header')
                self.counts['load_ok']+=1
            except Exception as error:
                if transition or self.transition.is_set():self.counts['transition_errors']+=1
                else:
                    self.counts['steady_errors']+=1
                    self.failures.append(type(error).__name__+': '+str(error)[:100])
            self.stop_load.wait(.25)

    def run(self):
        # Cert prewarming and full parity on the very same listeners, before promotion.
        self.launch('pathward');self.ready(60)
        candidate_types=self.contract()
        self.stop()
        self.launch('caddy');self.ready()
        fallback_types=self.contract()
        differences={n:[fallback_types[n],candidate_types[n]] for n in self.content if fallback_types[n]!=candidate_types[n]}
        require(all(n.endswith('.xml') for n in differences),'unexpected MIME parity difference')
        for i in range(4):
            flags=[True]*4;flags[i]=False
            self.gate(flags=flags,ok=False)
        self.gate(current='0'*64,ok=False)
        # Invalid candidates never stop Caddy or replace the active durable config.
        pid=self.process.pid
        bad=self.work/'bad.kdl'
        bad.write_text(self.configs['a'].read_text().replace('index.html','missing.html'))
        self.cli('check',bad,ok=False)
        require(self.process.pid==pid and self.response()[0]==200,'preflight disturbed fallback')
        self.counts['preflight_rejections']=6
        worker=threading.Thread(target=self.background)
        worker.start()
        try:
            self.handoff('pathward')
            for target in ('/%69ndex.html','/../private.txt','/%2e%2e/private.txt'):
                require(self.response(target)[0]==404,'unsafe path')
            require(self.response(authority='unknown.pathward.test')[0]==421,'SNI/Host mismatch')
            require(self.response(authority=HOST+':'+str(self.ports['tls']))[0]==400,'internal TLS port authority')
            require(self.response(plain=True,authority=HOST+':'+str(self.ports['http']))[0]==400,'internal HTTP port authority')
            began=time.monotonic()
            turn=0
            while time.monotonic()-began<self.seconds:
                require(self.process.poll() is None,'candidate crash')
                current=self.cli('status','--control-dir',self.control).stdout.strip()
                release='b' if turn%2==0 else 'a'
                self.cli('activate','--control-dir',self.control,'--expect',current,self.configs[release])
                code,headers,body=self.response('/release-'+release+'.txt')
                require(code==200 and body==release.encode() and headers['x-robots-tag']=='release-'+release,'ACK mismatch')
                revoked='a' if release=='b' else 'b'
                require(self.response('/release-'+revoked+'.txt')[0]==404,'revoked publication survived ACK')
                self.counts['commits']+=1
                if turn%10==0:
                    self.cli('activate','--control-dir',self.control,'--expect',current,self.configs[revoked],ok=False)
                    self.counts['stale_rejections']+=1
                    status=Path(f'/proc/{self.process.pid}/status').read_text()
                    rss=int(re.search(r'^VmRSS:\s+(\d+)',status,re.M)[1])
                    threads=int(re.search(r'^Threads:\s+(\d+)',status,re.M)[1])
                    fds=len(list(Path(f'/proc/{self.process.pid}/fd').iterdir()))
                    require(rss<131072 and threads<=32 and fds<=128,'resource ceiling')
                    self.resources.append({'rss_kib':rss,'threads':threads,'fds':fds})
                    code,_,body=self.response('/metrics',authority='localhost',monitor=True)
                    metrics={line.split()[0]:float(line.split()[1]) for line in body.decode().splitlines() if line and not line.startswith('#')}
                    require(code==200 and metrics['pathward_ready']==1 and metrics['pathward_acme_errors_total']==0
                            and metrics['pathward_log_dropped_total']==0
                            and metrics['pathward_certificate_not_after_seconds']>time.time(),'monitor health')
                    self.counts['monitor_checks']+=1
                if turn%60==0:
                    print('REHEARSAL_PROGRESS '+json.dumps({'elapsed_seconds':round(time.monotonic()-began),
                        'commits':self.counts['commits'],'renewals':self.events['acme_activated'],
                        'steady_errors':self.counts['steady_errors']}),flush=True)
                require(not self.failures,'steady request failure')
                turn+=1
                time.sleep(.5)
            current=self.cli('status','--control-dir',self.control).stdout.strip()
            self.cli('activate','--control-dir',self.control,'--expect',current,self.configs['a'])
            self.contract()
            require(self.events['acme_activated']>=3 and self.overlap>=1,'renewal/config overlap not demonstrated')
            require(self.events['acme_failed']==0,'ACME failure')
            for directory,names in ((self.cache,('.account','.certificate')),(self.control,('.config','.previous'))):
                require(directory.stat().st_mode&0o7777==0o700,'private directory mode')
                for name in names:
                    info=(directory/name).stat()
                    require(info.st_mode&0o7777==0o600 and info.st_nlink==1,'private file mode/link')
            self.handoff('caddy')
            self.handoff('pathward',broken=True)
            self.handoff('pathward')
            # Unplanned candidate death: controller detects loss and restores Caddy.
            self.transition.set()
            began=time.monotonic()
            self.process.kill();self.process.wait(timeout=5)
            require(self.process.poll()!=0,'injected crash')
            self.stop();self.launch('caddy');self.ready()
            self.handoffs.append({'target':'caddy','injected_crash':True,'seconds':round(time.monotonic()-began,3)})
            self.counts['automatic_rollbacks']+=1
            self.transition.clear()
            self.contract()
            time.sleep(2)
            require(not self.failures,'steady failures')
            require(self.snapshot()==self.inspected,'rehearsal inputs changed')
            require(self.counts['automatic_rollbacks']==2,'rollback coverage')
            return {'state':'passed','scope':'isolated static subset; shared Caddy replacement NO-GO',
                    'completed_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                    'harness_sha256':sha(Path(__file__).read_bytes()),
                    'binary_sha256':{name:sha(path.read_bytes()) for name,path in
                        (('pathward-server',BIN),('soak_server',DRIVER),('migration_gate',GATE),('caddy',Path(self.caddy)))},
                    'seconds':self.seconds,'content_files':len(self.content),'content_bytes':sum(map(len,self.content.values())),
                    'content_manifest_sha256':sha(json.dumps({n:sha(v) for n,v in self.content.items()},sort_keys=True).encode()),
                    'caddy_version':subprocess.check_output([self.caddy,'version'],text=True).strip(),
                    'counts':dict(self.counts),'events':dict(self.events),'commits_during_acme_order':self.overlap,
                    'distinct_certificates_including_caddy':len(self.certificates),'handoffs':self.handoffs,
                    'resources_peak':{k:max(r[k] for r in self.resources) for k in ('rss_kib','threads','fds')},
                    'mime_differences':differences,'private_storage_checked':True,'final_serving_process':'caddy'}
        finally:
            self.stop_load.set();worker.join(timeout=5)
            # A test failure after promotion still exercises verified Caddy recovery.
            if self.kind!='caddy' or self.process is None or self.process.poll() is not None:
                self.stop();self.launch('caddy');self.ready();self.contract()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--content',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--headers',type=Path)
    parser.add_argument('--seconds',type=int,default=180)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    require(120<=args.seconds<=900,'duration')
    content=read_manifest(args.content.resolve(strict=True),args.manifest)
    headers=json.loads(args.headers.read_text()) if args.headers else SECURITY
    require(set(headers)==set(SECURITY) and all(isinstance(v,str) and '\n' not in v and '\r' not in v for v in headers.values()),'security header input')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='pathward-rehearsal-') as directory:
        test=Rehearsal(Path(directory),content,args.seconds,headers)
        try:result=test.run()
        except BaseException as error:
            args.report.parent.mkdir(parents=True,exist_ok=True)
            args.report.write_text(json.dumps({'state':'failed','error':str(error)[:200],
                                               'counts':dict(test.counts),'handoffs':test.handoffs})+'\n')
            for log in test.logs:
                log.flush()
                print(Path(log.name).read_text()[-2000:])
            raise
        finally:
            test.stop()
            for log in test.logs:log.close()
        for p in test.ports.values():
            with socket.socket() as s:require(s.connect_ex(('127.0.0.1',p))!=0,'staging listener survived cleanup')
        result['staging_listeners_removed']=True
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('REHEARSAL_RESULT '+json.dumps(result,sort_keys=True),flush=True)

if __name__=='__main__':main()
