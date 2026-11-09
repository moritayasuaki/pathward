// Uses an existing Firefox binary and the ignored loopback Rust fixture.
// No npm packages, public origins, installed profiles, or trust-store changes.
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, writeFile, chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import assert from 'node:assert/strict';

const [firefox, testBinary] = process.argv.slice(2);
if (!firefox || !testBinary) throw Error('usage: node scripts/firefox_smoke.mjs FIREFOX SERVER_TEST_BINARY');
const evidence = await mkdtemp(join(tmpdir(), 'pathward-firefox-'));
await chmod(evidence, 0o700);
const fixture = spawn(testBinary, ['--ignored', '--exact', 'browser_fixture::firefox_loopback_fixture', '--nocapture'], {stdio:['ignore','pipe','pipe']});
let fixtureLog = '';
fixture.stdout.on('data', b => fixtureLog += b);
fixture.stderr.on('data', b => fixtureLog += b);
const sockets = new Set();
let proxy;
const results = [];
try {
  let port;
  for (let i=0;i<100;i++) {
    port = Number(fixtureLog.match(/BROWSER_FIXTURE_PORT=(\d+)/)?.[1]);
    if (port) break;
    if (fixture.exitCode !== null) throw Error(fixtureLog);
    await delay(100);
  }
  assert(port > 0 && port < 65536, fixtureLog);
  // Map only the fixture's HTTPS authority to its ephemeral TCP listener.
  // All other SOCKS destinations are refused, including background traffic.
  proxy = net.createServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {}); socket.setTimeout(20000, () => socket.destroy());
    let stage=0, data=Buffer.alloc(0);
    const receive = chunk => {
      data=Buffer.concat([data,chunk]); if(data.length>1024){socket.destroy();return;}
      if(stage===0) {
        if(data.length<2 || data.length<2+data[1])return;
        if(data[0]!==5 || !data.subarray(2,2+data[1]).includes(0)){socket.destroy();return;}
        data=data.subarray(2+data[1]);stage=1;socket.write(Buffer.from([5,0]));
      }
      if(stage===1) {
        if(data.length<5)return;
        if(data[0]!==5||data[1]!==1||data[2]!==0||data[3]!==3){socket.destroy();return;}
        const length=7+data[4]; if(data.length<length)return;
        if(data.subarray(5,length-2).toString()!=='app.example'||data.readUInt16BE(length-2)!==443){socket.destroy();return;}
        const extra=data.subarray(length);stage=2;socket.removeListener('data',receive);socket.pause();
        const upstream=net.connect(port,'127.0.0.1',()=>{
          socket.write(Buffer.from([5,0,0,1,127,0,0,1,0,0]));
          if(extra.length)upstream.write(extra);
          socket.pipe(upstream);upstream.pipe(socket);socket.resume();
        });
        sockets.add(upstream);upstream.on('close',()=>{sockets.delete(upstream);socket.destroy();});
        upstream.on('error',()=>socket.destroy());socket.on('close',()=>upstream.destroy());
      }
    };
    socket.on('data',receive);
  });
  await new Promise((ok, fail)=>{proxy.once('error',fail);proxy.listen(0,'127.0.0.1',ok);});
  for (const mode of ['h2','h3']) {
    const profile=join(evidence,mode);await mkdir(profile,{mode:0o700});
    const prefs={'browser.shell.checkDefaultBrowser':false,'browser.startup.homepage':'about:blank','browser.newtabpage.enabled':false,'app.update.auto':false,'datareporting.healthreport.uploadEnabled':false,'toolkit.telemetry.enabled':false};
    if(mode==='h2')Object.assign(prefs,{'network.http.http3.enable':false,'network.proxy.type':1,'network.proxy.socks':'127.0.0.1','network.proxy.socks_port':proxy.address().port,'network.proxy.socks_version':5,'network.proxy.socks_remote_dns':true,'network.proxy.no_proxies_on':''});
    else Object.assign(prefs,{'network.dns.localDomains':'app.example','network.dns.disableIPv6':true,'network.http.http3.enable':true,'network.http.http3.alt-svc-mapping-for-testing':`app.example;h3=":${port}"`,'network.http.http3.force-use-alt-svc-mapping-for-testing':true,'network.http.http3.disable_when_third_party_roots_found':false});
    await writeFile(join(profile,'user.js'),Object.entries(prefs).map(([k,v])=>`user_pref(${JSON.stringify(k)}, ${JSON.stringify(v)});`).join('\n'),{mode:0o600});
    const browser=spawn(firefox,['--headless','--no-remote','--new-instance','--profile',profile,'--remote-debugging-port','0','about:blank'],{stdio:['ignore','ignore','pipe'],env:{...process.env,MOZ_APP_DATA:profile,MOZ_LOCAL_APP_DATA:profile}});
    let stderr='', ws, next=0;const pending=new Map(), events=[];
    browser.stderr.on('data',b=>stderr=(stderr+b).slice(-12000));
    try {
      let endpoint;
      for(let i=0;i<150;i++){const port=stderr.match(/WebDriver BiDi listening on ws:\/\/(?:localhost|127\.0\.0\.1):(\d+)/)?.[1];endpoint=port?`ws://127.0.0.1:${port}`:undefined;if(endpoint)break;if(browser.exitCode!==null)throw Error(stderr);await delay(100);}
      assert(endpoint,stderr);ws=new WebSocket(`${endpoint}/session`);
      await new Promise((ok,fail)=>{ws.onopen=ok;ws.onerror=fail;});
      ws.onmessage=({data})=>{const msg=JSON.parse(data),p=pending.get(msg.id);if(p){pending.delete(msg.id);clearTimeout(p.timer);msg.type==='error'?p.fail(Error(JSON.stringify(msg))):p.ok(msg.result);}else events.push(msg);};
      const send=(method,params={})=>new Promise((ok,fail)=>{const id=++next,timer=setTimeout(()=>{pending.delete(id);fail(Error(`timeout: ${method}`));},20000);pending.set(id,{ok,fail,timer});ws.send(JSON.stringify({id,method,params}));});
      // The only navigated origin is the ephemeral self-signed loopback fixture.
      const session=await send('session.new',{capabilities:{alwaysMatch:{acceptInsecureCerts:true}}});
      await send('session.subscribe',{events:['network.responseStarted','network.fetchError','log.entryAdded']});
      const {context}=await send('browsingContext.create',{type:'tab'});
      for(let round=1;round<=2;round++) {
        await send('browsingContext.navigate',{context,url:'https://app.example/',wait:'complete'});
        const value=await send('script.evaluate',{expression:'JSON.stringify({title:document.title,text:document.body.innerText,image:document.images[0]?.naturalWidth,protocol:performance.getEntriesByType("navigation")[0].nextHopProtocol,status:performance.getEntriesByType("navigation")[0].responseStatus})',target:{context},awaitPromise:false});
        const page=JSON.parse(value.result.value);
        results.push({mode,round,version:session.capabilities.browserVersion,...page});
        assert.equal(page.title,'PathWard compatibility fixture');assert.equal(page.protocol,mode);assert.equal(page.status,200);assert.equal(page.image,1);
        console.log(JSON.stringify(results.at(-1)));
        await send('browsingContext.navigate',{context,url:'about:blank',wait:'complete'});
      }
      await send('browser.close').catch(()=>{});
    } finally {
      ws?.close();for(const p of pending.values())clearTimeout(p.timer);
      if(browser.exitCode===null)browser.kill('SIGTERM');
      await writeFile(join(profile,'stderr.log'),stderr,{mode:0o600});
      await writeFile(join(profile,'events.json'),JSON.stringify(events,null,2),{mode:0o600});
    }
  }
} finally {
  for(const socket of sockets)socket.destroy();proxy?.close();
  if(fixture.exitCode===null)fixture.kill('SIGTERM');
  await writeFile(join(evidence,'result.json'),JSON.stringify(results,null,2),{mode:0o600});
  await writeFile(join(evidence,'fixture.log'),fixtureLog,{mode:0o600});
  console.log(JSON.stringify({evidence}));
}
