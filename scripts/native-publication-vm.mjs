#!/usr/bin/env node
// Disposable NIC-free VM; no package install, production service or Python driver.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
const args=Object.fromEntries(process.argv.slice(2).reduce((a,v,i,all)=>i%2?a:[...a,[v,all[i+1]]],[]));
const base=args['--base-image'],bundle=args['--bundle'],out=args['--output'],scenario=args['--scenario']??'publication';
if(!base||!bundle||!out||!['publication','bootstrap','bridge'].includes(scenario)||Object.keys(args).some(k=>!['--base-image','--bundle','--output','--scenario','--legacy-bridge','--legacy-reader','--reference-server','--replay-policy','--replay-inventory'].includes(k)))throw Error('Use --base-image PINNED_IMAGE --bundle VERIFIED_BUNDLE --output NEW_DIRECTORY');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const baseSha='406630c08b5e545fcc7209854b129d47e3af822db128c9f19336593b5a2d3fe0';
if(sha(fs.readFileSync(base))!==baseSha)throw Error('Base image checksum');
const root=path.resolve(import.meta.dirname,'..');
const names=['pathward-admin','pathward-hosting','pathward-server','pathward-recovery','role_vm_guest','role_fixture',...(scenario!=='publication'?['pathward-publish','bootstrap_vm_guest']:[])];
const sums=new Map(fs.readFileSync(path.join(bundle,'SHA256SUMS'),'utf8').trim().split('\n').map(s=>{const m=/^([0-9a-f]{64})  ([A-Za-z0-9_-]+)$/.exec(s);if(!m)throw Error('Checksum line');return [m[2],m[1]];}));
const source=fs.readFileSync(path.join(bundle,'SOURCE_COMMIT'),'utf8').trim();
if(!/^[0-9a-f]{40}$/.test(source))throw Error('Source commit');
const files=names.map(name=>{const content=fs.readFileSync(path.join(bundle,name));if(sha(content)!==sums.get(name)||content.subarray(0,4).toString('hex')!=='7f454c46')throw Error(`Artifact mismatch ${name}`);return {name,mode:'0755',content};});
// Only the initial historical guard fixture is Python. It is tombstoned before
// exercising publication, collection or any subsequent reboot.
if(scenario==='publication')files.push({name:'pathward_recovery.py',mode:'0600',content:fs.readFileSync(path.join(root,'deploy/pathward_recovery.py'))});
const inputs={};
if(scenario==='bridge')for(const [flag,name] of [['--legacy-bridge','legacy-bridge.py'],['--legacy-reader','legacy-reader.py'],['--reference-server','reference-server']]){
 if(!args[flag])throw Error(`Bridge rehearsal requires reviewed ${flag}`);
 const content=fs.readFileSync(args[flag]);if(content.length>256*1024*1024)throw Error('Fixture input bound');
 inputs[name]=sha(content);files.push({name,mode:'0755',content});
}
if(args['--replay-policy']||args['--replay-inventory']){
 if(scenario!=='bridge'||!args['--replay-policy']||!args['--replay-inventory'])throw Error('Replay requires bridge scenario and both reviewed inputs');
 for(const [flag,name] of [['--replay-policy','replay-policy.json'],['--replay-inventory','replay-inventory.json']]){
  const content=fs.readFileSync(args[flag]);if(content.length>1024*1024)throw Error('Replay input bound');
  JSON.parse(content);inputs[name]=sha(content);files.push({name,mode:'0600',content});
 }
}
fs.mkdirSync(out,{mode:0o700});const seed=path.join(out,'seed');fs.mkdirSync(seed);
// Copy raw verified files from read-only media. Embedding entire ELF binaries
// in cloud-init YAML needlessly makes its parser emulate megabytes of text.
fs.mkdirSync(path.join(seed,'artifacts'));
for(const file of files)fs.writeFileSync(path.join(seed,'artifacts',file.name),file.content);
const guestRoot='/opt/pathward-reboot-test',media='/mnt/pathward-seed';
const commands=[['/usr/bin/install','-d','-m','0755',guestRoot,media],['/usr/bin/mount','-t','iso9660','-o','ro,nodev,nosuid,noexec','/dev/sr0',media],
 ...files.map(f=>['/usr/bin/install','-m',f.mode,`${media}/artifacts/${f.name}`,`${guestRoot}/${f.name}`]),['/usr/bin/umount',media],[`${guestRoot}/${scenario!=='publication'?'bootstrap_vm_guest':'role_vm_guest'}`,scenario==='bridge'?'--bridge-initialize':scenario==='bootstrap'?'--initialize':'--publication-initialize']];
fs.writeFileSync(path.join(seed,'user-data'),'#cloud-config\n'+JSON.stringify({package_update:false,package_upgrade:false,ssh_deletekeys:false,runcmd:commands}));
fs.writeFileSync(path.join(seed,'meta-data'),'instance-id: pathward-native-publication\nlocal-hostname: publication-test\n');fs.writeFileSync(path.join(seed,'network-config'),'version: 2\nethernets: {}\n');
function cmd(bin,a){const r=spawnSync(bin,a,{stdio:['ignore','ignore','inherit']});if(r.status!==0)throw Error(`${bin} failed`);}
const iso=path.join(out,'seed.iso'),disk=path.join(out,'disk.qcow2');
if(process.platform==='darwin')cmd('hdiutil',['makehybrid','-iso','-joliet','-default-volume-name','cidata','-o',iso,seed]);else cmd('genisoimage',['-output',iso,'-volid','cidata','-joliet','-rock',seed]);
cmd('qemu-img',['create','-f','qcow2','-F','qcow2','-b',fs.realpathSync(base),disk,'4G']);
const delay=ms=>new Promise(r=>setTimeout(r,ms));let owned;
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{owned?.kill('SIGTERM');process.exitCode=1;});
try{
 for(let attempt=0;attempt<7;attempt++){
  const log=path.join(out,`boot-${attempt}.log`),err=fs.openSync(path.join(out,`qemu-${attempt}.log`),'w');
  const q=spawn('qemu-system-x86_64',['-accel','tcg,thread=multi','-m','1024','-smp','2','-display','none','-monitor','none','-serial',`file:${log}`,'-nic','none','-no-reboot','-drive',`file=${disk},format=qcow2,if=virtio,cache=none`,'-drive',`file=${iso},format=raw,media=cdrom,readonly=on`],{stdio:['ignore','ignore',err]});owned=q;fs.closeSync(err);
  let exited=false;const stopped=new Promise((resolve,reject)=>{q.once('error',reject);q.once('exit',()=>{exited=true;resolve();});});
  try{
   const deadline=Date.now()+(attempt===0?1_200_000:420_000);
   while(Date.now()<deadline){
    const text=fs.existsSync(log)?fs.readFileSync(log,'utf8'):'';
    if(text.includes('PW_VM_FAILURE '))throw Error(`Guest assertion failed: ${log}`);
    if(text.includes('PW_VM_RECOVERY_PASS ')){
     const report=JSON.parse(text.split('PW_VM_RECOVERY_PASS ')[1].split(/\r?\n/)[0]);
     report.base_image_sha256=baseSha;report.source_commit=source;report.external_network=false;report.host_services_changed=false;report.reviewed_fixture_sha256=inputs;
     report.runtime_sha256=Object.fromEntries(['pathward-admin','pathward-hosting','pathward-publish'].filter(n=>names.includes(n)).map(n=>[n,sums.get(n)]));
     await Promise.race([stopped,delay(90000).then(()=>{throw Error('Guest did not stop');})]);
     fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(report,null,2)+'\n');console.log(`PASS ${path.join(out,'result.json')}`);process.exit(0);
    }
    if(text.includes('PW_CUT_POWER ')){console.log('Hard cut:',text.split('PW_CUT_POWER ')[1].split(/\r?\n/)[0]);q.kill('SIGKILL');await stopped;break;}
    if(exited){if(!text.includes('PW_COLD_REBOOT '))throw Error(`Unexpected VM exit: ${log}`);console.log('Cold reboot:',attempt);break;}
    await delay(250);
   }
   if(!exited)throw Error(`VM deadline exceeded: ${log}`);
  }finally{if(!exited){q.kill('SIGKILL');await stopped;}owned=undefined;}
 }
 throw Error('VM did not reach final verification');
}finally{owned?.kill('SIGKILL');}
