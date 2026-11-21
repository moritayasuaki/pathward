// Run with a local pinned guest image and an empty output directory.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {closeSync, createReadStream, copyFileSync, ftruncateSync, mkdirSync, openSync, readFileSync, readSync, realpathSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';

assert([4,5].includes(process.argv.length), 'usage: node scripts/pool_linux_stage.mjs IMAGE NEW_OUTPUT_DIRECTORY [s3|s4]');
const mode = process.argv[4] ?? 's3';
assert(['s3','s4'].includes(mode));
const root = fileURLToPath(new URL('../', import.meta.url));
const pin = JSON.parse(readFileSync(join(root, 'audit/pool-linux-target.json')));
const image = realpathSync(process.argv[2]);
const out = resolve(process.argv[3]);
const seed = join(out, 'seed');
async function digest(file) {
    const sha = createHash('sha256');
    for await (const chunk of createReadStream(file)) sha.update(chunk);
    return sha.digest('hex');
}
assert.equal(await digest(image), pin.guest.image_sha256, 'guest image');
const version = execFileSync('rustc', ['+' + pin.rust_release, '-vV'], {encoding:'utf8'});
assert(version.split('\n').includes('commit-hash: ' + pin.rust_commit));
const build = execFileSync('cargo', ['+' + pin.rust_release, 'test', '--offline', '--locked',
    '--manifest-path', 'server/Cargo.toml', '--lib', '--target', pin.target, '--no-run', '--message-format=json'],
    {cwd:root, encoding:'utf8', stdio:['ignore','pipe','inherit'], maxBuffer:16 << 20});
const artifacts = build.trim().split('\n').map(s => JSON.parse(s)).filter(a =>
    a.reason === 'compiler-artifact' && a.target.name === 'pathward_server' && a.executable);
assert.equal(artifacts.length, 1);
mkdirSync(out, {mode:0o700});
mkdirSync(seed, {mode:0o700});
copyFileSync(artifacts[0].executable, join(seed, 'pool-tests'));
const cli = execFileSync('cargo', ['+' + pin.rust_release, 'build', '--offline', '--locked', '--manifest-path',
    'server/Cargo.toml', '--target', pin.target, '--bin', 'pathward-server', '--message-format=json'],
    {cwd:root, encoding:'utf8', stdio:['ignore','pipe','inherit'], maxBuffer:16 << 20});
const servers = cli.trim().split('\n').map(line => JSON.parse(line)).filter(a =>
    a.reason === 'compiler-artifact' && a.target.name === 'pathward-server' && a.executable);
assert.equal(servers.length, 1);
copyFileSync(servers[0].executable, join(seed, 'pathward-server'));
copyFileSync(join(root,'deploy/pathward-sleep.conf'), join(seed,'sleep.conf'));
copyFileSync(join(root,'deploy/pathward-sleep.tmpfiles'), join(seed,'sleep.tmpfiles'));
copyFileSync(join(root,'scripts/pool_sleep_guest.sh'), join(seed,'sleep-guest'));
copyFileSync(join(root,'scripts/pool_linux_guest.sh'), join(seed,'run'));
if (mode === 's4') {
    copyFileSync(join(root,'scripts/pool_linux_s4_guest.sh'), join(seed,'run-s4'));
}
function file(name, contents) { writeFileSync(join(seed, name), contents + '\n'); }
file('release', pin.guest.release);
file('version-signature', pin.guest.version_signature);
file('kernel.sha256', pin.guest.kernel_sha256 + '  /boot/vmlinuz-' + pin.guest.release);
file('binary.sha256', (await Promise.all(['pool-tests','pathward-server','sleep.conf','sleep.tmpfiles','sleep-guest']
    .map(async name => await digest(join(seed,name)) + '  ' + name))).join('\n'));
file('meta-data', 'instance-id: pool-linux-refinement\nlocal-hostname: pool-lab');
file('network-config', 'version: 2\nethernets: {}');
file('user-data', '#cloud-config\npackage_update: false\npackage_upgrade: false\nruncmd:\n' +
    '  - ["/bin/sh", "-c", "mkdir -p /mnt/pool-lab && mount -o ro /dev/sr0 /mnt/pool-lab && /bin/sh /mnt/pool-lab/run >/dev/ttyS0 2>&1; systemctl poweroff"]');
const run = (bin,args, opts={}) => execFileSync(bin,args,{cwd:out,stdio:'inherit',...opts});
run('xorriso',['-as','mkisofs','-quiet','-o','seed.iso','-V','cidata','-J','-r','seed']);
run('qemu-img',['create','-q','-f','qcow2','-F','qcow2','-b',image,'overlay.qcow2']);
const machine = ['-machine','pc','-accel','tcg,thread=multi','-m','1024','-smp','2',
    '-display','none','-monitor','none','-nic','none','-no-reboot',
    '-rtc','base=utc,clock=host','-smbios','type=1,product=PathWardPoolLab',
    '-drive','file=seed.iso,format=raw,media=cdrom,readonly=on'];
function boot(serial) {
    run('qemu-system-x86_64',[...machine,'-serial','file:' + serial],{timeout:600000,killSignal:'SIGKILL'});
    return readFileSync(join(out,serial),'utf8').replaceAll('\r','').split('\n');
}
if (mode === 's3') {
    machine.push('-drive','file=overlay.qcow2,format=qcow2,if=virtio,cache=none');
    assert(boot('serial.log').includes('POOL_LINUX_REFINEMENT_PASSED'), 'guest checks failed; see serial.log');
    console.log('POOL_LINUX_REFINEMENT_PASSED',join(out,'serial.log'));
} else {
    // The guest formats only this new scratch disk. Keep both disks unchanged while powered off.
    const path = join(out,'swap.raw');
    const swap = openSync(path,'wx',0o600);
    try { ftruncateSync(swap, 1024 ** 3); } finally { closeSync(swap); }
    machine.push('-drive','if=none,id=systemdisk,file=overlay.qcow2,format=qcow2,cache=none',
        '-device','virtio-blk-pci,drive=systemdisk,addr=0x5,bootindex=1',
        '-drive','if=none,id=hibswap,file=swap.raw,format=raw,cache=none',
        '-device','virtio-blk-pci,drive=hibswap,addr=0x6,serial=PathWardS4Swap');
    function signature() {
        const fd = openSync(path,'r');
        try {
            const bytes = Buffer.alloc(10);
            assert.equal(readSync(fd,bytes,0,10,4096-10),10);
            return bytes.toString('ascii');
        } finally { closeSync(fd); }
    }
    for (let cycle=0; cycle<=2; cycle++) {
        const lines = boot('serial-' + cycle + '.log');
        if (cycle > 0) {
            assert(lines.some(s => s.includes('Kernel command line:') && s.includes('resume=/dev/vdb resumewait') &&
                s.includes('root=/dev/pathward-no-root')), 'restore-only kernel did not boot');
            assert(lines.some(s => /PM: hibernation: Read [1-9]\d* kbytes/.test(s)), 'kernel did not read a disk image');
            assert(lines.includes('S4_CONTINUITY trial=' + cycle + ' same_boot_id=true both_workers_alive=true'));
            assert(lines.includes('S4_RESTORED trial=' + cycle), 'hibernated tests did not continue');
        }
        if (cycle < 2) {
            assert(lines.includes('S4_HIBERNATE trial=' + (cycle+1)), 'guest did not request hibernation');
            assert.equal(signature(),'S1SUSPEND\0','Linux swap hibernation image');
            const off = process.hrtime.bigint();
            await delay(7000);
            const elapsed = process.hrtime.bigint() - off;
            assert(elapsed >= 5000000000n);
            console.log('S4_IMAGE trial=%d signature=S1SUSPEND powered_off_ns=%s',cycle+1,elapsed.toString());
        } else {
            assert(lines.includes('POOL_LINUX_S4_PASSED'));
            assert.equal(signature(),'SWAPSPACE2','consumed hibernation image');
        }
    }
    console.log('POOL_LINUX_S4_PASSED',out);
}
