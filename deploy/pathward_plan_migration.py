#!/usr/bin/env python3
"""Same-service recovery-plan handoff and bounded, reboot-fenced guard GC.

Standard library only. CLI callers hold the shared administrator lock. Plans,
kernels and application configuration outside the guard store are never deleted.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('upgrade',Path(__file__).with_name('pathward_guard_upgrade.py'))
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
r=u.r


def read_request(path,expected,kind):
    u.trusted_path(path)
    raw=r.private_bytes(path)
    r.require(hashlib.sha256(raw).hexdigest()==expected,'Request digest mismatch')
    value=r.decode(raw)
    r.require(type(value.get('schema')) is int and value['schema']==1 and value.get('kind')==kind,'Invalid request')
    for key in ['store','units','kernel']:
        r.require(r.absolute(value.get(key)),'Unsafe request path');u.trusted_path(value[key])
    u.boot_storage(Path(value['store']))
    r.require(r.digest_file(value['kernel'])==value['kernel_sha256'],'Policy binary changed')
    return value


def policy(value,mode,*bits):
    reply=r.command([value['kernel'],mode,*[str(int(b)) for b in bits]]).stdout
    r.require(reply in ['ALLOW\n','DENY\n'],'Invalid policy response')
    return reply=='ALLOW\n'


def save_request(path,value):
    u.trusted_path(path)
    if path.exists() or path.is_symlink():
        r.require(r.read_record(path)==value,'Request exists; retry its original apply')
    else:r.write_record(path,value)
    return r.digest_file(path)


def loaded(value,generation):
    for unit,prop in [('pathward-recovery.service','ExecStart'),
                      ('pathward-recovery-fallback.service','ExecStart'),
                      (generation['old_unit'],'ExecStartPre'),(generation['new_unit'],'ExecStartPre')]:
        out=r.command(['systemctl','show',unit,'--property='+prop,'--value']).stdout
        r.require(generation['helper'] in out and generation['plan_sha256'] in out,'Loaded guard differs')


def plan_pair(base,target,store,units):
    old=u.validate_generation(base);new=u.validate_generation(target)
    r.require(base['plan']!=target['plan'] and old['transaction']!=new['transaction'],'Distinct plan and transaction required')
    r.require(all(old[s]['units']==new[s]['units'] for s in ['old','new']),'Service roles cannot change during handoff')
    records=[old['journal'],old['permit'],new['journal'],new['permit']]
    r.require(len(set(records))==4,'Plan records must be disjoint')
    reserved={base['plan'],target['plan'],base['helper'],target['helper'],old['kernel'],new['kernel']}
    for p in [old,new]:
        for side in ['old','new']:reserved.update(p[side]['files']);reserved.add(p[side]['check'][0])
    r.require(not set(records)&reserved,'Record aliases executable or sealed configuration')
    for name in records:
        path=Path(name)
        r.require(not path.is_relative_to(store) and not path.is_relative_to(units),'Records overlap managed guards')
        if name==new['permit'] and not path.parent.exists():
            u.trusted_path(path.parent.parent);u.directory(path.parent)
        u.trusted_path(path)
    r.require(type(new.get('state_seed')) is dict,'Missing target state seed')
    return old,new


def prepare_migration(store,units,plan,plan_sha,candidate,candidate_sha,kernel,kernel_sha,request):
    for path in [store,units,plan,candidate,kernel,request]:
        r.require(r.absolute(str(path)),'Absolute paths required');u.trusted_path(path)
    u.boot_storage(store);u.directory(store);u.directory(units)
    r.require(r.digest_file(kernel)==kernel_sha,'Policy binary changed')
    base=u.current(store);r.require(base is not None and base['epoch']<u.MAX,'Managed guard required')
    u.installed(units,store,base,managed_only=True)
    old=u.validate_generation(base);r.require(u.stable(old,base['plan_sha256']),'Source is not stable')
    side=r.select(old);r.require(side in ['OLD','NEW'],'No selected service')
    module=u.checked_module(candidate,candidate_sha)
    blob=store/'blobs'/(candidate_sha+'.py')
    if blob.exists():r.require(r.digest_file(blob)==candidate_sha,'Conflicting helper')
    else:r.replace_bytes(blob,candidate.read_bytes())
    target=u.generation(base['epoch']+1,u.identity(base),blob,candidate_sha,plan,plan_sha,base['old_unit'],base['new_unit'])
    r.require(target['units']==u.unit_files(blob,plan,plan_sha,base['old_unit'],base['new_unit'],module),'Unsupported unit contract')
    old,new=plan_pair(base,target,store,units)
    r.require(r.verified(new['old']) and r.verified(new[side.lower()]),'Target configuration is not verified')
    record=dict(new['state_seed'],phase=r.journal(old)['phase'],transaction=new['transaction'],
                recovery_plan_sha256=target['plan_sha256'])
    existing=r.read_record(new['journal'])
    r.require(not os.path.lexists(new['journal']) or existing==record,'Target journal already belongs to another operation')
    u.stage(store,target,lambda _:None)
    value={'schema':1,'kind':'migrate','store':str(store),'units':str(units),'kernel':str(kernel),
           'kernel_sha256':kernel_sha,'base':base,'target':target,'side':side,
           'source_journal_sha256':r.digest_file(old['journal']),'target_record':record}
    return save_request(request,value)


def apply_migration(request,expected,checkpoint=lambda _:None):
    value=read_request(request,expected,'migrate');store=Path(value['store']);units=Path(value['units'])
    base,target=value['base'],value['target']
    r.require(target['parent']==u.identity(base),'Wrong parent')
    for g in [base,target]:u.verify_generation(store,g)
    active=u.current(store)
    u.action(value,active,True,True,compatibility=True) # Reject stale identity before touching target records.
    old,new=plan_pair(base,target,store,units)
    u.installed(units,store,base,managed_only=True)
    r.require(r.digest_file(old['journal'])==value['source_journal_sha256'],'Source application changed')
    r.require(value['side'] in ['OLD','NEW'],'Invalid selected service')
    live=old if active==base else new
    r.require(u.stable(live,active['plan_sha256']) and r.select(live)==value['side'],'Active application is not stable')
    path=Path(new['journal'])
    if os.path.lexists(path):r.require(r.read_record(path)==value['target_record'],'Target application changed')
    else:r.write_record(path,value['target_record'],lambda p:checkpoint('journal:'+p))
    permit=r.read_record(new['permit'])
    if os.path.lexists(new['permit']):
        r.require(permit is not None and permit.get('plan_sha256')==target['plan_sha256'] and
                  permit.get('selection')==value['side'],'Foreign target permit')
    r.publish(new,target['plan_sha256'],value['side']);checkpoint('permit_published')
    def agreement():
        return policy(value,'migrate',True,True,
                      u.stable(live,active['plan_sha256']) and r.digest_file(old['journal'])==value['source_journal_sha256'],
                      r.read_record(new['journal'])==value['target_record'] and u.stable(new,target['plan_sha256']),
                      r.select(old)==r.select(new)==value['side'],r.verified(old['old']) and r.verified(new['old']))
    r.require(agreement(),'Plans disagree or are not ready')
    r.command(['systemd-analyze','verify',store/'generations'/u.identity(target)/'pathward-recovery.service',
               store/'generations'/u.identity(target)/'pathward-recovery-fallback.service'])
    choice=u.action(value,u.current(store),True,True,compatibility=agreement())
    if choice=='INSTALL':u.link(store/'current','generations/'+u.identity(target),checkpoint,'migrate')
    else:r.sync_directory(store)
    r.require(u.current(store)==target,'Activation readback failed')
    checkpoint('before_reload');r.command(['systemctl','daemon-reload']);checkpoint('after_reload')
    loaded(value,target)
    return u.completed(store,base,target,checkpoint)


def fence(value):
    store=Path(value['store']);current=u.current(store)
    r.require(current is not None and u.identity(current)==value['current'],'GC request is stale')
    receipt=r.read_record(store/'last-applied.json') or {}
    complete=(receipt.get('target')==value['current'] and receipt.get('base')==current['parent'] and
              receipt.get('epoch')==current['epoch'] and receipt.get('plan_sha256')==current['plan_sha256'])
    boot=receipt.get('boot_id');now=r.BOOT_ID.read_text().strip()
    later=type(boot) is str and bool(re.fullmatch('[0-9a-f-]{36}',boot)) and boot!=now
    u.installed(Path(value['units']),store,current,managed_only=True);loaded(value,current)
    quiet=u.stable(u.validate_generation(current),current['plan_sha256'])
    guarded={'pathward-recovery.service','pathward-recovery-fallback.service'}
    plan=u.validate_generation(current)
    guarded.update(plan['old']['units']);guarded.update(plan['new']['units'])
    quiet=quiet and not r.command(['systemctl','list-jobs','--no-legend','--no-pager',*sorted(guarded)]).stdout.strip()
    r.require(policy(value,'collect',complete,later,quiet,False,True,True),'GC requires completion, a later boot and quiescent verified guards')
    return current


def inventory(store,current,keep):
    generations={}
    for path in sorted((store/'generations').iterdir()):
        if path.name.startswith('.stage-'):continue # Orphans are not promoted or implicitly collected.
        r.require(re.fullmatch('[0-9a-f]{64}',path.name) and not path.is_symlink(),'Unexpected generation member')
        g=r.read_record(path/'manifest.json');r.require(g is not None and u.identity(g)==path.name,'Invalid generation')
        u.verify_generation(store,g);generations[path.name]=g
    roots={u.identity(current),current['parent'],*keep}
    roots.update(k for k,g in generations.items() if g['epoch']>=current['epoch'])
    r.require(roots<=generations.keys(),'Protected generation missing')
    # Conservatively pin explicit managed-store references of every live plan.
    def strings(x):
        if isinstance(x,str):yield x
        elif isinstance(x,dict):
            for k,v in x.items():yield from strings(k);yield from strings(v)
        elif isinstance(x,list):
            for v in x:yield from strings(v)
    blobs=set()
    while True:
        before=set(roots)
        for key in list(roots):
            g=generations[key];blobs.add(g['helper'])
            for s in strings(u.validate_generation(g)):
                if str(store) not in s:continue
                r.require(s.startswith(str(store)+'/'),'Embedded guard-store reference cannot be collected safely')
                p=Path(s);u.trusted_path(p)
                parts=p.relative_to(store).parts
                if len(parts)>=2 and parts[0]=='generations':roots.add(parts[1])
                elif len(parts)==2 and parts[0]=='blobs':blobs.add(str(p))
                else:r.require(False,'Unsupported managed-store reference')
        r.require(roots<=generations.keys(),'Referenced generation missing')
        if roots==before:return generations,roots,blobs


def prepare_gc(store,units,kernel,kernel_sha,request,keep=(),limit=8):
    for p in [store,units,kernel,request]:r.require(r.absolute(str(p)),'Absolute paths required');u.trusted_path(p)
    u.boot_storage(store);r.require(r.digest_file(kernel)==kernel_sha,'Policy binary changed')
    r.require(type(limit) is int and 1<=limit<=8,'GC batch must contain 1..8 generations')
    active=u.current(store);r.require(active is not None,'Managed guard required')
    value={'schema':1,'kind':'gc','store':str(store),'units':str(units),'kernel':str(kernel),
           'kernel_sha256':kernel_sha,'current':u.identity(active),'keep':sorted(set(keep))}
    current=fence(value);all_gen,roots,blobs=inventory(store,current,keep)
    chosen=sorted((k for k,g in all_gen.items() if policy(value,'collect',True,True,True,k in roots,g['epoch']<current['epoch'],True)),key=lambda k:(all_gen[k]['epoch'],k))[:limit]
    retained={g['helper'] for k,g in all_gen.items() if k not in chosen}|blobs
    remove_blobs={all_gen[k]['helper'] for k in chosen}-retained
    value['generations']={k:all_gen[k] for k in chosen};value['blobs']={}
    for name in sorted(remove_blobs):
        path=Path(name)
        if path.parent!=store/'blobs':continue # Never delete original releases or external resources.
        r.require(re.fullmatch('[0-9a-f]{64}\.py',path.name),'Invalid blob name')
        digest=r.digest_file(path);r.require(path.stem==digest,'Invalid helper blob')
        value['blobs'][path.name]=digest
    return save_request(request,value)


def remove_tree(path,generation,checkpoint):
    names={'manifest.json':None,**generation['units']}
    actual={str(p.relative_to(path)) for p in path.rglob('*') if not p.is_dir()}
    r.require(actual<=names.keys() and not any(p.is_symlink() for p in path.rglob('*')),'Foreign trash members')
    for name in sorted(actual):
        member=path/name
        if name=='manifest.json':r.require(r.read_record(member)==generation,'Trash manifest changed')
        else:r.require(r.digest_file(member)==hashlib.sha256(names[name].encode()).hexdigest(),'Trash unit changed')
        member.unlink();checkpoint('gc:unlink:'+name);r.sync_directory(member.parent)
    for child in sorted((p for p in path.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):child.rmdir()
    path.rmdir()


def apply_gc(request,expected,checkpoint=lambda _:None):
    value=read_request(request,expected,'gc');store=Path(value['store']);current=fence(value)
    all_gen,roots,pinned_blobs=inventory(store,current,value['keep'])
    # Missing members may already have been moved/deleted by this same request.
    r.require(set(value['generations']).isdisjoint(roots),'GC candidate became protected')
    for key,g in value['generations'].items():
        r.require(u.identity(g)==key and policy(value,'collect',True,True,True,key in roots,g['epoch']<current['epoch'],True),'Unsafe GC candidate')
        if key in all_gen:r.require(all_gen[key]==g,'GC generation changed')
    surviving={g['helper'] for key,g in all_gen.items() if key not in value['generations']}|pinned_blobs
    r.require(not {str(store/'blobs'/name) for name in value['blobs']}&surviving,'GC helper became referenced')
    for directory in [store/'trash',store/'trash'/expected]:u.directory(directory)
    trash=store/'trash'/expected
    members=[('generations',key,g) for key,g in value['generations'].items()]+[('blobs',key,digest) for key,digest in value['blobs'].items()]
    for kind,key,content in members:
        r.require(bool(re.fullmatch('[0-9a-f]{64}'+('' if kind=='generations' else r'\.py'),key)),'Invalid collection name')
        source=store/kind/key;retired=trash/(kind+'-'+key)
        r.require(not source.is_symlink() and not retired.is_symlink(),'Linked collection member')
        if source.exists():
            r.require(not retired.exists(),'Conflicting trash member')
            if kind=='blobs':r.require(r.digest_file(source)==content,'Helper changed')
            os.rename(source,retired);checkpoint('gc:moved:'+kind)
            r.sync_directory(source.parent);r.sync_directory(trash);checkpoint('gc:move_synced:'+kind)
        if retired.exists():
            # Re-sync both names before resuming a rename interrupted before fsync.
            r.sync_directory(source.parent);r.sync_directory(trash)
            if kind=='generations':remove_tree(retired,content,checkpoint)
            else:r.require(r.digest_file(retired)==content,'Retired helper changed');retired.unlink();checkpoint('gc:blob_unlinked')
            r.sync_directory(trash);checkpoint('gc:removed:'+kind)
    r.require(u.identity(u.current(store))==value['current'],'Current guard changed during GC')
    r.write_record(trash/'complete.json',{'request_sha256':expected,'current':value['current']})
    return {'current':value['current'],'generations':len(value['generations']),'blobs':len(value['blobs'])}


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
    m=sub.add_parser('prepare-migration')
    for name in ['store','units','plan','candidate','kernel','request']:m.add_argument('--'+name,type=Path,required=True)
    for name in ['plan-sha','candidate-sha','kernel-sha']:m.add_argument('--'+name,required=True)
    g=sub.add_parser('prepare-gc')
    for name in ['store','units','kernel','request']:g.add_argument('--'+name,type=Path,required=True)
    g.add_argument('--kernel-sha',required=True);g.add_argument('--keep',action='append',default=[]);g.add_argument('--limit',type=int,default=8)
    for name in ['apply-migration','apply-gc']:
        a=sub.add_parser(name);a.add_argument('--request',type=Path,required=True);a.add_argument('--sha256',required=True)
    a=p.parse_args();r.require(os.uname().sysname=='Linux' and os.geteuid()==0,'Linux administrator required');os.umask(0o077)
    with r.LOCK.open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.mode=='prepare-migration':result=prepare_migration(a.store,a.units,a.plan,a.plan_sha,a.candidate,a.candidate_sha,a.kernel,a.kernel_sha,a.request)
        elif a.mode=='apply-migration':result=apply_migration(a.request,a.sha256)
        elif a.mode=='prepare-gc':result=prepare_gc(a.store,a.units,a.kernel,a.kernel_sha,a.request,a.keep,a.limit)
        else:result=apply_gc(a.request,a.sha256)
        print(a.mode.upper().replace('-','_')+' '+str(result))


if __name__=='__main__':main()
