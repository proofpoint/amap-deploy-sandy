"""Dedicated mixed-connector pilot. Preview first; fleet changes require apply.

Sandy-specific discovery, runtime translation, features and services live here.
The connector only sees configured paths and the launcher-control v1 protocol.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shlex
import shutil
import subprocess
import sys
import time
import uuid

import amap_sandy as deployment
import fleet_policy as fp

HERE=Path(__file__).resolve().parent


def run(argv, *, timeout=30):
    return subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=timeout,check=True).stdout


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, content, mode=0o600):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(content if isinstance(content,bytes) else content.encode()); f.flush(); os.fsync(f.fileno())
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if temporary.exists(): temporary.unlink()


def json_text(value): return json.dumps(value,indent=2,sort_keys=True)+'\n'


def toml_value(value):
    if isinstance(value,str): return json.dumps(value)
    if type(value) is bool: return 'true' if value else 'false'
    if isinstance(value,list): return '['+', '.join(toml_value(v) for v in value)+']'
    if isinstance(value,dict): return '{'+', '.join(json.dumps(k)+' = '+toml_value(v) for k,v in value.items())+'}'
    if type(value) in (int,float): return str(value)
    raise ValueError('unsupported TOML value')


def config_text(config):
    lanes=config['lanes']
    lines=[k+' = '+toml_value(v) for k,v in config.items() if k!='lanes']
    for name,values in lanes.items():
        lines += ['',f'[lanes.{name}]']+[k+' = '+toml_value(v) for k,v in values.items()]
    return '\n'.join(lines)+'\n'


def inventory(sandy):
    return {'version':1,'host_os':platform.system(),'python':sys.version.split()[0],
            'python_executable':sys.executable,'uid':os.getuid(),'gid':os.getgid(),
            'sandy_schema':json.loads(run([sandy,'--print-schema'])),
            'sandboxes':deployment.discover_sandboxes(sandy),
            'docker_context':run(['docker','context','show']).strip(),
            'docker_daemon_id':run(['docker','info','--format','{{.ID}}']).strip()}


def choose(boxes, workspace, kind):
    workspace=str(Path(workspace).expanduser().resolve())
    matches=[b for b in boxes if b['workspace_path'] and str(Path(b['workspace_path']).resolve())==workspace]
    if len(matches)!=1: raise ValueError('workspace must have one Sandy-reported sandbox; provision it normally first')
    box=matches[0]
    if box['agents']!=[kind]: raise ValueError('pilot endpoints must each report exactly the assigned agent')
    return box


def render(home, boxes, c, b, model, codex_src, sandy_src, python, plan_path, schema):
    feature=home/'features'/'amap'
    base=json.loads((feature/'feature.json').read_text())
    if 'submounts' not in schema.get('manifest',{}).get('top_level_keys',[]):
        raise ValueError('Sandy must advertise manifest.top_level_keys submounts')
    policy=fp.load_policy(feature/'feature.json')
    members=deployment.load_membership(home,boxes)
    if b['name'] not in members or c['name'] in members:
        raise ValueError('Claude must already be selected and Codex must be a fresh namespace')
    if any(box['agents']!=['claude'] for box in boxes if box['name'] in members):
        raise ValueError('this first pilot requires existing selected single-Claude sandboxes')
    oldnames=sorted(members)
    graph=fp.resolve_task_graph(policy,oldnames)
    peers=fp.resolve_peers(policy,oldnames,members)
    graph={k:sorted(v) for k,v in graph.items()}
    graph.setdefault(b['name'],[]).append(c['name']); graph[c['name']]=[b['name']]
    policy.update(task_graph=graph,peers={**{k:sorted(v) for k,v in peers.items()},c['name']:[]},
                  default_peers=[],groups={})
    policy['sandboxes']={'include':oldnames+[c['name']],'exclude':[]}
    policy['agents']={'include':['claude','codex'],'exclude':[]}
    common=deployment.render_manifest(policy,receives=True)
    common.pop('entry',None)
    common['create'] += ['instances/${slug}/outbox/ext','instances/${slug}/outbox/ext/codex','codex-runtime/${slug}']
    common['mounts'].append({'name':'codex-home','from':'codex-runtime/${slug}','mode':'rw','export':'AMAP_CODEX_HOME'})
    common['submounts']=[{'parent':'outbox','path':name,'from':f'instances/${{slug}}/outbox/{name}'} for name in ('results','processed')]
    common['submounts'] += [
        {'parent':'outbox','path':'ext','from':'payload/codex/empty','agents':['codex']},
        {'parent':'codex-home','path':'config.toml','from':'payload/codex/configs/${slug}.toml','agents':['codex']}]
    legacy={'schema':1,'sandboxes':{'include':oldnames,'exclude':[b['name']]},
            'agents':{'include':['claude'],'exclude':['codex']},
            'mounts':[{'name':'payload','from':'payload','mode':'ro'}],'entry':'payload/relay'}
    updated_members={**members,c['name']:{'source':'reviewed-pilot'}}
    router_before=json.loads((feature/'router.json').read_text())
    router=deployment.render_router_sibling(policy,updated_members,home,Path(router_before['state_dir']))['_doc']
    router['connector_outcome_ids']=['claude-code','codex']
    if router['state_dir']!=router_before['state_dir']: raise ValueError('router state must stay unchanged')
    private=home/'amap-controllers'
    owner_domain='host:'+hashlib.sha256((platform.node()+':'+str(os.getuid())+':'+str(home.resolve())).encode()).hexdigest()[:32]
    outputs={str(feature/'feature.json'):json_text(common),
             str(home/'features'/'amap-claude'/'feature.json'):json_text(legacy),
             str(feature/'router.json'):json_text(router)}
    sources={}
    # Snapshot the current immutable Claude payload for its new feature entry.
    for source in sorted((feature/'payload').rglob('*')):
        if source.is_file(): sources[str(home/'features'/'amap-claude'/'payload'/source.relative_to(feature/'payload'))]=str(source)
    for name in ('inbox-mcp-vol','inbox-submit','_inboxlib.py'):
        sources[str(feature/'payload'/'codex'/'bin'/name)]=str(codex_src/'bin'/name)
    sources[str(feature/'payload'/'codex'/'operator-instructions.md')]=str(codex_src/'config'/'operator-instructions.md')
    sources[str(feature/'payload'/'managed_exec.py')]=str(sandy_src/'managed_exec.py')
    instances={}
    for kind,box in [('codex',c),('claude',b)]:
        slug=box['name']; root=private/slug
        controller={'instance_id':slug,'self_address':slug+'@'+policy['fleet_domain'],
                    'launch_argv':[python,str(HERE/'codex_pilot.py'),'--plan',str(plan_path),'launch','--kind',kind],
                    'launcher_control_argv':[python,str(HERE/'codex_pilot.py'),'--plan',str(plan_path),'control','--kind',kind],
                    'deployment_id':'amap:'+slug,'owner_domain':owner_domain,
                    'launcher_control_timeout_seconds':15,'state_dir':str(root),
                    'codex_model':model,'codex_version':'codex-cli 0.160.1','cwd':'/workspace',
                    'sandbox':'workspace-write','approval_policy':'never',
                    'operator_instructions':str(feature/'payload'/'codex'/'operator-instructions.md'),
                    'outcome_idempotent_replay':False,'operator_kickoff_enabled':kind=='codex',
                    'lanes':{lane:{'notice_dir':str(feature/'instances'/slug/tree/'notices'),
                                   'message_dir':str(feature/'instances'/slug/tree/'messages'),
                                   'claim_path':str(root/(lane+'.claim.json'))} for lane,tree in [('mail','inbox'),('peer','peer')]}}
        if kind=='codex': controller['outcome_dir']=str(feature/'instances'/slug/'outbox'/'ext'/'codex'/'outcomes')
        target=root/'controller.toml'; outputs[str(target)]=config_text(controller)
        # The sandbox working directory is learned at launch; thread start uses
        # the same value from the trusted binding, rendered before the service.
        instances[kind]={'slug':slug,'workspace':box['workspace_path'],'sandbox_path':box['path'],
                         'state_dir':str(root),'controller_config':str(target),'deployment_id':'amap:'+slug}
    preimages={path:(sha(path) if Path(path).is_file() else None) for path in outputs}
    registry=home/'amap-codex-pilot.json'
    outputs[str(registry)]=json_text({'version':1,'plan':str(plan_path)})
    preimages[str(registry)]=sha(registry) if registry.is_file() else None
    dependency_files=[*sorted((codex_src/'src'/'amap_codex').glob('*.py')),
                      codex_src/'pyproject.toml',HERE/'codex_pilot.py',HERE/'amap_sandy.py',
                      HERE/'fleet_policy.py',sandy_src/'managed_exec.py']
    return {'version':1,'home':str(home),'sandy':str(sandy_src/'sandy'),'python':python,
            'model':model,'codex_src':str(codex_src),'owner_domain':owner_domain,
            'instances':instances,'outputs':outputs,'sources':sources,
            'source_hashes':{dst:sha(src) for dst,src in sources.items()},'preimages':preimages,
            'dependency_hashes':{str(path):sha(path) for path in dependency_files if path.is_file()},
            'directories':[str(feature/'payload'/'codex'/'empty')],
            'old_members':oldnames,'future_members':'frozen explicit membership; re-plan enrollment',
            'router_state':router['state_dir'],'plan_path':str(plan_path)}


def load_plan(path):
    path=Path(path)
    if path.is_symlink() or path.stat().st_uid!=os.getuid() or path.stat().st_mode & 0o022:
        raise ValueError('plan must be operator-owned and not group/world writable')
    doc=json.loads(path.read_text())
    if doc.get('version')!=1: raise ValueError('unsupported plan')
    return doc


def current_container(workspace):
    ids=run(['docker','ps','--no-trunc','-q','--filter','label=sandy.daemon=true',
             '--filter','label=sandy.workspace_path='+workspace]).split()
    if len(ids)!=1: raise ValueError('one labelled running Sandy container required')
    cid=ids[0]
    if len(cid)!=64: raise ValueError('full container identity required')
    return cid


def container_identity(cid, expected_slug):
    script='import json,pwd,os; s=json.load(open("/etc/sandy-session.json")); p=pwd.getpwuid(int(os.environ["PILOT_UID"])); print(json.dumps({"home":p.pw_dir,"cwd":s["workspace"],"slug":s["sandbox_name"]}))'
    result=json.loads(run(['docker','exec','-u','0','-e','PILOT_UID='+str(os.getuid()),cid,'python3','-c',script]))
    if result['slug']!=expected_slug: raise ValueError('runtime sandbox identity mismatch')
    return result


def codex_config(home,slug,domain,model,cwd):
    root=home+'/.amap'
    reader='/opt/sandy/features/amap/codex/bin/inbox-mcp-vol'
    servers={name:{'command':reader,'required':True,'enabled_tools':['list_messages','read_message','read_attachment'],
                   'default_tools_approval_mode':'approve','env':{'INBOX_MESSAGE_DIR':root+'/'+tree+'/messages','INBOX_LANE':lane}}
             for name,tree,lane in [('inbox','inbox','mail'),('delegation','peer','peer')]}
    servers['inbox_submit']={'command':'/opt/sandy/features/amap/codex/bin/inbox-submit','args':['mcp'],'required':True,
                             'enabled_tools':['submit','submit_result','peers'],'default_tools_approval_mode':'approve',
                             'env':{'OUTBOX_DIR':root+'/outbox','AMAP_ROSTER_DIR':root+'/roster','AMAP_SELF':slug+'@'+domain}}
    return '\n'.join(k+' = '+toml_value(v) for k,v in {'model':model,'sandbox_mode':'workspace-write','approval_policy':'never','model_reasoning_effort':'low',
        'sandbox_workspace_write':{'writable_roots':[cwd],'network_access':False},'mcp_servers':servers}.items())+'\n'


def prepare_runtime_config(plan,kind):
    instance=plan['instances'][kind]; cid=current_container(instance['workspace'])
    identity=container_identity(cid,instance['slug'])
    # Before the new projection is launched, inspect the existing/provisioned
    # sandbox marker. No model is invoked and no fleet file is written here.
    import tomllib
    text=plan['outputs'][instance['controller_config']]
    config=tomllib.loads(text); config['cwd']=identity['cwd']
    plan['outputs'][instance['controller_config']]=config_text(config)
    if kind=='codex':
        domain=config['self_address'].split('@',1)[1]
        path=Path(plan['home'])/'features'/'amap'/'payload'/'codex'/'configs'/(instance['slug']+'.toml')
        plan['outputs'][str(path)]=codex_config(identity['home'],instance['slug'],domain,plan['model'],identity['cwd'])
        plan['preimages'][str(path)]=sha(path) if path.is_file() else None
        config['trusted_config_file']=str(path)
        plan['outputs'][instance['controller_config']]=config_text(config)
    instance['container_identity']=identity


def apply_plan(plan):
    for path,expected in plan['dependency_hashes'].items():
        if sha(path)!=expected: raise ValueError('dependency changed since preview: '+path)
    for path,prior in plan['preimages'].items():
        actual=sha(path) if Path(path).is_file() else None
        if actual!=prior and (not Path(path).is_file() or Path(path).read_text()!=plan['outputs'][path]):
            raise ValueError('host state changed since preview: '+path)
    for dst,src in plan['sources'].items():
        if sha(src)!=plan['source_hashes'][dst]: raise ValueError('dependency source changed: '+src)
    backup=Path(plan['plan_path']).parent/'rollback'; backup.mkdir(mode=0o700,exist_ok=True)
    manifest=backup/'manifest.json'
    if not manifest.exists():
        saved=[]
        for index,(path,content) in enumerate(plan['outputs'].items()):
            target=Path(path); prior=plan['preimages'][path]
            if prior is not None:
                if not target.is_file() or sha(target)!=prior:
                    raise ValueError('original rollback preimage unavailable: '+path)
                write(backup/str(index),target.read_bytes())
            saved.append({'path':path,'backup':str(index) if prior is not None else None,
                          'applied_sha256':hashlib.sha256(content.encode()).hexdigest()})
        write(manifest,json_text(saved))
    for directory in plan['directories']: Path(directory).mkdir(parents=True,exist_ok=True)
    for instance in plan['instances'].values():
        root=Path(instance['state_dir']); root.mkdir(mode=0o700,parents=True,exist_ok=True)
        if root.stat().st_mode & 0o077: raise ValueError('controller state must be private')
        (root/'bindings').mkdir(mode=0o700,exist_ok=True)
    for dst,src in plan['sources'].items():
        write(dst,Path(src).read_bytes(),0o755 if os.access(src,os.X_OK) else 0o644)
    for path,content in plan['outputs'].items(): write(path,content,0o600 if 'controller.toml' in path else 0o644)
    print(json_text({'applied':True,'services_started':False,'router_state_preserved':plan['router_state']}))


def rollback(plan):
    # Both canonical services must be stopped and positive runtime cleanup must
    # have completed. Retain journals, bindings, spools and runtime homes.
    locks=[]
    try:
        for instance in plan['instances'].values():
            fd=os.open(Path(instance['state_dir'])/'controller.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            locks.append(fd); fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            record=Path(instance['state_dir'])/'process.json'
            if record.exists():
                execution=json.loads(record.read_text())['execution_id']
                result=subprocess.run([plan['python'],str(HERE/'codex_pilot.py'),'--plan',plan['plan_path'],
                    'control','--kind','codex' if instance is plan['instances']['codex'] else 'claude','inspect'],
                    input=json.dumps({'version':1,'deployment_id':instance['deployment_id'],'execution_id':execution}),
                    capture_output=True,text=True,timeout=18,check=True)
                if json.loads(result.stdout)['state']!='stopped': raise ValueError('positive cleanup required')
        backup=Path(plan['plan_path']).parent/'rollback'
        entries=json.loads((backup/'manifest.json').read_text())
        for entry in entries:
            target=Path(entry['path'])
            if target.exists() and sha(target)!=entry['applied_sha256']:
                raise ValueError('rollback target changed: '+str(target))
        for entry in entries:
            target=Path(entry['path'])
            if entry['backup'] is None:
                if target.exists(): target.unlink()
            else: write(target,(backup/entry['backup']).read_bytes(),0o644)
        print(json_text({'restored':True,'services_started':False,'journals_and_router_state_preserved':True}))
    finally:
        for fd in locks: os.close(fd)


def router_inventory(plan,source,name):
    doc=json.loads(run(['docker','inspect',name]))[0]
    config=str(Path(plan['home'])/'features'/'amap'/'router.json')
    mounted={m['Source']:m for m in doc['Mounts']}
    if config not in mounted or mounted[config]['Destination']!=config:
        raise ValueError('router must mount this deployment config at its host path')
    if doc['HostConfig']['NetworkMode']!='none' or doc['Config'].get('User')!=str(os.getuid())+':'+str(os.getgid()):
        raise ValueError('router runtime differs from the supported run.sh contract; review explicitly')
    environment=dict(item.split('=',1) for item in doc['Config'].get('Env',[]) if '=' in item)
    interval=environment.get('ROUTER_INTERVAL','5')
    if not 0<float(interval)<float('inf'): raise ValueError('invalid router interval')
    plan['router_runtime']={'container_id':doc['Id'],'name':doc['Name'].lstrip('/'),
        'image':doc['Config']['Image'],'interval':interval,'source':str(source.resolve()),'config':config}
    plan['dependency_hashes'][str(source/'router'/'config.py')]=sha(source/'router'/'config.py')
    plan['dependency_hashes'][str(source/'router'/'outcomes.py')]=sha(source/'router'/'outcomes.py')


def isolation_probe(plan):
    checks=[]
    for kind,instance in plan['instances'].items():
        cid=current_container(instance['workspace']); identity=container_identity(cid,instance['slug'])
        root=identity['home']+'/.amap'
        suffix='.isolation-probe-'+uuid.uuid4().hex
        paths=[]; fixtures=[]
        for tree in ('results','processed'):
            host=Path(plan['home'])/'features'/'amap'/'instances'/instance['slug']/'outbox'/tree/suffix
            host.mkdir(mode=0o755)
            file=host/'fixture'; file.write_text('probe'); fixtures.append(host)
            paths.append(root+'/outbox/'+tree+'/'+suffix+'/fixture')
        if kind=='codex': paths.append(root+'/codex-home/config.toml')
        script="""import json,os,sys
checks=[]
for path in sys.argv[1:]:
 try:
  fd=os.open(path,os.O_WRONLY); os.close(fd); denied=False
 except OSError: denied=True
 checks.append({'path':path,'operation':'open_write','denied':denied})
 if '/.isolation-probe-' in path:
  for operation,call in [('rename',lambda:os.rename(path,path+'.moved')),('chmod',lambda:os.chmod(path,0o600)),('replace',lambda:os.symlink('/tmp',path+'.link'))]:
   try: call(); denied=False
   except OSError: denied=True
   checks.append({'path':path,'operation':operation,'denied':denied})
print(json.dumps(checks))
"""
        try:
            result=json.loads(run(['docker','exec','-u',str(os.getuid())+':'+str(os.getgid()),cid,
                'python3','-c',script,*paths]))
            checks.extend({'name':kind+':'+r['operation']+':'+r['path'],
                           'result':'PASS' if r['denied'] else 'FAIL'} for r in result)
            if kind=='codex':
                script="import os; p=os.environ['P']; denied=False\ntry: fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.close(fd)\nexcept OSError: denied=True\nprint('denied' if denied else 'writable')"
                result=run(['docker','exec','-u',str(os.getuid())+':'+str(os.getgid()),'-e',
                    'P='+root+'/outbox/ext/'+suffix,cid,'python3','-c',script]).strip()
                checks.append({'name':'codex:outcome extension shadow','result':'PASS' if result=='denied' else 'FAIL'})
        finally:
            for fixture in fixtures: shutil.rmtree(fixture)
        mounts=json.loads(run(['docker','inspect',cid]))[0]['Mounts']
        private=Path(plan['home'])/'amap-controllers'
        forbidden=[]
        for mount in mounts:
            source=Path(mount['Source'])
            if private.is_relative_to(source) or source.is_relative_to(private) or 'docker.sock' in str(source): forbidden.append(str(source))
            instances=Path(plan['home'])/'features'/'amap'/'instances'
            if instances.is_relative_to(source): forbidden.append(str(source))
        checks.append({'name':kind+':private state and fleet roots absent','result':'FAIL' if forbidden else 'PASS'})
    print(json_text({'checks':checks,'passed':all(c['result']=='PASS' for c in checks)}))
    return 0 if all(c['result']=='PASS' for c in checks) else 1


def binding_path(instance, execution):
    import re
    if not re.fullmatch(r'[a-f0-9]{32}',execution): raise ValueError('invalid execution ID')
    return Path(instance['state_dir'])/'bindings'/(execution+'.json')


def launch(plan,kind):
    instance=plan['instances'][kind]; execution=os.environ['AMAP_EXECUTION_ID']
    if os.environ.get('AMAP_DEPLOYMENT_ID')!=instance['deployment_id']: raise ValueError('launch binding mismatch')
    # Enforce the shared guard on every supported launcher route.
    for lane in ('mail','peer'):
        guard=json.loads((Path(instance['state_dir'])/(lane+'.claim.json')).read_text())
        if guard.get('execution_id')!=execution or guard.get('owner_domain')!=plan['owner_domain']:
            raise ValueError('canonical host guard required')
        os.kill(guard['pid'],0)
    path=binding_path(instance,execution)
    if path.exists(): raise ValueError('execution identity reused')
    cid=current_container(instance['workspace']); identity=container_identity(cid,instance['slug'])
    if identity!=instance['container_identity']: raise ValueError('sandbox paths changed; re-plan required')
    daemon=run(['docker','info','--format','{{.ID}}']).strip()
    record={'container_id':cid,'daemon_id':daemon,'deployment_id':instance['deployment_id'],'execution_id':execution}
    lock=os.open(path.with_suffix('.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if path.exists(): raise ValueError('execution identity used or revoked')
        write(path,json_text(record))  # committed before remote spawn
    finally: os.close(lock)
    helper='/opt/sandy/features/amap/managed_exec.py'
    argv=['docker','exec','-i','-u','0',cid,'python3',helper,'launch','--namespace',instance['deployment_id'],
          '--execution-id',execution,'--uid',str(os.getuid()),'--gid',str(os.getgid()),
          '--home',identity['home'],'--cwd',identity['cwd']]
    if kind=='codex':
        runtime=identity['home']+'/.amap/codex-home'
        # Provision auth once using the agent identity; neither file is logged.
        copy='import os,shutil; a=os.environ["HOME"]+"/.codex/auth.json"; b=os.environ["RUNTIME"]+"/auth.json"; shutil.copyfile(a,b) if os.path.isfile(a) and not os.path.exists(b) else None; os.chmod(b,0o600) if os.path.exists(b) else None'
        run(['docker','exec','-u',str(os.getuid())+':'+str(os.getgid()),'-e','HOME='+identity['home'],
             '-e','RUNTIME='+runtime,cid,'python3','-c',copy])
        argv += ['--env','CODEX_HOME='+runtime,'--','codex','app-server','--listen','stdio://']
    else:
        argv += ['--','/opt/sandy/features/amap/relay']
    os.execvp(argv[0],argv)


def control(plan,kind,verb):
    request=json.loads(sys.stdin.buffer.read(65537))
    instance=plan['instances'][kind]
    if set(request)!={'version','deployment_id','execution_id'} or type(request['version']) is not int or request['version']!=1 or request['deployment_id']!=instance['deployment_id']:
        raise ValueError('invalid control request')
    path=binding_path(instance,request['execution_id'])
    state='unknown'
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=os.open(path.with_suffix('.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if not path.exists() and verb=='stop':
            write(path,json_text({'revoked':True}))
        record=json.loads(path.read_text()) if path.exists() else None
    finally: os.close(lock)
    if record and record.get('revoked'): state='stopped'
    elif record:

        daemon=run(['docker','info','--format','{{.ID}}']).strip()
        if daemon==record['daemon_id']:
            present=run(['docker','ps','-a','--no-trunc','-q','--filter','id='+record['container_id']]).split()
            if not present: state='stopped'
            else:
                status=json.loads(run(['docker','inspect',record['container_id']]))[0]['State']
                if not status.get('Running'): state='stopped'
                else:
                    result=json.loads(run(['docker','exec','-u','0',record['container_id'],'python3',
                        '/opt/sandy/features/amap/managed_exec.py',verb,'--namespace',instance['deployment_id'],
                        '--execution-id',request['execution_id']],timeout=12))
                    if result.get('execution_id')==request['execution_id']: state=result['state']
    print(json.dumps({**request,'state':state}))


def service(plan,kind):
    instance=plan['instances'][kind]
    label='org.amap.controller.'+instance['slug']
    argv=[plan['python'],'-m','amap_codex.cli','--config',instance['controller_config'],
          'run' if kind=='codex' else 'guard-command']
    if platform.system()=='Darwin':
        return label,plistlib.dumps({'Label':label,'ProgramArguments':argv,'RunAtLoad':True,'KeepAlive':True,
            'ThrottleInterval':10,'StandardOutPath':instance['state_dir']+'/service.stdout.log',
            'StandardErrorPath':instance['state_dir']+'/service.stderr.log',
            'EnvironmentVariables':{'PATH':os.environ['PATH']}})
    return label,('[Unit]\nDescription=AMAP isolated controller\n[Service]\nExecStart='+
                  ' '.join('"'+a.replace('%','%%').replace('\\','\\\\').replace('"','\\"')+'"' for a in argv)+
                  '\nRestart=on-failure\nRestartSec=10\n[Install]\nWantedBy=default.target\n').encode()


def roundtrip(plan,direction,run_id):
    import re
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}',run_id): raise ValueError('invalid run ID')
    directory=Path(plan['plan_path']).parent/'evidence'/run_id
    if directory.exists(): raise ValueError('run ID already prepared; inspect its evidence instead of resending')
    sender='codex' if direction=='codex-claude' else 'claude'
    receiver='claude' if sender=='codex' else 'codex'
    instance=plan['instances'][sender]
    cid=current_container(instance['workspace']); identity=container_identity(cid,instance['slug'])
    marker='AMAP_PILOT_'+run_id+'_'+uuid.uuid4().hex
    content=(marker+'\n').encode()
    attachment=identity['cwd']+'/amap-pilot-'+run_id+'.txt'
    script='import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_bytes(bytes.fromhex(sys.argv[2]))'
    run(['docker','exec','-u',str(os.getuid())+':'+str(os.getgid()),cid,'python3','-c',script,attachment,content.hex()])
    import tomllib
    target=tomllib.loads(plan['outputs'][plan['instances'][receiver]['controller_config']])['self_address']
    instructions=(f'Operator-authorized synthetic AMAP round trip {run_id}. Send exactly one peer request to {target} '
        f'with subject AMAP {run_id} and attachment path {attachment}. Ask the receiver to call delegation.read_message '
        'and delegation.read_attachment, read the bytes and reply once with the attachment marker and SHA-256 reported '
        'by that tool. Both agents must call the MCP submit_result tool and check the runtime accepted result. '
        'A queued receipt is insufficient. The receiver replies to runtime-asserted peer_from with in_reply_to equal '
        'to peer_message_id. Keep the run ID in both subjects. Consume the reply and finish without an acknowledgment. '
        'No extra sends, no task_id submit argument, no direct spool writes. Report the two actual request/message IDs.')
    directory.mkdir(mode=0o700,parents=True)
    write(directory/'fixture.json',json_text({'run_id':run_id,'direction':direction,'marker':marker,
        'sha256':hashlib.sha256(content).hexdigest(),'bytes':len(content),'attachment':attachment,'created_at':time.time()}))
    write(directory/'kickoff.txt',instructions+'\n')
    if sender=='codex':
        print(run([plan['python'],'-m','amap_codex.cli','--config',instance['controller_config'],
            'kickoff',run_id,'--instructions-file',directory/'kickoff.txt']))
    else:
        print('Paste this operator instruction into the existing Claude session:\n'+instructions)
    print('Evidence directory: '+str(directory))


def check_roundtrip(plan,run_id):
    import re
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,99}',run_id): raise ValueError('invalid run ID')
    directory=Path(plan['plan_path']).parent/'evidence'/run_id
    fixture=json.loads((directory/'fixture.json').read_text())
    requests=[]
    for kind,instance in plan['instances'].items():
        outbox=Path(plan['home'])/'features'/'amap'/'instances'/instance['slug']/'outbox'
        for path in (outbox/'processed').glob('req-*.json'):
            doc=json.loads(path.read_text()); draft=doc.get('draft',{})
            if 'AMAP '+run_id not in draft.get('subject',''): continue
            req_id=doc['req_id']; result_path=outbox/'results'/(req_id+'.json')
            result=json.loads(result_path.read_text()) if result_path.is_file() else {}
            requests.append({'kind':kind,'req_id':req_id,'draft':draft,'result':result})
    checks=[]
    checks.append({'name':'exactly one request from each endpoint','result':'PASS' if len(requests)==2 and {r['kind'] for r in requests}=={'codex','claude'} else 'FAIL'})
    checks.append({'name':'both runtime submissions accepted','result':'PASS' if len(requests)==2 and all(r['result'].get('outcome')=='accepted' for r in requests) else 'FAIL'})
    first=next((r for r in requests if not r['draft'].get('reply_to_message_id')),None)
    reply=next((r for r in requests if r['draft'].get('reply_to_message_id')),None)
    checks.append({'name':'reply binds original peer message ID','result':'PASS' if first and reply and reply['draft']['reply_to_message_id']==first['result'].get('message_id') else 'FAIL'})
    checks.append({'name':'reply contains fixture marker and hash','result':'PASS' if reply and all(x in reply['draft'].get('body_text','') for x in (fixture['marker'],fixture['sha256'])) else 'FAIL'})
    checks.append({'name':'attachment-read traces and final reply consumption','result':'UNKNOWN','detail':'retain actual tool traces from both sessions and the receiving turn association'})
    checks.append({'name':'two idle polling cycles without another send','result':'UNKNOWN','detail':'repeat this check after two configured polls; archive both observations'})
    report={'run_id':run_id,'checks':checks,'requests':[{k:r[k] for k in ('kind','req_id','result')} for r in requests],
            'demonstration_complete':False}
    write(directory/'router-evidence.json',json_text(report)); print(json_text(report))
    return 0 if all(c['result']=='PASS' for c in checks[:4]) else 1


def operator_runbook(plan):
    q=shlex.quote
    cli=q(plan['python'])+' '+q(str(HERE/'codex_pilot.py'))+' --plan '+q(plan['plan_path'])
    c,b=plan['instances']['codex'],plan['instances']['claude']
    sandy=q(plan['sandy']); python=q(plan['python'])
    services=Path(plan['plan_path']).parent/'services'
    router=plan.get('router_runtime')
    config=lambda instance:q(instance['controller_config'])
    core=lambda instance:python+' -m amap_codex.cli --config '+config(instance)
    lines=['# Operator commands for the dedicated Codex pilot','',
        'Review and merge the prerequisite PRs yourself. This runbook performs no merges.',
        'Run engineering checks before these fleet actions. Retain the baseline fleet verification,',
        'router state and original container identities. Membership is frozen to this reviewed plan.',
        '', '## Apply the reviewed deployment','', '```bash',cli+' apply',
        sandy+' --stop --workspace '+q(b['workspace']),sandy+' --stop --workspace '+q(c['workspace']),
        sandy+' --start --workspace '+q(b['workspace'])+' --agent claude',
        sandy+' --start --workspace '+q(c['workspace'])+' --agent codex', '```','',
        'Stopping the original Claude container establishes the legacy relay cleanup gate.',
        '', '## Verify the isolation and Codex configuration','', '```bash',
        cli+' isolation-probe',core(c)+' doctor',core(c)+' doctor --probe',cli+' services --output '+q(str(services)), '```','',
        'Run the actual agent-uid mutation probes for results, processed, ext and config.toml.',
        'Confirm there is no engine socket, host journal, writable alias or other namespace mounted.',
        'The doctor probe checks the pinned build and effective MCP registry; it sends no messages.',
        '', '## Start the two host controllers','']
    if router:
        commands=['IMAGE='+q(router['image'])+' '+q(str(Path(router['source'])/'docker'/'build.sh')),
                  'docker stop '+q(router['container_id']),
                  'docker rm '+q(router['container_id']),
                  q(str(Path(router['source'])/'docker'/'run.sh'))+' --config '+q(router['config'])+
                  ' --image '+q(router['image'])+' --name '+q(router['name'])+' --interval '+q(router['interval'])+' --detach',
                  python+' -c '+q('from pathlib import Path; p=Path('+repr(plan['router_state'])+')/'+repr(c['slug'])+'/"first-seen.json"; assert p.is_file(), "wait for first router poll"')]
        index=lines.index('## Verify the isolation and Codex configuration')
        lines[index:index]=['## Replace the recorded router container','',
            'Retain the state directory. These commands target the inventoried full container ID.',
            'Run once; if the identity has changed, re-inventory before replacement.','',
            '```bash',*commands,'```','']
    if platform.system()=='Darwin':
        lines += ['```bash','mkdir -p "$HOME/Library/LaunchAgents"']
        for instance in (b,c):
            label='org.amap.controller.'+instance['slug']; basename=label+'.plist'
            lines += ['install -m 600 '+q(str(services/basename))+' "$HOME/Library/LaunchAgents/'+basename+'"',
                      'launchctl bootstrap gui/'+str(os.getuid())+' "$HOME/Library/LaunchAgents/'+basename+'"']
        lines += ['```']
    else:
        lines += ['```bash','mkdir -p "$HOME/.config/systemd/user"']
        for instance in (b,c):
            basename='org.amap.controller.'+instance['slug']+'.service'
            lines += ['install -m 600 '+q(str(services/basename))+' "$HOME/.config/systemd/user/'+basename+'"']
        lines += ['systemctl --user daemon-reload']
        lines += ['systemctl --user enable --now '+q('org.amap.controller.'+i['slug']+'.service') for i in (b,c)]
        lines += ['```']
    lines += ['', '```bash',core(c)+' status',cli+' verify','```','',
        'Verification reports configuration/runtime checks separately from pending live gates.',
        'In the existing Claude session, confirm exactly one delivery target and the effective AMAP tools.',
        '', '## Run both directions','', '```bash',cli+' roundtrip --direction codex-claude --run-id R1',
        cli+' check-roundtrip --run-id R1',cli+' roundtrip --direction claude-codex --run-id R2',
        cli+' check-roundtrip --run-id R2','```','',
        'The Claude-initiated command prints an operator instruction to paste into the existing Claude session.',
        'Run each evidence check after its reply settles. Keep attachment-read tool traces and the terminal',
        'receiving turn evidence; router acceptance alone leaves those checks UNKNOWN. Observe two idle polls',
        'with no additional send. Reusing a prepared run ID never queues another kickoff.',
        '', '## Recovery and rollback','',
        'Stop only the affected controller service. For a host-controller crash, acquire cleanup through:',
        '', '```bash',core(c)+' cleanup --stop',core(c)+' status','```','',
        'Unknown cleanup remains blocked. If the root execution supervisor was killed, stop the exact recorded',
        'container through Sandy and verify its termination before restarting. Retain the journal and runtime home.',
        '', 'After stopping both host services and completing cleanup for both endpoints:',
        '', '```bash',core(b)+' cleanup --stop',cli+' rollback','```','',
        'Rollback restores the retained feature/router manifests, removing only the',
        'two new policy edges and Codex selection, and recreate the affected sandbox after positive cleanup.',
        'Restore Claude activation once; never run both the feature entry and the host guard service.',
        'Preserve all router state, first-sight markers, spools and uncertainty evidence.']
    return '\n'.join(lines)+'\n'


def verify(plan, *, fleet=False):
    checks=[]
    for path,expected in plan['outputs'].items():
        checks.append({'name':path,'result':'PASS' if Path(path).is_file() and Path(path).read_text()==expected else 'FAIL'})
    for dst,expected in plan['source_hashes'].items():
        checks.append({'name':dst,'result':'PASS' if Path(dst).is_file() and sha(dst)==expected else 'FAIL'})
    for kind,instance in plan['instances'].items():
        try:
            cid=current_container(instance['workspace']); info=container_identity(cid,instance['slug'])
            mounts=json.loads(run(['docker','inspect',cid]))[0]['Mounts']
            root=info['home']+'/.amap'
            expected={root+'/inbox':False,root+'/peer':False,root+'/outbox':True,
                      root+'/outbox/results':False,root+'/outbox/processed':False}
            if kind=='codex': expected.update({root+'/outbox/ext':False,root+'/codex-home/config.toml':False})
            actual={m['Destination']:m['RW'] for m in mounts}
            for target,writable in expected.items():
                checks.append({'name':kind+':'+target,'result':'PASS' if actual.get(target) is writable else 'FAIL'})
            status_path=Path(instance['state_dir'])/'status.json'
            status=json.loads(status_path.read_text())
            os.kill(status['supervisor_pid'],0)
            checks.append({'name':kind+':controller','result':'PASS' if status.get('claim_state')=='held' and (kind!='codex' or status.get('thread_id')) else 'FAIL'})
            for lane in ('mail','peer'):
                claim=json.loads((Path(instance['state_dir'])/(lane+'.claim.json')).read_text())
                request={'version':1,'deployment_id':instance['deployment_id'],'execution_id':claim['execution_id']}
                output=subprocess.run([plan['python'],str(HERE/'codex_pilot.py'),'--plan',plan['plan_path'],'control','--kind',kind,'inspect'],
                    input=json.dumps(request),capture_output=True,text=True,timeout=18,check=True)
                state=json.loads(output.stdout)['state']
                checks.append({'name':kind+':'+lane+':execution','result':'PASS' if state=='running' else 'FAIL'})
        except Exception as exc: checks.append({'name':kind+':runtime','result':'UNKNOWN','detail':type(exc).__name__})
    if fleet:
        checks.append({'name':'whole-fleet acceptance','result':'UNKNOWN',
                       'detail':'pilot checks cover two endpoints; retain other-Claude, router/admission, inference and recovery observations'})
    print(json_text({'checks':checks,'configuration_and_runtime_checks_passed':all(c['result']=='PASS' for c in checks),
                     'rollout_ready':False,
                     'remaining_live_gates':'agent-uid mutation probes, router admission, startup inference, round trips and recovery'}))
    return 0 if all(c['result']=='PASS' for c in checks) else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path)
    parser.add_argument('--sandy-home',type=Path,default=Path.home()/'.sandy')
    parser.add_argument('--sandy',default='sandy')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('inventory')
    prepare=sub.add_parser('prepare')
    for name in ('codex-workspace','claude-workspace','codex-src','sandy-src','output','model'):
        prepare.add_argument('--'+name,required=True)
    prepare.add_argument('--router-src',type=Path,required=True)
    prepare.add_argument('--router-container',required=True)
    sub.add_parser('apply')
    sub.add_parser('rollback')
    sub.add_parser('isolation-probe')
    launch_parser=sub.add_parser('launch'); launch_parser.add_argument('--kind',choices=['codex','claude'],required=True)
    control_parser=sub.add_parser('control'); control_parser.add_argument('--kind',choices=['codex','claude'],required=True)
    control_parser.add_argument('verb',choices=['inspect','stop'])
    sub.add_parser('verify')
    services=sub.add_parser('services'); services.add_argument('--output',type=Path,required=True)
    trip=sub.add_parser('roundtrip'); trip.add_argument('--direction',choices=['codex-claude','claude-codex'],required=True)
    trip.add_argument('--run-id',required=True)
    evidence=sub.add_parser('check-roundtrip'); evidence.add_argument('--run-id',required=True)
    book=sub.add_parser('runbook'); book.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    if sys.version_info<(3,11): raise ValueError('pilot requires Python 3.11 or newer')
    if args.command=='inventory': print(json_text(inventory(args.sandy))); return 0
    if args.command=='prepare':
        output=Path(args.output).expanduser().absolute()
        snapshot=inventory(args.sandy)
        c=choose(snapshot['sandboxes'],args.codex_workspace,'codex'); b=choose(snapshot['sandboxes'],args.claude_workspace,'claude')
        plan=render(args.sandy_home.absolute(),snapshot['sandboxes'],c,b,args.model,Path(args.codex_src).absolute(),
                    Path(args.sandy_src).absolute(),sys.executable,output,snapshot['sandy_schema'])
        for kind in ('codex','claude'): prepare_runtime_config(plan,kind)
        router_inventory(plan,args.router_src.absolute(),args.router_container)
        plan['inventory']=snapshot
        write(output,json_text(plan))
        print(json_text({'plan':str(output),'fleet_changes_applied':False,'instances':plan['instances'],'future_members':plan['future_members']}))
        return 0
    plan=load_plan(args.plan)
    if args.command=='apply': apply_plan(plan)
    elif args.command=='launch': launch(plan,args.kind)
    elif args.command=='control': control(plan,args.kind,args.verb)
    elif args.command=='verify': return verify(plan)
    elif args.command=='isolation-probe': return isolation_probe(plan)
    elif args.command=='rollback': rollback(plan)
    elif args.command=='roundtrip': roundtrip(plan,args.direction,args.run_id)
    elif args.command=='check-roundtrip': return check_roundtrip(plan,args.run_id)
    elif args.command=='runbook': write(args.output,operator_runbook(plan))
    elif args.command=='services':
        for kind in ('codex','claude'):
            label,content=service(plan,kind); suffix='.plist' if platform.system()=='Darwin' else '.service'
            target=args.output/(label+suffix); write(target,content)
            print(target)
    return 0


if __name__=='__main__':
    try: sys.exit(main())
    except Exception as exc:
        print('codex-pilot: '+type(exc).__name__+': '+str(exc),file=sys.stderr); sys.exit(1)
