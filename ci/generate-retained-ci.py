#!/usr/bin/env python3
"""Generate an owned CI graph from its exact catalog and actual measured CLI inputs.
Generation is source maintenance, not execution or qualification. A graph must
be registered/tracked before the required prepared-project consumer admits it.
"""
import argparse,copy,hashlib,json,os,re,stat
from pathlib import Path

def stable_identity(info):
    # Reads may update atime; retain every other original stat identity field.
    return (info.st_mode, info.st_ino, info.st_dev, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def absolute(value):
    path=Path(value)
    if not path.is_absolute() or path.is_symlink(): raise ValueError('explicit canonical nonsymlink input required')
    result=path.resolve(strict=True)
    if result!=path: raise ValueError('noncanonical input')
    return path

def document(path):
    data=path.read_bytes()
    if len(data)>16*1024*1024: raise ValueError('catalog input exceeds bound')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate JSON object key: '+key)
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=unique)

def entries(values):
    result={}
    for value in values:
        name,separator,path=value.partition('=')
        if not separator or not re.fullmatch('[a-z][a-z0-9-]*',name) or name in result: raise ValueError('malformed/duplicate named entry')
        result[name]=absolute(path)
    return result

def bindings(path,selected,guest_paths=None):
    obj=document(path)
    if set(obj)!={'schema','bindings'} or obj['schema']!=1 or not obj['bindings']: raise ValueError('closed nonempty binding schema1 required')
    keys={'backend','producer_backend','executable','sha256','binary_build_sha','dev','ino','size','mtime','mtime_nsec','ctime','ctime_nsec'}
    seen=set()
    for row in obj['bindings']:
        if set(row)!=keys or row['backend'] in seen or row['backend'] not in selected: raise ValueError('unknown/duplicate binding')
        seen.add(row['backend']);path=selected[row['backend']]
        expected=guest_paths[row['backend']] if guest_paths is not None else str(path)
        if row['executable']!=expected: raise ValueError('named entry differs from actual binding')
        before=path.stat()
        if not stat.S_ISREG(before.st_mode) or not before.st_mode&0o111 or before.st_size==0: raise ValueError('entry is not executable regular data')
        expected={'dev':before.st_dev,'ino':before.st_ino,'size':before.st_size,'mtime':before.st_mtime_ns//10**9,'mtime_nsec':before.st_mtime_ns%10**9,'ctime':before.st_ctime_ns//10**9,'ctime_nsec':before.st_ctime_ns%10**9}
        if any(row[k]!=v for k,v in expected.items()): raise ValueError('selected executable metadata changed')
        with path.open('rb') as source:
            if source.read(4)!=b'\x7fELF': raise ValueError('selected entry is not actual ELF')
            source.seek(0);digest=hashlib.file_digest(source,'sha256').hexdigest()
        if digest!=row['sha256'] or stable_identity(path.stat())!=stable_identity(before): raise ValueError('selected executable changed while binding')
        if not re.fullmatch('[0-9a-fA-F]{7,40}',row['binary_build_sha']) or not row['producer_backend']: raise ValueError('missing actual producer identity')
    if seen!=set(selected): raise ValueError('named entries and actual binding population differ')
    # Static extension frontends cannot be the original core comparator.
    core=selected['ptrace']
    if any(path.samefile(core) for name,path in selected.items() if name!='ptrace'): raise ValueError('self parity is not a static extension')

def emit(path,value):
    path=Path(path)
    if not path.is_absolute(): raise ValueError('output must be explicit absolute path')
    with path.open('x') as output: json.dump(value,output,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())

def mounted(path,core,project,core_out,project_out):
    for host,guest in ((core_out/'target','/src/target'),(project_out/'target','/project/target'),(core,'/src'),(project,'/project')):
        if path==host: return guest
        if host in path.parents: return guest+'/'+str(path.relative_to(host))
    raise ValueError('pinned input is outside the paired source/output mounts: '+str(path))

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('core-dag','catalog','bindings','pinned-bindings','output','core-source','extension-root','core-tools','pinned-core-tools','host-descriptor','pinned-descriptor','core-pinned-out','project-pinned-out','inputs'): p.add_argument('--'+name,required=True)
    p.add_argument('--entry',action='append',required=True,help='logical backend=actual canonical host ELF')
    p.add_argument('--pinned-entry',action='append',required=True,help='logical backend=actual canonical pinned-output ELF')
    a=p.parse_args(argv);core=absolute(a.core_source);project=absolute(a.extension_root);tools=absolute(a.core_tools)
    core_out=absolute(a.core_pinned_out);project_out=absolute(a.project_pinned_out);pinned_tools=absolute(a.pinned_core_tools)
    # Host and pinned prepared executables have distinct actual output owners.
    # The prepared-project reader still holds/revalidates the original core record.
    if core/'target' not in tools.parents or core_out/'target' not in pinned_tools.parents or tools.samefile(pinned_tools): raise ValueError('distinct actual host and pinned core tool directories required')
    if core==project or core_out==project_out: raise ValueError('distinct source/output roots required')
    graph=document(absolute(a.core_dag));catalog=document(absolute(a.catalog));selected=entries(a.entry);pinned=entries(a.pinned_entry)
    bound=absolute(a.bindings);pinned_bound=absolute(a.pinned_bindings)
    if catalog['schema']!=1 or catalog['owner'] not in ('patching','dynamorio'): raise ValueError('unknown catalog owner')
    owner=catalog['owner'];required={'ptrace','sabre','e9patch'} if owner=='patching' else {'ptrace','dbt'}
    if set(selected)!=required or set(pinned)!=required: raise ValueError('exact owner entry population required in both contexts')
    guest_paths={name:mounted(path,core,project,core_out,project_out) for name,path in pinned.items()}
    bindings(bound,selected);bindings(pinned_bound,pinned,guest_paths)
    descriptors={'host':absolute(a.host_descriptor),'pinned':absolute(a.pinned_descriptor)}
    for context,path in descriptors.items():
        obj=document(path);expected={'schema':1,'repository':str(project) if context=='host' else '/project','graph':str(Path(a.output)) if context=='host' else '/project/ci/dag/validate.json','tools_root':str(core) if context=='host' else '/src','shared_package':'hermit-run'}
        if obj!=expected: raise ValueError('project descriptor is not the exact source/graph/tool cohort')
    inputs=document(absolute(a.inputs))
    if set(inputs)!={'schema','host','pinned'} or inputs['schema']!=1: raise ValueError('closed context input map required')
    required_inputs={'HERMIT_PATCHING_COHORT','HERMIT_SABRE_LOADER','HERMIT_E9TOOL','HERMIT_E9PATCH_BACKEND'} if owner=='patching' else {'HERMIT_DYNAMORIO_ENGINE_ARTIFACT','HERMIT_DYNAMORIO_ENGINE_CHECKER'}
    if any(not required_inputs <= set(inputs[context]) for context in ('host','pinned')): raise ValueError('required actual owner cohort/checker inputs are absent')
    contexts={}
    for context in ('host','pinned'):
        values={}
        for name,value in inputs[context].items():
            if not re.fullmatch('[A-Z][A-Z0-9_]*',name): raise ValueError('invalid explicit input name')
            actual=absolute(value);values[name]=str(actual) if context=='host' else mounted(actual,core,project,core_out,project_out)
        values.update(HERMIT_CORE_SOURCE=str(core) if context=='host' else '/src',HERMIT_EXTENSION_ROOT=str(project) if context=='host' else '/project',HERMIT_CORE_TOOLS=str(tools) if context=='host' else mounted(pinned_tools,core,project,core_out,project_out),HERMIT_CORE_BIN=str(selected['ptrace']) if context=='host' else guest_paths['ptrace'],HERMIT_E2E_COMMAND_BINDINGS=str(bound) if context=='host' else mounted(pinned_bound,core,project,core_out,project_out),HERMIT_NEXTEST_PROJECT=str(descriptors['host']) if context=='host' else '/project/ci/prepared-project-pinned.json')
        for name in required:
            values['HERMIT_'+name.upper()+'_BIN']=str(selected[name]) if context=='host' else guest_paths[name]
            values['HERMIT_'+name.upper()+'_BINDINGS']=values['HERMIT_E2E_COMMAND_BINDINGS']
        # Historical host tests use these actual package-specific input names.
        values['HERMIT_PATCHING_ROOT' if owner=='patching' else 'HERMIT_DYNAMORIO_ROOT']=values['HERMIT_EXTENSION_ROOT']
        if owner=='dynamorio':values['HERMIT_DYNAMORIO_BIN']=values['HERMIT_DBT_BIN']
        contexts[context]=values
    # Immutable original focused producer policy; no calibration/backend pin
    # is used to authorize changes to the first-party core producer.
    retained_host_policy = {'timeout': 420, 'cpu_timeout': 2400, 'jobs_flag': None, 'jobs_env': None, 'resources': {}, 'est_duration_s': 0.0, 'rss_baseline_bytes': None, 'rss_baseline_inner_jobs': None, 'hard_mem_max_bytes': 17179869184, 'classification': 'cpu-bound', 'preferred_inner_jobs': 8, 'measured_effective_cores': None, 'measured_cpu_utilization': None}
    for retained in catalog['steps']:
        if retained['group']+'.'+retained['job'] == 'compatprep.hermit_release':
            actual = {key:retained.get(key) for key in ('timeout','cpu_timeout','jobs_flag','jobs_env')}
            actual.update({key:retained['hint'].get(key) for key in ['resources', 'est_duration_s', 'rss_baseline_bytes', 'rss_baseline_inner_jobs', 'hard_mem_max_bytes', 'classification', 'preferred_inner_jobs', 'measured_effective_cores', 'measured_cpu_utilization']})
            if actual != retained_host_policy: raise ValueError('host focused producer changed complete retained resource policy')
    steps=graph['steps'];known={r['group']+'.'+r['job'] for r in steps}
    if len(known)!=len(steps):raise ValueError('duplicate actual core DAG tag')
    import shlex
    for original in catalog['steps']:
        row=copy.deepcopy(original);tag=row['group']+'.'+row['job']
        if tag in known: raise ValueError('external node still present in selected core graph: '+tag)
        known.add(tag);env=row.setdefault('env',{});context=row.pop('prepared_context',None)
        if context is not None:
            if context not in contexts: raise ValueError('unknown prepared context')
            values=contexts[context];env.update(values);env['HERMIT_PREPARED_NEXTEST_REQUIRED']='1'
            if context=='pinned':
                # The scheduler starts this command at the core root. Arguments
                # before the inner shell are host mount inputs; actual per-context
                # artifact values are exported only inside the guest payload.
                env.update(HERMIT_CORE_SOURCE=str(core),HERMIT_EXTENSION_ROOT=str(project),HERMIT_EXTENSION_PINNED_OUT=str(project_out))
                args=shlex.split(row['cmd']);payload=args[-1]
                args[-1]='export '+ ' '.join(k+'='+shlex.quote(v) for k,v in values.items())+'; '+payload
                row['cmd']=' '.join(('"'+v+'"' if v.startswith('${') else shlex.quote(v)) for v in args)
        else:env.update(contexts['host'])
        if 'manifest' in row and ' --execution-owner '+owner+' ' not in row['cmd']: raise ValueError('owned manifest node lacks explicit execution owner: '+tag)
        steps.append(row)
    # Normal per-project preparation consumes the original core preparation and
    # builds/lists the owner selectors through the same core wrapper at its own cwd.
    all_labels=sorted({label for row in catalog['steps'] if 'NEXTEST_PREPARED_BUILD_SELECTION' in row.get('env',{}) for label in row['labels']})
    by_tag={r['group']+'.'+r['job']:r for r in steps}
    for context,anchor in (('host','build.workspace'),('pinned','build.workspace_in_pinned_root')):
        if anchor not in by_tag:raise ValueError('missing original core preparation owner '+anchor)
        row=copy.deepcopy(by_tag[anchor]);row['group']='build';row['job']=owner+'_nextest'+('_in_pinned_root' if context=='pinned' else '')
        row['fail_fast_family']=owner+'_nextest'+('_in_pinned_root' if context=='pinned' else '');row['labels']=all_labels;row['result_manifests']=[];row['deps']=[anchor,'build.rust_scripts'+('_in_pinned_root' if context=='pinned' else '')]
        row['desc']='Prepare actual '+owner+' Nextest executables with the original core tool cohort'
        row['description']='Separate project cwd and target; required original core preparation/CPU wrapper held and rechecked. Original preparation resource limits retained, execution remains unqualified until measured.'
        row['env']={**row.get('env',{}),**contexts[context],'HERMIT_PREPARED_NEXTEST_REQUIRED':'1'}
        row['env'].pop('NEXTEST_PREPARED_BUILD_SELECTION',None);row['env'].pop('NEXTEST_EXPECTED_EXECUTED',None)
        payload='export '+ ' '.join(k+'='+shlex.quote(v) for k,v in contexts[context].items())+'; cd -- '+shlex.quote(str(project) if context=='host' else '/project')+' && "${HERMIT_CORE_SOURCE:?}/ci/run-with-core-build.sh" "${HERMIT_CORE_SOURCE:?}/ci/nextest-binaries.rs" prepare full'
        if context=='host': row['cmd']=payload
        else:
            args=[str(core/'ci/hermetic/run-in-pinned-root.sh'),'--src',str(core),'--out',str(core_out),'--src-rw','--cargo-home',str(core_out/'cargo'),'--project-src',str(project),'--project-out',str(project_out),'--project-descriptor',str(descriptors['pinned']),'--project-src-rw']
            for name in sorted(row['env']):args+=['--env',name]
            row['cmd']=' '.join(map(shlex.quote,args+['--','bash','-c','/src/ci/hermetic/assert-no-network.sh && /src/ci/hermetic/assert-build-dependencies.sh && '+payload]))
        tag=row['group']+'.'+row['job']
        if tag in known:raise ValueError('duplicate project producer '+tag)
        known.add(tag);steps.append(row)
    for row in steps:
        missing=set(row['deps'])-known
        if missing: raise ValueError('unprovided dependency owner: '+repr(sorted(missing)))
    emit(a.output,graph)
if __name__=='__main__': main()
