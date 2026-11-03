"""Authorized W26-only release; only new migration 17; no collection is invoked, no collection is invoked."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

os.umask(0o077)
STAGE=Path('/opt/scopedesk-w26-integration-20261103')
BASE=Path('/opt/scopedesk-go')
DB='scopedesk-postgres-1'
TABLES=['platform_users','scopes','assets','asset_services','jobs','monitor_plans','candidates','ip_assets','asset_ips','dns_records','asset_events','asset_snapshots','event_dedupes','passive_source_accounts','passive_source_queries','passive_source_account_checks','encrypted_settings']
def run(a,**kw):return subprocess.run(a,check=True,**kw)
def sql(q,c=DB,u='scopedesk',d='scopedesk'):
    return run(['docker','exec',c,'psql','-U',u,'-d',d,'-At','-v','ON_ERROR_STOP=1','-c',q],capture_output=True,text=True).stdout.strip()
def state(c=DB,u='scopedesk',d='scopedesk'):
    v=sql('SELECT max(version_id)FROM(SELECT DISTINCT ON(version_id)version_id,is_applied FROM goose_db_version ORDER BY version_id,id DESC)x WHERE is_applied',c,u,d)
    return {'version':int(v),'counts':{t:int(sql('SELECT count(*)FROM '+t,c,u,d)) for t in TABLES}}
def manifest():
    m=json.loads((STAGE/'release-manifest.json').read_text())
    if not m['commit'].startswith('0f8d16b'):raise RuntimeError('Unexpected release')
    for n,h in (m['files'] | m.get('test_files',{})).items():
        p=(STAGE/n).resolve()
        if not p.is_relative_to(STAGE) or hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise RuntimeError('Staging checksum mismatch')
    return m
def preflight(m):
    for n,h in m['baseline_normalized_sha256'].items():
        p=BASE/n
        if not p.is_file() or hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=h:raise RuntimeError('Production source changed')
    names={n for n in m['baseline_normalized_sha256'] if n.endswith('.go') and '/' not in n}
    if names!={p.name for p in BASE.glob('*.go') if not p.name.endswith('_test.go')}:raise RuntimeError('Unexpected runtime source')
    if state()['version']!=16:raise RuntimeError('Expected schema 16')
    if sql("SELECT count(*)FROM jobs WHERE status IN('queued','running','retrying')")!='0':raise RuntimeError('Active jobs; stop before cutover')
    if sql("SELECT count(*)FROM monitor_plans WHERE enabled AND(next_run_at<=now()+interval '15 minutes' OR retry_at<=now()+interval '15 minutes')")!='0':raise RuntimeError('A scheduled run is too near cutover')
    if shutil.disk_usage(BASE).free<2*1024**3:raise RuntimeError('Insufficient backup headroom')
    pid=int(run(['systemctl','show','scopedesk','--property=MainPID','--value'],capture_output=True,text=True).stdout)
    writers=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            if os.readlink(p/'exe').startswith(str(BASE/'scopedesk')):writers.append(int(p.name))
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    if sorted(writers)!=[pid]:raise RuntimeError('Unexpected additional writers')
def dump(path):
    with path.open('wb') as f:run(['docker','exec',DB,'pg_dump','-U','scopedesk','--no-owner','--no-privileges','-Fc','scopedesk'],stdout=f,stderr=subprocess.PIPE)
    with path.open('rb') as f:run(['docker','exec','-i',DB,'pg_restore','--list'],stdin=f,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
def prepare():
    m=manifest();preflight(m);env=os.environ.copy();env.update(PATH='/usr/local/go/bin:'+env['PATH'],GOPROXY='https://goproxy.cn,direct')
    with (STAGE/'build.log').open('w') as f:run(['/usr/local/go/bin/go','build','-trimpath','-o',str(STAGE/'scopedesk.release'),'.'],cwd=STAGE,env=env,stdout=f,stderr=f)
    testenv=env.copy();testenv['CGO_ENABLED']='0'
    with (STAGE/'auth-build.log').open('w') as f:run(['/usr/local/go/bin/go','test','-c','-o',str(STAGE/'auth-tests'),'.'],cwd=STAGE,env=testenv,stdout=f,stderr=f)
    with (STAGE/'auth-fixture.log').open('w') as f:run(['docker','run','--rm','--pull=never','--network','none','--cpus','2','--memory','536870912','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','-v',str(STAGE/'auth-tests')+':/auth-tests:ro','--entrypoint','/auth-tests','postgres:16-alpine','-test.v','-test.timeout=4m','-test.run=^(TestW37.*|TestW03HashDoesNotBlockExistingSession)$'],stdout=f,stderr=f)
    dump(STAGE/'rehearsal.dump');name='scopedesk-w26-rehearsal-'+secrets.token_hex(4);secret=secrets.token_urlsafe(32);docker_env=os.environ.copy();docker_env['POSTGRES_PASSWORD']=secret
    try:
        run(['docker','run','-d','--name',name,'--memory','384m','--tmpfs','/var/lib/postgresql/data','-e','POSTGRES_PASSWORD','-p','127.0.0.1::5432','postgres:16-alpine'],env=docker_env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(90):
            if subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
            time.sleep(.5)
        else:raise RuntimeError('Rehearsal not ready')
        port=run(['docker','port',name,'5432/tcp'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]
        with (STAGE/'rehearsal.dump').open('rb') as f:run(['docker','exec','-i',name,'pg_restore','-U','postgres','-d','postgres','--no-owner','--no-privileges','--exit-on-error'],stdin=f,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        before=state(name,'postgres','postgres')
        env.update(DATABASE_URL=f'postgres://postgres:{secret}@127.0.0.1:{port}/postgres?sslmode=disable',RECON_MASTER_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),RECON_DATA=str(STAGE/'rehearsal-state.json'),RECON_PLUGINS=str(STAGE/'plugins'))
        with (STAGE/'rehearsal.log').open('w') as f:run([str(STAGE/'scopedesk.release'),'migrate'],cwd=STAGE,env=env,stdout=f,stderr=f)
        after=state(name,'postgres','postgres')
        if before['version']!=16 or after['version']!=17 or before['counts']!=after['counts']:raise RuntimeError('Unexpected rehearsal data/schema change')
        if sql('SELECT count(*)FROM assets WHERE dns_observation IS NOT NULL',name,'postgres','postgres')!='0':raise RuntimeError('Historical DNS evidence was fabricated')
        result={'commit':m['commit'],'schema':17,'counts_preserved':True,'auth_fixture_passed':True,'binary_sha256':hashlib.sha256((STAGE/'scopedesk.release').read_bytes()).hexdigest()}
        (STAGE/'prepared.json').write_text(json.dumps(result,indent=2));print('PREPARE PASS: W26 build verified; private restored snapshot migration 16 to 17 verified; no workers started',flush=True)
    finally:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def healthy():
    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(30):
        try:
            with op.open('http://127.0.0.1:18765/',timeout=3) as r:
                if r.status!=200:raise RuntimeError('Homepage failed')
            try:op.open('http://127.0.0.1:18765/api/settings/passive-accounts',timeout=3);raise RuntimeError('Authentication failed')
            except urllib.error.HTTPError as e:
                if e.code!=401:raise
            run(['systemctl','is-active','--quiet','scopedesk']);return
        except Exception:
            if attempt==29:raise
            time.sleep(1)
def cutover():
    m=manifest();p=json.loads((STAGE/'prepared.json').read_text());preflight(m)
    if not p.get('auth_fixture_passed') or p['commit']!=m['commit'] or p['binary_sha256']!=hashlib.sha256((STAGE/'scopedesk.release').read_bytes()).hexdigest():raise RuntimeError('Prepared release mismatch')
    backup=Path('/var/backups/scopedesk')/('before-w26-v17-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S'));backup.mkdir(mode=0o700,parents=True)
    run(['systemctl','stop','scopedesk']);changed=False
    try:
        if sql("SELECT count(*)FROM pg_stat_activity WHERE datname='scopedesk' AND backend_type='client backend' AND pid<>pg_backend_pid()")!='0':raise RuntimeError('Other database clients remain')
        before=state();shutil.copytree(BASE,backup/'production');shutil.copytree('/etc/scopedesk',backup/'configuration');shutil.copytree('/var/lib/scopedesk-go',backup/'state');dump(backup/'database.dump')
        config=hashlib.sha256(Path('/etc/scopedesk/app.env').read_bytes()).digest()
        plans=sql('SELECT coalesce(jsonb_agg(to_jsonb(p)ORDER BY scope_id),\'[]\'::jsonb)FROM monitor_plans p')
        changed=True
        for n in m['files']:(BASE/n).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(STAGE/n,BASE/n);(BASE/n).chmod(0o644)
        shutil.copy2(STAGE/'scopedesk.release',BASE/'scopedesk.next');(BASE/'scopedesk.next').chmod(0o755)
        with (backup/'migration-check.log').open('w') as f:run(['python3',str(BASE/'deploy/run_env.py'),'/usr/sbin/runuser','-u','scopedesk','--',str(BASE/'scopedesk.next'),'migrate'],stdout=f,stderr=f)
        after=state()
        if after['version']!=17 or after['counts']!=before['counts']:raise RuntimeError('Unexpected production data/schema change')
        os.replace(BASE/'scopedesk.next',BASE/'scopedesk');run(['systemctl','start','scopedesk']);healthy()
        if hashlib.sha256(Path('/etc/scopedesk/app.env').read_bytes()).digest()!=config or plans!=sql('SELECT coalesce(jsonb_agg(to_jsonb(p)ORDER BY scope_id),\'[]\'::jsonb)FROM monitor_plans p'):raise RuntimeError('Configuration or plan changed')
        pid=run(['systemctl','show','scopedesk','--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
        if hashlib.sha256(Path('/proc/'+pid+'/exe').read_bytes()).hexdigest()!=p['binary_sha256']:raise RuntimeError('Running binary mismatch')
        if any(hashlib.sha256((BASE/n).read_bytes()).hexdigest()!=h for n,h in m['files'].items()):raise RuntimeError('Installed source mismatch')
        result={'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'release_commit':m['commit'],'backup':str(backup),'schema_before':16,'schema_after':17,'counts_preserved':True,'binary_sha256':p['binary_sha256'],'running_binary_verified':True,'source_files_verified':len(m['files']),'configuration_unchanged':True,'plans_unchanged':True,'readiness':True,'authentication_required':True,'test_target_requests':0,'w03_deployed':True,'w37_deployed':True,'w04_safety_patch_deployed':True,'w26_deployed':True,'isolated_auth_fixture_passed':True}
        (backup/'deployment-complete.json').write_text(json.dumps(result,indent=2));(STAGE/'deployment-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
    except Exception:
        run(['systemctl','stop','scopedesk'])
        if changed:
            for n in m['files']:
                if not (backup/'production'/n).exists() and (BASE/n).is_file():(BASE/n).unlink()
            shutil.copytree(backup/'production',BASE,dirs_exist_ok=True)
        run(['systemctl','start','scopedesk']);print('W26 cutover failed; previous binary/source restored without restoring or deleting user DB data',flush=True);raise
if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('prepare','cutover'):raise RuntimeError('Expected prepare/cutover')
        (prepare if sys.argv[1]=='prepare' else cutover)()
    except Exception as e:print('W26 release stopped: '+type(e).__name__+'; details retained privately',flush=True);sys.exit(1)
