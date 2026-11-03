"""Authorized W01 release only. Never prints credentials or target records.

prepare: verify baseline, build, restore a private DB snapshot, rehearse 15->16.
cutover: stop ALL old writers, backup, migrate, replace binary, verify readiness.
No collection, supplier calls, account import, or plan changes are performed.
"""
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
STAGE = Path('/opt/scopedesk-w01-integration-20261103')
BASE = Path('/opt/scopedesk-go')
DB = 'scopedesk-postgres-1'
SERVICE = 'scopedesk'
EXPECTED_COMMIT = 'ecc0e03a7e57252bb26e66614b3b8d2d3b8bdf3f'
TABLES = ['platform_users','scopes','assets','asset_services','jobs','monitor_plans',
          'candidates','ip_assets','asset_ips','dns_records','asset_events',
          'asset_snapshots','event_dedupes','passive_source_accounts',
          'passive_source_queries','passive_source_account_checks','encrypted_settings']

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def sql(query, container=DB, user='scopedesk', database='scopedesk'):
    return run(['docker','exec',container,'psql','-U',user,'-d',database,
                '-At','-v','ON_ERROR_STOP=1','-c',query],capture_output=True,text=True).stdout.strip()

def state(container=DB,user='scopedesk',database='scopedesk'):
    version = sql("SELECT coalesce(max(version_id),0) FROM (SELECT DISTINCT ON(version_id) version_id,is_applied FROM goose_db_version ORDER BY version_id,id DESC)x WHERE is_applied",container,user,database)
    counts = {t:int(sql('SELECT count(*) FROM '+t,container,user,database)) for t in TABLES}
    return {'version':int(version),'counts':counts}

def manifest():
    m=json.loads((STAGE/'release-manifest.json').read_text())
    if m['commit'] != EXPECTED_COMMIT: raise RuntimeError('Unexpected release commit')
    for name,digest in m['files'].items():
        path=(STAGE/name).resolve()
        if not path.is_relative_to(STAGE) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Staged source verification failed')
    return m

def baseline(m):
    for name,digest in m['baseline_normalized_sha256'].items():
        p=BASE/name
        if not p.is_file() or hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=digest:
            raise RuntimeError('Production source changed; refusing cutover')
    old=set(n for n in m['baseline_normalized_sha256'] if n.endswith('.go') and '/' not in n)
    live=set(p.name for p in BASE.glob('*.go') if not p.name.endswith('_test.go'))
    if old!=live: raise RuntimeError('Unexpected production runtime Go files')

def ready_for_cutover():
    if state()['version']!=15: raise RuntimeError('Expected production schema 15')
    if sql("SELECT count(*) FROM jobs WHERE status IN('queued','running','retrying')")!='0':
        raise RuntimeError('Active jobs; refusing to interrupt them')
    if sql("SELECT count(*)FROM monitor_plans WHERE enabled AND (next_run_at<=now()+interval '15 minutes' OR retry_at<=now()+interval '15 minutes')")!='0':
        raise RuntimeError('Scheduled run too near cutover; refusing to alter plan')
    if shutil.disk_usage(BASE).free<2*1024**3: raise RuntimeError('Insufficient backup headroom')
    main=int(run(['systemctl','show',SERVICE,'--property=MainPID','--value'],capture_output=True,text=True).stdout)
    processes=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            if Path(os.readlink(p/'exe')).name=='scopedesk': processes.append(int(p.name))
        except (FileNotFoundError,PermissionError,ProcessLookupError): pass
    if processes!=[main] and sorted(processes)!=[main]:
        raise RuntimeError('Unexpected event writer processes; refusing mixed-version deployment')

def dump(path):
    with path.open('wb') as f:
        run(['docker','exec',DB,'pg_dump','-U','scopedesk','--no-owner','--no-privileges','-Fc','scopedesk'],stdout=f,stderr=subprocess.PIPE)
    with path.open('rb') as f:
        run(['docker','exec','-i',DB,'pg_restore','--list'],stdin=f,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)

def build_env():
    env=os.environ.copy();env['PATH']='/usr/local/go/bin:'+env['PATH'];env['GOPROXY']='https://goproxy.cn,direct'
    return env

def prepare():
    m=manifest();baseline(m);ready_for_cutover()
    env=build_env()
    with (STAGE/'build.log').open('w') as f:
        run(['/usr/local/go/bin/go','build','-trimpath','-o',str(STAGE/'scopedesk.release'),'.'],cwd=STAGE,env=env,stdout=f,stderr=f)
    # A tiny Go helper uses the same migration library for an exact index-only
    # rollback, rather than editing Goose metadata by hand.
    helper='''package main
import("context";"database/sql";"os";_ "github.com/jackc/pgx/v5/stdlib";"github.com/pressly/goose/v3")
func main(){db,e:=sql.Open("pgx",os.Getenv("DATABASE_URL"));if e!=nil{os.Exit(1)};defer db.Close();if goose.SetDialect("postgres")!=nil{os.Exit(1)};if goose.DownToContext(context.Background(),db,"/opt/scopedesk-go/migrations",15)!=nil{os.Exit(1)}}
'''
    helper_path=STAGE/'rollback-helper.txt';helper_path.write_text(helper)
    # Explicit source filename build avoids changing the release's main package.
    helper_dir=STAGE/'rollback-helper';helper_dir.mkdir(exist_ok=True)
    (helper_dir/'main.go').write_text(helper)
    with (STAGE/'rollback-build.log').open('w') as f:
        run(['/usr/local/go/bin/go','build','-o',str(STAGE/'rollback-migration'),'./rollback-helper'],cwd=STAGE,env=env,stdout=f,stderr=f)
    rehearsal=STAGE/'rehearsal.dump';dump(rehearsal)
    name='scopedesk-w01-rehearsal-'+secrets.token_hex(4)
    password=secrets.token_urlsafe(32);docker_env=os.environ.copy();docker_env['POSTGRES_PASSWORD']=password
    try:
        run(['docker','run','-d','--name',name,'--memory','384m','--tmpfs','/var/lib/postgresql/data',
             '-e','POSTGRES_PASSWORD','-p','127.0.0.1::5432','postgres:16-alpine'],env=docker_env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(90):
            if subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
            time.sleep(.5)
        else: raise RuntimeError('Rehearsal database not ready')
        port=run(['docker','port',name,'5432/tcp'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]
        with rehearsal.open('rb') as f:
            run(['docker','exec','-i',name,'pg_restore','-U','postgres','-d','postgres','--no-owner','--no-privileges','--exit-on-error'],stdin=f,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        before=state(name,'postgres','postgres')
        env.update(DATABASE_URL=f'postgres://postgres:{password}@127.0.0.1:{port}/postgres?sslmode=disable',
                   RECON_MASTER_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),
                   RECON_DATA=str(STAGE/'rehearsal-state.json'),RECON_PLUGINS=str(STAGE/'plugins'))
        with (STAGE/'rehearsal-migrate.log').open('w') as f:
            run([str(STAGE/'scopedesk.release'),'migrate'],cwd=STAGE,env=env,stdout=f,stderr=f)
        after=state(name,'postgres','postgres')
        index=sql("SELECT count(*)FROM pg_indexes WHERE schemaname='public' AND indexname='event_dedupes_legacy_lookup'",name,'postgres','postgres')
        if before['version']!=15 or after['version']!=16 or before['counts']!=after['counts'] or index!='1':
            raise RuntimeError('Production-copy migration rehearsal failed')
        result={'commit':m['commit'],'schema_before':15,'schema_after':16,'counts_preserved':True,'index_present':True,
                'binary_sha256':hashlib.sha256((STAGE/'scopedesk.release').read_bytes()).hexdigest()}
        (STAGE/'prepared.json').write_text(json.dumps(result,indent=2))
        print('PREPARE PASS: verified build; production-copy 15->16; core counts preserved; no workers started',flush=True)
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def healthy():
    for attempt in range(30):
        try:
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open('http://127.0.0.1:18765/',timeout=3) as r:
                if r.status!=200 or b'passiveBatchForm' not in r.read():raise RuntimeError('Frontend readiness failed')
            try:
                opener.open('http://127.0.0.1:18765/api/settings/passive-accounts',timeout=3)
                raise RuntimeError('Authentication check failed')
            except urllib.error.HTTPError as e:
                if e.code!=401:raise
            run(['systemctl','is-active','--quiet',SERVICE]);return
        except Exception:
            if attempt==29:raise
            time.sleep(1)

def cutover():
    m=manifest();prepared=json.loads((STAGE/'prepared.json').read_text())
    if prepared['commit']!=m['commit'] or prepared['binary_sha256']!=hashlib.sha256((STAGE/'scopedesk.release').read_bytes()).hexdigest():
        raise RuntimeError('Prepared release identity mismatch')
    baseline(m);ready_for_cutover()
    backup=Path('/var/backups/scopedesk')/('before-w01-v16-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700,parents=True)
    run(['systemctl','stop',SERVICE]);changed=False
    try:
        if sql("SELECT count(*)FROM pg_stat_activity WHERE datname='scopedesk' AND backend_type='client backend' AND pid<>pg_backend_pid()")!='0':
            raise RuntimeError('Database still has other clients; refusing mixed writers')
        before=state()
        if before['version']!=15: raise RuntimeError('Schema changed during prepare')
        shutil.copytree(BASE,backup/'production');shutil.copytree('/etc/scopedesk',backup/'configuration');shutil.copytree('/var/lib/scopedesk-go',backup/'state')
        dump(backup/'database.dump');(backup/'before.json').write_text(json.dumps(before))
        config_hash=hashlib.sha256(Path('/etc/scopedesk/app.env').read_bytes()).digest()
        for name in m['files']:
            destination=BASE/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(STAGE/name,destination)
        shutil.copy2(STAGE/'scopedesk.release',BASE/'scopedesk.next');(BASE/'scopedesk.next').chmod(0o755);changed=True
        with (backup/'migration.log').open('w') as f:
            run(['python3',str(BASE/'deploy/run_env.py'),'/usr/sbin/runuser','-u','scopedesk','--',str(BASE/'scopedesk.next'),'migrate'],stdout=f,stderr=f)
        after=state()
        if after['version']!=16 or before['counts']!=after['counts']:raise RuntimeError('Production migration count/version mismatch')
        os.replace(BASE/'scopedesk.next',BASE/'scopedesk');run(['systemctl','start',SERVICE]);healthy()
        if hashlib.sha256(Path('/etc/scopedesk/app.env').read_bytes()).digest()!=config_hash:raise RuntimeError('Configuration changed')
        for name,digest in m['files'].items():
            if hashlib.sha256((BASE/name).read_bytes()).hexdigest()!=digest:raise RuntimeError('Installed source verification failed')
        pid=run(['systemctl','show',SERVICE,'--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
        digest=hashlib.sha256((BASE/'scopedesk').read_bytes()).hexdigest()
        if hashlib.sha256(Path('/proc/'+pid+'/exe').read_bytes()).hexdigest()!=digest or digest!=prepared['binary_sha256']:raise RuntimeError('Running binary identity mismatch')
        if sql("SELECT count(*)FROM pg_indexes WHERE schemaname='public' AND indexname='event_dedupes_legacy_lookup'")!='1':raise RuntimeError('Production compatibility index missing')
        result={'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'release_commit':m['commit'],'backup':str(backup),
                'schema_before':15,'schema_after':16,'migration_counts_preserved':True,'installed_source_files':len(m['files']),
                'binary_sha256':digest,'running_binary_verified':True,'readiness':True,'authentication_required':True,
                'configuration_unchanged':True,'plans_unchanged':True,'provider_keys_imported':False,'test_target_requests':0,'w02_deployed':False}
        (backup/'after.json').write_text(json.dumps(after));(backup/'deployment-complete.json').write_text(json.dumps(result,indent=2));(STAGE/'deployment-result.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(result),flush=True)
    except Exception:
        run(['systemctl','stop',SERVICE])
        if changed:
            # Do not destroy new user data by restoring a full DB snapshot. Index
            # rollback is safe only before any v2 events were written.
            if sql("SELECT count(*)FROM event_dedupes WHERE key LIKE 'v2:%'")!='0':
                print('CUTOVER FAILED: service stopped; v2 writes exist, automatic downgrade withheld; protected backup retained',flush=True)
                raise
            with (backup/'rollback.log').open('w') as f:
                run(['python3',str(BASE/'deploy/run_env.py'),str(STAGE/'rollback-migration')],stdout=f,stderr=f)
            for name in m['files']:
                if not (backup/'production'/name).exists() and (BASE/name).is_file():(BASE/name).unlink()
            shutil.copytree(backup/'production',BASE,dirs_exist_ok=True)
        run(['systemctl','start',SERVICE])
        print('CUTOVER FAILED: previous release restored without dropping user data; protected backup retained',flush=True)
        raise

if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('prepare','cutover'):raise RuntimeError('Expected prepare or cutover')
        (prepare if sys.argv[1]=='prepare' else cutover)()
    except Exception as e:
        # Do not print command arguments, environment values, or raw DB errors.
        print('W01 deployment stopped: '+type(e).__name__+' (private stage/backup logs retained)',flush=True)
        sys.exit(1)
