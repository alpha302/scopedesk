"""Verified UX release. No schema/config/authorization changes or test collection."""
import datetime,hashlib,json,os,shutil,subprocess,sys,time,urllib.error,urllib.request
from pathlib import Path
os.umask(0o077)
STAGE=Path('/opt/scopedesk-ux-20261103');BASE=Path('/opt/scopedesk-go');DB='scopedesk-postgres-1'
OLD_BINARY='0df9b7f83a310ea514251704df8d6b5634ba8643db70c5a0b8773af6c2b13e0a'
TABLES=['platform_users','scopes','assets','asset_services','jobs','monitor_plans','candidates','ip_assets','asset_ips','dns_records','asset_events','asset_snapshots','event_dedupes','passive_source_accounts','passive_source_queries','passive_source_account_checks','encrypted_settings','enterprise_candidates','enterprise_exploration_runs']
def run(args,**kw):return subprocess.run(args,check=True,**kw)
def sql(query):return run(['docker','exec',DB,'psql','-U','scopedesk','-d','scopedesk','-At','-v','ON_ERROR_STOP=1','-c',query],capture_output=True,text=True).stdout.strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def state():
 version=int(sql('SELECT max(version_id)FROM(SELECT DISTINCT ON(version_id)version_id,is_applied FROM goose_db_version ORDER BY version_id,id DESC)x WHERE is_applied'))
 # Service is stopped during comparisons; byte-level logical hashes include every user value.
 hashes={t:sql("SELECT md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text)FROM "+t+' t') for t in TABLES}
 return {'version':version,'counts':{t:int(sql('SELECT count(*)FROM '+t)) for t in TABLES},'hashes':hashes}
def validate(commit):
 m=json.loads((STAGE/'release-manifest.json').read_text())
 v=json.loads((STAGE/'verification-result.json').read_text())
 t=json.loads((STAGE/'isolated-result.json').read_text())
 if m['commit']!=commit or v['commit']!=commit or not v['ci_passed']:raise RuntimeError('Exact commit CI evidence missing')
 if not all(x['fail']==0 and x['skip']==0 for x in t['groups'].values()):raise RuntimeError('Isolated tests incomplete')
 if sha(STAGE/'scopedesk.release')!=t['binary_sha256']:raise RuntimeError('Unverified binary')
 for n,h in m['runtime_source_sha256'].items():
  path=(STAGE/n).resolve()
  if not path.is_relative_to(STAGE) or sha(path)!=h:raise RuntimeError('Stage source mismatch')
 for n,h in m['baseline_normalized_sha256'].items():
  path=BASE/n
  if not path.is_file() or hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=h:raise RuntimeError('Production source changed')
 expected={n for n in m['baseline_normalized_sha256'] if n.endswith('.go') and '/' not in n}
 if expected!={p.name for p in BASE.glob('*.go') if not p.name.endswith('_test.go')}:raise RuntimeError('Unexpected runtime source')
 pid=run(['systemctl','show','scopedesk','--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
 if sha(Path('/proc/'+pid+'/exe'))!=OLD_BINARY:raise RuntimeError('Production binary changed')
 writers=[]
 for path in Path('/proc').iterdir():
  if not path.name.isdigit():continue
  try:
   if os.readlink(path/'exe').startswith(str(BASE/'scopedesk')):writers.append(int(path.name))
  except (FileNotFoundError,PermissionError,ProcessLookupError):pass
 if writers!=[int(pid)]:raise RuntimeError('Additional production writers')
 if sql("SELECT count(*)FROM jobs WHERE status IN('queued','running','retrying')")!='0':raise RuntimeError('Active jobs; wait for completion')
 if sql("SELECT count(*)FROM monitor_plans WHERE enabled AND(next_run_at<=now()+interval '2 minutes' OR retry_at<=now()+interval '2 minutes')")!='0':raise RuntimeError('Scheduled run too near cutover')
 if shutil.disk_usage(BASE).free<1024**3:raise RuntimeError('Insufficient backup space')
 return m,v,t
def health(m,t):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 for attempt in range(30):
  try:
   for url,name in [('/','web/index.html'),('/app.js','web/app.js'),('/style.css','web/style.css')]:
    with opener.open('http://127.0.0.1:18765'+url,timeout=3) as response:
     if response.status!=200 or hashlib.sha256(response.read()).hexdigest()!=m['runtime_source_sha256'][name]:raise RuntimeError('Served embedded UI mismatch')
   for url in ['/api/state','/api/settings/passive-accounts']:
    try:opener.open('http://127.0.0.1:18765'+url,timeout=3);raise RuntimeError('Authentication not enforced')
    except urllib.error.HTTPError as error:
     if error.code!=401:raise
   run(['systemctl','is-active','--quiet','scopedesk'])
   pid=run(['systemctl','show','scopedesk','--property=MainPID','--value'],capture_output=True,text=True).stdout.strip()
   if sha(Path('/proc/'+pid+'/exe'))!=t['binary_sha256']:raise RuntimeError('Running binary mismatch')
   return
  except Exception:
   if attempt==29:raise
   time.sleep(1)
def release(commit):
 m,v,t=validate(commit)
 backup=Path('/var/backups/scopedesk')/('before-ux-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S'));backup.mkdir(parents=True,mode=0o700)
 changed=False;run(['systemctl','stop','scopedesk'])
 try:
  if sql("SELECT count(*)FROM pg_stat_activity WHERE datname='scopedesk' AND backend_type='client backend' AND pid<>pg_backend_pid()")!='0':raise RuntimeError('Other database writers remain')
  before=state()
  if before['version']!=18:raise RuntimeError('Unexpected schema version')
  shutil.copytree(BASE,backup/'production');shutil.copytree('/etc/scopedesk',backup/'configuration');shutil.copytree('/var/lib/scopedesk-go',backup/'state')
  with (backup/'database.dump').open('wb') as f:run(['docker','exec',DB,'pg_dump','-U','scopedesk','--no-owner','--no-privileges','-Fc','scopedesk'],stdout=f,stderr=subprocess.PIPE)
  with (backup/'database.dump').open('rb') as f:run(['docker','exec','-i',DB,'pg_restore','--list'],stdin=f,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  config=sha(Path('/etc/scopedesk/app.env'))
  changed=True
  for n in m['changed_runtime_files']:
   (BASE/n).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(STAGE/n,BASE/n);(BASE/n).chmod(0o644)
  shutil.copy2(STAGE/'scopedesk.release',BASE/'scopedesk.next');(BASE/'scopedesk.next').chmod(0o755);os.replace(BASE/'scopedesk.next',BASE/'scopedesk')
  # No migration: prove all persistent user data is identical before starting workers.
  after=state()
  if after!=before:raise RuntimeError('User data changed during source-only release')
  if sha(Path('/etc/scopedesk/app.env'))!=config:raise RuntimeError('Configuration changed')
  if any(sha(BASE/n)!=m['runtime_source_sha256'][n] for n in m['changed_runtime_files']):raise RuntimeError('Installed source mismatch')
  run(['systemctl','start','scopedesk']);health(m,t)
  result={'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'release_commit':commit,'ci_run':v['ci_run'],'ci_passed':True,'backup':str(backup),'schema_before':18,'schema_after':18,'user_table_counts_preserved':True,'user_table_values_preserved':True,'configuration_unchanged':True,'plans_unchanged':True,'authorization_unchanged':True,'binary_sha256':t['binary_sha256'],'running_binary_verified':True,'embedded_ui_verified':True,'readiness':True,'authentication_required':True,'test_target_requests':0,'changed_runtime_files':m['changed_runtime_files']}
  (backup/'deployment-complete.json').write_text(json.dumps(result,indent=2));(STAGE/'deployment-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
 except Exception:
  run(['systemctl','stop','scopedesk'])
  if changed:
   for n in m['changed_runtime_files']:
    if not (backup/'production'/n).exists() and (BASE/n).is_file():(BASE/n).unlink()
   shutil.copytree(backup/'production',BASE,dirs_exist_ok=True)
  run(['systemctl','start','scopedesk']);print('Previous binary/source restored; user DB was not overwritten',flush=True);raise
if __name__=='__main__':
 try:
  if len(sys.argv)!=2 or len(sys.argv[1])!=40:raise RuntimeError('Exact release commit required')
  release(sys.argv[1])
 except Exception as error:print('UX release stopped: '+type(error).__name__+'; private diagnostics retained',flush=True);sys.exit(1)
