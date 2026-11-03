"""Run only synthetic acceptance fixtures against a fresh disposable PG16 container."""
import base64,hashlib,json,os,secrets,subprocess,time
from pathlib import Path
os.umask(0o077)
stage=Path('/opt/scopedesk-ux-20261103')
env=os.environ.copy();env.update(PATH='/usr/local/go/bin:'+env['PATH'],GOPROXY='https://goproxy.cn,direct',GOMAXPROCS='2',CGO_ENABLED='0')
def run(args,**kw):return subprocess.run(args,check=True,**kw)
manifest=json.loads((stage/'test-source-manifest.json').read_text())
assert all(hashlib.sha256((stage/n).read_bytes()).hexdigest()==h for n,h in manifest['files'].items())
with (stage/'build.log').open('w') as log:
 run(['/usr/local/go/bin/go','build','-p=1','-trimpath','-o',str(stage/'scopedesk.release'),'.'],cwd=stage,env=env,stdout=log,stderr=log)
print('Release build passed',flush=True)
with (stage/'test-build.log').open('w') as log:
 run(['/usr/local/go/bin/go','test','-p=1','-c','-o',str(stage/'ux-tests'),'.'],cwd=stage,env=env,stdout=log,stderr=log)
print('Test build passed',flush=True)
name='scopedesk-ux-test-'+secrets.token_hex(4)
secret=secrets.token_urlsafe(32)
docker_env=os.environ.copy();docker_env['POSTGRES_PASSWORD']=secret
try:
 run(['docker','run','-d','--pull=never','--name',name,'--memory','384m','--tmpfs','/var/lib/postgresql/data','-e','POSTGRES_PASSWORD','-e','POSTGRES_DB=scopedesk_p0','-p','127.0.0.1::5432','postgres:16-alpine'],env=docker_env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 for _ in range(90):
  if subprocess.run(['docker','exec',name,'pg_isready','-U','postgres','-d','scopedesk_p0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
  time.sleep(.5)
 else:raise RuntimeError('Temporary PostgreSQL did not start')
 port=run(['docker','port',name,'5432/tcp'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]
 env.update(DATABASE_URL=f'postgres://postgres:{secret}@127.0.0.1:{port}/scopedesk_p0?sslmode=disable',RECON_MASTER_KEY=base64.b64encode(secrets.token_bytes(32)).decode(),P0_ISOLATED='ephemeral-ci',P0_ARTIFACT_DIR=str(stage/'test-artifacts'))
 groups={
  'ux':r'^(TestUX.*|TestSourcePolicyCombinations)$',
  'regression':r'^(TestPostgresScope.*|TestPostgres.*Enterprise.*|TestEnterprise.*|TestPostgresProject.*|TestPostgresScheduler.*|TestW04.*|TestW30.*|TestScopeGuardBoundaries|TestBudgetIsAtomic|TestPostgresQueueClaimsAndLeaseRecovery|TestPostgresCandidateSnapshotCannotAuthorizeProbeOrCommit)$'}
 result={'source_files':len(manifest['files']),'temporary_pg16':True,'production_db_used':False,'workers_started':False,'binary_sha256':hashlib.sha256((stage/'scopedesk.release').read_bytes()).hexdigest(),'groups':{}}
 for group,pattern in groups.items():
  with (stage/(group+'-tests.log')).open('w') as log:run([str(stage/'ux-tests'),'-test.v','-test.count=1','-test.timeout=6m','-test.run='+pattern],cwd=stage,env=env,stdout=log,stderr=log)
  content=(stage/(group+'-tests.log')).read_text()
  if '--- SKIP:' in content or '\nFAIL' in content:raise RuntimeError('Unexpected skipped or failed acceptance')
  result['groups'][group]={'pass':content.count('--- PASS:'),'skip':0,'fail':0}
  print(group+' PASS: '+str(result['groups'][group]['pass'])+' results',flush=True)
 (stage/'isolated-result.json').write_text(json.dumps(result,indent=2))
finally:
 subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
