import subprocess,os,secrets,time,json
from pathlib import Path
stage=Path('/opt/scopedesk-w05-fixture-20261103')
name='scopedesk-w05-fixture-'+secrets.token_hex(4)
r=lambda a,**kw:subprocess.run(a,check=True,**kw)
try:
 r(['docker','run','-d','--name',name,'--memory','384m','--tmpfs','/var/lib/postgresql/data','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB=scopedesk_p0','-e','POSTGRES_USER=scopedesk_p0','-p','127.0.0.1::5432','postgres:16-alpine'],stdout=subprocess.DEVNULL)
 for _ in range(60):
  if subprocess.run(['docker','exec',name,'pg_isready','-U','scopedesk_p0'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
  time.sleep(.5)
 port=r(['docker','port',name,'5432/tcp'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1]
 env=os.environ.copy();env.update(DATABASE_URL='postgres://scopedesk_p0@127.0.0.1:'+port+'/scopedesk_p0?sslmode=disable',P0_ISOLATED='ephemeral-ci',RECON_MASTER_KEY=__import__('base64').b64encode(secrets.token_bytes(32)).decode())
 with open('/tmp/w05-pg-green.jsonl','w') as f:
  r(['/usr/local/go/bin/go','test','-race','-json','-count=1','-timeout=5m','-run','^(TestW05.*|TestW04.*|TestW26PersistAndRecoverDNSWithoutChangingHTTP|TestPostgresCandidateSnapshotCannotAuthorizeProbeOrCommit|TestPostgresDiffIdempotencyAndPartialFailure)$','.'],cwd=stage,env=env,stdout=f,stderr=f)
 print('W05 PG16 and state/auth regressions PASS')
finally: subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
