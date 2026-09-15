#!/usr/bin/env python3
"""Fail-closed checks against dedicated proof resources only."""
import base64,hashlib,hmac,json,os,subprocess,urllib.request,urllib.error,uuid
from transport import opener
from qualification import URL,KEY,checks,check,call,ok,issue,auth,future
CONFIG=os.environ.get('G4_CONFIG')
if not CONFIG:
 assert URL=='https://lenso-workers-g4-proof.lenso.workers.dev', 'Set G4_CONFIG for a different proof Worker before database fault injection'
 CONFIG='wrangler.jsonc'
def probe(fault=None):
 req=urllib.request.Request(URL, json.dumps({'operation':'read_status','request':{'subject':'missing'}}).encode(),headers={'content-type':'application/json','x-proof-key':KEY,'User-Agent':'Lenso-G4-Qualification/1.0',**({'x-proof-fault':fault} if fault else {})})
 try:
  with opener.open(req,timeout=30) as r:return r.status,r.read().decode()
 except urllib.error.HTTPError as e:return e.code,e.read().decode()
identity=ok('ensure_identity',{'provider':'g4','external_subject':str(uuid.uuid4())})
session=ok('issue',issue(identity['subject']))
check('forced generation abandonment fails closed',probe('abandon')[0]==503)
check('session persists across generation replacement',auth(session['credential'])['Ok']['kind']=='authenticated')
status,body=probe('storage')
check('real D1 missing-table failure prevents Ready',status==503 and '"ready":true' not in body)
private=json.load(open(os.environ.get('G4_SECRETS','/tmp/lenso-workers-g4-secrets.json')))
check('storage failure redacts every configured secret',all(v not in body for v in private.values()))
check('fresh event recovers after storage failure',probe()[0]==200)
def sql(command,database='ACCOUNT_DB'):
 result=subprocess.run(['node_modules/.bin/wrangler','d1','execute',database,'--remote','--config',CONFIG,'--command',command,'--json'],capture_output=True,text=True)
 assert result.returncode==0,'owned D1 operator command';return json.loads(result.stdout)
try:
 sql("UPDATE auth_account_schema SET fingerprint='g4-intentionally-mismatched' WHERE version=1")
 check('owned D1 schema mismatch prevents Ready',probe()[0]==503)
finally:
 sql("UPDATE auth_account_schema SET fingerprint='e2ab982504b77776e928387519fb612fcd4b0213007713ad5389d79910a1db12' WHERE version=1")
check('restored owned migration record recovers',probe()[0]==200)
r=sql('SELECT COUNT(*) AS orphans FROM identity_subjects s WHERE NOT EXISTS (SELECT 1 FROM identity_bindings b WHERE b.subject_id=s.subject_id)')
check('identity races left no orphan subjects',r[0]['results'][0]['orphans']==0)
check('database evidence served by primary',r[0]['meta']['served_by_primary'] is True)
flow=ok('create',{'provider':'g4','return_to':'/qualification','expires_at':future(300)})
digest=base64.urlsafe_b64encode(hmac.new(private['OAUTH_KEY'].encode(),flow['state'].encode(),hashlib.sha256).digest()).decode().rstrip('=')
sql("UPDATE oauth_flows SET encrypted_verifier='AA' WHERE state_digest='"+digest+"'",'OAUTH_DB')
check('corrupt encrypted custody fails closed',call('consume',{'provider':'g4','state':flow['state']})=={'RuntimeFailure':True})
check('decryption failure does not restore consumed state',call('consume',{'provider':'g4','state':flow['state']})=={'Err':'already_consumed'})
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
