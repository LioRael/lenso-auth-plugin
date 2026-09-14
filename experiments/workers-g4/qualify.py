#!/usr/bin/env python3
"""Private real-D1 qualification; emits assertions only, never credentials."""
import json,time,uuid
from qualification import checks,check,call,ok,future,issue,auth,parallel
identity={'provider':'g4','external_subject':str(uuid.uuid4())}
rows=parallel(lambda _:ok('ensure_identity',identity))
subject=rows[0]['subject']
check('concurrent identity uniqueness',len({r['subject'] for r in rows})==1 and sum(r['created'] for r in rows)==1)
session=ok('issue',issue(subject)); token=session['credential']
check('issue and authenticate through Router',auth(token)['Ok']['assertion']['subject']==subject)
check('absent credential preserved',call('authenticate',{'credential':None})['Ok']['kind']=='absent')
check('unsupported credential preserved',call('authenticate',{'credential':{'scheme':'other','value':'x'}})=={'Err':'unsupported'})
check('admin caller guard',call('list_subjects',{'limit':10,'cursor':None},True)=={'Err':'forbidden'})
check('delegation caller guard',call('grant',{'parent_credential':token,'audience':['proof.resource@1:read'],'expires_at':future(600)},True)=={'Err':'permission_denied'})
check('delegation cannot broaden audience',call('grant',{'parent_credential':token,'audience':['outside@1'],'expires_at':future(600)})=={'Err':'invalid_scope'})
child=ok('grant',{'parent_credential':token,'audience':['proof.resource@1:read'],'expires_at':future(600)})
check('narrowed delegation authenticates',auth(child['credential'])['Ok']['assertion']['audience']==['proof.resource@1:read'])
check('nested delegation rejected',call('grant',{'parent_credential':child['credential'],'audience':['proof.resource@1:read'],'expires_at':future(300)})=={'Err':'nested_delegation'})
revocations=parallel(lambda _:ok('revoke',{'session_id':session['session_id']}))
check('concurrent revocation exactly one change',sum(r['changed'] for r in revocations)==1)
check('root revocation immediately visible',auth(token)=={'Err':'revoked'})
check('parent revocation invalidates delegation',auth(child['credential'])=={'Err':'revoked'})
status={'subject':subject,'status':'disabled','reason':'qualification','disabled_until':None}
races=parallel(lambda i:call('set_subject_status',status) if i==0 else call('issue',issue(subject)))
check('disable racing issue has documented outcomes',all('Ok' in r or r=={'Err':'disabled'} for r in races))
check('disabled subject rejects new issuance',call('issue',issue(subject))=={'Err':'disabled'})
check('sessions issued before disable are revoked',all(auth(r['Ok']['credential'])=={'Err':'revoked'} for r in races[1:] if 'Ok' in r))
check('disabled status visible',ok('read_status',{'subject':subject})['status']=='disabled')
ok('set_subject_status',dict(status,status='active',reason=None))
new=ok('issue',issue(subject))
check('reactivation allows new session',auth(new['credential'])['Ok']['kind']=='authenticated')
check('reactivation does not revive old credential',auth(token)=={'Err':'revoked'})
check('credential revoke succeeds',ok('revoke_credential',{'scheme':'session','credential':new['credential']})['changed'])
check('credential revoke idempotent',not ok('revoke_credential',{'scheme':'session','credential':new['credential']})['changed'])
check('pagination limits results',len(ok('list_sessions',{'subject':subject,'limit':1,'cursor':None})['sessions'])==1)
f=ok('create',{'provider':'g4','return_to':'/qualification','expires_at':future(300)})
check('flow provider mismatch preserves flow',call('consume',{'provider':'other','state':f['state']})=={'Err':'provider_mismatch'})
consumed=parallel(lambda _:call('consume',{'provider':'g4','state':f['state']}))
check('concurrent OAuth consume exactly once',sum('Ok' in r for r in consumed)==1 and sum(r=={'Err':'already_consumed'} for r in consumed)==7)
check('encrypted verifier roundtrip',next(r['Ok'] for r in consumed if 'Ok' in r)['code_verifier']==f['code_verifier'])
before=ok('list_sessions',{'subject':subject,'limit':200,'cursor':None})['sessions']
parent=ok('issue',issue(subject))
call('grant',{'parent_credential':parent['credential'],'audience':['outside@1:read'],'expires_at':future(300)})
call('grant',{'parent_credential':parent['credential'],'audience':['proof.resource@1:read'],'expires_at':future(300)},True)
after=ok('list_sessions',{'subject':subject,'limit':200,'cursor':None})['sessions']
check('denied grants create no session rows',len(after)==len(before)+1)
short=ok('issue',dict(issue(subject),expires_at=future(2)))
shortflow=ok('create',{'provider':'g4','return_to':'/qualification','expires_at':future(2)})
time.sleep(3)
check('expired session rejected on fresh event',auth(short['credential'])=={'Err':'expired'})
check('expired OAuth state rejected',call('consume',{'provider':'g4','state':shortflow['state']})=={'Err':'expired'})
ok('set_subject_status',dict(status,disabled_until=future(2)))
time.sleep(3)
check('temporary disable expires',ok('read_status',{'subject':subject})['status']=='active')
check('expired temporary disable permits usable issuance',auth(ok('issue',issue(subject))['credential'])['Ok']['kind']=='authenticated')
queued=ok('create',{'provider':'g4','return_to':'/qualification','expires_at':future(30)})
# Reach the expiry boundary after creation; TLS setup must not consume the creation TTL.
import datetime
remaining=(datetime.datetime.fromisoformat(queued['expires_at'].replace('Z','+00:00'))-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
time.sleep(max(0,remaining-1))
check('OAuth queued past expiry cannot consume',call('consume',{'provider':'g4','state':queued['state']},fault='delayed-consume')=={'Err':'expired'})
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
