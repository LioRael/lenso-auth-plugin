#!/usr/bin/env python3
"""Private real-D1 qualification; emits assertions only, never credentials."""
import concurrent.futures, datetime, json, os, time, urllib.request, urllib.error, uuid
URL=os.environ.get('G4_URL','https://lenso-workers-g4-proof.lenso.workers.dev')
KEY=json.load(open(os.environ.get('G4_SECRETS','/tmp/lenso-workers-g4-secrets.json')))['PROOF_KEY']
from transport import opener
checks=[]
def check(name, value):
    assert value, name
    checks.append(name)
def call(operation, request, denied=False, fault=None):
    req=urllib.request.Request(URL+'/?probe='+str(uuid.uuid4()),json.dumps(dict(operation=operation,request=request,denied=denied)).encode(),headers={'content-type':'application/json','x-proof-key':KEY,'User-Agent':'Lenso-G4-Qualification/1.0',**({'x-proof-fault':fault} if fault else {})})
    try:
        with opener.open(req, timeout=30) as r: response=json.load(r)
    except urllib.error.HTTPError as e:
        raise AssertionError('HTTP '+str(e.code)) from None
    assert response.get('ready') and response.get('shutdown')=='clean', 'event lifecycle'
    return response['outcome']
def ok(op,req):
    r=call(op,req); assert 'Ok' in r, op+' success'; return r['Ok']
def future(seconds=3600):return (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=seconds)).isoformat().replace('+00:00','Z')
def issue(subject):return dict(subject=subject,actor_kind='user',assurance='oidc',audience=['proof.resource@1:read','proof.other@1:read'],claims={},expires_at=future())
def auth(token):return call('authenticate',{'credential':{'scheme':'session','value':token}})
def parallel(fn,n=8):
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:return list(pool.map(fn,range(n)))
