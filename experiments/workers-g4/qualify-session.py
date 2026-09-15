#!/usr/bin/env python3
"""Actual WebSession/OIDC/Ingress/Egress, controlled IdP, redacted evidence."""
import json,urllib.request,urllib.error,urllib.parse
from qualification import URL,KEY,checks,check,call,auth
from transport import opener
def http(url,method='GET',headers=None):
 req=urllib.request.Request(url,method=method,headers={'x-proof-key':KEY,'User-Agent':'Lenso-G4-Qualification/1.0',**(headers or {})})
 try:r=opener.open(req,timeout=30)
 except urllib.error.HTTPError as e:r=e
 return r.code,r.headers,r.read()
status,h,b=http(URL+'/auth/oidc/start?return_to=%2Fqualification')
check('WebSession start reaches actual OIDC Client',status==302)
status,h,b=http(h['location'])
check('controlled IdP authorization issues PKCE-bound code',status==302)
callback=h['location']
status,h,b=http(callback)
check('actual RSA/JWKS/token verification completes session issuance',status==303)
check('safe callback return',h['location']=='/qualification')
cookies=h.get_all('set-cookie')
check('separate secure cookie fields',len(cookies)==2 and all('Secure' in c and 'SameSite=Lax' in c and 'Path=/' in c for c in cookies))
session=next(c for c in cookies if c.startswith('__Host-session='));csrf=next(c for c in cookies if c.startswith('__Host-csrf='))
check('session is HttpOnly and CSRF readable', 'HttpOnly' in session and 'HttpOnly' not in csrf)
token=session.split(';')[0].split('=',1)[1];csrf_value=csrf.split(';')[0].split('=',1)[1]
check('issued cookie authenticates through Account and Router',auth(token)['Ok']['kind']=='authenticated')
r=call('verify_target',{'credential':{'scheme':'session','value':token}})
check('target SDK verifies signature and audience',r['valid'] and r['wrong_audience_rejected'])
status,_,_=http(callback)
check('OIDC state cannot be replayed',status==400)
cookie=session.split(';')[0]+'; '+csrf.split(';')[0]
status,_,_=http(URL+'/auth/logout','POST',{'cookie':cookie})
check('Ingress blocks logout without CSRF header',status==403)
check('CSRF rejection did not revoke credential',auth(token)['Ok']['kind']=='authenticated')
status,h,_=http(URL+'/auth/logout','POST',{'cookie':cookie,'x-csrf-token':csrf_value})
check('shared WebSession logout revokes credential',status==204 and all('Max-Age=0' in c for c in h.get_all('set-cookie')))
check('revocation visible in fresh Account event',auth(token)=={'Err':'revoked'})
print(json.dumps({'passed':len(checks),'checks':checks,'identity_provider':'controlled qualification fixture; external provider not qualified'},indent=2))
