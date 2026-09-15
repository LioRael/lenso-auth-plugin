#!/usr/bin/env python3
"""Expiry and unavailable-dependency qualification on dedicated real D1 bindings."""
import base64, hashlib, json, secrets, time, uuid
from qualification import call, ok, check, checks, future, auth
suffix=uuid.uuid4().hex
subject=ok('ensure_identity',{'provider':'proof','external_subject':suffix})['subject']
phone='+1555'+str(int(suffix[:10],16)%10000000).zfill(7)
expired_otp=ok('phone.start_otp',{'phone':phone,'purpose':'register','client_ip':'203.0.113.'+str(int(suffix[:2],16))})
started=time.monotonic()
verifier=secrets.token_urlsafe(48)
challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
code=ok('oidc.authorize',dict(subject=subject,client_id='proof-client',redirect_uri='https://client.proof.invalid/callback',response_type='code',scope='openid',state=None,nonce=None,code_challenge=challenge,code_challenge_method='S256'))
token=ok('api.issue',dict(subject=subject,actor_kind='service',assurance='api_token',audience=['proof.resource@1:read'],claims={},expires_at=future(5)))
wrong=ok('phone.start_otp',{'phone':'+1556'+phone[-7:],'purpose':'register','client_ip':'198.51.100.'+str(int(suffix[2:4],16))})
wrong_code='000000' if wrong['debug_code']!='000000' else '111111'
request=dict(challenge_id=wrong['challenge_id'],code=wrong_code,device_id=None)
check('Phone wrong OTP attempt one',call('phone.verify_otp',request)=={'Err':'invalid_code'})
check('Phone wrong OTP attempt two',call('phone.verify_otp',request)=={'Err':'invalid_code'})
check('Phone OTP attempt limit is exact',call('phone.verify_otp',request)=={'Err':'too_many_attempts'})
check('Phone correct OTP cannot bypass exhausted attempts',call('phone.verify_otp',{**request,'code':wrong['debug_code']})=={'Err':'too_many_attempts'})
for operation,request in [
 ('password.login',dict(identifier='missing-'+suffix,password='invalid-password')),
 ('phone.password_login',dict(phone='+1557'+phone[-7:],password='invalid-password',device_id=None)),
 ('device.list',dict(subject=subject)),
 ('api.authenticate',{'credential':{'scheme':'bearer','value':'invalid'}}),
 ('oidc.metadata',{}),
]:
 for fault in ['method-storage','method-missing-binding']:
  failed=False
  try:call(operation,request,fault=fault)
  except AssertionError as e:failed=str(e)=='HTTP 503'
  check(operation+' fails closed for '+fault,failed)
 result=call(operation,request)
 check(operation+' recovers after unavailable binding', 'RuntimeFailure' not in result)
# Expiry is measured from challenge creation, independent of host build/boot speed.
remaining=75-(time.monotonic()-started)
if remaining>0:time.sleep(remaining)
check('Phone expired OTP rejected',call('phone.verify_otp',dict(challenge_id=expired_otp['challenge_id'],code=expired_otp['debug_code'],device_id=None))=={'Err':'expired'})
check('OIDC expired authorization code rejected',call('oidc.exchange',dict(client_id='proof-client',redirect_uri='https://client.proof.invalid/callback',grant_type='authorization_code',code=code['code'],code_verifier=verifier))=={'Err':'invalid_grant'})
check('API Token expired credential rejected',call('api.authenticate',{'credential':{'scheme':'bearer','value':token['credential']}})=={'Err':'expired'})
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
