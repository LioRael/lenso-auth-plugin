#!/usr/bin/env python3
"""Real Workers method qualification. Outputs check names, never credentials."""
import base64, hashlib, json, secrets, uuid, sys
from qualification import check as record_check, checks, call, ok, auth, parallel, future

def check(name, value):
    record_check(name, value)
    print("PASS " + name, file=sys.stderr, flush=True)

suffix = uuid.uuid4().hex
password = secrets.token_urlsafe(24)
identifier = 'proof-' + suffix
registered = ok('password.register', dict(identifier=identifier, password=password))
check('Password issued session authenticates', auth(registered['credential'])['Ok']['kind'] == 'authenticated')
check('Password duplicate is rejected', call('password.register', dict(identifier=identifier, password=password)) == {'Err': 'identifier_taken'})
check('Password login persists across events', ok('password.login', dict(identifier=identifier, password=password))['subject'] == registered['subject'])
failures = parallel(lambda _: call('password.login', dict(identifier=identifier, password='incorrect-password')), 6)
check('Password concurrent failures admit exactly three attempts', sum(r == {'Err': 'invalid_credentials'} for r in failures) == 3)
check('Password remaining attempts rate limited', all(r.get('Err') in ('invalid_credentials', 'rate_limited') for r in failures))
check('Password correct secret cannot bypass lockout', call('password.login', dict(identifier=identifier, password=password)) == {'Err': 'rate_limited'})

subject = registered['subject']
def observe(device): return dict(subject=subject, device_id=device, client_ip='192.0.2.1', user_agent='qualification')
observed = parallel(lambda _: call('device.observe', observe('device-a')), 6)
check('Device concurrent creation has one creator', sum(r.get('Ok', {}).get('created', False) for r in observed) == 1)
ok('device.observe', observe('device-b'))
promotions = parallel(lambda i: call('device.set_trust', dict(subject=subject, device_id=['device-a','device-b'][i % 2], trusted=True, primary=True)), 6)
check('Device concurrent promotions all succeed', all(r.get('Ok', {}).get('changed') for r in promotions))
devices = ok('device.list', dict(subject=subject))['devices']
check('Device concurrent promotion has exactly one primary', sum(d['primary'] for d in devices) == 1)
previous = next(d['device_id'] for d in devices if d['primary'])
check('Device missing promotion reports unchanged', call('device.set_trust', dict(subject=subject, device_id='missing', trusted=True, primary=True)) == {'Err':'not_found'})
check('Device missing promotion preserves current primary', next(d['device_id'] for d in ok('device.list', dict(subject=subject))['devices'] if d['primary']) == previous)

phone = '+1555' + str(int(suffix[:10], 16) % 10000000).zfill(7)
challenge = ok('phone.start_otp', dict(phone=phone, purpose='register', client_ip='192.0.2.' + str(int(suffix[:2], 16))))
check('Phone cooldown rejects immediate resend', call('phone.start_otp', dict(phone=phone, purpose='register', client_ip='198.51.100.2')) == {'Err': 'resend_too_soon'})
verified = parallel(lambda _: call('phone.verify_otp', dict(challenge_id=challenge['challenge_id'], code=challenge['debug_code'], device_id=None)), 4)
check('Phone OTP has one concurrent consumer', sum('Ok' in r for r in verified) == 1)
check('Phone OTP replay rejected', all('Ok' in r or r == {'Err': 'invalid_challenge'} for r in verified))
phone_session = next(r['Ok'] for r in verified if 'Ok' in r)
check('Phone OTP session authenticates', auth(phone_session['credential'])['Ok']['kind'] == 'authenticated')
check('Phone set password denies untrusted caller', call('phone.set_password', dict(subject=phone_session['subject'], password=password), denied=True) == {'Err':'forbidden'})
check('Phone set password permits configured caller', ok('phone.set_password', dict(subject=phone_session['subject'], password=password))['updated'])
check('Phone password login persists', ok('phone.password_login', dict(phone=phone, password=password, device_id=None))['subject'] == phone_session['subject'])
failures = parallel(lambda _: call('phone.password_login', dict(phone=phone, password='incorrect-password', device_id=None)), 6)
check('Phone concurrent password failures admit exactly three attempts', sum(r == {'Err':'invalid_credentials'} for r in failures) == 3)
check('Phone password lockout enforced', call('phone.password_login', dict(phone=phone, password=password, device_id=None)) == {'Err':'rate_limited'})

spec = dict(subject=subject, actor_kind='service', assurance='api_token', audience=['proof.resource@1:read'], claims={}, expires_at=future())
token = ok('api.issue', spec)
def api_auth(token): return call('api.authenticate', {'credential':{'scheme':'bearer','value':token['credential']}})
check('API Token authenticates through Router', api_auth(token)['Ok']['kind'] == 'authenticated')
projection = call('api.verify_target', {'credential':{'scheme':'bearer','value':token['credential']}})
check('API Token target verifies signature and rejects wrong audience', projection['valid'] and projection['wrong_audience_rejected'])
check('API Token revocation changes persisted token', ok('api.revoke_token', dict(id=token['token_id']))['changed'])
check('API Token revoked credential rejected', api_auth(token) == {'Err':'revoked'})
check('API Token revocation is idempotent', not ok('api.revoke_token', dict(id=token['token_id']))['changed'])
token = ok('api.issue', spec)
check('API Token session revocation persists', ok('api.revoke_session', dict(id=token['session_id']))['changed'])
check('API Token session revocation rejects credential', api_auth(token) == {'Err':'revoked'})

verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
authorize = dict(subject=subject, client_id='proof-client', redirect_uri='https://client.proof.invalid/callback', response_type='code', scope='openid', state='proof-state', nonce='proof-nonce', code_challenge=challenge, code_challenge_method='S256')
check('OIDC Provider rejects untrusted authorization caller', call('oidc.authorize', authorize, denied=True) == {'Err':'forbidden'})
code = ok('oidc.authorize', authorize)
exchange = dict(client_id='proof-client', redirect_uri=authorize['redirect_uri'], grant_type='authorization_code', code=code['code'], code_verifier=verifier)
check('OIDC wrong PKCE is rejected', call('oidc.exchange', {**exchange,'code_verifier':secrets.token_urlsafe(48)}) == {'Err':'invalid_grant'})
results = parallel(lambda _: call('oidc.exchange', exchange), 4)
check('OIDC authorization code has one concurrent consumer', sum('Ok' in r for r in results) == 1)
check('OIDC replay rejected', all('Ok' in r or r == {'Err':'invalid_grant'} for r in results))
tokens = next(r['Ok'] for r in results if 'Ok' in r)
check('OIDC access token authenticates', auth(tokens['access_token'])['Ok']['kind'] == 'authenticated')
check('OIDC metadata issuer preserved', ok('oidc.metadata', {})['issuer'] == 'https://oidc.proof.invalid')
check('OIDC public JWKS contains configured key', ok('oidc.jwks', {})['jwks']['keys'][0]['kid'] == 'proof-rsa')
import subprocess
from pathlib import Path
jwk = ok('oidc.jwks', {})['jwks']['keys'][0]
def decode64(value): return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
header, payload, signature = tokens['id_token'].split('.')
verified = subprocess.run(['node', str(Path(__file__).with_name('verify-jwt.mjs'))],
    input=json.dumps({'token':tokens['id_token'],'jwk':jwk}),text=True,capture_output=True)
assert verified.returncode == 0, 'OIDC independent RS256 verification'
claims = json.loads(decode64(payload))
check('OIDC ID token RS256 signature independently verifies', json.loads(decode64(header))['alg'] == 'RS256')
check('OIDC ID token preserves issuer audience subject nonce', claims['iss']=='https://oidc.proof.invalid' and claims['aud']=='proof-client' and claims['sub']==subject and claims['nonce']=='proof-nonce')

print(json.dumps({'passed':len(checks),'checks':checks,'sms':'controlled delivery fixture'}, indent=2))
