#!/usr/bin/env python3
"""Real OIDC Fetch abandonment on the isolated G4 Worker; redacted evidence."""
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from qualification import URL, KEY, check, checks, auth
from transport import opener


def http(url, data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers={
        'x-proof-key': KEY, 'User-Agent': 'Lenso-G4-Qualification/1.0', **(headers or {})})
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    return response.code, response.headers, response.read()


status, headers, _ = http(URL + '/auth/oidc/start?return_to=%2Fqualification')
check('actual WebSession starts pending-egress qualification', status == 302)
status, headers, _ = http(headers['location'])
check('controlled IdP provides a valid callback before abandonment', status == 302)
callback = urllib.parse.urlsplit(headers['location'])
request = {'method': 'GET', 'uri': callback.path + '?' + callback.query, 'headers': [], 'body': []}
status, _, body = http(URL + '/', json.dumps(request).encode(), {
    'content-type': 'application/json', 'x-proof-http': '1', 'x-proof-fault': 'egress-abandon'})
result = json.loads(body)
check('pending actual OIDC Fetch fails with generation abandonment',
      status == 503 and result.get('runtime_failure') and 'abandoned' in result.get('detail', ''))
check('native Fetch started and owner finalizer aborted its signal',
      result.get('egress_proof') == {'started': True, 'aborted': True})
# The controlled token endpoint delays its response 750 ms, beyond the forced
# reset. A subsequent actual Rust graph must remain healthy after that response.
time.sleep(1)
result = auth('g4-deliberately-invalid-session')
check('fresh Account Router graph is healthy after late IdP completion', isinstance(result, dict) and 'Err' in result)
print(json.dumps({'passed': len(checks), 'checks': checks,
                  'scope': 'actual controlled OIDC Fetch; external IdP remains unqualified'}, indent=2))
