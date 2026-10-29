"""Publish only Google's public signing certificates, never user data or credentials."""
import json, re, ssl, time
from pathlib import Path
from urllib.request import urlopen, Request

UPSTREAM = 'https://www.googleapis.com/oauth2/v1/certs'

def envelope(body, cache_control, age, now):
    certs = json.loads(body)
    if not isinstance(certs, dict) or not 1 <= len(certs) <= 16:
        raise ValueError('Unexpected Google certificate map')
    for key, pem in certs.items():
        if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', key):
            raise ValueError('Unexpected certificate key')
        if not isinstance(pem, str) or not pem.startswith('-----BEGIN CERTIFICATE-----\n'):
            raise ValueError('Unexpected certificate')
        ssl.PEM_cert_to_DER_cert(pem)
    match = re.search(r'(?:^|,)\s*max-age=(\d+)', cache_control)
    if not match:
        raise ValueError('Missing upstream cache expiry')
    remaining = min(3600, int(match.group(1)) - int(age or '0'))
    if remaining < 300:
        raise ValueError('Upstream response expires too soon')
    return {'fetched_at': now, 'expires_at': now + remaining, 'certificates': certs}

def main():
    with urlopen(Request(UPSTREAM, headers={'Accept':'application/json'}), timeout=20) as response:
        if response.status != 200 or response.url != UPSTREAM:
            raise ValueError('Unexpected upstream response')
        body = response.read(131073)
        if len(body) > 131072:
            raise ValueError('Response exceeds size limit')
        data = envelope(body, response.headers.get('Cache-Control',''), response.headers.get('Age','0'), int(time.time()))
    target = Path('google-certs.json')
    temp = target.with_suffix('.tmp')
    temp.write_text(json.dumps(data, sort_keys=True, separators=(',',':')) + '\n')
    temp.replace(target)
    print('Updated public certificates:', len(data['certificates']), 'expires_at:', data['expires_at'])

if __name__ == '__main__':
    main()
