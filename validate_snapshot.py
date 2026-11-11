"""Reject stale, malformed or invalid public signing keys before Pages publication."""
import calendar,datetime,json,re,subprocess,sys,time
from pathlib import Path

def validate(body,now=None):
    now=int(time.time()) if now is None else now
    if len(body)>131072:raise ValueError('Snapshot exceeds size limit')
    data=json.loads(body)
    if not isinstance(data,dict):raise ValueError('Expected an envelope')
    fetched,expires=data.get('fetched_at'),data.get('expires_at')
    if type(fetched) is not int or type(expires) is not int:raise ValueError('Invalid timestamp type')
    if fetched>now+30 or fetched<now-3600 or expires<=fetched or expires>fetched+3600 or expires-now<300:
        raise ValueError('Snapshot invalid or expires too soon')
    certificates=data.get('certificates')
    if not isinstance(certificates,dict) or not 1<=len(certificates)<=16:raise ValueError('Invalid certificate map')
    for kid,pem in certificates.items():
        if not isinstance(kid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',kid):raise ValueError('Invalid key identifier')
        if not isinstance(pem,str) or not pem.startswith('-----BEGIN CERTIFICATE-----\n') or len(pem)>16384:raise ValueError('Invalid certificate PEM')
        result=subprocess.run(['openssl','x509','-noout','-dates'],input=pem.encode('ascii'),capture_output=True,check=True)
        dates=dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines())
        parse=lambda value:calendar.timegm(datetime.datetime.strptime(value,'%b %d %H:%M:%S %Y %Z').timetuple())
        if parse(dates['notBefore'])>now or parse(dates['notAfter'])<=now:raise ValueError('X.509 certificate not currently valid')
    return {'certificate_count':len(certificates),'seconds_remaining':expires-now}

if __name__=='__main__':
    print(json.dumps(validate(Path(sys.argv[1]).read_bytes()),sort_keys=True))
