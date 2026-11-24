"""Bounded registry evidence. Never fetch the submitted website itself."""
import json
from pathlib import Path
from urllib.parse import urlsplit, quote
import httpx

BOOTSTRAP = json.loads(Path(__file__).with_name('rdap-bootstrap.json').read_text())

async def bounded_json(client, url, **kwargs):
    async with client.stream('GET', url, **kwargs) as response:
        response.raise_for_status()
        if response.is_redirect:
            raise ValueError('Redirected evidence request')
        data = bytearray()
        async for chunk in response.aiter_bytes():
            data.extend(chunk)
            if len(data) > 262144:
                raise ValueError('Evidence response too large')
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError('Invalid evidence schema')
        return value

async def domain_evidence(client, url):
    host = urlsplit(url).hostname or ''
    tld = host.rsplit('.', 1)[-1]
    endpoint = next((base for suffixes, bases in BOOTSTRAP['services'] if tld in suffixes for base in bases if base.startswith('https://')), None)
    if not endpoint:
        return {'source': 'RDAP', 'status': 'unavailable', 'reason': 'No supported registry endpoint'}
    # COM and NET register at the second level. Other TLDs use the complete
    # submitted host rather than guessing a registrable domain.
    domain = '.'.join(host.split('.')[-2:]) if tld in ('com', 'net') else host
    lookup = endpoint.rstrip('/') + '/domain/' + quote(domain, safe='')
    try:
        record = await bounded_json(client, lookup, timeout=2)
        dates = [{'event': x.get('eventAction'), 'date': x.get('eventDate')}
                 for x in record.get('events', []) if isinstance(x, dict)
                 and x.get('eventAction') in ('registration', 'expiration', 'last changed')][:8]
        return {'source': 'RDAP registry', 'status': 'available', 'domain': domain,
                'url': lookup, 'events': dates,
                'reason': 'Registration dates are context only. A new or old domain does not prove fraud or safety.'}
    except (httpx.HTTPError, ValueError, TypeError):
        return {'source': 'RDAP', 'status': 'unavailable', 'domain': domain,
                'reason': 'Registry evidence unavailable; no safety conclusion can be drawn.'}
