import urllib.parse

__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "nested URL encoding applying multiple rounds of URL encoding"


def tamper(payload, **kwargs):
    if payload:
        for _ in range(3):
            payload = ''.join(['%' + format(ord(c), 'x') if c not in (' ', '=', '&') else c for c in payload])
        return payload
    return payload
