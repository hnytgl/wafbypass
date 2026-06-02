import random

__example_payload__ = "' AND 1=1--"
__type__ = "HTTP parameter pollution to bypass WAF"


def tamper(payload, **kwargs):
    if "=" in payload:
        parts = payload.split("=", 1)
        retval = "{}={}&{}={}".format(parts[0], parts[1], parts[0], parts[1])
        return retval
    return payload
