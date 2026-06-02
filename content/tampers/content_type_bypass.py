import random

__example_payload__ = "' UNION SELECT NULL--"
__type__ = "content-type bypass: adds content-type switching params to evade WAF parsing"


def tamper(payload, **kwargs):
    if not payload:
        return payload
    strategies = [
        lambda s: "{}&content-type=application/json".format(s),
        lambda s: "{}&format=json".format(s),
        lambda s: "{}&_format=xml".format(s),
    ]
    return random.choice(strategies)(payload)
