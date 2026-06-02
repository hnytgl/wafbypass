__example_payload__ = "id=1 UNION SELECT NULL--"
__type__ = "parameter fragmentation splitting payload across multiple parameters"


def tamper(payload, **kwargs):
    if "=" in payload:
        parts = payload.split("=", 1)
        param = parts[0]
        value = parts[1]
        mid = len(value) // 2
        first = value[:mid]
        second = value[mid:]
        return "{}=first_part&{}={}".format(param, param, first + second)
    return payload
