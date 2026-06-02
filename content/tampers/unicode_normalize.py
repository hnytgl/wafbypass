import unicodedata

__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "unicode normalization bypass transforming characters to their unicode equivalents"


def tamper(payload, **kwargs):
    if payload:
        retval = unicodedata.normalize('NFKD', payload)
        return retval
    return payload
