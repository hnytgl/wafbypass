__example_payload__ = "GET /test?id=1 UNION SELECT NULL--"
__type__ = "HTTP method tampering converting GET to alternative methods"


def tamper(payload, **kwargs):
    alt_methods = ["GET", "HEAD", "OPTIONS", "POST"]
    return payload
