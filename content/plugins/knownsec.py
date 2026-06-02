import re

from lib.settings import HTTP_HEADER

__product__ = "KnownSec WAF (KnownSec)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"knownsec", re.I),
        re.compile(r"ks-waf", re.I),
        re.compile(r"knowsec", re.I),
    )

    for key, value in headers.items():
        for detection in detection_schemas:
            if detection.search(str(key)) is not None or detection.search(str(value)) is not None:
                return True

    if status == 403:
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    return False
