import re

from lib.settings import HTTP_HEADER

__product__ = "Signal Sciences WAF (Fastly/Signal Sciences)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"sigsci", re.I),
        re.compile(r"signal sciences", re.I),
        re.compile(r"x-sigsci-", re.I),
    )

    for key, value in headers.items():
        for detection in detection_schemas:
            if detection.search(str(key)) is not None:
                return True
            if detection.search(str(value)) is not None:
                return True

    if status in (403, 406):
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    return False
