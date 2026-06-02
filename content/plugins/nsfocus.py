import re

from lib.settings import HTTP_HEADER

__product__ = "NSFOCUS Web Application Firewall (NSFOCUS)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"nsfocus", re.I),
        re.compile(r"nsf\.?waf", re.I),
        re.compile(r"x-nsf", re.I),
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
