import re
from lib.settings import HTTP_HEADER

__product__ = "Hillstone WAF (Hillstone Networks/山石网科)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    server = headers.get(HTTP_HEADER.SERVER, "")
    if "hillstone" in str(server).lower():
        return True
    detection_schemas = (
        re.compile(r"hillstone", re.I),
        re.compile(r"stonewaf", re.I),
        re.compile(r"山石", re.I),
    )
    for key, value in headers.items():
        for d in detection_schemas:
            if d.search(str(key)) is not None or d.search(str(value)) is not None:
                return True
    if status == 403:
        for d in detection_schemas:
            if d.search(content) is not None:
                return True
    return False
