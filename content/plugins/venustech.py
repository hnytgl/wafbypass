import re
from lib.settings import HTTP_HEADER

__product__ = "Venustech WAF (Venustech/启明星辰)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"venustech", re.I),
        re.compile(r"venus", re.I),
        re.compile(r"启明星辰", re.I),
        re.compile(r"天清", re.I),
        re.compile(r"tianqing", re.I),
    )
    for key, value in headers.items():
        for d in detection_schemas:
            if d.search(str(key)) is not None or d.search(str(value)) is not None:
                return True
    server = headers.get(HTTP_HEADER.SERVER, "")
    if "venustech" in str(server).lower():
        return True
    if status == 403:
        for d in detection_schemas:
            if d.search(content) is not None:
                return True
    return False
