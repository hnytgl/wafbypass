import re
from lib.settings import HTTP_HEADER

__product__ = "DBAPP Security WAF (安恒信息)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"dbappsecurity", re.I),
        re.compile(r"dbapp", re.I),
        re.compile(r"安恒", re.I),
        re.compile(r"明御", re.I),
        re.compile(r"mingyu", re.I),
    )
    for key, value in headers.items():
        for d in detection_schemas:
            if d.search(str(key)) is not None or d.search(str(value)) is not None:
                return True
    server = headers.get(HTTP_HEADER.SERVER, "")
    if "dbapp" in str(server).lower() or "mingyu" in str(server).lower():
        return True
    if status in (403, 405):
        for d in detection_schemas:
            if d.search(content) is not None:
                return True
    return False
