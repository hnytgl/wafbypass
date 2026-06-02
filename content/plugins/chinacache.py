import re
from lib.settings import HTTP_HEADER

__product__ = "ChinaCache CDN WAF (ChinaCache)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    server = headers.get(HTTP_HEADER.SERVER, "")
    powered = headers.get(HTTP_HEADER.X_POWERED_BY, "")
    via = headers.get(HTTP_HEADER.VIA, "")

    if "chinacache" in str(server).lower() or "chinacache" in str(via).lower():
        if status == 403:
            return True

    detection_schemas = (
        re.compile(r"chinacache", re.I),
        re.compile(r"ccwaf", re.I),
        re.compile(r"cc-cache", re.I),
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
