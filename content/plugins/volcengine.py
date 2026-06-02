import re
from lib.settings import HTTP_HEADER

__product__ = "Volcengine WAF (ByteDance/火山引擎)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"volcengine", re.I),
        re.compile(r"bytedance", re.I),
        re.compile(r"火山引擎", re.I),
        re.compile(r"vewaf", re.I),
    )
    for key, value in headers.items():
        for d in detection_schemas:
            if d.search(str(key)) is not None or d.search(str(value)) is not None:
                return True
    server = headers.get(HTTP_HEADER.SERVER, "")
    if "volc" in str(server).lower() and status in (403, 405):
        return True
    if status == 403:
        for d in detection_schemas:
            if d.search(content) is not None:
                return True
    return False
