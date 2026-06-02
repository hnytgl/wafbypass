import re
from lib.settings import HTTP_HEADER

__product__ = "Qianxin WAF (QiAnXin/奇安信)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"qianxin", re.I),
        re.compile(r"qax", re.I),
        re.compile(r"qianxin-waf", re.I),
        re.compile(r"奇安信", re.I),
        re.compile(r"天守", re.I),
    )
    for key, value in headers.items():
        for d in detection_schemas:
            if d.search(str(key)) is not None or d.search(str(value)) is not None:
                return True
    if status in (403, 405, 501):
        for d in detection_schemas:
            if d.search(content) is not None:
                return True
    return False
