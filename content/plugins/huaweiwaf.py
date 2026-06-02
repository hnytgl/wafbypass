import re

from lib.settings import HTTP_HEADER

__product__ = "Huawei Cloud WAF (Huawei)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"huawei", re.I),
        re.compile(r"hwwaf", re.I),
        re.compile(r"huaweicloud waf", re.I),
    )

    for key, value in headers.items():
        for detection in detection_schemas:
            if detection.search(str(key)) is not None or detection.search(str(value)) is not None:
                return True

    if status in (403, 418):
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    server = headers.get(HTTP_HEADER.SERVER, "")
    if "huawei" in str(server).lower() and status == 403:
        return True

    return False
