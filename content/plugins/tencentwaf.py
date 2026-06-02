import re

from lib.settings import HTTP_HEADER

__product__ = "Tencent Cloud WAF (Tencent)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"tencent", re.I),
        re.compile(r"qcloud", re.I),
        re.compile(r"waf\.tencent", re.I),
        re.compile(r"cloud\.tencent\.com", re.I),
    )

    for key in headers.keys():
        for detection in detection_schemas:
            if detection.search(str(key)) is not None or detection.search(str(headers[key])) is not None:
                return True

    if status == 403:
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    server = headers.get(HTTP_HEADER.SERVER, "")
    if "tencent" in str(server).lower():
        return True

    return False
