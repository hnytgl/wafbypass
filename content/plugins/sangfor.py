import re

from lib.settings import HTTP_HEADER

__product__ = "Sangfor Web Application Firewall (Sangfor Technologies)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"sangfor", re.I),
        re.compile(r"x-sangfor", re.I),
    )

    for key, value in headers.items():
        for detection in detection_schemas:
            if detection.search(str(key)) is not None or detection.search(str(value)) is not None:
                return True

    if status in (403, 405):
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    server = headers.get(HTTP_HEADER.SERVER, "")
    if "sangfor" in str(server).lower():
        return True

    return False
