import re

from lib.settings import HTTP_HEADER

__product__ = "NAXSI Web Application Firewall (NBS System)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"naxsi", re.I),
        re.compile(r"blocked by naxsi", re.I),
        re.compile(r"x-nbs", re.I),
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
    if "naxsi" in str(server).lower() and status in (403, 418):
        return True

    return False
