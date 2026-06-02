import re

from lib.settings import HTTP_HEADER

__product__ = "Fastly WAF (Fastly)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"fastly", re.I),
        re.compile(r"x-served-by", re.I),
        re.compile(r"x-cache-hits", re.I),
        re.compile(r"x-timer", re.I),
    )

    for detection in detection_schemas:
        if detection.search(content) is not None and status in (403, 406):
            return True

    server = headers.get(HTTP_HEADER.SERVER, "")
    via = headers.get(HTTP_HEADER.VIA, "")

    if "fastly" in str(server).lower() or "fastly" in str(via).lower():
        if status == 403:
            return True

    x_served_by = headers.get("X-Served-By", "")
    x_cache = headers.get("X-Cache", "")

    if x_served_by and x_cache and status == 403:
        if "blocked" in content.lower() or "forbidden" in content.lower():
            return True

    return False
