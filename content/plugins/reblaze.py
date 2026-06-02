import re

from lib.settings import HTTP_HEADER

__product__ = "Reblaze Web Application Firewall (Reblaze)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"reblaze", re.I),
        re.compile(r"rbzid", re.I),
        re.compile(r"rbz-sess", re.I),
    )

    cookie = headers.get(HTTP_HEADER.COOKIE, "")
    set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, "")

    if "rbzid" in cookie.lower() or "rbzid" in set_cookie.lower():
        return True

    for detection in detection_schemas:
        if detection.search(content) is not None:
            return True

    server = headers.get(HTTP_HEADER.SERVER, "")
    if "reblaze" in str(server).lower():
        return True

    if status == 403 and "rbz" in str(headers).lower():
        return True

    return False
