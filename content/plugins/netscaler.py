import re

from lib.settings import HTTP_HEADER

__product__ = "NetScaler AppFirewall (Citrix)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"netscaler", re.I),
        re.compile(r"ns_af", re.I),
        re.compile(r"citrix", re.I),
        re.compile(r"x-requested-with", re.I),
    )

    server = headers.get(HTTP_HEADER.SERVER, "")
    if "netscaler" in str(server).lower() or "citrix" in str(server).lower():
        if status in (403, 406):
            return True

    if status == 403:
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, "")
    if "ns_af" in str(set_cookie).lower():
        return True

    return False
