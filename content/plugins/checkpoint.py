import re
from lib.settings import HTTP_HEADER

__product__ = "Check Point WAF (Check Point Software)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"check.point", re.I),
        re.compile(r"checkpoint", re.I),
        re.compile(r"cp_waf", re.I),
    )
    for key, value in headers.items():
        for d in detection_schemas:
            if d.search(str(key)) is not None or d.search(str(value)) is not None:
                return True
    server = headers.get(HTTP_HEADER.SERVER, "")
    if "checkpoint" in str(server).lower() or "check point" in str(server).lower():
        return True
    if status == 403:
        for d in detection_schemas:
            if d.search(content) is not None:
                return True
    return False
