import re

from lib.settings import HTTP_HEADER

__product__ = "OpenResty WAF (OpenResty/LuaNginx)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    server = headers.get(HTTP_HEADER.SERVER, "")
    x_powered = headers.get(HTTP_HEADER.X_POWERED_BY, "")

    if "openresty" in str(server).lower() or "openresty" in str(x_powered).lower():
        if status in (403, 405, 406):
            return True

    detection_schemas = (
        re.compile(r"openresty", re.I),
        re.compile(r"lua-resty", re.I),
        re.compile(r"ngx_waf", re.I),
    )

    for key, value in headers.items():
        for detection in detection_schemas:
            if detection.search(str(key)) is not None or detection.search(str(value)) is not None:
                return True

    if status in (403, 406):
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True

    return False
