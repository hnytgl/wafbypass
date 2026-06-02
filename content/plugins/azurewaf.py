import re

from lib.settings import HTTP_HEADER

__product__ = "Azure Application Gateway WAF (Microsoft)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    detection_schemas = (
        re.compile(r"request has been blocked by the application gateway", re.I),
        re.compile(r"microsoft-azure-application-gateway", re.I),
        re.compile(r"x-ms-request-id", re.I),
        re.compile(r"azure web application firewall", re.I),
        re.compile(r"x-azure-ref", re.I),
    )
    status = kwargs.get("status", 0)

    server = headers.get(HTTP_HEADER.SERVER, "")
    x_powered = headers.get(HTTP_HEADER.X_POWERED_BY, "")
    x_ms_req = headers.get("X-Ms-Request-Id", "")
    set_cookie = headers.get(HTTP_HEADER.SET_COOKIE, "")

    if x_ms_req:
        for detection in detection_schemas:
            if detection.search(content) is not None:
                return True
            if detection.search(server) is not None:
                return True
        if status == 403 and "microsoft" in str(headers).lower():
            return True

    if "azure" in x_powered.lower() and status in (403, 502):
        return True

    if "azure" in str(server).lower() and "blocked" in content.lower():
        return True

    if "ARR/3.0" in str(server) and status == 403:
        return True

    return False
