import re

from lib.settings import HTTP_HEADER

__product__ = "GCP Cloud Armor (Google Cloud Platform)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", {})
    content = str(content)
    status = kwargs.get("status", 0)

    detection_schemas = (
        re.compile(r"x-cloud-trace-context", re.I),
        re.compile(r"cloud armor", re.I),
        re.compile(r"google frontend", re.I),
    )

    server = headers.get(HTTP_HEADER.SERVER, "")
    via = headers.get(HTTP_HEADER.VIA, "")

    if "google" in str(server).lower() or "gfe" in str(server).lower() or "gws" in str(server).lower():
        if status in (403, 429, 502):
            if "blocked" in content.lower() or "forbidden" in content.lower():
                return True

    if "google frontend" in str(via).lower() and status == 403:
        return True

    for detection in detection_schemas:
        if detection.search(content) is not None:
            if status in (403, 429):
                return True
        if detection.search(str(headers).lower()) is not None:
            return True

    for key in headers.keys():
        if "x-goog-" in key.lower() or "x-gfe" in key.lower():
            if status == 403:
                return True

    return False
