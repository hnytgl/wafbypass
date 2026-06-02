__example_payload__ = "' UNION SELECT NULL--"
__type__ = "content-type manipulation swapping between different content types"


def tamper(payload, **kwargs):
    content_types = [
        "application/json",
        "text/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    ]
    return payload
